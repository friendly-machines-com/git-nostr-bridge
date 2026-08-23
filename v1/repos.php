<?php
/**
 * Authenticated repository-to-30617 registration endpoint.
 * The publisher calls this after the announcement is visible on a relay.
 */
declare(strict_types=1);

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib/util.php';
require_once __DIR__ . '/lib/secrets.php';
require_once __DIR__ . '/lib/relay.php';
require_once __DIR__ . '/lib/repository.php';

header('Content-Type: application/json');
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit(json_encode(['error' => 'POST required']));
}

$provided = (string)($_SERVER['HTTP_X_BRIDGE_SECRET'] ?? '');
if ($provided === '' || !hash_equals(fm_secret_repo_registration(), $provided)) {
    http_response_code(403);
    exit(json_encode(['error' => 'invalid registration secret']));
}

$rawInput = file_get_contents('php://input');
if (!is_string($rawInput) || strlen($rawInput) > 32768) {
    http_response_code(413);
    exit(json_encode(['error' => 'request body too large']));
}
$input = json_decode($rawInput, true);
if (!is_array($input)) {
    http_response_code(400);
    exit(json_encode(['error' => 'invalid JSON']));
}

$full = is_string($input['github_full_name'] ?? null)
    ? $input['github_full_name'] : '';
$repoId = is_string($input['repo_id'] ?? null) ? $input['repo_id'] : '';
$ownerPk = is_string($input['owner_pubkey'] ?? null)
    ? strtolower($input['owner_pubkey']) : '';
$relayInput = $input['relays'] ?? null;
$relays = [];
if (is_array($relayInput) && array_is_list($relayInput)) {
    foreach ($relayInput as $relay) {
        if (!is_string($relay)) {
            $relays = [];
            break;
        }
        $relays[] = $relay;
    }
    $relays = relay_url_set($relays);
}

if (!preg_match('#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $full)
    || $repoId === '' || strlen($repoId) > 200
    || !is_hex64($ownerPk)
    || !$relays || count($relays) > 4) {
    http_response_code(422);
    exit(json_encode(['error' => 'invalid mapping fields']));
}

$owner = explode('/', $full, 2)[0];
$existingMapping = db()->prepare(
    'SELECT repo_id,owner_pubkey FROM repos WHERE github_full_name=?'
);
$existingMapping->execute([$full]);
$existingMapping = $existingMapping->fetch();
if ($existingMapping
    && (!hash_equals((string)$existingMapping['owner_pubkey'], $ownerPk)
        || !hash_equals((string)$existingMapping['repo_id'], $repoId))) {
    http_response_code(409);
    exit(json_encode([
        'error' => 'GitHub repository is already bound to another Nostr repository address',
    ]));
}

$accepted = db()->prepare(
    "SELECT 1
     FROM github_installation_repositories gir
     JOIN github_installations gi
       ON gi.installation_id=gir.installation_id
     WHERE gir.github_full_name=? AND gir.status='active'
       AND gi.account_login=? AND gi.status='active'
       AND gi.token_enc IS NOT NULL"
);
$accepted->execute([$full, $owner]);
if (!$accepted->fetchColumn()) {
    http_response_code(403);
    exit(json_encode([
        'error' => 'GitHub App is not authoritatively installed for repository',
    ]));
}
$bridgePk = fm_pubkey_hex(fm_secret_bridge_key());
$announcement = null;
$mappingVerified = relay_verify_repo_owner(
    $repoId,
    $ownerPk,
    $relays,
    null,
    $relays,
    $announcement
);
if ($mappingVerified === null) {
    http_response_code(503);
    exit(json_encode([
        'error' => 'could not complete repository verification on every relay',
    ]));
}
if (!$mappingVerified) {
    http_response_code(409);
    exit(json_encode([
        'error' => '30617 missing/invalid or registered relays differ from its relays tag',
    ]));
}
if (!is_array($announcement)) {
    http_response_code(503);
    exit(json_encode([
        'error' => 'verified announcement was not retained',
    ]));
}
$bridgeAuthorized = repo_announcement_authorizes(
    $announcement,
    $bridgePk
) ? 1 : 0;

$existingAddress = db()->prepare(
    "SELECT github_full_name FROM repos
     WHERE owner_pubkey=? AND repo_id=? AND github_full_name<>?"
);
$existingAddress->execute([$ownerPk, $repoId, $full]);
$conflictingFull = $existingAddress->fetchColumn();
if (is_string($conflictingFull) && $conflictingFull !== '') {
    http_response_code(409);
    exit(json_encode([
        'error' => 'Nostr repository address is already mapped to another GitHub repository',
        'github_full_name' => $conflictingFull,
    ]));
}

$t = now();
try {
    db()->prepare("INSERT INTO repos
                   (github_full_name,repo_id,owner_pubkey,relays,verified,
                    bridge_authorized,created_at,updated_at)
                   VALUES (?,?,?,?,1,?,?,?)
                   ON CONFLICT(github_full_name) DO UPDATE SET
                     relays=excluded.relays, verified=1,
                     bridge_authorized=excluded.bridge_authorized,
                     updated_at=excluded.updated_at
                   WHERE repos.repo_id=excluded.repo_id
                     AND repos.owner_pubkey=excluded.owner_pubkey")
       ->execute([
           $full, $repoId, $ownerPk, json_c($relays),
           $bridgeAuthorized, $t, $t,
       ]);
    if ((int)db()->query('SELECT changes()')->fetchColumn() !== 1) {
        http_response_code(409);
        exit(json_encode([
            'error' => 'GitHub repository mapping changed concurrently',
        ]));
    }
    $registered = db()->prepare(
        'SELECT * FROM repos WHERE github_full_name=?'
    );
    $registered->execute([$full]);
    $registered = $registered->fetch();
    if (!is_array($registered)
        || !repo_bank_announcement(
            $registered,
            $announcement,
            $bridgePk
        )) {
        throw new RuntimeException(
            'could not bank verified repository announcement'
        );
    }
    $active = db()->prepare(
        'SELECT verified FROM repos WHERE github_full_name=?'
    );
    $active->execute([$full]);
    if ((int)$active->fetchColumn() !== 1) {
        http_response_code(409);
        exit(json_encode([
            'error' => '30617 is tombstoned by a same-author address deletion',
        ]));
    }
} catch (PDOException $error) {
    if (!str_contains($error->getMessage(), 'UNIQUE')) throw $error;
    http_response_code(409);
    exit(json_encode([
        'error' => 'Nostr repository address is already mapped to another GitHub repository',
    ]));
}

echo json_encode([
    'ok' => true, 'github_full_name' => $full,
    'bridge_status_authorized' => (bool)$bridgeAuthorized,
]);

<?php
/**
 * Offline NIP-39 identity workflow tests.
 *
 * No GitHub, relay, or signer network access is permitted here. The seams
 * below exercise reducer ordering, complete-set preservation, reconfirmation,
 * durable one-signature recovery, and per-relay publication jobs.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') exit(1);

define('BRIDGE_ENTRY', true);
$dbPath = sys_get_temp_dir() . '/fm-nip39-' . getmypid() . '.db';
putenv('BRIDGE_DB=' . $dbPath);
foreach ([$dbPath, "$dbPath-wal", "$dbPath-shm"] as $file) @unlink($file);

$secrets = sys_get_temp_dir() . '/fm-nip39-secrets-' . getmypid();
@mkdir($secrets, 0700, true);
file_put_contents(
    "$secrets/db-crypt.php",
    '<?php return "' . bin2hex(random_bytes(32)) . '";'
);
file_put_contents(
    "$secrets/bridge-key.php",
    '<?php return "' . bin2hex(random_bytes(32)) . '";'
);
chmod("$secrets/db-crypt.php", 0600);
chmod("$secrets/bridge-key.php", 0600);
$GLOBALS['__fm_test_secrets_dir'] = $secrets;
$GLOBALS['__fm_test_log'] = sys_get_temp_dir()
    . '/fm-nip39-' . getmypid() . '.log';

$GLOBALS['__nip39_relay_events'] = [];
$GLOBALS['__nip39_published'] = [];
$GLOBALS['__nip39_sign_count'] = 0;

function relay_defaults(): array
{
    return ['wss://relay.damus.io', 'wss://nos.lol'];
}

function relay_query(array $filter, array $relays, float $timeout = 4.0): array
{
    $events = [];
    foreach ($GLOBALS['__nip39_relay_events'] as $event) {
        if (isset($filter['kinds'])
            && !in_array($event['kind'], $filter['kinds'], true)) {
            continue;
        }
        if (isset($filter['authors'])
            && !in_array($event['pubkey'], $filter['authors'], true)) {
            continue;
        }
        $matchesTags = true;
        foreach ($filter as $name => $values) {
            if (!is_string($name) || !str_starts_with($name, '#')) continue;
            $tagName = substr($name, 1);
            if (!array_filter(
                $event['tags'],
                static fn(array $tag): bool =>
                    ($tag[0] ?? null) === $tagName
                    && in_array($tag[1] ?? null, $values, true)
            )) {
                $matchesTags = false;
                break;
            }
        }
        if ($matchesTags) $events[$event['id']] = $event;
    }
    return [array_values($events), true];
}

function relay_publish(
    array $event,
    array $relays,
    float $timeout = 6.0
): array {
    $relay = $relays[0] ?? '';
    $GLOBALS['__nip39_published'][$relay][$event['id']] = $event;
    return [$relay => 'ok'];
}

function relay_find_event(string $id, array $relays): ?array
{
    foreach ($relays as $relay) {
        if (isset($GLOBALS['__nip39_published'][$relay][$id])) {
            return $GLOBALS['__nip39_published'][$relay][$id];
        }
    }
    return null;
}

function bridge_nip39_sign_event(
    array $author,
    array $proposal,
    ?callable $onAuthUrl = null,
    ?callable $onSignerError = null
): ?array {
    $GLOBALS['__nip39_sign_count']++;
    $wire = nip46_unsigned_event($proposal);
    $wire['pubkey'] = $proposal['pubkey'];
    return fm_event_sign($wire, $GLOBALS['__nip39_user_secret']);
}

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../lib/secrets.php';
require_once __DIR__ . '/../lib/jobs.php';
require_once __DIR__ . '/../lib/bridge.php';

$passed = 0;
$failed = 0;
function ok(bool $condition, string $name): void
{
    global $passed, $failed;
    if ($condition) {
        $passed++;
        echo "  ok  $name\n";
    } else {
        $failed++;
        echo "FAIL  $name\n";
    }
}

function signed_event(
    string $secret,
    int $kind,
    int $createdAt,
    array $tags,
    string $content = ''
): array {
    return fm_event_sign([
        'pubkey' => fm_pubkey_hex($secret),
        'kind' => $kind,
        'created_at' => $createdAt,
        'tags' => $tags,
        'content' => $content,
    ], $secret);
}

function confirm_identity_job(int $id): void
{
    $query = db()->prepare('SELECT payload FROM jobs WHERE id=?');
    $query->execute([$id]);
    $payload = json_decode((string)$query->fetchColumn(), true);
    $payload['confirmed_base_event_id'] =
        $payload['base_event_id'] ?? null;
    $payload['phase'] = 'ready_to_sign';
    db()->prepare(
        'UPDATE jobs SET payload=?,run_at=?,last_error=NULL WHERE id=?'
    )->execute([json_c($payload), now(), $id]);
}

echo "== NIP-39 proof and replacement algebra ==\n";
$userSecret = bin2hex(random_bytes(32));
$GLOBALS['__nip39_user_secret'] = $userSecret;
$userPubkey = fm_pubkey_hex($userSecret);
$login = 'alice';
$gistId = 'abcde12345';
$proof = nip39_proof_text($userPubkey);
$GLOBALS['__fm_test_gh_public_gist'] = static fn(string $id): array => [
    'id' => $id,
    'owner' => ['login' => 'Alice'],
    'files' => [
        'nostr.txt' => [
            'content' => $proof,
            'truncated' => false,
        ],
    ],
];

$parsed = nip39_parse_gist_url(
    "https://gist.github.com/$login/$gistId",
    $login
);
ok(
    $parsed['id'] === $gistId
    && $parsed['url'] === "https://gist.github.com/$login/$gistId",
    'Gist URL is fixed to the linked GitHub account'
);
try {
    nip39_parse_gist_url(
        "https://gist.github.com/mallory/$gistId",
        $login
    );
    ok(false, 'different Gist owner is rejected');
} catch (InvalidArgumentException $error) {
    ok(true, 'different Gist owner is rejected');
}
nip39_verify_github_gist($login, $userPubkey, $gistId);
ok(true, 'one exact proof file owned by the linked account verifies');
$validGist = $GLOBALS['__fm_test_gh_public_gist'];
$GLOBALS['__fm_test_gh_public_gist'] =
    static function (string $id) use ($proof): array {
        return [
            'owner' => ['login' => 'alice'],
            'files' => [
                'nostr.txt' => ['content' => $proof],
                'extra.txt' => ['content' => $proof],
            ],
        ];
    };
try {
    nip39_verify_github_gist($login, $userPubkey, $gistId);
    ok(false, 'multi-file proof is rejected');
} catch (Nip39ProofError $error) {
    ok(true, 'multi-file proof is rejected');
}
$GLOBALS['__fm_test_gh_public_gist'] = $validGist;

$older = signed_event(
    $userSecret,
    NIP39_KIND,
    now() - 100,
    [['i', 'twitter:alice', 'tweet-proof']],
    'preserved content'
);
$newer = signed_event(
    $userSecret,
    NIP39_KIND,
    now() - 50,
    [['i', 'mastodon:example/@alice', 'post-proof']],
    'new content'
);
$deleteNewer = signed_event(
    $userSecret,
    5,
    now() - 25,
    [['e', $newer['id']]]
);
/*
 * IDs cannot be chosen independently of valid signatures, so find a pair and
 * assert the reducer follows their actual lexical ID ordering at one second.
 */
$tieA = signed_event(
    $userSecret,
    NIP39_KIND,
    now() - 40,
    [['i', 'telegram:1', 'a/b']]
);
$tieB = signed_event(
    $userSecret,
    NIP39_KIND,
    $tieA['created_at'],
    [['i', 'telegram:1', 'a/c']]
);
$tieExpected = strcmp($tieA['id'], $tieB['id']) < 0 ? $tieA : $tieB;
ok(
    nip39_latest_replaceable(
        [$tieA, $tieB],
        $userPubkey,
        NIP39_KIND
    )['id'] === $tieExpected['id'],
    'same-second replacement selects the lowest event ID'
);
ok(
    nip39_active_replaceable(
        [$older, $newer],
        [$deleteNewer],
        $userPubkey,
        NIP39_KIND
    ) === null,
    'deleting the newest snapshot never resurrects the older snapshot'
);
$proposal = nip39_build_proposal(
    $older,
    $userPubkey,
    $login,
    $gistId
);
ok(
    $proposal['content'] === 'preserved content'
    && nip39_identity_preview($proposal['tags']) === [
        ['identity' => 'github:alice', 'proof' => $gistId],
        ['identity' => 'twitter:alice', 'proof' => 'tweet-proof'],
    ],
    'proposal preserves the complete prior identity set and content'
);
$removed = nip39_build_proposal(
    $proposal + ['id' => str_repeat('a', 64)],
    $userPubkey,
    $login,
    null
);
ok(
    nip39_identity_preview($removed['tags']) === [
        ['identity' => 'twitter:alice', 'proof' => 'tweet-proof'],
    ],
    'removal changes only the managed GitHub claim'
);

echo "== durable optional identity workflow ==\n";
$now = now();
db()->prepare(
    'INSERT INTO github_accounts
     (login,github_user_id,token_enc,refresh_token_enc,token_expires_at,
      refresh_token_expires_at,provider,auth_status,scopes,linked_at,updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)'
)->execute([
    $login,
    '1234',
    'unused',
    'unused',
    $now + 3600,
    $now + 7200,
    'github_app',
    'active',
    '',
    $now,
    $now,
]);
$clientSecret = bin2hex(random_bytes(32));
db()->prepare(
    'INSERT INTO nostr_accounts
     (pubkey,bunker_enc,client_key_enc,status,linked_at,updated_at)
     VALUES (?,?,?,?,?,?)'
)->execute([
    $userPubkey,
    fm_encrypt_at_rest(
        'bunker://' . str_repeat('b', 64)
        . '?relay=' . rawurlencode('wss://signer.example')
    ),
    fm_encrypt_at_rest($clientSecret),
    'linked',
    $now,
    $now,
]);
db()->prepare(
    'INSERT INTO links(login,pubkey,created_at) VALUES (?,?,?)'
)->execute([$login, $userPubkey, $now]);

$relayList = signed_event(
    $userSecret,
    NIP39_RELAY_LIST_KIND,
    now() - 80,
    [
        ['r', 'wss://personal.example', 'write'],
        ['r', 'wss://read-only.example', 'read'],
    ]
);
$GLOBALS['__nip39_relay_events'] = [$relayList, $older];
$jobId = jobs_enqueue(
    'nip39_identity',
    [
        'phase' => 'preparing',
        'action' => 'add',
        'github_login' => $login,
        'pubkey' => $userPubkey,
        'gist_id' => $gistId,
        'gist_url' => "https://gist.github.com/$login/$gistId",
    ],
    'nip39:' . $userPubkey
);
bridge_run_job_id($jobId);
$job = db()->prepare('SELECT * FROM jobs WHERE id=?');
$job->execute([$jobId]);
$prepared = $job->fetch();
$preparedPayload = json_decode($prepared['payload'], true);
ok(
    $prepared['status'] === 'pending'
    && $preparedPayload['phase'] === 'awaiting_confirmation'
    && $preparedPayload['base_event_id'] === $older['id']
    && in_array(
        ['identity' => 'twitter:alice', 'proof' => 'tweet-proof'],
        $preparedPayload['identities'],
        true
    )
    && $GLOBALS['__nip39_sign_count'] === 0,
    'preparation is durable and cannot sign before explicit confirmation'
);

confirm_identity_job($jobId);
$GLOBALS['__nip39_relay_events'][] = $newer;
bridge_run_job_id($jobId);
$job->execute([$jobId]);
$reconfirm = $job->fetch();
$reconfirmPayload = json_decode($reconfirm['payload'], true);
ok(
    $reconfirm['status'] === 'pending'
    && $reconfirmPayload['phase'] === 'awaiting_confirmation'
    && $reconfirmPayload['base_event_id'] === $newer['id']
    && in_array(
        ['identity' => 'mastodon:example/@alice', 'proof' => 'post-proof'],
        $reconfirmPayload['identities'],
        true
    )
    && $GLOBALS['__nip39_sign_count'] === 0,
    'a concurrent newer snapshot forces a refreshed human review'
);

confirm_identity_job($jobId);
bridge_run_job_id($jobId);
$job->execute([$jobId]);
$signedParent = $job->fetch();
$signedPayload = json_decode($signedParent['payload'], true);
$signed = $signedPayload['signed_event'] ?? null;
ok(
    $signedParent['status'] === 'done'
    && $signedPayload['phase'] === 'publishing'
    && is_array($signed)
    && fm_event_verify($signed)
    && $GLOBALS['__nip39_sign_count'] === 1
    && nip39_identity_preview($signed['tags']) === [
        ['identity' => 'github:alice', 'proof' => $gistId],
        ['identity' => 'mastodon:example/@alice', 'proof' => 'post-proof'],
    ],
    'stable confirmation produces one valid signature over the complete set'
);
ok(
    array_keys($signedPayload['publication_jobs']) === [
        'wss://nos.lol',
        'wss://personal.example',
        'wss://relay.damus.io',
        'wss://relay.nostr.band',
    ],
    'publication targets collaboration defaults and the NIP-65 write relay'
);

$children = db()->query(
    "SELECT id FROM jobs
     WHERE type='nip39_publish_relay' ORDER BY id"
)->fetchAll(PDO::FETCH_COLUMN);
foreach ($children as $childId) bridge_run_job_id((int)$childId);
ok(
    (int)db()->query(
        "SELECT COUNT(*) FROM jobs
         WHERE type='nip39_publish_relay' AND status='done'"
    )->fetchColumn() === 4
    && count($GLOBALS['__nip39_published']) === 4,
    'each relay publication is an independently retryable durable job'
);

$childCount = count($children);
$recoveryId = jobs_enqueue(
    'nip39_identity',
    [
        ...$signedPayload,
        'phase' => 'signed',
    ],
    'nip39-recovery-test'
);
bridge_run_job_id($recoveryId);
ok(
    $GLOBALS['__nip39_sign_count'] === 1
    && (int)db()->query(
        "SELECT COUNT(*) FROM jobs WHERE type='nip39_publish_relay'"
    )->fetchColumn() === $childCount,
    'crash recovery after signing neither re-signs nor duplicates terminal publications'
);

echo "\n$passed passed, $failed failed\n";

unset($GLOBALS['__fm_test_gh_public_gist']);
foreach ([$dbPath, "$dbPath-wal", "$dbPath-shm"] as $file) @unlink($file);
foreach (['db-crypt.php', 'bridge-key.php'] as $file) @unlink("$secrets/$file");
@rmdir($secrets);
@unlink($GLOBALS['__fm_test_log']);
exit($failed === 0 ? 0 : 1);

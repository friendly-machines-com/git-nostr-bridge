<?php
/**
 * Optional public GitHub ↔ Nostr profile assertion workflow.
 *
 * GET is read-only. Every mutation is an explicit JSON POST bound to a live,
 * fully linked browser session. The durable queue owns relay reads, the one
 * remote-signer request, and publication retries; this endpoint only records
 * user intent/confirmation and may advance that exact user's due job to avoid
 * waiting for the next cron tick.
 */
declare(strict_types=1);

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) {
    http_response_code(405);
    header('Allow: GET, HEAD, POST');
    exit;
}

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib/util.php';
require_once __DIR__ . '/lib/jobs.php';
require_once __DIR__ . '/lib/bridge.php';
require_once __DIR__ . '/lib/nip39.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

/** @return array{login:string,pubkey:string,npub:string,nonce:string}|null */
function nip39_browser_identity(): ?array
{
    $nonce = is_string($_COOKIE['bridge_oauth'] ?? null)
        ? $_COOKIE['bridge_oauth'] : '';
    if (!preg_match('/^[0-9a-f]{64}$/D', $nonce)) return null;
    $session = db()->prepare(
        'SELECT github_login,nostr_pubkey
         FROM oauth_states WHERE nonce=? AND expires_at>?'
    );
    $session->execute([$nonce, now()]);
    $row = $session->fetch();
    if (!is_array($row)) return null;
    $sessionLogin = is_string($row['github_login'] ?? null)
        ? $row['github_login'] : '';
    $sessionPubkey = strtolower((string)($row['nostr_pubkey'] ?? ''));

    $sql =
        "SELECT l.login,l.pubkey
         FROM links l
         JOIN github_accounts ga ON ga.login=l.login
         JOIN nostr_accounts na ON na.pubkey=l.pubkey
         WHERE ga.provider='github_app' AND ga.auth_status='active'
           AND na.status='linked'";
    $params = [];
    if ($sessionLogin !== '') {
        $sql .= ' AND l.login=?';
        $params[] = $sessionLogin;
    }
    if (is_hex64($sessionPubkey)) {
        $sql .= ' AND l.pubkey=?';
        $params[] = $sessionPubkey;
    }
    if (!$params) return null;
    $sql .= ' LIMIT 2';
    $linked = db()->prepare($sql);
    $linked->execute($params);
    $matches = $linked->fetchAll();
    if (count($matches) !== 1) return null;
    $login = (string)$matches[0]['login'];
    $pubkey = strtolower((string)$matches[0]['pubkey']);
    if (!nip39_github_login_valid($login) || !is_hex64($pubkey)) {
        return null;
    }
    return [
        'login' => $login,
        'pubkey' => $pubkey,
        'npub' => fm_npub_encode($pubkey),
        'nonce' => $nonce,
    ];
}

function nip39_input(): array
{
    $raw = isset($GLOBALS['__fm_nip39_test_input'])
        && is_string($GLOBALS['__fm_nip39_test_input'])
        ? $GLOBALS['__fm_nip39_test_input']
        : file_get_contents('php://input');
    if (!is_string($raw) || $raw === '' || strlen($raw) > 32768) {
        throw new InvalidArgumentException('Invalid identity request.');
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new InvalidArgumentException('Invalid identity request.');
    }
    return $decoded;
}

function nip39_owned_job(int $id, array $identity): ?array
{
    if ($id < 1) return null;
    $query = db()->prepare(
        "SELECT * FROM jobs WHERE id=? AND type='nip39_identity'"
    );
    $query->execute([$id]);
    $job = $query->fetch();
    if (!is_array($job)) return null;
    $payload = json_decode((string)$job['payload'], true);
    if (!is_array($payload)
        || !hash_equals(
            strtolower((string)($payload['pubkey'] ?? '')),
            $identity['pubkey']
        )
        || !hash_equals(
            strtolower((string)($payload['github_login'] ?? '')),
            strtolower($identity['login'])
        )) {
        return null;
    }
    $job['payload_arr'] = $payload;
    return $job;
}

function nip39_latest_job(array $identity): ?array
{
    $query = db()->prepare(
        "SELECT * FROM jobs
         WHERE type='nip39_identity' AND dedupe_key=?
         ORDER BY id DESC LIMIT 1"
    );
    $query->execute(['nip39:' . $identity['pubkey']]);
    foreach ($query as $job) {
        $payload = json_decode((string)$job['payload'], true);
        if (is_array($payload)
            && hash_equals(
                strtolower((string)($payload['pubkey'] ?? '')),
                $identity['pubkey']
            )
            && hash_equals(
                strtolower((string)($payload['github_login'] ?? '')),
                strtolower($identity['login'])
            )) {
            $job['payload_arr'] = $payload;
            return $job;
        }
    }
    return null;
}

/** @return array<string,array{status:string,last_error:?string}> */
function nip39_publication_states(array $publicationJobs): array
{
    $states = [];
    foreach ($publicationJobs as $relay => $dedupe) {
        if (!is_string($relay) || !is_string($dedupe)
            || relay_url_set([$relay]) !== [$relay]) {
            continue;
        }
        $query = db()->prepare(
            'SELECT status,last_error FROM jobs
             WHERE dedupe_key=? ORDER BY id DESC LIMIT 1'
        );
        $query->execute([$dedupe]);
        $row = $query->fetch();
        $states[$relay] = [
            'status' => is_array($row)
                ? (string)$row['status'] : 'missing',
            'last_error' => is_array($row)
                && is_string($row['last_error'] ?? null)
                ? $row['last_error'] : null,
        ];
    }
    ksort($states, SORT_STRING);
    return $states;
}

function nip39_job_view(?array $job): ?array
{
    if ($job === null) return null;
    $payload = $job['payload_arr'];
    $phase = (string)($payload['phase'] ?? 'preparing');
    if (($job['status'] ?? '') === 'dead') $phase = 'failed';
    $publications = nip39_publication_states(
        is_array($payload['publication_jobs'] ?? null)
            ? $payload['publication_jobs'] : []
    );
    if ($phase === 'publishing' && $publications) {
        $statuses = array_column($publications, 'status');
        if (!in_array('pending', $statuses, true)
            && !in_array('missing', $statuses, true)) {
            $phase = in_array('dead', $statuses, true)
                ? (in_array('done', $statuses, true)
                    ? 'published_partially' : 'publication_failed')
                : 'published';
        }
    }
    return [
        'id' => (int)$job['id'],
        'status' => (string)$job['status'],
        'phase' => $phase,
        'action' => (string)($payload['action'] ?? ''),
        'gist_url' => is_string($payload['gist_url'] ?? null)
            ? $payload['gist_url'] : null,
        'base_event_id' => is_string($payload['base_event_id'] ?? null)
            ? $payload['base_event_id'] : null,
        'event_id' => is_array($payload['signed_event'] ?? null)
            ? (string)($payload['signed_event']['id'] ?? '') : null,
        'identities' => is_array($payload['identities'] ?? null)
            ? $payload['identities'] : [],
        'notice' => is_string($payload['notice'] ?? null)
            ? $payload['notice'] : null,
        'error' => is_string($payload['error'] ?? null)
            ? $payload['error']
            : (($job['status'] ?? '') === 'dead'
                && is_string($job['last_error'] ?? null)
                ? $job['last_error'] : null),
        'auth_url' => is_string($payload['auth_url'] ?? null)
            ? $payload['auth_url'] : null,
        'publications' => $publications,
        'created_at' => (int)$job['created_at'],
        'updated_at' => (int)$job['updated_at'],
    ];
}

function nip39_response(array $identity, ?array $job = null): array
{
    if ($job === null) $job = nip39_latest_job($identity);
    return [
        'available' => true,
        'github' => ['login' => $identity['login']],
        'nostr' => [
            'pubkey' => $identity['pubkey'],
            'npub' => $identity['npub'],
        ],
        'proof_text' => nip39_proof_text($identity['pubkey']),
        'workflow' => nip39_job_view($job),
    ];
}

function nip39_exit(array $body, int $status = 200): never
{
    http_response_code($status);
    exit(json_encode($body));
}

$identity = nip39_browser_identity();
if ($identity === null) {
    nip39_exit([
        'available' => false,
        'error' => 'A fully linked GitHub and Nostr identity is required.',
    ], 403);
}

if ($method !== 'POST') {
    echo json_encode(nip39_response($identity));
    exit;
}

try {
    $input = nip39_input();
    $action = $input['action'] ?? null;
    if ($action === 'start') {
        $mode = $input['mode'] ?? null;
        if (!in_array($mode, ['add', 'remove'], true)) {
            throw new InvalidArgumentException('Invalid identity action.');
        }
        $existing = nip39_latest_job($identity);
        if (is_array($existing)
            && ($existing['status'] ?? '') === 'pending') {
            nip39_exit([
                'error' =>
                    'An identity update is already in progress. Finish it before starting another.',
                ...nip39_response($identity, $existing),
            ], 409);
        }
        $gistId = null;
        $gistUrl = null;
        if ($mode === 'add') {
            $gistUrlInput = is_string($input['gist_url'] ?? null)
                ? $input['gist_url'] : '';
            $gist = nip39_parse_gist_url(
                trim($gistUrlInput),
                $identity['login']
            );
            $gistId = $gist['id'];
            $gistUrl = $gist['url'];
        }
        $jobId = jobs_enqueue(
            'nip39_identity',
            [
                'phase' => 'preparing',
                'action' => $mode,
                'github_login' => $identity['login'],
                'pubkey' => $identity['pubkey'],
                'gist_id' => $gistId,
                'gist_url' => $gistUrl,
            ],
            'nip39:' . $identity['pubkey']
        );
        if ($jobId < 1) {
            throw new RuntimeException(
                'Could not create the durable identity update.'
            );
        }
        $job = nip39_owned_job($jobId, $identity);
        nip39_exit(nip39_response($identity, $job), 202);
    }

    $jobId = filter_var(
        $input['job_id'] ?? null,
        FILTER_VALIDATE_INT,
        ['options' => ['min_range' => 1]]
    );
    $job = $jobId !== false
        ? nip39_owned_job((int)$jobId, $identity) : null;
    if ($job === null) {
        nip39_exit(['error' => 'Identity update not found.'], 404);
    }

    if ($action === 'confirm') {
        $payload = $job['payload_arr'];
        if ($job['status'] !== 'pending'
            || ($payload['phase'] ?? '') !== 'awaiting_confirmation') {
            nip39_exit([
                'error' => 'This identity update is not awaiting confirmation.',
                ...nip39_response($identity, $job),
            ], 409);
        }
        $payload['confirmed_base_event_id'] =
            $payload['base_event_id'] ?? null;
        $payload['phase'] = 'ready_to_sign';
        $payload['error'] = null;
        unset($payload['notice']);
        db()->prepare(
            "UPDATE jobs SET payload=?,run_at=?,updated_at=?,last_error=NULL
             WHERE id=? AND status='pending'"
        )->execute([json_c($payload), now(), now(), (int)$job['id']]);
        $job = nip39_owned_job((int)$job['id'], $identity);
        nip39_exit(nip39_response($identity, $job));
    }

    if ($action === 'cancel') {
        $payload = $job['payload_arr'];
        if ($job['status'] !== 'pending'
            || ($payload['phase'] ?? '') !== 'awaiting_confirmation') {
            nip39_exit([
                'error' => 'Only an unconfirmed identity update can be cancelled.',
                ...nip39_response($identity, $job),
            ], 409);
        }
        $payload['phase'] = 'cancelled';
        $payload['error'] = null;
        db()->prepare(
            "UPDATE jobs
             SET payload=?,status='done',updated_at=?,last_error=NULL
             WHERE id=? AND status='pending'"
        )->execute([json_c($payload), now(), (int)$job['id']]);
        $job = nip39_owned_job((int)$job['id'], $identity);
        nip39_exit(nip39_response($identity, $job));
    }

    if ($action === 'advance') {
        if ($job['status'] === 'pending') {
            $phase = (string)($job['payload_arr']['phase'] ?? '');
            if ($phase !== 'awaiting_confirmation'
                && ((int)$job['attempts'] === 0
                    || (int)$job['run_at'] <= now())) {
                bridge_run_job_id((int)$job['id']);
            }
        } elseif (($job['payload_arr']['phase'] ?? '') === 'publishing') {
            foreach (($job['payload_arr']['publication_jobs'] ?? []) as $dedupe) {
                $child = db()->prepare(
                    "SELECT id,attempts,run_at FROM jobs
                     WHERE dedupe_key=? AND status='pending'
                     ORDER BY id DESC LIMIT 1"
                );
                $child->execute([(string)$dedupe]);
                $row = $child->fetch();
                if (is_array($row)
                    && (int)$row['attempts'] === 0
                    && (int)$row['run_at'] <= now()) {
                    bridge_run_job_id((int)$row['id']);
                    break;
                }
            }
        }
        $job = nip39_owned_job((int)$job['id'], $identity);
        nip39_exit(nip39_response($identity, $job));
    }
    throw new InvalidArgumentException('Invalid identity action.');
} catch (InvalidArgumentException $error) {
    nip39_exit(['error' => $error->getMessage()], 400);
} catch (Throwable $error) {
    bridge_log('nip39', 'identity endpoint failed', [
        'error' => $error->getMessage(),
    ]);
    nip39_exit([
        'error' => 'The identity workflow could not be updated.',
    ], 500);
}

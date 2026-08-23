<?php
/**
 * status.php  ==  /v1/status.php
 *
 * GET/HEAD reads this browser's server-backed link status without renewal.
 * POST is the explicit NIP-07 recovery flow:
 *   challenge -> create/reuse one empty five-minute browser session
 *   recover   -> verify its signed challenge, consume the empty state by
 *                attaching the proven durable identity, and refresh the cookie
 *
 * A claimed pubkey is never trusted by itself. Recovery requires a complete
 * signed Nostr event from the claimed key, and the event is never published.
 */
declare(strict_types=1);

$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($requestMethod, ['GET', 'HEAD', 'POST'], true)) {
    http_response_code(405);
    header('Allow: GET, HEAD, POST');
    exit;
}

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib/util.php';
require_once __DIR__ . '/lib/crypto.php';
require_once __DIR__ . '/lib/secrets.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

const STATUS_RECOVERY_KIND = 27235;
const STATUS_RECOVERY_URL =
    'https://auth.friendly-machines.com/v1/status.php';
const STATUS_RECOVERY_ACTION = 'recover-link-session';
const STATUS_RECOVERY_SECS = 300;
const STATUS_RECOVERY_ACTIVE_CAP = 100;

function status_cookie(): string
{
    $cookie = is_string($_COOKIE['bridge_oauth'] ?? null)
        ? $_COOKIE['bridge_oauth'] : '';
    return preg_match('/^[0-9a-f]{64}$/', $cookie) ? $cookie : '';
}

/** @return array<string,mixed> */
function status_for_cookie(string $cookie): array
{
    $out = [
        'browser_session' => false,
        'identity_recognized' => false,
        'github' => null,
        'nostr' => null,
        'fully_linked' => false,
    ];
    if ($cookie === '') return $out;

    $st = db()->prepare(
        'SELECT github_login,nostr_pubkey
         FROM oauth_states WHERE nonce=? AND expires_at>?'
    );
    $st->execute([$cookie, now()]);
    $session = $st->fetch();
    if (!is_array($session)) return $out;
    $out['browser_session'] = true;

    $login = is_string($session['github_login'] ?? null)
        ? $session['github_login'] : '';
    $sessionPk = strtolower((string)($session['nostr_pubkey'] ?? ''));
    if (is_hex64($sessionPk)) {
        $na = db()->prepare(
            "SELECT status FROM nostr_accounts WHERE pubkey=?"
        );
        $na->execute([$sessionPk]);
        if ($na->fetchColumn() === 'linked') {
            $out['nostr'] = [
                'npub' => fm_npub_encode($sessionPk),
                'pubkey' => $sessionPk,
            ];
        }
    }

    if ($login !== '') {
        $ga = db()->prepare(
            "SELECT 1 FROM github_accounts
             WHERE login=? AND provider='github_app' AND auth_status='active'"
        );
        $ga->execute([$login]);
        if (!$ga->fetchColumn()) $login = '';
    }
    if ($login !== '') {
        $out['github'] = ['login' => $login];
        $nl = db()->prepare(
            'SELECT na.pubkey,na.status
             FROM nostr_accounts na
             JOIN links l ON l.pubkey=na.pubkey
             WHERE l.login=?'
        );
        $nl->execute([$login]);
        $linkedNostr = $nl->fetch();
        if (is_array($linkedNostr)
            && $linkedNostr['status'] === 'linked') {
            $out['nostr'] = [
                'npub' => fm_npub_encode($linkedNostr['pubkey']),
                'pubkey' => $linkedNostr['pubkey'],
            ];
        }
    } elseif ($out['nostr'] !== null) {
        /*
         * This browser proved the exact Nostr key when its session was
         * created or recovered. Recovering that key's durable GitHub mapping
         * therefore does not expose a public account-lookup endpoint.
         */
        $linkedGithub = db()->prepare(
            "SELECT ga.login
             FROM links l
             JOIN github_accounts ga ON ga.login=l.login
             WHERE l.pubkey=? AND ga.provider='github_app'
               AND ga.auth_status='active'"
        );
        $linkedGithub->execute([$sessionPk]);
        $linkedLogin = $linkedGithub->fetchColumn();
        if (is_string($linkedLogin) && $linkedLogin !== '') {
            $out['github'] = ['login' => $linkedLogin];
        }
    }

    $out['identity_recognized'] =
        $out['github'] !== null || $out['nostr'] !== null;
    $out['fully_linked'] =
        $out['github'] !== null && $out['nostr'] !== null;
    return $out;
}

function status_json_input(): string
{
    if (isset($GLOBALS['__fm_status_test_input'])
        && is_string($GLOBALS['__fm_status_test_input'])) {
        return $GLOBALS['__fm_status_test_input'];
    }
    $raw = file_get_contents('php://input');
    return is_string($raw) ? $raw : '';
}

/** @return array{kind:int,created_at:int,tags:array<int,array<int,string>>,content:string} */
function status_recovery_template(string $sessionNonce): array
{
    $challenge = hash_hmac(
        'sha256',
        'friendly-machines:nostr-session-recovery:' . $sessionNonce,
        fm_secret_db_crypt_key()
    );
    return [
        'kind' => STATUS_RECOVERY_KIND,
        'created_at' => now(),
        'tags' => [
            ['u', STATUS_RECOVERY_URL],
            ['method', 'POST'],
            ['action', STATUS_RECOVERY_ACTION],
            ['challenge', $challenge],
        ],
        'content' => '',
    ];
}

function status_recovery_challenge(): never
{
    $cookie = status_cookie();
    $session = null;
    if ($cookie !== '') {
        $query = db()->prepare(
            'SELECT github_login,nostr_pubkey,expires_at
             FROM oauth_states WHERE nonce=? AND expires_at>?'
        );
        $query->execute([$cookie, now()]);
        $session = $query->fetch();
    }

    /*
     * Never turn a session already bound to an identity into a challenge.
     * The caller must re-read its status or use the separate account/signer
     * maintenance flow; sign-in cannot overwrite a bound browser cookie.
     */
    if (is_array($session)
        && ($session['github_login'] || $session['nostr_pubkey'])) {
        http_response_code(409);
        exit(json_encode([
            'error' => 'This browser is already signed in; refresh its status.',
        ]));
    }
    if (is_array($session)) {
        $expiresAt = max(
            (int)$session['expires_at'],
            now() + STATUS_RECOVERY_SECS
        );
        db()->prepare(
            'UPDATE oauth_states SET expires_at=MAX(expires_at,?) WHERE nonce=?'
        )->execute([$expiresAt, $cookie]);
    } else {
        $active = db()->prepare(
            'SELECT COUNT(*) FROM oauth_states
             WHERE github_login IS NULL AND nostr_pubkey IS NULL
               AND expires_at>=?'
        );
        $active->execute([now()]);
        if ((int)$active->fetchColumn() >= STATUS_RECOVERY_ACTIVE_CAP) {
            http_response_code(503);
            exit(json_encode([
                'error' => 'Too many active recovery attempts; retry shortly.',
            ]));
        }
        $cookie = random_hex(32);
        $expiresAt = now() + STATUS_RECOVERY_SECS;
        db()->prepare(
            'INSERT INTO oauth_states(nonce,created_at,expires_at)
             VALUES (?,?,?)'
        )->execute([$cookie, now(), $expiresAt]);
    }

    fm_set_link_session_cookie($cookie, $expiresAt);
    exit(json_encode([
        'challenge' => status_recovery_template($cookie),
        'expires_at' => $expiresAt,
    ]));
}

function status_recover_nostr(array $event): never
{
    $cookie = status_cookie();
    $expected = status_recovery_template($cookie);
    $createdAt = is_int($event['created_at'] ?? null)
        ? $event['created_at'] : 0;
    if ($cookie === ''
        || !fm_event_verify($event)
        || ($event['kind'] ?? null) !== $expected['kind']
        || ($event['tags'] ?? null) !== $expected['tags']
        || ($event['content'] ?? null) !== ''
        || $createdAt < now() - STATUS_RECOVERY_SECS
        || $createdAt > now() + 60) {
        http_response_code(403);
        exit(json_encode(['error' => 'Invalid or expired signer proof.']));
    }

    $pubkey = strtolower((string)$event['pubkey']);
    $account = db()->prepare(
        "SELECT na.pubkey,l.login
         FROM nostr_accounts na
         LEFT JOIN links l ON l.pubkey=na.pubkey
         WHERE na.pubkey=? AND na.status='linked'"
    );
    $account->execute([$pubkey]);
    $durable = $account->fetch();
    if (!is_array($durable)) {
        http_response_code(404);
        exit(json_encode([
            'error' => 'No existing durable link was found for this signer.',
        ]));
    }
    $login = is_string($durable['login'] ?? null)
        && $durable['login'] !== '' ? $durable['login'] : null;
    $expiresAt = now() + FM_PARTIAL_LINK_SESSION_SECS;

    db()->beginTransaction();
    try {
        /*
         * This conditional transition consumes the challenge. A replay sees
         * non-NULL identity fields and cannot refresh or replace the session.
         */
        $consume = db()->prepare(
            'UPDATE oauth_states
             SET github_login=?,nostr_pubkey=?,expires_at=?
             WHERE nonce=? AND expires_at>=?
               AND github_login IS NULL AND nostr_pubkey IS NULL'
        );
        $consume->execute([
            $login,
            $pubkey,
            $expiresAt,
            $cookie,
            now(),
        ]);
        if ($consume->rowCount() !== 1) {
            throw new RuntimeException('recovery challenge already used');
        }
        db()->commit();
    } catch (Throwable $error) {
        if (db()->inTransaction()) db()->rollBack();
        http_response_code(409);
        exit(json_encode([
            'error' => 'Recovery challenge was already used or expired.',
        ]));
    }

    fm_set_link_session_cookie($cookie, $expiresAt);
    $out = status_for_cookie($cookie);
    $out['recovered'] = true;
    exit(json_encode($out));
}

if ($requestMethod === 'POST') {
    $raw = status_json_input();
    if ($raw === '' || strlen($raw) > 32768) {
        http_response_code(400);
        exit(json_encode(['error' => 'Invalid recovery request.']));
    }
    $input = json_decode($raw, true);
    if (!is_array($input)) {
        http_response_code(400);
        exit(json_encode(['error' => 'Invalid recovery request.']));
    }
    $action = $input['action'] ?? null;
    if ($action === 'challenge') status_recovery_challenge();
    if ($action === 'recover' && is_array($input['event'] ?? null)) {
        status_recover_nostr($input['event']);
    }
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid recovery action.']));
}

echo json_encode(status_for_cookie(status_cookie()));

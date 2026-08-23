<?php
/**
 * nostr-link.php  ==  /v1/nostr-link.php
 * Step 2 of the linking handshake: Nostr identity via NIP-46.
 *
 * We are the NIP-46 CLIENT (nostrconnect:// flow):
 *   GET          -> read-only status or explicit start form
 *   POST start   -> allocate one connection, then 303 to its status page
 *   ?wait=ID     -> sub-second, read-only JSON state poll
 *   POST listen  -> background relay listener; never awaited by the GUI
 *   POST connect -> bank one browser-observed approval event
 *
 * On connect:
 *   - validate returned secret (prevents spoofed binders)
 *   - bank signer pubkey + relay set and enqueue nip46_finish atomically
 *   - cron obtains the user pubkey and commits the account/link; this page
 *     only polls and reports that durable state
 *
 * Each link gets a distinct encrypted NIP-46 client keypair.
 */
declare(strict_types=1);

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib/util.php';
$fastStatusPoll = isset($_GET['wait'])
    && !isset($_GET['connect'])
    && !isset($_POST['listen'])
    && !isset($_POST['restart'])
    && !isset($_POST['start']);
if (!$fastStatusPoll) {
    require_once __DIR__ . '/lib/secrets.php';
    require_once __DIR__ . '/lib/crypto.php';
    require_once __DIR__ . '/lib/nip44.php';
    require_once __DIR__ . '/lib/ws.php';
    require_once __DIR__ . '/lib/nip46.php';
    require_once __DIR__ . '/lib/jobs.php';
    require_once __DIR__ . '/lib/bridge.php';
}

const NL_PERMS = 'sign_event:5,sign_event:7,sign_event:1621,sign_event:1111,sign_event:1630,sign_event:1631,sign_event:1632,sign_event:10011,get_public_key,switch_relays,ping';
// This is background relay listening, not a GUI response timeout. The browser
// polls durable state separately, so a slow/missing approval never freezes UI.
const NL_BACKGROUND_LISTEN_SECS = 30.0;
$replacementPubkey = null;

function nl_page(string $title, string $body): string
{
    $t = e($title);
    return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
         . "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
         . "<title>$t</title><style>"
         . "body{font-family:system-ui,sans-serif;max-width:44em;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#202124}"
         . "[hidden]{display:none!important}code,pre{background:#f4f4f4;padding:.15em .35em;border-radius:3px;word-break:break-all;font-size:.9em}"
         . "pre{padding:1em;overflow-x:auto}.btn{display:inline-block;margin-top:1rem;padding:.65rem 1.1rem;border:0;"
         . "background:#6d45d8;color:#fff;border-radius:7px;text-decoration:none;font:inherit;cursor:pointer}.btn.secondary{background:#555}"
         . ".card{border:1px solid #ddd;border-radius:12px;padding:1.1rem 1.25rem;margin:1.25rem 0;background:#fff}"
         . ".steps{list-style:none;padding:0;margin:1rem 0}.steps li{display:flex;gap:.8rem;padding:.65rem 0;color:#70757a}"
         . ".stepmark{display:grid;place-items:center;flex:0 0 1.7rem;height:1.7rem;border:2px solid #bbb;border-radius:50%;font-weight:700;font-size:.85rem}"
         . ".steps strong{display:block;color:inherit}.steps small{display:block;margin-top:.15rem}.steps li.current{color:#4f2db8}"
         . ".steps li.current .stepmark{border-color:#6d45d8;background:#eee9ff;animation:pulse 1s ease-in-out infinite}.steps li.done{color:#237a3b}"
         . ".steps li.done .stepmark{border-color:#2f8f4e;background:#e8f6ec}.statusbox{padding:.85rem 1rem;border-radius:8px;background:#f4f0ff;margin-top:1rem}"
         . "#statusElapsed{display:block;margin-top:.25rem;color:#666}.ok{color:#176b32}.success{border-color:#9ed5ad;background:#f2fbf4}.muted{color:#666}details{margin:1rem 0}"
         . "details summary{cursor:pointer;font-weight:600}#diagnosticText{display:block;white-space:pre-wrap;margin-top:.5rem}"
         . "@keyframes pulse{50%{box-shadow:0 0 0 5px rgba(109,69,216,.13)}}"
         . "@media(prefers-reduced-motion:reduce){.steps li.current .stepmark{animation:none}}"
         . "@media(max-width:35em){body{margin:1.5rem auto}.card{padding:.9rem}}</style></head>"
         . "<body>$body</body></html>";
}

/** Read the explicit durable phase; invalid or absent state starts at step two. */
function nl_job_phase(?array $job): string
{
    $payload = is_array($job)
        ? json_decode((string)($job['payload'] ?? ''), true) : null;
    $phase = is_array($payload) ? ($payload['phase'] ?? null) : null;
    if (is_string($phase) && in_array($phase, [
        'checking_relays',
        'identifying_account',
        'verifying_signer',
        'saving_link',
    ], true)) {
        return $phase;
    }
    return 'checking_relays';
}

function nl_phase_message(string $phase): string
{
    return match ($phase) {
        'checking_relays' =>
            'Signer approved. Finding a reliable connection to your signer…',
        'identifying_account' =>
            'Connection found. Confirming which Nostr account is yours…',
        'verifying_signer' =>
            'Account found. Verifying that your signer can sign for it…',
        'saving_link' =>
            'Verification passed. Saving your link…',
        default =>
            'Continuing the link in the background…',
    };
}

/** Decode a stored NIP-46 auth challenge without loading the relay stack. */
function nl_state_auth_url(mixed $value): ?string
{
    $prefix = 'nip46-auth-url:';
    if (!is_string($value) || !str_starts_with($value, $prefix)) return null;
    $url = substr($value, strlen($prefix));
    if ($url === '' || strlen($url) > 2048
        || preg_match('/[\x00-\x20\x7f]/', $url)) {
        return null;
    }
    $parts = parse_url($url);
    if (!is_array($parts)
        || strtolower((string)($parts['scheme'] ?? '')) !== 'https'
        || !is_string($parts['host'] ?? null)
        || $parts['host'] === ''
        || isset($parts['user'])
        || isset($parts['pass'])) {
        return null;
    }
    return $url;
}

// --- mode: explicitly replace an unusable banked signer connection --------
if (isset($_POST['restart'])) {
    header('Cache-Control: no-store');
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        exit;
    }
    $stateId = is_string($_POST['restart']) ? $_POST['restart'] : '';
    $cookie = is_string($_COOKIE['bridge_oauth'] ?? null)
        ? $_COOKIE['bridge_oauth'] : '';
    if (!preg_match('/^[0-9a-f]{32}$/', $stateId)
        || !preg_match('/^[0-9a-f]{64}$/', $cookie)) {
        http_response_code(400);
        exit('Invalid signer connection');
    }
    $state = db()->prepare(
        "SELECT oauth_nonce FROM nip46_states
         WHERE state_id=? AND status='connected' AND expires_at>=?"
    );
    $state->execute([$stateId, now()]);
    $oauthNonce = $state->fetchColumn();
    if (!is_string($oauthNonce)
        || $oauthNonce === ''
        || !hash_equals($oauthNonce, $cookie)) {
        http_response_code(403);
        exit('Signer connection does not belong to this browser session');
    }
    $replacementJob = db()->prepare(
        "SELECT payload FROM jobs
         WHERE dedupe_key=? AND status='pending'
         ORDER BY id DESC LIMIT 1"
    );
    $replacementJob->execute(['nip46finish:' . $stateId]);
    $replacementPayload = json_decode(
        (string)($replacementJob->fetchColumn() ?: ''),
        true
    );
    $replacementCandidate = is_array($replacementPayload)
        ? ($replacementPayload['replace_pubkey'] ?? null) : null;
    if (is_string($replacementCandidate)
        && is_hex64($replacementCandidate)) {
        $replacementPubkey = strtolower($replacementCandidate);
    }

    db()->beginTransaction();
    try {
        $cancel = db()->prepare(
            "UPDATE nip46_states
             SET status='failed',error=?
             WHERE state_id=? AND oauth_nonce=? AND status='connected'"
        );
        $cancel->execute([
            'Signer connection replaced by its browser session',
            $stateId,
            $cookie,
        ]);
        if ($cancel->rowCount() !== 1) {
            db()->rollBack();
            http_response_code(409);
            exit('Signer connection changed; reload and try again');
        }
        // Queue status "done" means this superseded job has no work left.
        // The state and error retain why it stopped; a new connection gets
        // its own state ID and dedupe key.
        db()->prepare(
            "UPDATE jobs
             SET status='done',last_error=?,updated_at=?
             WHERE dedupe_key=? AND status='pending'"
        )->execute([
            'Superseded by an explicit same-session signer reconnect',
            now(),
            'nip46finish:' . $stateId,
        ]);
        db()->commit();
    } catch (Throwable $error) {
        if (db()->inTransaction()) db()->rollBack();
        throw $error;
    }
    // The same explicit POST now allocates the replacement below. A plain
    // redirected GET remains read-only.
    $_POST['start'] = '1';
}

// --- mode: explicitly replace the durable remote signer connection --------
if (isset($_POST['replace'])) {
    header('Cache-Control: no-store');
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
        || $_POST['replace'] !== '1') {
        http_response_code(405);
        header('Allow: POST');
        exit;
    }
    $replacementSession = nl_browser_session();
    $replacementIdentity = is_array($replacementSession)
        ? nl_durable_identity_for_session($replacementSession) : null;
    if (!is_array($replacementIdentity)
        || !is_hex64((string)$replacementIdentity['pubkey'])) {
        http_response_code(403);
        exit(nl_page(
            'Signer replacement denied',
            '<h1>Sign in before replacing a signer</h1>'
            . '<p>The current browser has not proved ownership of an existing '
            . 'durable Nostr signer connection.</p><p><a href="/">'
            . 'Return to account status</a></p>'
        ));
    }
    $replacementPubkey = strtolower($replacementIdentity['pubkey']);
    $_POST['start'] = '1';
}

// --- mode: live encrypted connect-response intake --------------------------
if (isset($_GET['connect'])) {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        exit(json_encode(['accepted' => false]));
    }
    $stateId = is_string($_GET['connect']) ? $_GET['connect'] : '';
    if (!preg_match('/^[0-9a-f]{32}$/', $stateId)) {
        http_response_code(400);
        exit(json_encode(['accepted' => false]));
    }
    $query = db()->prepare(
        "SELECT oauth_nonce FROM nip46_states
         WHERE state_id=? AND status='waiting' AND expires_at>=?"
    );
    $query->execute([$stateId, now()]);
    $oauthNonce = $query->fetchColumn();
    $cookie = is_string($_COOKIE['bridge_oauth'] ?? null)
        ? $_COOKIE['bridge_oauth'] : '';
    if (!is_string($oauthNonce)
        || $oauthNonce === ''
        || $cookie === ''
        || !hash_equals($oauthNonce, $cookie)) {
        http_response_code(403);
        exit(json_encode(['accepted' => false]));
    }
    $raw = file_get_contents('php://input');
    if (!is_string($raw) || strlen($raw) > 65536) {
        http_response_code(413);
        exit(json_encode(['accepted' => false]));
    }
    $input = json_decode($raw, true);
    $event = is_array($input['event'] ?? null) ? $input['event'] : [];
    $relays = is_array($input['relays'] ?? null)
        && array_is_list($input['relays'])
        ? $input['relays'] : [];
    $accepted = bridge_accept_nip46_connect($stateId, $event, $relays);
    echo json_encode(['accepted' => $accepted]);
    exit;
}

// --- mode: acknowledge completed link and extend this browser session ------
if (isset($_POST['complete'])) {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        exit(json_encode(['ok' => false]));
    }
    $stateId = is_string($_POST['complete']) ? $_POST['complete'] : '';
    $cookie = is_string($_COOKIE['bridge_oauth'] ?? null)
        ? $_COOKIE['bridge_oauth'] : '';
    if (!preg_match('/^[0-9a-f]{32}$/', $stateId)
        || !preg_match('/^[0-9a-f]{64}$/', $cookie)) {
        http_response_code(400);
        exit(json_encode(['ok' => false]));
    }
    $completed = db()->prepare(
        "SELECT 1 FROM nip46_states
         WHERE state_id=? AND oauth_nonce=? AND status='done'
           AND expires_at>=?"
    );
    $completed->execute([$stateId, $cookie, now()]);
    if (!$completed->fetchColumn()) {
        http_response_code(403);
        exit(json_encode(['ok' => false]));
    }
    $expiresAt = now() + FM_PARTIAL_LINK_SESSION_SECS;
    db()->prepare(
        'UPDATE oauth_states SET expires_at=MAX(expires_at, ?) WHERE nonce=?'
    )->execute([$expiresAt, $cookie]);
    fm_set_link_session_cookie($cookie, $expiresAt);
    echo json_encode(['ok' => true]);
    exit;
}

// --- mode: background approval listener ------------------------------------
if (isset($_POST['listen'])) {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        exit(json_encode(['accepted' => false]));
    }
    $stateId = is_string($_POST['listen']) ? $_POST['listen'] : '';
    if (!preg_match('/^[0-9a-f]{32}$/', $stateId)) {
        http_response_code(400);
        exit(json_encode(['accepted' => false]));
    }
    $listener = db()->prepare(
        'SELECT * FROM nip46_states WHERE state_id=? AND expires_at>=?'
    );
    $listener->execute([$stateId, now()]);
    $state = $listener->fetch();
    $listener->closeCursor();
    $cookie = is_string($_COOKIE['bridge_oauth'] ?? null)
        ? $_COOKIE['bridge_oauth'] : '';
    $oauthNonce = is_array($state)
        && is_string($state['oauth_nonce'] ?? null)
        ? $state['oauth_nonce'] : '';
    if (!is_array($state)
        || $cookie === ''
        || $oauthNonce === ''
        || !hash_equals($oauthNonce, $cookie)) {
        http_response_code(403);
        exit(json_encode(['accepted' => false]));
    }

    if ($state['status'] === 'waiting') {
        /*
         * This request is intentionally long-lived background work. The GUI
         * never waits for it: a separate read-only status poll remains fast.
         * If opening Amber suspends the browser, this already-running server
         * subscription can still bank the ephemeral approval.
         */
        ignore_user_abort(true);
        @set_time_limit((int)NL_BACKGROUND_LISTEN_SECS + 10);
        $responses = nip46_collect_connect_events(
            [(string)$state['client_pk']],
            nip46_listen_relays(),
            max(1, (int)$state['created_at'] - 120),
            NL_BACKGROUND_LISTEN_SECS
        );
        foreach ($responses as $response) {
            if (bridge_accept_nip46_connect(
                $stateId,
                $response['event'],
                $response['relays']
            )) break;
        }
        $listener->execute([$stateId, now()]);
        $state = $listener->fetch();
        $listener->closeCursor();
    }
    echo json_encode([
        'accepted' => is_array($state)
            && in_array($state['status'], ['connected', 'done'], true),
        'status' => is_array($state) ? $state['status'] : 'expired',
    ]);
    exit;
}

// --- mode: fast, read-only GUI status poll ---------------------------------
if (isset($_GET['wait'])) {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    $stateId = is_string($_GET['wait']) ? $_GET['wait'] : '';
    if (!preg_match('/^[0-9a-f]{32}$/', $stateId)) {
        http_response_code(400);
        exit(json_encode(['status' => 'expired']));
    }

    $st = db()->prepare('SELECT * FROM nip46_states WHERE state_id = ?');
    $st->execute([$stateId]);
    $row = $st->fetch();
    if (!$row || (int)$row['expires_at'] < now()) {
        exit(json_encode(['status' => 'expired']));
    }
    $cookie = is_string($_COOKIE['bridge_oauth'] ?? null)
        ? $_COOKIE['bridge_oauth'] : '';
    $oauthNonce = is_string($row['oauth_nonce'] ?? null)
        ? $row['oauth_nonce'] : '';
    if ($cookie === '' || $oauthNonce === ''
        || !hash_equals($oauthNonce, $cookie)) {
        http_response_code(403);
        exit(json_encode(['status' => 'expired']));
    }

    if ($row['status'] === 'done' && is_hex64((string)$row['pubkey'])) {
        exit(json_encode([
            'status' => 'done',
            'phase' => 'done',
            'linked' => (bool)nl_login_for($row['pubkey']),
        ]));
    }
    if ($row['status'] === 'connected') {
        $job = db()->prepare(
            "SELECT payload,last_error,attempts,run_at FROM jobs
             WHERE dedupe_key=? AND status='pending'
             ORDER BY id DESC LIMIT 1"
        );
        $job->execute(['nip46finish:' . $stateId]);
        $jobState = $job->fetch();
        $job->closeCursor();
        $phase = nl_job_phase(is_array($jobState) ? $jobState : null);
        $lastError = is_array($jobState)
            ? ($jobState['last_error'] ?? null) : null;
        $attempts = is_array($jobState)
            ? (int)($jobState['attempts'] ?? 0) : 0;
        $authUrl = nl_state_auth_url($row['error'] ?? null);
        if ($authUrl !== null) {
            exit(json_encode([
                'status' => 'auth_required',
                'phase' => $phase,
                'url' => $authUrl,
                'message' => 'Your signer needs one more confirmation.',
                'attempts' => $attempts,
            ]));
        }
        exit(json_encode([
            'status' => 'pending',
            'phase' => $phase,
            'message' => nl_phase_message($phase),
            'attempts' => $attempts,
            'retry_at' => is_array($jobState)
                ? (int)($jobState['run_at'] ?? 0) : 0,
            'diagnostic' => is_string($lastError) && $lastError !== ''
                ? $lastError : null,
        ]));
    }
    if ($row['status'] === 'failed') {
        exit(json_encode([
            'status' => 'failed',
            'error' => 'Nostr link failed. Reload to retry; the server log has details.',
        ]));
    }
    exit(json_encode([
        'status' => 'waiting',
        'phase' => 'waiting_for_approval',
        'message' => 'Waiting for approval in your signer…',
    ]));
}

/** Ensure this browser has an unguessable, server-backed two-half session. */
function nl_ensure_link_session(): string
{
    $cookie = is_string($_COOKIE['bridge_oauth'] ?? null)
        ? $_COOKIE['bridge_oauth'] : '';
    if (preg_match('/^[0-9a-f]{64}$/', $cookie)) {
        $st = db()->prepare('SELECT * FROM oauth_states WHERE nonce=? AND expires_at>?');
        $st->execute([$cookie, now()]);
        $session = $st->fetch();
        if ($session) {
            $ttl = ($session['github_login'] || $session['nostr_pubkey'])
                ? FM_PARTIAL_LINK_SESSION_SECS
                : FM_EMPTY_LINK_SESSION_SECS;
            $expiresAt = now() + $ttl;
            db()->prepare('UPDATE oauth_states SET expires_at=MAX(expires_at, ?) WHERE nonce=?')
               ->execute([$expiresAt, $cookie]);
            fm_set_link_session_cookie($cookie, $expiresAt);
            return $cookie;
        }
    }

    $nonce = random_hex(32);
    $expiresAt = now() + FM_EMPTY_LINK_SESSION_SECS;
    db()->prepare('INSERT INTO oauth_states (nonce,created_at,expires_at) VALUES (?,?,?)')
       ->execute([$nonce, now(), $expiresAt]);
    fm_set_link_session_cookie($nonce, $expiresAt);
    return $nonce;
}

/** existing link (if any) for a pubkey */
function nl_login_for(string $pubkey): ?string
{
    $gh = db()->prepare(
        "SELECT l.login FROM links l
         JOIN github_accounts ga ON ga.login=l.login
         WHERE l.pubkey=? AND ga.provider='github_app'
           AND ga.auth_status='active'"
    );
    $gh->execute([$pubkey]);
    $v = $gh->fetchColumn();
    return $v ?: null;
}

/** Read this request's current server-backed browser session without renewal. */
function nl_browser_session(): ?array
{
    $cookie = is_string($_COOKIE['bridge_oauth'] ?? null)
        ? $_COOKIE['bridge_oauth'] : '';
    if (!preg_match('/^[0-9a-f]{64}$/', $cookie)) return null;
    $query = db()->prepare(
        'SELECT * FROM oauth_states WHERE nonce=? AND expires_at>?'
    );
    $query->execute([$cookie, now()]);
    $session = $query->fetch();
    return is_array($session) ? $session : null;
}

/** Read one active handshake for a browser session; never allocate one. */
function nl_active_state_for_session(
    string $oauthNonce,
    bool $ongoingOnly = false
): ?array
{
    $statuses = $ongoingOnly
        ? "'waiting','connected'"
        : "'waiting','connected','done'";
    $active = db()->prepare(
    "SELECT * FROM nip46_states
     WHERE oauth_nonce=?
       AND status IN ($statuses)
       AND expires_at>=?
     ORDER BY CASE status
                WHEN 'connected' THEN 0
                WHEN 'waiting' THEN 1
                ELSE 2
              END,
              created_at DESC
     LIMIT 1"
    );
    $active->execute([$oauthNonce, now()]);
    $state = $active->fetch();
    return is_array($state) ? $state : null;
}

/**
 * A browser that has proved either identity may recover that exact durable
 * link. An unidentified browser receives no public account lookup.
 */
function nl_durable_identity_for_session(array $session): ?array
{
    $login = is_string($session['github_login'] ?? null)
        ? $session['github_login'] : '';
    $pubkey = strtolower((string)($session['nostr_pubkey'] ?? ''));
    if ($login !== '') {
        $query = db()->prepare(
            "SELECT na.pubkey
             FROM github_accounts ga
             JOIN links l ON l.login=ga.login
             JOIN nostr_accounts na ON na.pubkey=l.pubkey
             WHERE ga.login=? AND ga.provider='github_app'
               AND ga.auth_status='active' AND na.status='linked'"
        );
        $query->execute([$login]);
        $linkedPk = strtolower((string)($query->fetchColumn() ?: ''));
        if (is_hex64($linkedPk)) {
            return ['login' => $login, 'pubkey' => $linkedPk];
        }
    }
    if (is_hex64($pubkey)) {
        $query = db()->prepare(
            "SELECT status FROM nostr_accounts WHERE pubkey=?"
        );
        $query->execute([$pubkey]);
        if ($query->fetchColumn() === 'linked') {
            return ['login' => nl_login_for($pubkey), 'pubkey' => $pubkey];
        }
    }
    return null;
}

function nl_start_page(?array $session): string
{
    $identified = is_array($session)
        && (
            (is_string($session['github_login'] ?? null)
             && $session['github_login'] !== '')
            || is_hex64(strtolower((string)(
                $session['nostr_pubkey'] ?? ''
            )))
        );
    $notice = $identified
        ? 'This browser has a verified identity half but no active Nostr '
          . 'connection attempt.'
        : 'This browser is not currently associated with a verified identity. '
          . 'That does not mean an existing durable bridge link was removed.';
    return nl_page(
        'Connect Nostr signer',
        '<h1>Connect a Nostr signer</h1><div class="card"><strong>'
        . e($notice)
        . '</strong><p>Viewing this page is read-only. No session, keypair, '
        . 'queue entry, or signer connection is created until you explicitly '
        . 'start below.</p></div>'
        . '<form method="post" action="/v1/nostr-link.php">'
        . '<button class="btn" type="submit" name="start" value="1">'
        . 'Start Nostr signer connection</button></form>'
        . '<p><a href="/">Back to account status</a></p>'
    );
}

// --- mode: explicit connection allocation ---------------------------------
header('Cache-Control: no-store');
if (isset($_POST['start'])) {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
        || $_POST['start'] !== '1') {
        http_response_code(405);
        header('Allow: POST');
        exit;
    }
    $oauthNonce = nl_ensure_link_session();
    $browserSession = nl_browser_session();
    if (!is_array($browserSession)) {
        throw new RuntimeException('new link session was not persisted');
    }
    $durableIdentity = nl_durable_identity_for_session($browserSession);
    if ($durableIdentity !== null && $replacementPubkey === null) {
        header('Location: /v1/nostr-link.php', true, 303);
        exit;
    }
    if ($replacementPubkey !== null
        && (!is_array($durableIdentity)
            || !hash_equals(
                strtolower((string)$durableIdentity['pubkey']),
                $replacementPubkey
            ))) {
        http_response_code(403);
        exit('Signer replacement identity changed; reload and try again');
    }
    $activeState = nl_active_state_for_session(
        $oauthNonce,
        $replacementPubkey !== null
    );
    if ($activeState === null
        && (int)db()->query(
            "SELECT COUNT(*) FROM nip46_states
             WHERE status='waiting' AND expires_at>=" . now()
        )->fetchColumn() >= 100) {
        http_response_code(503);
        exit(nl_page('Busy', '<h1>Too many link attempts</h1>'
            . '<p>Please retry after the current ten-minute link window.</p>'));
    }
    if ($activeState === null) {
        $stateId = random_hex(16);
        $secret  = random_hex(16);
        $clientPriv = fm_private_key_generate();
        $clientPk = fm_pubkey_hex($clientPriv);
        try {
            $clientKeyEnc = fm_encrypt_at_rest($clientPriv);
        } catch (Throwable $ex) {
            bridge_log('nostr-link', 'cannot create encrypted link state', [
                'error' => $ex->getMessage(),
            ]);
            http_response_code(500);
            exit(nl_page(
                'Setup needed',
                '<h1>Bridge not fully configured</h1><p>'
                . 'The server-side bridge configuration is incomplete.</p>'
            ));
        }
        try {
            db()->prepare(
                'INSERT INTO nip46_states
                 (state_id,secret,client_pk,client_key_enc,oauth_nonce,error,
                  created_at,expires_at)
                 VALUES (?,?,?,?,?,?,?,?)'
            )->execute([
                $stateId,
                $secret,
                $clientPk,
                $clientKeyEnc,
                $oauthNonce,
                $replacementPubkey !== null
                    ? NIP46_REPLACE_STATE_PREFIX . $replacementPubkey
                    : null,
                now(),
                now() + 600,
            ]);
        } catch (PDOException $error) {
            // A simultaneous explicit POST may have won the unique waiting
            // state. Reuse that winner rather than allocate another.
            $activeState = nl_active_state_for_session(
                $oauthNonce,
                $replacementPubkey !== null
            );
            if ($activeState === null) throw $error;
        }
    }
    header('Location: /v1/nostr-link.php', true, 303);
    exit;
}

// --- mode: read-only interactive page -------------------------------------
$readMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($readMethod, ['GET', 'HEAD'], true)) {
    http_response_code(405);
    header('Allow: GET, HEAD, POST');
    exit;
}
$browserSession = nl_browser_session();
if ($browserSession === null) {
    exit(nl_start_page(null));
}
$oauthNonce = (string)$browserSession['nonce'];
$activeState = nl_active_state_for_session($oauthNonce);
$durableIdentity = nl_durable_identity_for_session($browserSession);
if ($durableIdentity !== null
    && ($activeState === null || $activeState['status'] === 'done')) {
    $npub = fm_npub_encode($durableIdentity['pubkey']);
    $linked = is_string($durableIdentity['login'])
        && $durableIdentity['login'] !== '';
    $message = $linked
        ? '<p>Your GitHub and Nostr identities remain durably linked: '
          . '<strong>@' . e($durableIdentity['login']) . '</strong> ↔ '
          . '<code>' . e($npub) . '</code>.</p>'
        : '<p>Your Nostr signer remains durably connected: <code>'
          . e($npub) . '</code>. GitHub remains optional.</p>';
    exit(nl_page(
        'Nostr signer linked',
        '<h1>✓ Nostr signer linked</h1><section class="card success">'
        . $message
        . '<p><a class="btn" href="/">Back to account linking</a></p>'
        . '<details><summary>Signer settings</summary>'
        . '<p>Only replace the remote signer connection if you revoked or '
        . 'lost the existing Amber connection. Signing in again never '
        . 'replaces it.</p>'
        . '<form method="post" action="/v1/nostr-link.php">'
        . '<button class="btn secondary" type="submit" name="replace" value="1">'
        . 'Replace remote signer connection</button></form></details>'
        . '</section>'
    ));
}

if ($activeState === null) {
    exit(nl_start_page($browserSession));
}
$browserHasIdentity =
    (is_string($browserSession['github_login'] ?? null)
     && $browserSession['github_login'] !== '')
    || is_hex64(strtolower((string)(
        $browserSession['nostr_pubkey'] ?? ''
    )));
$stateId = (string)$activeState['state_id'];
$secret = (string)$activeState['secret'];
$clientPk = (string)$activeState['client_pk'];

if ($stateId === '' || $secret === '' || $clientPk === '') {
    throw new RuntimeException('active NIP-46 state is incomplete');
}

/*
 * From here on, rendering uses only the existing state selected above.
 * There are deliberately no INSERT/UPDATE statements on the plain GET path.
 */

// Advertise every configured listen relay using repeated relay= parameters.
$relayParams = '';
foreach (nip46_listen_relays() as $lr) $relayParams .= '&relay=' . urlencode($lr);
$connectUri = 'nostrconnect://' . $clientPk
    . '?secret=' . $secret
    . $relayParams
    . '&perms=' . urlencode(NL_PERMS)
    . '&name=' . urlencode('friendly-machines bridge')
    . '&url=' . urlencode('https://auth.friendly-machines.com/v1');

// Keep HTML and JavaScript encodings separate. HTML entities are not
// decoded inside <script>, so feeding e($connectUri) to QR/copy corrupts
// every "&relay=" into "&amp;relay=".
$uriHtml = e($connectUri);
$uriJs = json_encode($connectUri, JSON_UNESCAPED_SLASHES);
$sidJs = json_encode($stateId);
$clientPkJs = json_encode($clientPk);
$listenRelaysJs = json_encode(
    nip46_listen_relays(),
    JSON_UNESCAPED_SLASHES
);
$connectionBanked = in_array(
    $activeState['status'] ?? 'waiting',
    ['connected', 'done'],
    true
);
$connectionBankedJs = $connectionBanked ? 'true' : 'false';
$initialPhase = 'waiting_for_approval';
if (($activeState['status'] ?? '') === 'connected') {
    $initialJob = db()->prepare(
        "SELECT payload,last_error FROM jobs
         WHERE dedupe_key=? AND status='pending'
         ORDER BY id DESC LIMIT 1"
    );
    $initialJob->execute(['nip46finish:' . $stateId]);
    $initialJobState = $initialJob->fetch();
    $initialJob->closeCursor();
    $initialPhase = nl_job_phase(
        is_array($initialJobState) ? $initialJobState : null
    );
} elseif (($activeState['status'] ?? '') === 'done') {
    $initialPhase = 'done';
}
$initialPhaseJs = json_encode($initialPhase);
$initialMessage = $initialPhase === 'waiting_for_approval'
    ? 'Waiting for approval in your signer…'
    : ($initialPhase === 'done'
        ? 'Nostr link complete.'
        : nl_phase_message($initialPhase));
$initialMessageJs = json_encode($initialMessage);
$initialDone = $initialPhase === 'done'
    && is_hex64((string)($activeState['pubkey'] ?? ''));
$initialNpub = $initialDone
    ? fm_npub_encode((string)$activeState['pubkey']) : '';
$initialLinked = $initialDone
    ? (bool)nl_login_for((string)$activeState['pubkey']) : false;
$initialNpubJs = json_encode($initialNpub);
$initialLinkedJs = $initialLinked ? 'true' : 'false';

$connectInstructions = $connectionBanked
    ? ''
    : '<p>Open this connection in Amber or another NIP-46 signer, then approve '
      . 'it there. You only approve once; everything after that is automatic.</p>'
      . '<div id="qr" style="margin:1rem 0"></div>'
      . '<p><a class="btn" href="' . $uriHtml . '">Open in signer app</a> '
      . '<button id="copy" class="btn secondary" type="button">'
      . 'Copy connection code</button></p>'
      . '<details><summary>Show the full connection code</summary>'
      . '<pre>' . $uriHtml . '</pre></details>';

$steps = [
    [
        'waiting_for_approval',
        'Approve in your signer',
        'Amber sends an encrypted approval through Nostr; this page waits for it.',
    ],
    [
        'checking_relays',
        'Find a working connection',
        'The bridge asks your signer where future requests should be sent.',
    ],
    [
        'identifying_account',
        'Identify your Nostr account',
        'The bridge requests your public key. Your private key never leaves your signer.',
    ],
    [
        'verifying_signer',
        'Verify signing access',
        'Your signer signs one private challenge. The challenge is checked, not published.',
    ],
    [
        'saving_link',
        'Save the link',
        'The encrypted signer connection is stored and joined to GitHub if you linked GitHub.',
    ],
];
$phaseNames = array_column($steps, 0);
$initialStep = array_search($initialPhase, $phaseNames, true);
if ($initialPhase === 'done') $initialStep = count($steps);
if (!is_int($initialStep)) $initialStep = 0;
$stepsHtml = '';
foreach ($steps as $index => [$phase, $label, $description]) {
    $class = $index < $initialStep
        ? 'done' : ($index === $initialStep ? 'current' : '');
    $mark = $index < $initialStep ? '✓' : (string)($index + 1);
    $current = $index === $initialStep ? ' aria-current="step"' : '';
    $stepsHtml .= '<li data-phase="' . e($phase) . '" class="' . $class . '"'
        . $current . '>'
        . '<span class="stepmark">' . $mark . '</span><span><strong>'
        . e($label) . '</strong><small>' . e($description)
        . '</small></span></li>';
}

$troubleshooting = ($activeState['status'] ?? '') === 'connected'
    ? '<details id="troubleshooting"><summary>Having trouble?</summary>'
      . '<p>The bridge retries automatically, even if this page is closed. '
      . 'Only start over if you removed this connection in Amber or intentionally '
      . 'want to replace it.</p>'
      . '<form method="post" action="/v1/nostr-link.php">'
      . '<input type="hidden" name="restart" value="'
      . e((string)$activeState['state_id']) . '">'
      . '<button class="btn secondary" type="submit">Start over with Amber</button>'
      . '</form></details>'
    : '';

$setupHidden = $initialDone ? ' hidden' : '';
$successHidden = $initialDone ? '' : ' hidden';
$successText = $initialDone
    ? '<p>Nostr account: <code>' . e($initialNpub) . '</code></p>'
      . ($initialLinked
          ? '<p>Your GitHub and Nostr identities are linked. Mirrored GitHub '
            . 'activity can now use your signer.</p>'
          : '<p>Your Nostr signer is connected. GitHub remains optional; '
            . '<a href="/">identify it from the account page</a> only if you want '
            . 'GitHub activity associated with this identity.</p>')
    : '';
$browserSessionNotice = $browserHasIdentity
    ? ''
    : '<div class="card"><strong>This browser is not currently associated '
      . 'with a verified identity.</strong><p>That does not mean an existing '
      . 'durable bridge link was removed. This page can only report an '
      . 'identity after this browser proves it through GitHub or a Nostr '
      . 'signer.</p><p><a href="/">Return to account status</a> or continue '
      . 'below to identify with this signer.</p></div>';

$body = <<<HTML
<h1>Link your Nostr identity</h1>
<p id="intro">This optional connection lets the bridge mirror GitHub activity
under your own Nostr identity. Without it, the standalone Nostr client still
works and GitHub activity is mirrored under the clearly labeled bridge account.</p>
$browserSessionNotice
<section id="linkSetup"$setupHidden>
<div id="nip07warn" style="display:none;border:1px solid #b06000;background:#fff7e8;
     padding:1em;border-radius:8px;margin:1rem 0">
<strong>A browser extension cannot finish this particular link.</strong>
The bridge needs a signer such as Amber or Bunker46 that can answer later,
when your browser is closed.
</div>
$connectInstructions
<section class="card" aria-labelledby="progressTitle">
<h2 id="progressTitle">What happens next</h2>
<ol id="progressSteps" class="steps">$stepsHtml</ol>
<p id="status" class="statusbox" aria-live="polite"><span
id="statusMessage">$initialMessage</span><small id="statusElapsed"
aria-hidden="true"></small></p>
<p class="muted"><small>No action is needed after approval. You may close this
page; the link continues in the background.</small></p>
</section>
<details id="diagnostics" hidden>
<summary>Technical details</summary>
<code id="diagnosticText"></code>
</details>
$troubleshooting
<details>
<summary>What the bridge is allowed to ask your signer to do</summary>
<p>Sign mirrored repository stars, issues, comments, status changes, and deletion requests;
confirm your public key; and choose connection relays. If you separately opt
in on the account page, the bridge may also ask for one kind 10011 signature
that publicly identifies your linked GitHub account. That profile assertion is
never required for linking or bridging. The bridge never receives your private
key, and you can revoke the connection in your signer.</p>
<p><small>Protocol permissions: Nostr kinds 5, 7, 1111, 1621, 1630, 1631,
1632, and the optional identity kind 10011; plus
<code>get_public_key</code>, <code>switch_relays</code>, and
<code>ping</code>.</small></p>
</details>
<p><a href="/">Identify with GitHub from the account page</a></p>
</section>
<section id="success" class="card success" aria-live="polite"$successHidden>
<h2>✓ Nostr signer linked</h2>
<div id="successText">$successText</div>
<p><a class="btn" href="/">Back to account linking</a></p>
</section>
<script src="/v1/js/qrcode.min.js"></script>
<script>
/* NIP-07-only detection. NIP-07 defines NO ready event -- extensions
   just assign window.nostr whenever they like (nos2x: document_idle,
   i.e. after page scripts; DOMContentLoaded/onload fire BEFORE that, so
   they cannot be used). Platform pattern for "act when a global
   appears": defineProperty setter trap, firing the instant the
   extension assigns window.nostr. Inline placement is guaranteed to
   precede any content-script injection, by browser architecture. */
(function () {
  if ($connectionBankedJs) return;
  var warned = false;
  function check(n) {
    if (!n || warned) return;
    try {
      if (!(n.nip46 || n.bunker || n.connect)) {   // no bunker capability
        document.getElementById('nip07warn').style.display = '';
        warned = true;
      }
    } catch (e) { /* never block the page */ }
  }
  var current = window.nostr;
  if (current) { check(current); return; }          // extension beat us
  var pending;
  Object.defineProperty(window, 'nostr', {
    configurable: true,
    get: function () { return pending; },
    set: function (v) { pending = v; check(v); }    // extension arrives now
  });
})();
</script>
<script>
/* QR render + wait loop */
const qrElement = document.getElementById('qr');
if (qrElement && typeof qrcode !== 'undefined') {
  qrcode.stringToBytes = qrcode.stringToBytesFuncs['UTF-8'];
  var qr = qrcode(0, 'L');
  qr.addData($uriJs, 'Byte');
  qr.make(4, 16);

//  return qr.createTableTag();
//  return qr.createSvgTag();
  qrElement.innerHTML = qr.createImgTag();

  //qrcode(document.getElementById('qr'), { text: $uriJs, width: 220, height: 220 });
} else if (qrElement) {
  qrElement.innerHTML =
    '<small style="color:#b06000">QR library failed to load — use the buttons below instead.</small>';
}
(async () => {
  const sid = $sidJs;
  const clientPk = $clientPkJs;
  const listenRelays = $listenRelaysJs;
  const connectionBanked = $connectionBankedJs;
  const initialPhase = $initialPhaseJs;
  const initialMessage = $initialMessageJs;
  const initialNpub = $initialNpubJs;
  const initialLinked = $initialLinkedJs;
  const linkSetup = document.getElementById('linkSetup');
  const success = document.getElementById('success');
  const successText = document.getElementById('successText');
  const st = document.getElementById('status');
  const statusMessage = document.getElementById('statusMessage');
  const statusElapsed = document.getElementById('statusElapsed');
  const diagnostic = document.getElementById('diagnostics');
  const diagnosticText = document.getElementById('diagnosticText');
  const phases = [
    'waiting_for_approval',
    'checking_relays',
    'identifying_account',
    'verifying_signer',
    'saving_link'
  ];
  let relayWatchersStopped = false;
  let approvalListenerStopped = connectionBanked;
  let displayedPhase = null;
  let phaseStartedAt = performance.now();
  const relaySockets = new Map();
  const pendingEvents = new Map();

  function setPhase(phase, message, detail, attempts, retryAt) {
    let current = phases.indexOf(phase);
    if (current < 0) current = 0;
    if (phase !== displayedPhase) {
      displayedPhase = phase;
      phaseStartedAt = performance.now();
      statusElapsed.textContent = '';
    }
    document.querySelectorAll('#progressSteps li').forEach((item, index) => {
      item.className = index < current
        ? 'done' : (index === current ? 'current' : '');
      if (index === current) item.setAttribute('aria-current', 'step');
      else item.removeAttribute('aria-current');
      item.querySelector('.stepmark').textContent =
        index < current ? '✓' : String(index + 1);
    });
    st.className = 'statusbox';
    statusMessage.textContent = message || 'Continuing automatically…';
    if (detail) {
      const retry = retryAt > Math.floor(Date.now() / 1000)
        ? ' Next automatic attempt: '
          + new Date(retryAt * 1000).toLocaleTimeString() + '.'
        : '';
      diagnostic.hidden = false;
      diagnosticText.textContent =
        'Automatic attempt ' + Number(attempts || 0) + '. '
        + 'Last result: ' + detail + '.' + retry;
    } else {
      diagnostic.hidden = true;
      diagnosticText.textContent = '';
    }
  }

  setInterval(() => {
    if (linkSetup.hidden || displayedPhase === null) return;
    const elapsed = (performance.now() - phaseStartedAt) / 1000;
    if (elapsed < 1) {
      statusElapsed.textContent = '';
      return;
    }
    const seconds = Math.floor(elapsed);
    statusElapsed.textContent = displayedPhase === 'waiting_for_approval'
      ? 'Waiting for your approval — ' + seconds + 's.'
      : 'Still working on this step — ' + seconds + 's.';
  }, 250);

  function showDone(npub, linked) {
    stopRelayWatchers();
    linkSetup.hidden = true;
    success.hidden = false;
    successText.replaceChildren();
    const identity = document.createElement('p');
    identity.append(document.createTextNode('Nostr account: '));
    const code = document.createElement('code');
    code.textContent = npub;
    identity.append(code);
    successText.append(identity);
    const outcome = document.createElement('p');
    if (linked) {
      outcome.textContent =
        'Your GitHub and Nostr identities are linked. Mirrored GitHub activity can now use your signer.';
    } else {
      outcome.append(document.createTextNode(
        'Your Nostr signer is connected. GitHub remains optional; '
      ));
      const github = document.createElement('a');
      github.href = '/';
      github.textContent = 'identify it from the account page';
      outcome.append(github, document.createTextNode(
        ' only if you want GitHub activity associated with this identity.'
      ));
    }
    successText.append(outcome);
  }

  function stopRelayWatchers() {
    relayWatchersStopped = true;
    approvalListenerStopped = true;
    for (const socket of relaySockets.values()) {
      try { socket.close(); } catch (_) {}
    }
    relaySockets.clear();
  }

  async function forwardConnectEvent(event, observedRelays) {
    try {
      const response = await fetch('?connect=' + encodeURIComponent(sid), {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({event: event, relays: observedRelays})
      });
      const result = await response.json();
      if (result.accepted) {
        stopRelayWatchers();
        setPhase(
          'checking_relays',
          'Signer approved. Finding a reliable connection to your signer…'
        );
      }
    } catch (_) {
      // The state poll and cron remain independent backstops.
    }
  }

  function observeConnectEvent(event, relay) {
    if (!event || typeof event.id !== 'string') return;
    let pending = pendingEvents.get(event.id);
    if (!pending) {
      pending = {event: event, relays: new Set(), timer: null};
      pendingEvents.set(event.id, pending);
    }
    pending.relays.add(relay);
    clearTimeout(pending.timer);
    pending.timer = setTimeout(() => {
      pendingEvents.delete(event.id);
      forwardConnectEvent(
        pending.event,
        Array.from(pending.relays).sort()
      );
    }, 150);
  }

  function watchRelay(relay) {
    if (relayWatchersStopped) return;
    let socket;
    try { socket = new WebSocket(relay); }
    catch (_) {
      setTimeout(() => watchRelay(relay), 1000);
      return;
    }
    relaySockets.set(relay, socket);
    socket.onopen = () => {
      const random = new Uint8Array(8);
      crypto.getRandomValues(random);
      const sub = 'nip46-' + Array.from(random)
        .map(byte => byte.toString(16).padStart(2, '0')).join('');
      socket.send(JSON.stringify([
        'REQ',
        sub,
        {kinds: [24133], '#p': [clientPk], since: Math.max(1, Math.floor(Date.now() / 1000) - 120)}
      ]));
    };
    socket.onmessage = message => {
      let decoded;
      try { decoded = JSON.parse(message.data); } catch (_) { return; }
      if (
        !Array.isArray(decoded)
        || decoded[0] !== 'EVENT'
        || !decoded[2]
        || decoded[2].kind !== 24133
        || !Array.isArray(decoded[2].tags)
        || !decoded[2].tags.some(tag => (
          Array.isArray(tag) && tag[0] === 'p' && tag[1] === clientPk
        ))
      ) return;
      observeConnectEvent(decoded[2], relay);
    };
    socket.onclose = () => {
      relaySockets.delete(relay);
      if (!relayWatchersStopped) setTimeout(() => watchRelay(relay), 500);
    };
    socket.onerror = () => {
      try { socket.close(); } catch (_) {}
    };
  }

  async function listenForApproval() {
    while (!approvalListenerStopped) {
      try {
        const response = await fetch(
          '/v1/nostr-link.php',
          {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: new URLSearchParams({listen: sid})
          }
        );
        const result = await response.json();
        if (result.accepted) {
          stopRelayWatchers();
          setPhase(
            'checking_relays',
            'Signer approved. Finding a reliable connection to your signer…'
          );
          return;
        }
      } catch (_) {
        // Browser relay watchers and cron are independent backstops.
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  async function acknowledgeCompletion() {
    try {
      const response = await fetch('/v1/nostr-link.php', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams({complete: sid})
      });
      return response.ok;
    } catch (_) {
      return false;
    }
  }

  if (!connectionBanked) listenRelays.forEach(watchRelay);
  if (!connectionBanked) listenForApproval();
  if (initialPhase === 'done') {
    await acknowledgeCompletion();
    showDone(initialNpub, initialLinked);
    return;
  }
  setPhase(initialPhase, initialMessage);
  const copyButton = document.getElementById('copy');
  if (copyButton) {
    copyButton.onclick = () => {
      navigator.clipboard.writeText($uriJs);
      copyButton.textContent = "Copied!";
    };
  }
  while (true) {
    let r;
    try {
      r = await (await fetch(
        '?wait=' + encodeURIComponent(sid),
        {credentials: 'same-origin', cache: 'no-store'}
      )).json();
    } catch (e) {
      statusMessage.textContent =
        'The page lost contact with the server. Retrying…';
      await new Promise(resolve => setTimeout(resolve, 500));
      continue;
    }
    if (r.status === 'done') {
      stopRelayWatchers();
      setPhase('saving_link', 'Link complete. Loading your account…');
      await acknowledgeCompletion();
      window.location.reload();
      return;
    }
    if (r.status === 'failed' || r.status === 'expired') {
      stopRelayWatchers();
      st.className = 'statusbox';
      statusMessage.textContent =
        '✖ ' + (r.error || 'session expired') + ' — reload to retry.';
      statusElapsed.textContent = '';
      return;
    }
    if (r.status === 'timeout') {
      statusMessage.textContent = 'Still waiting; checking again…';
    }
    if (r.status === 'pending') {
      stopRelayWatchers();
      setPhase(
        r.phase,
        r.message,
        r.diagnostic,
        r.attempts,
        r.retry_at
      );
    }
    if (r.status === 'auth_required') {
      stopRelayWatchers();
      setPhase(r.phase, r.message, null, r.attempts, 0);
      statusMessage.replaceChildren();
      statusMessage.append(document.createTextNode(
        (r.message || 'Your signer requires authorization.') + ' '
      ));
      const link = document.createElement('a');
      link.className = 'btn';
      link.href = r.url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = 'Continue signer authorization';
      statusMessage.append(link);
    }
    if (r.status === 'waiting') {
      setPhase(
        'waiting_for_approval',
        r.message || 'Waiting for approval in your signer…',
        null,
        0,
        0
      );
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
})();
</script>
HTML;
echo nl_page('Link Nostr', $body);

<?php
/**
 * github/callback.php  ==  /v1/github/callback
 * Step 1 completion: GitHub App user authorization -> login; store encrypted.
 *
 * State is a single-use server nonce bound to the browser's server-side link
 * session. Tokens are encrypted at rest and are never returned to the page.
 * Either the GitHub or Nostr half may complete first.
 */
declare(strict_types=1);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../lib/secrets.php';
require_once __DIR__ . '/../lib/util.php';
require_once __DIR__ . '/../lib/linking.php';
require_once __DIR__ . '/../lib/github_app.php';

header('Cache-Control: no-store');

function page(string $title, string $body): string
{
    $t = e($title);
    return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
         . "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
         . "<title>$t</title>"
         . "<style>body{font-family:system-ui,sans-serif;max-width:42em;margin:3rem auto;padding:0 1rem;line-height:1.5}"
         . "code{background:#f4f4f4;padding:.1em .3em;border-radius:3px}"
         . ".ok{color:#0a7d28}.warn{color:#b06000}.btn{display:inline-block;margin-top:1rem;padding:.6rem 1.2rem;"
         . "background:#24292f;color:#fff;border-radius:6px;text-decoration:none}</style></head>"
         . "<body>$body</body></html>";
}

function fail(string $msg, int $code = 400): string
{
    http_response_code($code);
    return page('Linking failed', "<h1>GitHub linking failed</h1><p>" . e($msg) . '</p>'
        . '<form method="post" action="/v1/github/login">'
        . '<button class="btn" type="submit">Try again</button></form>');
}

// 0. loud secret check -----------------------------------------------------
try {
    fm_secret_github_app();
} catch (MissingSecret $ex) {
    bridge_log('gh-callback', 'GitHub App configuration missing', [
        'error' => $ex->getMessage(),
    ]);
    http_response_code(500);
    exit(page('Setup needed', '<h1>Bridge not fully configured</h1>'
        . '<p>The server-side GitHub App configuration is incomplete.</p>'));
}

// 1. state must be a live, single-use attempt bound to this browser's
//    long-lived link session -----------------------------------------------
$code  = $_GET['code'] ?? '';
$state = $_GET['state'] ?? '';
$cookie = $_COOKIE['bridge_oauth'] ?? '';
$oauthError = $_GET['error_description'] ?? $_GET['error'] ?? '';
if (is_string($oauthError) && $oauthError !== '') {
    exit(fail('GitHub authorization was not completed: ' . $oauthError));
}
if (!is_string($code) || !is_string($state) || !is_string($cookie)
    || $code === '' || $state === '' || $cookie === '') {
    exit(fail('Missing code/state (try again from the start).'));
}

$row = db()->prepare('SELECT * FROM github_oauth_attempts WHERE state = ?');
$row->execute([$state]);
$attempt = $row->fetch();
if (!$attempt || (int)$attempt['expires_at'] < now()
    || !hash_equals((string)$attempt['session_nonce'], $cookie)
    || !is_string($attempt['code_verifier'] ?? null)
    || strlen($attempt['code_verifier']) < 43) {
    exit(fail('Login session expired or invalid. Start again.'));
}
$sessionNonce = (string)$attempt['session_nonce'];
$row = db()->prepare('SELECT * FROM oauth_states WHERE nonce = ? AND expires_at > ?');
$row->execute([$sessionNonce, now()]);
$st = $row->fetch();
if (!$st) exit(fail('Link session expired. Start again.'));

// 2. exchange code for expiring user + refresh tokens ----------------------
try {
    $tokens = gh_app_exchange_code(
        $code,
        $attempt['code_verifier'],
        'https://auth.friendly-machines.com/v1/github/callback'
    );
} catch (Throwable $error) {
    bridge_log('gh-callback', 'token exchange failed', [
        'err' => $error->getMessage(),
    ]);
    exit(fail('GitHub did not return a usable App user token.', 502));
}
$token = $tokens['access_token'];

// 3. who are we? ------------------------------------------------------------
try {
    $user = gh_request('GET', '/user', $token);
} catch (Throwable $error) {
    bridge_log('gh-callback', 'user lookup failed', [
        'err' => $error->getMessage(),
    ]);
    exit(fail('Could not fetch GitHub user.', 502));
}
$login = is_array($user) && is_string($user['login'] ?? null) ? $user['login'] : '';
$githubUserId = (is_int($user['id'] ?? null) || is_string($user['id'] ?? null))
    && ctype_digit((string)$user['id'])
    ? (string)$user['id'] : '';
if ($login === '' || $githubUserId === ''
    || !preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/', $login)) {
    bridge_log('gh-callback', 'user lookup failed', [
        'err' => 'invalid user response',
    ]);
    exit(fail('Could not fetch GitHub user.', 502));
}

// 4. persist (encrypted) ----------------------------------------------------
db()->beginTransaction();
try {
    $consume = db()->prepare('DELETE FROM github_oauth_attempts WHERE state = ?');
    $consume->execute([$state]);
    if ($consume->rowCount() !== 1) {
        throw new GhUserIdentityConflict(
            'This GitHub authorization was already used'
        );
    }
    gh_app_store_user_authorization($login, $githubUserId, $tokens);

    // record the github half on this handshake row
    db()->prepare('UPDATE oauth_states
                   SET github_login = ?, expires_at = MAX(expires_at, ?)
                   WHERE nonce = ?')
       ->execute([
           $login,
           now() + FM_PARTIAL_LINK_SESSION_SECS,
           $sessionNonce,
       ]);

    // Nostr-first completion. Re-read inside this transaction after writing
    // the GitHub half: nip46_finish may have committed while the OAuth
    // network calls were in flight.
    $freshSession = db()->prepare(
        'SELECT nostr_pubkey FROM oauth_states WHERE nonce=?'
    );
    $freshSession->execute([$sessionNonce]);
    $nostrPk = strtolower((string)($freshSession->fetchColumn() ?: ''));
    if (is_hex64($nostrPk)) {
        $na = db()->prepare(
            "SELECT 1 FROM nostr_accounts WHERE pubkey=? AND status='linked'"
        );
        $na->execute([$nostrPk]);
        if ($na->fetchColumn()) {
            fm_link_identities($login, $nostrPk);
        }
    }
    db()->commit();
} catch (IdentityLinkConflict|GhUserIdentityConflict $error) {
    if (db()->inTransaction()) db()->rollBack();
    exit(fail(
        'That GitHub or Nostr identity is already linked to another account.',
        409
    ));
} catch (Throwable $error) {
    if (db()->inTransaction()) db()->rollBack();
    bridge_log('gh-callback', 'authorization persistence failed', [
        'err' => $error->getMessage(),
    ]);
    exit(fail('Could not securely save the GitHub authorization.', 500));
}

// Burn only the OAuth attempt. The server-backed link session remains, so
// Nostr may finish later without another GitHub authorization.
fm_set_link_session_cookie(
    $sessionNonce,
    now() + FM_PARTIAL_LINK_SESSION_SECS
);

// 5. show status; offer nostr half if missing -------------------------------
$linked = db()->prepare('
    SELECT na.pubkey, na.status FROM nostr_accounts na
    JOIN links l ON l.pubkey = na.pubkey
    WHERE l.login = ?');
$linked->execute([$login]);
$nostr = $linked->fetch();

$npub = $nostr ? fm_npub_encode($nostr['pubkey']) : null;

$body = '<h1 class="ok">GitHub linked ✔</h1>'
      . '<p>GitHub identity <strong>@' . e($login) . '</strong> is now linked'
      . ' through the Friendly Machines Nostr Bridge GitHub App.</p>';
if ($nostr && $nostr['status'] === 'linked') {
    $body .= '<p class="ok">Nostr already linked too: <code>' . e($npub) . '</code>.'
           . ' <strong>You are fully bridged — nothing more to do.</strong></p>';
} else {
    $body .= '<p>Next step (optional but recommended): link your Nostr identity'
           . ' so your comments and issues get signed with YOUR key.</p>'
           . '<a class="btn" href="/v1/nostr-link.php">Link Nostr</a>';
}
$body .= '<p style="margin-top:2rem;color:#666"><small>This bridge never sees your keys.'
      . ' GitHub token and Nostr session are stored encrypted server-side.</small></p>'
      . '<p><a href="/">Back to account linking</a></p>';
echo page('GitHub linked', $body);

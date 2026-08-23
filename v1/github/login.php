<?php
/**
 * github/login.php  ==  /v1/github/login
 * Step 1 of the linking handshake: authorize the GitHub App as this user.
 *
 * Flow:
 *   - accept an explicit POST only; a page view never allocates OAuth state
 *   - ensure a long-lived, server-backed link session in an HttpOnly cookie
 *   - mint a separate, single-use OAuth state (+15 min)
 *   - 302 -> github.com/login/oauth/authorize?client_id..&state=<state>
 *   - github/callback.php completes the handshake.
 */
declare(strict_types=1);

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('POST required');
}

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../lib/secrets.php';
require_once __DIR__ . '/../lib/github_app.php';

header('Cache-Control: no-store');
$app = fm_secret_github_app();   // loud failure if not set up yet

// GC old attempts/sessions opportunistically (cheap at this scale).
db()->prepare('DELETE FROM github_oauth_attempts WHERE expires_at < ?')->execute([now()]);
db()->prepare('DELETE FROM oauth_states WHERE expires_at < ?')->execute([now()]);

// Reuse the server-backed browser link session when Nostr arrived first.
// OAuth state is deliberately separate and single-use.
$sessionNonce = is_string($_COOKIE['bridge_oauth'] ?? null)
    ? $_COOKIE['bridge_oauth'] : '';
$session = null;
if (preg_match('/^[0-9a-f]{64}$/', $sessionNonce)) {
    $st = db()->prepare('SELECT * FROM oauth_states WHERE nonce=? AND expires_at>?');
    $st->execute([$sessionNonce, now()]);
    $session = $st->fetch();
}
if (!$session) {
    $sessionNonce = random_hex(32);
    db()->prepare('INSERT INTO oauth_states (nonce, created_at, expires_at) VALUES (?,?,?)')
       ->execute([
           $sessionNonce,
           now(),
           now() + FM_EMPTY_LINK_SESSION_SECS,
       ]);
} else {
    $ttl = ($session['github_login'] || $session['nostr_pubkey'])
        ? FM_PARTIAL_LINK_SESSION_SECS : FM_EMPTY_LINK_SESSION_SECS;
    db()->prepare('UPDATE oauth_states SET expires_at=MAX(expires_at, ?) WHERE nonce=?')
       ->execute([now() + $ttl, $sessionNonce]);
}

$sessionExpiry = $session
    && ($session['github_login'] || $session['nostr_pubkey'])
    ? now() + FM_PARTIAL_LINK_SESSION_SECS
    : now() + FM_EMPTY_LINK_SESSION_SECS;
fm_set_link_session_cookie($sessionNonce, $sessionExpiry);

$oauthState = random_hex(32);
$codeVerifier = gh_base64url(random_bytes(32));
$codeChallenge = gh_base64url(hash('sha256', $codeVerifier, true));
db()->prepare('INSERT INTO github_oauth_attempts
               (state,session_nonce,code_verifier,created_at,expires_at)
               VALUES (?,?,?,?,?)')
   ->execute([
       $oauthState,
       $sessionNonce,
       $codeVerifier,
       now(),
       now() + 900,
   ]);

$authorize = 'https://github.com/login/oauth/authorize?' . http_build_query([
    'client_id'    => $app['client_id'],
    'redirect_uri' => 'https://auth.friendly-machines.com/v1/github/callback',
    'state'        => $oauthState,
    'code_challenge' => $codeChallenge,
    'code_challenge_method' => 'S256',
    'allow_signup' => 'true',
]);
header('Location: ' . $authorize, true, 302);
exit;

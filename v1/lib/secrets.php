<?php
/**
 * secrets.php -- loud loader for server-side secret files.
 *
 * Secrets NEVER live in the webroot. Layout (created by the operator):
 *   /home/dh_4nnf3n/secrets/github-webhook.php
 *   /home/dh_4nnf3n/secrets/github-app.php
 *   /home/dh_4nnf3n/secrets/github-app-private-key.pem
 *   /home/dh_4nnf3n/secrets/repo-registration.php
 *   /home/dh_4nnf3n/secrets/db-crypt.php
 *   /home/dh_4nnf3n/secrets/bridge-key.php
 *
 * Every getter fails LOUD with exact setup instructions, so a missing
 * secret is an obvious 500 at first use, never a silent insecure default.
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';

class MissingSecret extends RuntimeException {}

/** Secret ownership is a required runtime check, not a best-effort warning. */
function fm_secret_process_uid(): int
{
    if (!function_exists('posix_geteuid')) {
        throw new MissingSecret(
            'PHP POSIX support is required to verify secret-file ownership'
        );
    }
    return posix_geteuid();
}

/** @return array{dir:string, path:string, name:string} */
function fm_secret_path(string $name): array
{
    if (!preg_match('/\A[a-z0-9][a-z0-9.-]*\z/', $name)) {
        throw new MissingSecret('invalid secret filename');
    }
    $dir = fm_secrets_dir();
    if (!is_dir($dir)) {
        throw new MissingSecret("Secrets directory missing at $dir");
    }
    $mode = fileperms($dir);
    if ($mode === false || ($mode & 0777) !== 0700) {
        throw new MissingSecret(
            "Secrets directory $dir must have mode 0700"
        );
    }
    $owner = fileowner($dir);
    if ($owner === false || $owner !== fm_secret_process_uid()) {
        throw new MissingSecret(
            "Secrets directory $dir must be owned by the server account"
        );
    }
    return ['dir' => $dir, 'path' => "$dir/$name", 'name' => $name];
}

function fm_require_secret_file_security(string $path): void
{
    if (is_link($path)) {
        throw new MissingSecret("Secret $path must not be a symbolic link");
    }
    $mode = fileperms($path);
    if ($mode === false || ($mode & 0777) !== 0600) {
        throw new MissingSecret("Secret $path must have mode 0600");
    }
    $owner = fileowner($path);
    if ($owner === false || $owner !== fm_secret_process_uid()) {
        throw new MissingSecret(
            "Secret $path must be owned by the server account"
        );
    }
}

/** Require a secrets file that `return`s a string. */
function fm_secret_string(string $name): string
{
    ['path' => $path, 'dir' => $dir] = fm_secret_path($name);
    if (!is_file($path)) {
        throw new MissingSecret(sprintf(
            "Secret %s missing. Create it on the server as:\n  %s\ncontaining exactly:\n  <?php return 'PUT-SECRET-HERE';",
            $name, $path));
    }
    fm_require_secret_file_security($path);
    $v = require $path;
    if (!is_string($v) || $v === '' || str_starts_with($v, 'PUT-')) {
        throw new MissingSecret("$name at $path must return a non-empty string");
    }
    return $v;
}

/** Require a secrets file that `return`s an array. */
function fm_secret_array(string $name): array
{
    ['path' => $path] = fm_secret_path($name);
    if (!is_file($path)) {
        throw new MissingSecret("Secret $name missing. Create it at $path returning an array.");
    }
    fm_require_secret_file_security($path);
    $v = require $path;
    if (!is_array($v)) {
        throw new MissingSecret("$name at $path must return an array");
    }
    return $v;
}

/** Require an opaque non-PHP secret file. */
function fm_secret_file(string $name): string
{
    ['path' => $path] = fm_secret_path($name);
    if (!is_file($path) || !is_readable($path)) {
        throw new MissingSecret("Secret $name missing or unreadable at $path");
    }
    fm_require_secret_file_security($path);
    $value = file_get_contents($path);
    if (!is_string($value) || trim($value) === '') {
        throw new MissingSecret("$name at $path must be a non-empty file");
    }
    return $value;
}

function fm_secret_github_webhook(): string { return fm_secret_string('github-webhook.php'); }
function fm_secret_repo_registration(): string { return fm_secret_string('repo-registration.php'); }

/**
 * Organization-owned GitHub App registration. The App may be installed on
 * either organization or personal accounts.
 *
 * @return array{client_id:string,client_secret:string}
 */
function fm_secret_github_app(): array
{
    if (is_array($GLOBALS['__fm_test_github_app'] ?? null)) {
        $a = $GLOBALS['__fm_test_github_app'];
    } else {
        $a = fm_secret_array('github-app.php');
    }
    foreach (['client_id', 'client_secret'] as $key) {
        if ((!is_string($a[$key] ?? null) && !is_int($a[$key] ?? null))
            || (string)$a[$key] === '') {
            throw new MissingSecret("github-app.php must define '$key'");
        }
    }
    return [
        'client_id' => (string)$a['client_id'],
        'client_secret' => (string)$a['client_secret'],
    ];
}

function fm_secret_github_app_private_key(): string
{
    if (is_string($GLOBALS['__fm_test_github_app_private_key'] ?? null)
        && $GLOBALS['__fm_test_github_app_private_key'] !== '') {
        return $GLOBALS['__fm_test_github_app_private_key'];
    }
    $pem = fm_secret_file('github-app-private-key.pem');
    $key = openssl_pkey_get_private($pem);
    if ($key === false) {
        throw new MissingSecret('github-app-private-key.pem is not a valid private key');
    }
    $details = openssl_pkey_get_details($key);
    if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
        throw new MissingSecret('github-app-private-key.pem must contain the GitHub App RSA key');
    }
    return $pem;
}

/** 32-byte raw AES-256-GCM key derived from 64-hex secret. */
function fm_secret_db_crypt_key(): string
{
    $hex = fm_secret_string('db-crypt.php');
    if (!is_hex64($hex)) {
        throw new MissingSecret('db-crypt.php must be 64 hex chars (32 bytes)');
    }
    return h2b($hex);
}

/** Bridge identity private key (64 hex). */
function fm_secret_bridge_key(): string
{
    $hex = fm_secret_string('bridge-key.php');
    if (!is_hex64($hex)) {
        throw new MissingSecret('bridge-key.php must be 64 hex chars (nsec material, hex form)');
    }
    return $hex;
}

// --------------------------------------------------------------------------
// at-rest encryption for tokens / bunker URIs (AES-256-GCM via ext-sodium)
// --------------------------------------------------------------------------

/** Encrypt plaintext for storage; returns "v1:<b64 iv>|<b64 tag>|<b64 ct>". */
function fm_encrypt_at_rest(string $pt): string
{
    fm_require_aes256gcm();
    $key = fm_secret_db_crypt_key();
    $iv  = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
    $ct  = sodium_crypto_aead_aes256gcm_encrypt($pt, '', $iv, $key);
    $tag = substr($ct, -16);
    return 'v1:' . base64_encode($iv) . '|' . base64_encode($tag) . '|' . base64_encode(substr($ct, 0, -16));
}

function fm_decrypt_at_rest(string $blob): string
{
    fm_require_aes256gcm();
    if (!str_starts_with($blob, 'v1:')) throw new RuntimeException('unknown crypt blob version');
    $rest = substr($blob, 3);
    $parts = explode('|', $rest);
    if (count($parts) !== 3) throw new RuntimeException('malformed crypt blob');
    [$iv, $tag, $ct] = array_map(fn($p) => base64_decode($p, true), $parts);
    if ($iv === false || $tag === false || $ct === false) throw new RuntimeException('bad b64 in crypt blob');
    if (strlen($iv) !== SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES || strlen($tag) !== 16) {
        throw new RuntimeException('malformed crypt blob lengths');
    }
    $key = fm_secret_db_crypt_key();
    $pt = sodium_crypto_aead_aes256gcm_decrypt($ct . $tag, '', $iv, $key);
    if ($pt === false) throw new RuntimeException('crypt blob does not decrypt (wrong key?)');
    return $pt;
}

function fm_require_aes256gcm(): void
{
    if (!function_exists('sodium_crypto_aead_aes256gcm_is_available')
        || !sodium_crypto_aead_aes256gcm_is_available()) {
        throw new RuntimeException('libsodium AES-256-GCM is unavailable on this host/CPU');
    }
}

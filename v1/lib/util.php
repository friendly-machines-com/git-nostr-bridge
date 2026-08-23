<?php
/**
 * util.php -- shared helpers for the friendly-machines bridge.
 * No dependencies beyond PHP core. Everything pure.
 */
declare(strict_types=1);

// Every runtime-created database, queue, lock, and log file is private.
umask(0077);

/*
 * An empty link session is unauthenticated server state, so retain it for
 * only one hour to bound abandoned rows and cookie-driven allocation. Once
 * either verified identity half exists, retain the session for 30 days so
 * the user can complete the other half later and in either order.
 */
const FM_EMPTY_LINK_SESSION_SECS = 3600;
const FM_PARTIAL_LINK_SESSION_SECS = 86400 * 30;

/*
 * This deployment runs under one fixed hosting account. mod_fcgid does not
 * provide HOME, so security-sensitive paths must not depend on environment
 * discovery or on the web document root.
 */
const FM_SECRETS_DIR = '/home/dh_4nnf3n/secrets';
const FM_LOG_FILE = '/home/dh_4nnf3n/github-webhook.log';

/**
 * Keep the browser cookie and its server-side session on the same deadline.
 * Cron cannot refresh a browser cookie, so every browser endpoint that sees
 * or completes a verified identity half calls this helper.
 */
function fm_set_link_session_cookie(string $nonce, int $expiresAt): void
{
    if (!preg_match('/^[0-9a-f]{64}$/', $nonce) || $expiresAt <= now()) {
        throw new InvalidArgumentException('invalid link-session cookie');
    }
    setcookie('bridge_oauth', $nonce, [
        'expires' => $expiresAt,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $_COOKIE['bridge_oauth'] = $nonce;
}

/** Test seam: when set (by tests/), use this dir for secrets instead. */
function fm_secrets_dir(): string
{
    if ($GLOBALS['__fm_test_secrets_dir'] ?? null) return $GLOBALS['__fm_test_secrets_dir'];
    return FM_SECRETS_DIR;
}
function fm_log_file(): string
{
    if ($GLOBALS['__fm_test_log'] ?? null) return $GLOBALS['__fm_test_log'];
    return FM_LOG_FILE;
}

function now(): int { return time(); }

function random_hex(int $bytes = 32): string { return bin2hex(random_bytes($bytes)); }

function b2h(string $bin): string { return bin2hex($bin); }
function h2b(string $hex): string
{
    if (!preg_match('/^[0-9a-fA-F]*$/', $hex) || strlen($hex) % 2 !== 0) {
        throw new InvalidArgumentException('bad hex');
    }
    return hex2bin($hex);
}

function is_hex64(string $s): bool { return (bool)preg_match('/^[0-9a-f]{64}$/', strtolower($s)); }

/** JSON encode in the canonical nostr style (compact, no escaped slashes). */
function json_c($data): string
{
    $s = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($s === false) throw new RuntimeException('json_encode failed');
    return $s;
}

/** Append one line to the bridge log (outside webroot). Never fatal. */
function bridge_log(string $tag, string $msg, array $ctx = []): void
{
    try {
        $context = $ctx ? json_c($ctx) : '-';
    } catch (Throwable $e) {
        $context = '{"log_context":"encoding failed"}';
    }
    $line = sprintf("%s\t%s\t%s\t%s\n",
        date('c'), $tag, $msg, $context);
    $file = fm_log_file();
    @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    @chmod($file, 0600);
}

/** HTML-escape for the rare times we render something user-visible. */
function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

/** Clamp an int between bounds. */
function clamp(int $v, int $lo, int $hi): int { return max($lo, min($hi, $v)); }

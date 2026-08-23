<?php
/** Offline request-boundary tests for the real optional NIP-39 endpoint. */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') exit(1);

$database = sys_get_temp_dir() . '/fm-nip39-page-' . getmypid() . '.db';
putenv('BRIDGE_DB=' . $database);
foreach ([$database, "$database-wal", "$database-shm"] as $file) {
    @unlink($file);
}

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../lib/crypto.php';

$pass = 0;
$fail = 0;
function ok(bool $condition, string $name): void
{
    global $pass, $fail;
    if ($condition) {
        $pass++;
        echo "  ok  $name\n";
    } else {
        $fail++;
        echo "FAIL  $name\n";
    }
}

function run_nip39_endpoint(
    string $database,
    string $method,
    string $cookie,
    array $input = []
): array {
    $page = realpath(__DIR__ . '/../nip39.php');
    if (!is_string($page)) throw new RuntimeException('nip39.php missing');
    $code = <<<'PHP'
$_SERVER['REQUEST_METHOD'] = $argv[1];
if ($argv[2] !== '') $_COOKIE['bridge_oauth'] = $argv[2];
$GLOBALS['__fm_nip39_test_input'] = base64_decode($argv[3], true);
require $argv[4];
PHP;
    $environment = getenv();
    if (!is_array($environment)) $environment = [];
    $environment['BRIDGE_DB'] = $database;
    $process = proc_open(
        [
            PHP_BINARY,
            '-r',
            $code,
            $method,
            $cookie,
            base64_encode($input ? json_encode($input) : ''),
            $page,
        ],
        [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes,
        dirname($page),
        $environment
    );
    if (!is_resource($process)) {
        throw new RuntimeException('cannot start isolated NIP-39 endpoint');
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [
        'status' => proc_close($process),
        'stdout' => is_string($stdout) ? $stdout : '',
        'stderr' => is_string($stderr) ? $stderr : '',
        'json' => json_decode(is_string($stdout) ? $stdout : '', true),
    ];
}

$db = db();
$secret = bin2hex(random_bytes(32));
$pubkey = fm_pubkey_hex($secret);
$nonce = str_repeat('a', 64);
$now = now();
$db->prepare(
    'INSERT INTO github_accounts
     (login,github_user_id,token_enc,refresh_token_enc,token_expires_at,
      refresh_token_expires_at,provider,auth_status,scopes,linked_at,updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)'
)->execute([
    'alice', '123', 'unused', 'unused', $now + 3600, $now + 7200,
    'github_app', 'active', '', $now, $now,
]);
$db->prepare(
    'INSERT INTO nostr_accounts
     (pubkey,bunker_enc,client_key_enc,status,linked_at,updated_at)
     VALUES (?,?,?,?,?,?)'
)->execute([$pubkey, 'unused', 'unused', 'linked', $now, $now]);
$db->prepare(
    'INSERT INTO links(login,pubkey,created_at) VALUES (?,?,?)'
)->execute(['alice', $pubkey, $now]);
$db->prepare(
    'INSERT INTO oauth_states
     (nonce,github_login,nostr_pubkey,created_at,expires_at)
     VALUES (?,?,?,?,?)'
)->execute([$nonce, 'alice', $pubkey, $now, $now + 3600]);

echo "== optional NIP-39 endpoint boundary ==\n";
$before = [
    (int)$db->query('SELECT COUNT(*) FROM oauth_states')->fetchColumn(),
    (int)$db->query('SELECT COUNT(*) FROM jobs')->fetchColumn(),
];
$anonymous = run_nip39_endpoint($database, 'GET', '');
$afterAnonymous = [
    (int)$db->query('SELECT COUNT(*) FROM oauth_states')->fetchColumn(),
    (int)$db->query('SELECT COUNT(*) FROM jobs')->fetchColumn(),
];
ok(
    $anonymous['status'] === 0
    && $anonymous['stderr'] === ''
    && ($anonymous['json']['available'] ?? true) === false
    && $afterAnonymous === $before,
    'anonymous GET reveals no identity and allocates no state'
);

$linked = run_nip39_endpoint($database, 'GET', $nonce);
$afterLinked = [
    (int)$db->query('SELECT COUNT(*) FROM oauth_states')->fetchColumn(),
    (int)$db->query('SELECT COUNT(*) FROM jobs')->fetchColumn(),
];
ok(
    $linked['status'] === 0
    && $linked['stderr'] === ''
    && ($linked['json']['available'] ?? false) === true
    && ($linked['json']['github']['login'] ?? '') === 'alice'
    && ($linked['json']['nostr']['pubkey'] ?? '') === $pubkey
    && str_contains(
        (string)($linked['json']['proof_text'] ?? ''),
        fm_npub_encode($pubkey)
    )
    && $afterLinked === $before,
    'linked GET is read-only and returns only its exact identity pair'
);

$wrongOwner = run_nip39_endpoint($database, 'POST', $nonce, [
    'action' => 'start',
    'mode' => 'add',
    'gist_url' => 'https://gist.github.com/mallory/abcde',
]);
ok(
    $wrongOwner['status'] === 0
    && $wrongOwner['stderr'] === ''
    && isset($wrongOwner['json']['error'])
    && (int)$db->query('SELECT COUNT(*) FROM jobs')->fetchColumn() === 0,
    'a Gist URL for another GitHub account creates no durable intent'
);

$started = run_nip39_endpoint($database, 'POST', $nonce, [
    'action' => 'start',
    'mode' => 'add',
    'gist_url' => 'https://gist.github.com/alice/abcde',
]);
ok(
    $started['status'] === 0
    && $started['stderr'] === ''
    && ($started['json']['workflow']['phase'] ?? '') === 'preparing'
    && ($started['json']['workflow']['action'] ?? '') === 'add'
    && (int)$db->query(
        "SELECT COUNT(*) FROM jobs WHERE type='nip39_identity'"
    )->fetchColumn() === 1,
    'explicit POST creates one durable unconfirmed identity intent'
);

$duplicate = run_nip39_endpoint($database, 'POST', $nonce, [
    'action' => 'start',
    'mode' => 'remove',
]);
ok(
    $duplicate['status'] === 0
    && $duplicate['stderr'] === ''
    && isset($duplicate['json']['error'])
    && (int)$db->query(
        "SELECT COUNT(*) FROM jobs WHERE type='nip39_identity'"
    )->fetchColumn() === 1,
    'a second intent cannot replace an active durable workflow'
);

$activeJobId = (int)$db->query(
    "SELECT id FROM jobs WHERE type='nip39_identity' ORDER BY id DESC LIMIT 1"
)->fetchColumn();
$activePayload = json_decode((string)$db->query(
    "SELECT payload FROM jobs WHERE id=$activeJobId"
)->fetchColumn(), true);
$activePayload['phase'] = 'awaiting_confirmation';
$activePayload['base_event_id'] = null;
$activePayload['identities'] = [];
$db->prepare('UPDATE jobs SET payload=?,run_at=? WHERE id=?')
   ->execute([json_c($activePayload), now() + 86400, $activeJobId]);
$cancelled = run_nip39_endpoint($database, 'POST', $nonce, [
    'action' => 'cancel',
    'job_id' => $activeJobId,
]);
ok(
    $cancelled['status'] === 0
    && $cancelled['stderr'] === ''
    && ($cancelled['json']['workflow']['phase'] ?? '') === 'cancelled'
    && $db->query(
        "SELECT status FROM jobs WHERE id=$activeJobId"
    )->fetchColumn() === 'done',
    'an unconfirmed preview can be cancelled without signing or publication'
);

$remove = run_nip39_endpoint($database, 'POST', $nonce, [
    'action' => 'start',
    'mode' => 'remove',
]);
ok(
    $remove['status'] === 0
    && $remove['stderr'] === ''
    && ($remove['json']['workflow']['phase'] ?? '') === 'preparing'
    && ($remove['json']['workflow']['action'] ?? '') === 'remove'
    && (int)$db->query(
        "SELECT COUNT(*) FROM jobs WHERE type='nip39_identity'"
    )->fetchColumn() === 2,
    'a cancelled workflow does not block a later explicit update'
);

echo "\n$pass passed, $fail failed\n";
foreach ([$database, "$database-wal", "$database-shm"] as $file) {
    @unlink($file);
}
exit($fail === 0 ? 0 : 1);

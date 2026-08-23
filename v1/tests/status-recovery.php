<?php
/**
 * Offline tests for POST-only NIP-07 browser-session recovery.
 *
 * Recovery proves an existing Nostr key and restores only oauth_states. It
 * must never create an identity link or replace durable NIP-46 credentials.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') exit(1);

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

/** Execute the real status endpoint in an isolated PHP process. */
function run_status(
    string $database,
    string $method,
    string $cookie = '',
    array $input = []
): array {
    $page = realpath(__DIR__ . '/../status.php');
    if (!is_string($page)) throw new RuntimeException('status.php missing');
    $code = <<<'PHP'
$_SERVER['REQUEST_METHOD'] = $argv[1];
if ($argv[2] !== '') $_COOKIE['bridge_oauth'] = $argv[2];
$GLOBALS['__fm_status_test_input'] = base64_decode($argv[3], true);
$GLOBALS['__fm_test_secrets_dir'] = $argv[5];
require $argv[4];
PHP;
    $environment = getenv();
    if (!is_array($environment)) $environment = [];
    $environment['BRIDGE_DB'] = $database;
    $encoded = base64_encode($input ? json_encode($input) : '');
    $secretDir = $GLOBALS['__fm_status_secret_dir'] ?? '';
    if (!is_string($secretDir) || $secretDir === '') {
        throw new RuntimeException('status test secret directory missing');
    }
    $pipes = [];
    $process = proc_open(
        [
            PHP_BINARY,
            '-r',
            $code,
            $method,
            $cookie,
            $encoded,
            $page,
            $secretDir,
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
        throw new RuntimeException('cannot start isolated status endpoint');
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

function challenge_value(array $response): string
{
    $tags = $response['json']['challenge']['tags'] ?? [];
    foreach ($tags as $tag) {
        if (is_array($tag) && ($tag[0] ?? null) === 'challenge'
            && is_string($tag[1] ?? null)) {
            return $tag[1];
        }
    }
    return '';
}

function newest_challenge_cookie(string $database): string
{
    $pdo = inspect_status_db($database);
    $value = $pdo->query(
        'SELECT nonce FROM oauth_states
         WHERE github_login IS NULL AND nostr_pubkey IS NULL
         ORDER BY rowid DESC LIMIT 1'
    )->fetchColumn();
    return is_string($value) ? $value : '';
}

function signed_challenge(array $response, string $privateKey): array
{
    $event = $response['json']['challenge'];
    $event['pubkey'] = fm_pubkey_hex($privateKey);
    return fm_event_sign($event, $privateKey);
}

function inspect_status_db(string $database): PDO
{
    $pdo = new PDO('sqlite:' . $database);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;
}

echo "== browser Nostr sign-in recovery ==\n";
$database = sys_get_temp_dir() . '/fm-status-recovery-' . getmypid() . '.db';
$secretDir = sys_get_temp_dir() . '/fm-status-recovery-secrets-' . getmypid();
foreach ([$database, "$database-wal", "$database-shm"] as $file) {
    @unlink($file);
}
@mkdir($secretDir, 0700);
file_put_contents(
    "$secretDir/db-crypt.php",
    "<?php return '" . str_repeat('e', 64) . "';\n"
);
chmod("$secretDir/db-crypt.php", 0600);
$GLOBALS['__fm_status_secret_dir'] = $secretDir;
$db = new PDO('sqlite:' . $database);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec('PRAGMA journal_mode=WAL');
$db->exec('PRAGMA foreign_keys=ON');
db_init($db);

$privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
$pubkey = fm_pubkey_hex($privateKey);
$otherPrivateKey = str_pad('2', 64, '0', STR_PAD_LEFT);
$otherPubkey = fm_pubkey_hex($otherPrivateKey);
$nostrOnlyPrivateKey = str_pad('3', 64, '0', STR_PAD_LEFT);
$nostrOnlyPubkey = fm_pubkey_hex($nostrOnlyPrivateKey);
$now = time();
$db->prepare(
    'INSERT INTO github_accounts
     (login,github_user_id,token_enc,provider,auth_status,
      linked_at,updated_at)
     VALUES (?,?,?,?,?,?,?)'
)->execute(['alice', '101', 'encrypted-token', 'github_app', 'active', $now, $now]);
$db->prepare(
    'INSERT INTO nostr_accounts
     (pubkey,bunker_enc,client_key_enc,status,linked_at,updated_at)
     VALUES (?,?,?,?,?,?)'
)->execute([$pubkey, 'original-bunker', 'original-client', 'linked', $now, $now]);
$db->prepare(
    'INSERT INTO nostr_accounts
     (pubkey,bunker_enc,client_key_enc,status,linked_at,updated_at)
     VALUES (?,?,?,?,?,?)'
)->execute([
    $nostrOnlyPubkey,
    'nostr-only-bunker',
    'nostr-only-client',
    'linked',
    $now,
    $now,
]);
$db->prepare(
    'INSERT INTO links(login,pubkey,created_at) VALUES (?,?,?)'
)->execute(['alice', $pubkey, $now]);

$statesBeforeGet = (int)$db->query(
    'SELECT COUNT(*) FROM oauth_states'
)->fetchColumn();
$anonymous = run_status($database, 'GET');
$statesAfterGet = (int)$db->query(
    'SELECT COUNT(*) FROM oauth_states'
)->fetchColumn();
ok(
    $anonymous['status'] === 0
    && $anonymous['stderr'] === ''
    && ($anonymous['json']['identity_recognized'] ?? null) === false
    && $statesAfterGet === $statesBeforeGet,
    'anonymous GET remains read-only'
);

$issued = run_status($database, 'POST', '', ['action' => 'challenge']);
$challenge = newest_challenge_cookie($database);
$publicChallenge = challenge_value($issued);
$inspect = inspect_status_db($database);
$challengeRow = $inspect->prepare(
    'SELECT github_login,nostr_pubkey,expires_at
     FROM oauth_states WHERE nonce=?'
);
$challengeRow->execute([$challenge]);
$emptyState = $challengeRow->fetch();
ok(
    $issued['status'] === 0
    && $issued['stderr'] === ''
    && preg_match('/^[0-9a-f]{64}$/', $challenge)
    && preg_match('/^[0-9a-f]{64}$/', $publicChallenge)
    && !hash_equals($challenge, $publicChallenge)
    && is_array($emptyState)
    && $emptyState['github_login'] === null
    && $emptyState['nostr_pubkey'] === null
    && (int)$emptyState['expires_at'] <= time() + 301,
    'explicit POST creates one bounded empty challenge session'
);

$signed = signed_challenge($issued, $privateKey);
$recovered = run_status(
    $database,
    'POST',
    $challenge,
    ['action' => 'recover', 'event' => $signed]
);
$inspect = inspect_status_db($database);
$savedSession = $inspect->prepare(
    'SELECT github_login,nostr_pubkey,expires_at
     FROM oauth_states WHERE nonce=?'
);
$savedSession->execute([$challenge]);
$savedSession = $savedSession->fetch();
$savedSigner = $inspect->prepare(
    'SELECT bunker_enc,client_key_enc FROM nostr_accounts WHERE pubkey=?'
);
$savedSigner->execute([$pubkey]);
$savedSigner = $savedSigner->fetch();
$validRecovery =
    $recovered['status'] === 0
    && $recovered['stderr'] === ''
    && ($recovered['json']['recovered'] ?? false) === true
    && ($recovered['json']['fully_linked'] ?? false) === true
    && ($savedSession['github_login'] ?? null) === 'alice'
    && ($savedSession['nostr_pubkey'] ?? null) === $pubkey;
if (!$validRecovery) {
    echo '  diagnostic valid recovery: '
        . json_encode([
            'endpoint' => $recovered,
            'session' => $savedSession,
        ]) . "\n";
}
ok(
    $validRecovery,
    'valid signed challenge restores the existing linked browser session'
);
ok(
    ($savedSigner['bunker_enc'] ?? null) === 'original-bunker'
    && ($savedSigner['client_key_enc'] ?? null) === 'original-client'
    && (int)$inspect->query('SELECT COUNT(*) FROM links')->fetchColumn() === 1,
    'session recovery neither replaces signer credentials nor creates a link'
);

$expiryAfterRecovery = (int)$savedSession['expires_at'];
$readRecovered = run_status($database, 'GET', $challenge);
$inspect = inspect_status_db($database);
$expiryAfterGet = (int)$inspect->query(
    "SELECT expires_at FROM oauth_states WHERE nonce='$challenge'"
)->fetchColumn();
ok(
    ($readRecovered['json']['fully_linked'] ?? false) === true
    && $expiryAfterGet === $expiryAfterRecovery,
    'recognized GET reports the link without sliding the session'
);

$challengeWhileSignedIn = run_status(
    $database,
    'POST',
    $challenge,
    ['action' => 'challenge']
);
$inspect = inspect_status_db($database);
$sessionAfterRejectedChallenge = $inspect->prepare(
    'SELECT github_login,nostr_pubkey,expires_at
     FROM oauth_states WHERE nonce=?'
);
$sessionAfterRejectedChallenge->execute([$challenge]);
$sessionAfterRejectedChallenge = $sessionAfterRejectedChallenge->fetch();
ok(
    str_contains(
        (string)($challengeWhileSignedIn['json']['error'] ?? ''),
        'already signed in'
    )
    && ($sessionAfterRejectedChallenge['github_login'] ?? null) === 'alice'
    && ($sessionAfterRejectedChallenge['nostr_pubkey'] ?? null) === $pubkey
    && (int)$sessionAfterRejectedChallenge['expires_at']
        === $expiryAfterRecovery,
    'challenge POST cannot overwrite an already identified browser cookie'
);

$replay = run_status(
    $database,
    'POST',
    $challenge,
    ['action' => 'recover', 'event' => $signed]
);
$inspect = inspect_status_db($database);
ok(
    is_array($replay['json'])
    && str_contains(
        (string)($replay['json']['error'] ?? ''),
        'already used'
    )
    && (int)$inspect->query(
        "SELECT expires_at FROM oauth_states WHERE nonce='$challenge'"
    )->fetchColumn() === $expiryAfterRecovery,
    'signed challenge is single-use'
);

$forgedIssued = run_status(
    $database,
    'POST',
    '',
    ['action' => 'challenge']
);
$forgedChallenge = newest_challenge_cookie($database);
$forged = signed_challenge($forgedIssued, $otherPrivateKey);
$forgedResult = run_status(
    $database,
    'POST',
    $forgedChallenge,
    ['action' => 'recover', 'event' => $forged]
);
$inspect = inspect_status_db($database);
$forgedState = $inspect->prepare(
    'SELECT github_login,nostr_pubkey FROM oauth_states WHERE nonce=?'
);
$forgedState->execute([$forgedChallenge]);
$forgedState = $forgedState->fetch();
$forgedRemainedEmpty = is_array($forgedState)
    && $forgedState['github_login'] === null
    && $forgedState['nostr_pubkey'] === null;
if (!$forgedRemainedEmpty) {
    echo '  diagnostic forged challenge: '
        . json_encode([
            'issued' => $forgedIssued,
            'challenge' => $forgedChallenge,
            'endpoint' => $forgedResult,
            'session' => $forgedState,
        ]) . "\n";
}
ok(
    str_contains(
        (string)($forgedResult['json']['error'] ?? ''),
        'No existing durable link'
    )
    && $forgedRemainedEmpty,
    'an unlinked signer cannot create an identity or link'
);

$mutatedIssued = run_status(
    $database,
    'POST',
    '',
    ['action' => 'challenge']
);
$mutatedChallenge = newest_challenge_cookie($database);
$mutatedTemplate = $mutatedIssued;
$mutatedTemplate['json']['challenge']['tags'][] = ['challenge', 'attacker'];
$mutated = signed_challenge($mutatedTemplate, $privateKey);
$mutatedResult = run_status(
    $database,
    'POST',
    $mutatedChallenge,
    ['action' => 'recover', 'event' => $mutated]
);
ok(
    str_contains(
        (string)($mutatedResult['json']['error'] ?? ''),
        'Invalid or expired'
    ),
    'changed or duplicate challenge tags are rejected'
);

$nostrOnlyIssued = run_status(
    $database,
    'POST',
    '',
    ['action' => 'challenge']
);
$nostrOnlyChallenge = newest_challenge_cookie($database);
$nostrOnlyResult = run_status(
    $database,
    'POST',
    $nostrOnlyChallenge,
    [
        'action' => 'recover',
        'event' => signed_challenge(
            $nostrOnlyIssued,
            $nostrOnlyPrivateKey
        ),
    ]
);
$inspect = inspect_status_db($database);
ok(
    ($nostrOnlyResult['json']['identity_recognized'] ?? false) === true
    && ($nostrOnlyResult['json']['fully_linked'] ?? true) === false
    && ($nostrOnlyResult['json']['github'] ?? null) === null
    && ($nostrOnlyResult['json']['nostr']['pubkey'] ?? null)
        === $nostrOnlyPubkey
    && (int)$inspect->query('SELECT COUNT(*) FROM links')->fetchColumn() === 1,
    'Nostr-only durable signer recovery does not invent a GitHub link'
);

foreach ([$database, "$database-wal", "$database-shm"] as $file) {
    @unlink($file);
}
@unlink("$secretDir/db-crypt.php");
@rmdir($secretDir);

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);

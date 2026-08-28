<?php
/**
 * Offline regression tests for the actual NIP-46 browser endpoint.
 *
 * In particular, a reload after signer approval must resume the banked
 * connected state. It must not prefer a newer waiting attempt and show the
 * user another QR code.
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

/** Execute the real page in an isolated PHP process against the test DB. */
function run_nostr_link_page(
    string $database,
    string $nonce,
    string $mode,
    string $stateId,
    string $secretDir
): array {
    $page = realpath(__DIR__ . '/../nostr-link.php');
    if (!is_string($page)) throw new RuntimeException('nostr-link.php missing');
$code = <<<'PHP'
if ($argv[1] !== '') $_COOKIE['bridge_oauth'] = $argv[1];
$GLOBALS['__fm_test_secrets_dir'] = $argv[5];
    $_SERVER['REQUEST_METHOD'] = in_array(
    $argv[2],
    ['complete', 'start', 'listen', 'restart', 'replace'],
    true
) ? 'POST' : 'GET';
if ($argv[2] === 'wait') {
    $_GET['wait'] = $argv[3];
} elseif ($argv[2] === 'listen') {
    $_POST['listen'] = $argv[3];
} elseif ($argv[2] === 'restart') {
    $_POST['restart'] = $argv[3];
} elseif ($argv[2] === 'start') {
    $_POST['start'] = '1';
} elseif ($argv[2] === 'complete') {
    $_POST['complete'] = $argv[3];
} elseif ($argv[2] === 'replace') {
    $_POST['replace'] = '1';
}
require $argv[4];
PHP;
    $environment = getenv();
    if (!is_array($environment)) $environment = [];
    $environment['BRIDGE_DB'] = $database;
    $pipes = [];
    $process = proc_open(
        [
            PHP_BINARY,
            '-r',
            $code,
            $nonce,
            $mode,
            $stateId,
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
        throw new RuntimeException('cannot start isolated PHP endpoint');
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
    ];
}

echo "== NIP-46 browser reload ==\n";
$database = sys_get_temp_dir() . '/fm-nostr-link-page-' . getmypid() . '.db';
$secretDir = sys_get_temp_dir() . '/fm-nostr-link-secrets-' . getmypid();
putenv('BRIDGE_DB=' . $database);
foreach ([$database, "$database-wal", "$database-shm"] as $file) @unlink($file);
@mkdir($secretDir, 0700);
file_put_contents(
    "$secretDir/db-crypt.php",
    "<?php return '" . str_repeat('a', 64) . "';\n"
);
chmod("$secretDir/db-crypt.php", 0600);
$GLOBALS['__fm_test_secrets_dir'] = $secretDir;
$db = new PDO('sqlite:' . $database);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec('PRAGMA journal_mode=WAL');
$db->exec('PRAGMA foreign_keys=ON');
db_init($db);

$timestamp = time();
$anonymousBefore = [
    (int)$db->query('SELECT COUNT(*) FROM oauth_states')->fetchColumn(),
    (int)$db->query('SELECT COUNT(*) FROM nip46_states')->fetchColumn(),
];
$anonymous = run_nostr_link_page(
    $database,
    '',
    'page',
    '',
    $secretDir
);
$anonymousAfter = [
    (int)$db->query('SELECT COUNT(*) FROM oauth_states')->fetchColumn(),
    (int)$db->query('SELECT COUNT(*) FROM nip46_states')->fetchColumn(),
];
ok(
    $anonymous['status'] === 0
    && $anonymous['stderr'] === ''
    && str_contains(
        $anonymous['stdout'],
        'Viewing this page is read-only'
    )
    && $anonymousAfter === $anonymousBefore,
    'anonymous GET renders without allocating any authentication state'
);

$start = run_nostr_link_page(
    $database,
    '',
    'start',
    '',
    $secretDir
);
ok(
    $start['status'] === 0
    && $start['stderr'] === ''
    && (int)$db->query(
        'SELECT COUNT(*) FROM oauth_states'
    )->fetchColumn() === $anonymousBefore[0] + 1
    && (int)$db->query(
        'SELECT COUNT(*) FROM nip46_states'
    )->fetchColumn() === $anonymousBefore[1] + 1,
    'explicit POST allocates exactly one browser session and connection'
);

$linkedNonce = str_repeat('a', 64);
$linkedPubkey = str_repeat('b', 64);
$db->prepare(
    "INSERT INTO github_accounts
     (login,github_user_id,token_enc,refresh_token_enc,token_expires_at,
      refresh_token_expires_at,provider,auth_status,scopes,linked_at,updated_at)
     VALUES ('linked-user','42','encrypted','encrypted',?,?,
             'github_app','active','',?,?)"
)->execute([
    $timestamp + 3600,
    $timestamp + 86400,
    $timestamp,
    $timestamp,
]);
$db->prepare(
    "INSERT INTO nostr_accounts
     (pubkey,bunker_enc,client_key_enc,status,linked_at,updated_at)
     VALUES (?, 'encrypted', 'encrypted', 'linked', ?, ?)"
)->execute([$linkedPubkey, $timestamp, $timestamp]);
$db->prepare(
    'INSERT INTO links(login,pubkey,created_at) VALUES (?,?,?)'
)->execute(['linked-user', $linkedPubkey, $timestamp]);
$db->prepare(
    'INSERT INTO oauth_states
     (nonce,github_login,nostr_pubkey,created_at,expires_at)
     VALUES (?,?,?,?,?)'
)->execute([
    $linkedNonce,
    'linked-user',
    $linkedPubkey,
    $timestamp,
    $timestamp + 3600,
]);
$statesBeforeLinkedGet = (int)$db->query(
    'SELECT COUNT(*) FROM nip46_states'
)->fetchColumn();
$linkedPage = run_nostr_link_page(
    $database,
    $linkedNonce,
    'page',
    '',
    $secretDir
);
ok(
    $linkedPage['status'] === 0
    && $linkedPage['stderr'] === ''
    && str_contains(
        $linkedPage['stdout'],
        'remain durably linked'
    )
    && (int)$db->query(
        'SELECT COUNT(*) FROM nip46_states'
    )->fetchColumn() === $statesBeforeLinkedGet,
    'identified browser recovers its durable link without a new connection'
);
ok(
    str_contains(
        $linkedPage['stdout'],
        'Replace remote signer connection'
    ),
    'durably linked page exposes replacement only as an explicit setting'
);

require_once __DIR__ . '/../lib/nip44.php';
require_once __DIR__ . '/../lib/bridge.php';
$replacementStart = run_nostr_link_page(
    $database,
    $linkedNonce,
    'replace',
    '',
    $secretDir
);
$replacementState = $db->prepare(
    "SELECT * FROM nip46_states
     WHERE oauth_nonce=? AND status='waiting'
     ORDER BY created_at DESC LIMIT 1"
);
$replacementState->execute([$linkedNonce]);
$replacementState = $replacementState->fetch();
ok(
    $replacementStart['status'] === 0
    && $replacementStart['stderr'] === ''
    && is_array($replacementState)
    && ($replacementState['error'] ?? null)
        === NIP46_REPLACE_STATE_PREFIX . $linkedPubkey,
    'explicit replacement POST banks the exact existing signer identity'
);
$replacementSignerSecret = fm_private_key_generate();
$replacementSignerPubkey = fm_pubkey_hex($replacementSignerSecret);
$replacementConnect = fm_event_sign([
    'kind' => 24133,
    'pubkey' => $replacementSignerPubkey,
    'created_at' => time(),
    'tags' => [['p', $replacementState['client_pk']]],
    'content' => nip44_encrypt(
        $replacementSignerSecret,
        $replacementState['client_pk'],
        json_c([
            'id' => 'replacement-connect',
            'result' => $replacementState['secret'],
        ])
    ),
], $replacementSignerSecret);
$replacementDecoded = nip46_decode_connect_event(
    $replacementConnect,
    fm_decrypt_at_rest($replacementState['client_key_enc']),
    $replacementState['client_pk']
);
$replacementAccepted = bridge_accept_nip46_connect(
    $replacementState['state_id'],
    $replacementConnect,
    ['wss://nos.lol']
);
$replacementJob = $db->prepare(
    "SELECT payload FROM jobs WHERE dedupe_key=?"
);
$replacementJob->execute([
    'nip46finish:' . $replacementState['state_id'],
]);
$replacementPayload = json_decode(
    (string)$replacementJob->fetchColumn(),
    true
);
$replacementIntentBanked = $replacementAccepted
    && ($replacementPayload['replace_pubkey'] ?? null) === $linkedPubkey;
if (!$replacementIntentBanked) {
    echo '  diagnostic replacement bank: '
        . json_encode([
            'accepted' => $replacementAccepted,
            'state' => $replacementState,
            'decoded' => $replacementDecoded,
            'listen_relays' => nip46_listen_relays(),
            'payload' => $replacementPayload,
        ]) . "\n";
}
ok(
    $replacementIntentBanked,
    'banked connect carries explicit replacement intent into durable job'
);

$nonce = str_repeat('1', 64);
$connectedId = str_repeat('2', 32);
$waitingId = str_repeat('3', 32);
$connectedClient = str_repeat('4', 64);
$waitingClient = str_repeat('5', 64);
$signer = str_repeat('6', 64);
$db->prepare(
    'INSERT INTO oauth_states (nonce,created_at,expires_at) VALUES (?,?,?)'
)->execute([$nonce, $timestamp - 300, $timestamp + 3600]);
$db->prepare(
    "INSERT INTO nip46_states
       (state_id,secret,client_pk,client_key_enc,bunker_pk,relays,
        oauth_nonce,status,created_at,expires_at)
     VALUES (?,?,?,?,?,?,?,'connected',?,?)"
)->execute([
    $connectedId,
    str_repeat('7', 32),
    $connectedClient,
    'encrypted-test-key',
    $signer,
    '["wss://nos.lol"]',
    $nonce,
    $timestamp - 120,
    $timestamp + 86400,
]);
$db->prepare(
    "INSERT INTO nip46_states
       (state_id,secret,client_pk,client_key_enc,oauth_nonce,status,
        created_at,expires_at)
     VALUES (?,?,?,?,?,'waiting',?,?)"
)->execute([
    $waitingId,
    str_repeat('8', 32),
    $waitingClient,
    'encrypted-test-key',
    $nonce,
    $timestamp,
    $timestamp + 600,
]);
$db->prepare(
    "INSERT INTO jobs
       (type,payload,dedupe_key,run_at,status,last_error,created_at,updated_at)
     VALUES ('nip46_finish',?,?,?,'pending',?,?,?)"
	)->execute([
	    json_encode([
	        'state_id' => $connectedId,
	        'phase' => 'identifying_account',
	    ]),
    'nip46finish:' . $connectedId,
    $timestamp + 300,
    'get_public_key failed after connect',
    $timestamp - 120,
    $timestamp,
]);
$db = null;

$page = run_nostr_link_page(
    $database,
    $nonce,
    'page',
    $connectedId,
    $secretDir
);
ok(
    $page['status'] === 0 && $page['stderr'] === '',
    'real NIP-46 page renders without an endpoint error'
);
ok(
    str_contains(
        $page['stdout'],
        '<a class="btn" href="/">Back to account linking</a>'
    )
    && !str_contains(
        $page['stdout'],
        '<a class="btn" href="/v1/">Back to account linking</a>'
    ),
    'success action returns to the site account page, not /v1/index.html'
);
ok(
    str_contains($page['stdout'], "const sid = \"$connectedId\";")
    && str_contains($page['stdout'], 'const connectionBanked = true;'),
    'reload selects the banked connected state over a newer waiting state'
);
ok(
    !str_contains($page['stdout'], 'id="qr"')
    && !str_contains($page['stdout'], 'Open in signer app')
    && !str_contains($page['stdout'], 'Copy connection code')
    && str_contains($page['stdout'], '<details id="troubleshooting">')
    && str_contains($page['stdout'], 'Start over with Amber'),
    'reload does not present another signer connection'
);
ok(
    substr_count($page['stdout'], 'data-phase=') === 5
    && str_contains(
        $page['stdout'],
        'data-phase="identifying_account" class="current"'
    )
    && str_contains($page['stdout'], 'What happens next')
    && str_contains($page['stdout'], 'Technical details')
    && str_contains($page['stdout'], 'id="statusElapsed"')
    && str_contains($page['stdout'], 'listenForApproval'),
    'connected page renders five human-readable durable progress steps'
);

$connectedPollStarted = microtime(true);
$wait = run_nostr_link_page(
    $database,
    $nonce,
    'wait',
    $connectedId,
    $secretDir
);
$connectedPollElapsed = microtime(true) - $connectedPollStarted;
$waitPayload = json_decode($wait['stdout'], true);
ok(
    $wait['status'] === 0
    && $wait['stderr'] === ''
    && is_array($waitPayload)
    && ($waitPayload['status'] ?? null) === 'pending'
    && ($waitPayload['phase'] ?? null) === 'identifying_account'
    && str_contains(
        (string)($waitPayload['message'] ?? ''),
        'Confirming which Nostr account'
    )
    && str_contains(
        (string)($waitPayload['diagnostic'] ?? ''),
        'get_public_key'
    )
    && $connectedPollElapsed < 1.0,
    'wait endpoint separates progress from diagnostics in under one second ('
    . number_format($connectedPollElapsed, 3) . 's)'
);
$alreadyConnectedListener = run_nostr_link_page(
    $database,
    $nonce,
    'listen',
    $connectedId,
    $secretDir
);
$listenPayload = json_decode($alreadyConnectedListener['stdout'], true);
ok(
    $alreadyConnectedListener['status'] === 0
    && $alreadyConnectedListener['stderr'] === ''
    && ($listenPayload['accepted'] ?? false) === true,
    'background listener is independent from the fast GUI status path'
);

$restart = run_nostr_link_page(
    $database,
    $nonce,
    'restart',
    $connectedId,
    $secretDir
);
$check = new PDO('sqlite:' . $database);
$replacedState = $check->query(
    "SELECT status,error FROM nip46_states
     WHERE state_id='$connectedId'"
)->fetch(PDO::FETCH_ASSOC);
$replacedJob = $check->query(
    "SELECT status,last_error FROM jobs
     WHERE dedupe_key='nip46finish:$connectedId'"
)->fetch(PDO::FETCH_ASSOC);
ok(
    $restart['status'] === 0
    && $restart['stderr'] === ''
    && ($replacedState['status'] ?? null) === 'failed'
    && ($replacedJob['status'] ?? null) === 'done',
    'same-session restart supersedes both the connected state and its job'
);
ok(
    str_contains((string)($replacedState['error'] ?? ''), 'replaced')
    && str_contains((string)($replacedJob['last_error'] ?? ''), 'reconnect'),
    'superseded state and job retain an explicit recovery reason'
);

$stateCountBeforeReplacementPage = (int)$check->query(
    'SELECT COUNT(*) FROM nip46_states'
)->fetchColumn();
$replacementPage = run_nostr_link_page(
    $database,
    $nonce,
    'page',
    $waitingId,
    $secretDir
);
ok(
    $replacementPage['status'] === 0
    && $replacementPage['stderr'] === ''
    && str_contains(
        $replacementPage['stdout'],
        "const sid = \"$waitingId\";"
    )
    && str_contains(
        $replacementPage['stdout'],
        'const connectionBanked = false;'
    )
    && str_contains($replacementPage['stdout'], 'id="qr"'),
    'page returns to the surviving fresh signer connection after restart'
);

ok(
    (int)$check->query(
        'SELECT COUNT(*) FROM nip46_states'
    )->fetchColumn() === $stateCountBeforeReplacementPage,
    'rendering the resumed page does not allocate another NIP-46 state'
);
$waitingPollStarted = microtime(true);
$waitingPoll = run_nostr_link_page(
    $database,
    $nonce,
    'wait',
    $waitingId,
    $secretDir
);
$waitingPollElapsed = microtime(true) - $waitingPollStarted;
$waitingPayload = json_decode($waitingPoll['stdout'], true);
ok(
    $waitingPoll['status'] === 0
    && $waitingPoll['stderr'] === ''
    && ($waitingPayload['status'] ?? null) === 'waiting'
    && $waitingPollElapsed < 1.0,
    'waiting-state GUI poll returns in under one second ('
    . number_format($waitingPollElapsed, 3) . 's)'
);
$donePubkey = str_repeat('9', 64);
$check->prepare(
    "UPDATE nip46_states SET status='done',pubkey=?
     WHERE state_id=?"
)->execute([$donePubkey, $waitingId]);
$expiryBeforeDonePoll = (int)$check->query(
    "SELECT expires_at FROM oauth_states WHERE nonce='$nonce'"
)->fetchColumn();
$donePoll = run_nostr_link_page(
    $database,
    $nonce,
    'wait',
    $waitingId,
    $secretDir
);
$expiryAfterDonePoll = (int)$check->query(
    "SELECT expires_at FROM oauth_states WHERE nonce='$nonce'"
)->fetchColumn();
ok(
    $donePoll['status'] === 0
    && $donePoll['stderr'] === ''
    && (json_decode($donePoll['stdout'], true)['status'] ?? null) === 'done'
    && $expiryAfterDonePoll === $expiryBeforeDonePoll,
    'completed GET poll remains read-only'
);
$complete = run_nostr_link_page(
    $database,
    $nonce,
    'complete',
    $waitingId,
    $secretDir
);
$expiryAfterComplete = (int)$check->query(
    "SELECT expires_at FROM oauth_states WHERE nonce='$nonce'"
)->fetchColumn();
ok(
    $complete['status'] === 0
    && $complete['stderr'] === ''
    && (json_decode($complete['stdout'], true)['ok'] ?? false) === true
    && $expiryAfterComplete > $expiryAfterDonePoll,
    'explicit completion POST extends the browser link session'
);
$donePage = run_nostr_link_page(
    $database,
    $nonce,
    'page',
    $waitingId,
    $secretDir
);
ok(
    $donePage['status'] === 0
    && $donePage['stderr'] === ''
    && str_contains($donePage['stdout'], 'id="linkSetup" hidden')
    && str_contains($donePage['stdout'], 'id="success" class="card success"')
    && !str_contains(
        $donePage['stdout'],
        'id="success" class="card success" hidden'
    )
    && str_contains($donePage['stdout'], fm_npub_encode($donePubkey)),
    'completed reload shows the result and hides setup instructions'
);
$check = null;

foreach ([$database, "$database-wal", "$database-shm"] as $file) @unlink($file);
@unlink("$secretDir/db-crypt.php");
@rmdir($secretDir);

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);

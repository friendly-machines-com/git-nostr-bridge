<?php
/**
 * Offline exact schema-contract tests.
 *
 * Existing databases are never guessed at or upgraded in place. Only an
 * empty database may be initialized; every non-empty database must already
 * satisfy the exact current schema.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') exit(1);

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/../db.php';

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

function test_db(string $path): PDO
{
    foreach ([$path, "$path-wal", "$path-shm"] as $file) @unlink($file);
    $db = new PDO('sqlite:' . $path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('PRAGMA foreign_keys=ON');
    return $db;
}

function rejected(PDO $db, string $messagePart): bool
{
    try {
        db_init($db);
        return false;
    } catch (RuntimeException $error) {
        return str_contains($error->getMessage(), $messagePart);
    }
}

echo "== exact schema contract ==\n";
$base = sys_get_temp_dir() . '/fm-schema-' . getmypid();

$freshPath = $base . '-fresh.db';
$fresh = test_db($freshPath);
db_init($fresh);
ok(
    $fresh->query("SELECT v FROM schema_meta WHERE k='schema_version'")
          ->fetchColumn() === BRIDGE_SCHEMA_VERSION
    && $fresh->query("SELECT v FROM schema_meta WHERE k='schema_contract'")
             ->fetchColumn() === BRIDGE_SCHEMA_CONTRACT,
    'empty database initializes directly to the exact current schema'
);
try {
    db_init($fresh);
    ok(true, 'exact current schema reopens without mutation');
} catch (Throwable $error) {
    ok(false, 'exact current schema reopens without mutation');
}

$extraPath = $base . '-extra.db';
$extra = test_db($extraPath);
db_init($extra);
$extra->exec('ALTER TABLE repos ADD COLUMN retired_value TEXT');
ok(
    rejected($extra, 'unexpected repos.retired_value'),
    'current marker does not permit extra old-schema columns'
);

$indexPath = $base . '-index.db';
$wrongIndex = test_db($indexPath);
db_init($wrongIndex);
$wrongIndex->exec('DROP INDEX github_installations_account');
$wrongIndex->exec(
    'CREATE UNIQUE INDEX github_installations_account
     ON github_installations(account_id)'
);
ok(
    rejected($wrongIndex, 'github_installations_account shape'),
    'current marker does not permit old installation-account index'
);

$missingSemanticPath = $base . '-missing-semantic-index.db';
$missingSemantic = test_db($missingSemanticPath);
db_init($missingSemantic);
$missingSemantic->exec('DROP INDEX em_nos');
ok(
    rejected($missingSemantic, 'em_nos shape'),
    'current marker cannot omit the Nostr event loop-kill index'
);

$wrongPartialPath = $base . '-wrong-partial-index.db';
$wrongPartial = test_db($wrongPartialPath);
db_init($wrongPartial);
$wrongPartial->exec('DROP INDEX jobs_dedupe');
$wrongPartial->exec(
    "CREATE UNIQUE INDEX jobs_dedupe
     ON jobs(dedupe_key) WHERE status='done'"
);
ok(
    rejected($wrongPartial, 'jobs_dedupe shape'),
    'current marker cannot change a behavioral partial-index predicate'
);

$unsupportedPath = $base . '-unsupported.db';
$unsupported = test_db($unsupportedPath);
$unsupported->exec('CREATE TABLE users (github_login TEXT, nostr_pubkey TEXT)');
ok(
    rejected($unsupported, 'schema_meta is missing'),
    'unversioned non-empty database is rejected'
);
ok(
    (bool)$unsupported->query(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'"
    )->fetchColumn()
    && !(bool)$unsupported->query(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta'"
    )->fetchColumn(),
    'rejection does not rewrite the unversioned database'
);

$oldPath = $base . '-old.db';
$old = test_db($oldPath);
$old->exec('CREATE TABLE schema_meta (k TEXT PRIMARY KEY,v TEXT)');
$old->exec("INSERT INTO schema_meta VALUES ('schema_version','2')");
ok(
    rejected($old, 'expected version ' . BRIDGE_SCHEMA_VERSION),
    'older versioned database is rejected'
);
ok(
    !(bool)$old->query(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='jobs'"
    )->fetchColumn(),
    'older schema rejection does not alter the database'
);

$partialPath = $base . '-partial.db';
$partial = test_db($partialPath);
$partial->exec('CREATE TABLE schema_meta (k TEXT PRIMARY KEY,v TEXT)');
$partial->prepare('INSERT INTO schema_meta VALUES (?,?)')
        ->execute(['schema_version', BRIDGE_SCHEMA_VERSION]);
$partial->prepare('INSERT INTO schema_meta VALUES (?,?)')
        ->execute(['schema_contract', BRIDGE_SCHEMA_CONTRACT]);
ok(
    rejected($partial, 'missing github_accounts.login'),
    'partial database claiming the current contract is rejected'
);

$unmarkedPath = $base . '-unmarked.db';
$unmarked = test_db($unmarkedPath);
$unmarked->exec('CREATE TABLE schema_meta (k TEXT PRIMARY KEY,v TEXT)');
$unmarked->prepare('INSERT INTO schema_meta VALUES (?,?)')
         ->execute(['schema_version', BRIDGE_SCHEMA_VERSION]);
ok(
    rejected($unmarked, 'exact schema contract is missing'),
    'same-number database without the exact contract is rejected'
);

foreach ([
    $freshPath,
    $extraPath,
    $indexPath,
    $missingSemanticPath,
    $wrongPartialPath,
    $unsupportedPath,
    $oldPath,
    $partialPath,
    $unmarkedPath,
] as $path) {
    foreach ([$path, "$path-wal", "$path-shm"] as $file) @unlink($file);
}

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);

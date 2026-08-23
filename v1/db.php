<?php
/**
 * db.php -- PDO/SQLite singleton + exact current schema.
 * Direct web access is denied via .htaccess; guard anyway.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' && !defined('BRIDGE_ENTRY')) {
    http_response_code(404);
    exit;
}
if (PHP_SAPI !== 'cli') {
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
}

require_once __DIR__ . '/lib/util.php';

const BRIDGE_SCHEMA_VERSION = '6';
const BRIDGE_SCHEMA_CONTRACT =
    'github-app-only;pkce-required;unique-nostr-repositories;nip46-relay-sets;v6';

function db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) return $pdo;

    $file = getenv('BRIDGE_DB') ?: __DIR__ . '/bridge.db';
    if (file_exists($file) && !chmod($file, 0600)) {
        throw new RuntimeException("Cannot secure bridge database at $file");
    }
    $pdo = new PDO('sqlite:' . $file);
    if (!chmod($file, 0600)) {
        $pdo = null;
        throw new RuntimeException("Cannot secure bridge database at $file");
    }
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA busy_timeout=5000');
    $pdo->exec('PRAGMA foreign_keys=ON');
    foreach ([$file . '-wal', $file . '-shm'] as $sidecar) {
        if (file_exists($sidecar) && !chmod($sidecar, 0600)) {
            $pdo = null;
            throw new RuntimeException(
                "Cannot secure SQLite sidecar at $sidecar"
            );
        }
    }

    try {
        db_init($pdo);
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        $pdo = null;
        throw $e;
    }
    return $pdo;
}

function db_init(PDO $db): void
{
    $tables = $db->query(
        "SELECT name FROM sqlite_master
         WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )->fetchAll(PDO::FETCH_COLUMN);
    if ($tables) {
        if (!in_array('schema_meta', $tables, true)) {
            throw new RuntimeException(
                'Unsupported bridge database: schema_meta is missing'
            );
        }
        $version = $db->query(
            "SELECT v FROM schema_meta WHERE k='schema_version'"
        )->fetchColumn();
        if ($version !== BRIDGE_SCHEMA_VERSION) {
            throw new RuntimeException(
                'Unsupported bridge database schema; expected version '
                . BRIDGE_SCHEMA_VERSION
            );
        }
        $contract = $db->query(
            "SELECT v FROM schema_meta WHERE k='schema_contract'"
        )->fetchColumn();
        if ($contract !== BRIDGE_SCHEMA_CONTRACT) {
            throw new RuntimeException(
                'Unsupported bridge database: exact schema contract is missing'
            );
        }
        db_require_current_schema($db);
        return;
    }

    // --- current schema: new empty databases only -------------------------
    $db->exec("
    CREATE TABLE IF NOT EXISTS schema_meta (k TEXT PRIMARY KEY, v TEXT);

    CREATE TABLE IF NOT EXISTS github_accounts (
      login       TEXT PRIMARY KEY,
      github_user_id TEXT,
      token_enc   TEXT NOT NULL,
      refresh_token_enc TEXT,
      token_expires_at INTEGER,
      refresh_token_expires_at INTEGER,
      provider    TEXT NOT NULL CHECK (provider = 'github_app'),
      auth_status TEXT NOT NULL DEFAULT 'reauthorize',
      scopes      TEXT,
      linked_at   INTEGER NOT NULL,
      updated_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS github_installations (
      installation_id TEXT PRIMARY KEY,
      account_id       TEXT NOT NULL,
      account_login    TEXT NOT NULL,
      account_type     TEXT NOT NULL
                       CHECK (account_type IN ('Organization','User')),
      repository_selection TEXT,
      status           TEXT NOT NULL
                       CHECK (status IN ('active','suspended','deleted')),
      token_enc        TEXT,
      token_expires_at INTEGER,
      created_at       INTEGER NOT NULL,
      updated_at       INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS github_installations_account
      ON github_installations(account_id,status);

    CREATE TABLE IF NOT EXISTS github_installation_repositories (
      repository_id   TEXT PRIMARY KEY,
      installation_id TEXT NOT NULL
                      REFERENCES github_installations(installation_id),
      github_full_name TEXT NOT NULL,
      status          TEXT NOT NULL
                      CHECK (status IN ('active','removed')),
      created_at      INTEGER NOT NULL,
      updated_at      INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS github_installation_repo_name
      ON github_installation_repositories(github_full_name)
      WHERE status='active';

    CREATE TABLE IF NOT EXISTS nostr_accounts (
      pubkey      TEXT PRIMARY KEY,
      bunker_enc  TEXT NOT NULL,
      client_key_enc TEXT,
      status      TEXT NOT NULL DEFAULT 'linked'
                  CHECK (status IN ('linked','expired','revoked')),
      signer_name TEXT,
      linked_at   INTEGER NOT NULL,
      updated_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS links (
      login       TEXT NOT NULL
                  REFERENCES github_accounts(login) ON UPDATE CASCADE,
      pubkey      TEXT NOT NULL REFERENCES nostr_accounts(pubkey),
      created_at  INTEGER NOT NULL,
      PRIMARY KEY (login, pubkey)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS links_one_pubkey_per_login ON links(login);
    CREATE UNIQUE INDEX IF NOT EXISTS links_one_login_per_pubkey ON links(pubkey);

    CREATE TABLE IF NOT EXISTS repos (
      github_full_name TEXT PRIMARY KEY,
      repo_id     TEXT NOT NULL,
      owner_pubkey TEXT NOT NULL,
      relays      TEXT,
      verified    INTEGER NOT NULL DEFAULT 0,
      bridge_authorized INTEGER NOT NULL DEFAULT 0,
      created_at  INTEGER NOT NULL,
      updated_at  INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS repos_nostr_address
      ON repos(owner_pubkey,repo_id);

    CREATE TABLE IF NOT EXISTS event_map (
      github_id   TEXT NOT NULL,
      nostr_id    TEXT NOT NULL,
      direction   TEXT NOT NULL CHECK (direction IN ('gh2nostr','nostr2gh')),
      kind        INTEGER NOT NULL,
      author_pk   TEXT,
      signed_by   TEXT,
      parent_github_id TEXT,                 -- issue root or repository-star pair
      meta        TEXT,                      -- JSON: full, number, title...
      created_at  INTEGER NOT NULL,
      PRIMARY KEY (github_id, nostr_id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS em_gh  ON event_map(github_id);
    CREATE UNIQUE INDEX IF NOT EXISTS em_nos ON event_map(nostr_id);
    CREATE INDEX IF NOT EXISTS em_parent ON event_map(parent_github_id, kind);

    CREATE TABLE IF NOT EXISTS jobs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      type        TEXT NOT NULL,
      payload     TEXT NOT NULL,
      dedupe_key  TEXT,
      attempts    INTEGER NOT NULL DEFAULT 0,
      fails       INTEGER NOT NULL DEFAULT 0,   -- failed EXECUTIONS (dead at 8)
      run_at      INTEGER NOT NULL,
      status      TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','done','dead')),
      last_error  TEXT,
      created_at  INTEGER NOT NULL,
      updated_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS jobs_due ON jobs(status, run_at);
    CREATE UNIQUE INDEX IF NOT EXISTS jobs_dedupe
      ON jobs(dedupe_key) WHERE status='pending';

    CREATE TABLE IF NOT EXISTS poll_cursor (
      relay       TEXT PRIMARY KEY,
      last_seen   INTEGER NOT NULL,
      scan_until  INTEGER,
      scan_max    INTEGER
    );

    CREATE TABLE IF NOT EXISTS nostr_roots (
      nostr_id    TEXT PRIMARY KEY,
      kind        INTEGER NOT NULL,
      pubkey      TEXT NOT NULL,
      github_full_name TEXT NOT NULL REFERENCES repos(github_full_name),
      event_created_at INTEGER NOT NULL,
      discovered_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS deletion_map (
      deletion_nostr_id TEXT NOT NULL,
      target_nostr_id TEXT NOT NULL,
      marker_id TEXT NOT NULL,
      github_id TEXT NOT NULL,
      parent_github_id TEXT,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (deletion_nostr_id,target_nostr_id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS deletion_marker ON deletion_map(marker_id);

    CREATE TABLE IF NOT EXISTS oauth_states (
      nonce       TEXT PRIMARY KEY,
      github_login TEXT,
      nostr_pubkey TEXT,
      created_at  INTEGER NOT NULL,
      expires_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS github_oauth_attempts (
      state         TEXT PRIMARY KEY,
      session_nonce TEXT NOT NULL REFERENCES oauth_states(nonce) ON DELETE CASCADE,
      code_verifier TEXT NOT NULL,
      created_at    INTEGER NOT NULL,
      expires_at    INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS nip46_states (
      state_id    TEXT PRIMARY KEY,          -- shown in URL to browser
      secret      TEXT NOT NULL,             -- expected connect result
      client_pk   TEXT NOT NULL,             -- per-connection NIP-46 client
      client_key_enc TEXT,                   -- encrypted matching private key
      bunker_pk   TEXT,                      -- discovered on connect
      pubkey      TEXT,                      -- get_public_key result
      relays      TEXT,                      -- canonical JSON active NIP-46 relay set
      oauth_nonce TEXT,                      -- server-side browser/link session
      status      TEXT NOT NULL DEFAULT 'waiting'
                  CHECK (status IN ('waiting','connected','failed','done')),
      error       TEXT,
      created_at  INTEGER NOT NULL,
      expires_at  INTEGER NOT NULL
    );
    ");
    $db->exec("CREATE UNIQUE INDEX IF NOT EXISTS github_accounts_user_id
               ON github_accounts(github_user_id)
               WHERE github_user_id IS NOT NULL");
    $db->exec("CREATE UNIQUE INDEX IF NOT EXISTS nip46_one_waiting_per_session
               ON nip46_states(oauth_nonce) WHERE status='waiting'");

    $meta = $db->prepare(
        'INSERT INTO schema_meta (k,v) VALUES (?,?)'
    );
    $meta->execute(['schema_version', BRIDGE_SCHEMA_VERSION]);
    $meta->execute(['schema_contract', BRIDGE_SCHEMA_CONTRACT]);
    db_require_current_schema($db);
}

/**
 * Require one named index whose uniqueness, partialness, columns, and partial
 * predicate are part of the current schema's behavior.
 */
function db_require_index(
    PDO $db,
    string $table,
    string $name,
    bool $unique,
    bool $partial,
    array $columns,
    ?string $predicate = null
): void {
    $found = null;
    foreach ($db->query("PRAGMA index_list($table)") as $index) {
        if (($index['name'] ?? '') === $name) {
            $found = $index;
            break;
        }
    }
    $actualColumns = $found
        ? $db->query("PRAGMA index_info($name)")
             ->fetchAll(PDO::FETCH_COLUMN, 2)
        : [];
    $shapeValid = $found
        && (bool)(int)$found['unique'] === $unique
        && (bool)(int)$found['partial'] === $partial
        && $actualColumns === $columns;
    if ($shapeValid && $predicate !== null) {
        $sql = $db->prepare(
            "SELECT sql FROM sqlite_master
             WHERE type='index' AND tbl_name=? AND name=?"
        );
        $sql->execute([$table, $name]);
        $normalized = preg_replace(
            '/\s+/',
            ' ',
            strtolower(trim((string)$sql->fetchColumn()))
        );
        $shapeValid = is_string($normalized)
            && str_ends_with($normalized, strtolower($predicate));
    }
    if (!$shapeValid) {
        throw new RuntimeException(
            "Unsupported bridge database: $name shape"
        );
    }
}

/** Reject partial or older schemas; runtime never mutates them into shape. */
function db_require_current_schema(PDO $db): void
{
    $required = [
        'schema_meta' => ['k', 'v'],
        'github_accounts' => [
            'login', 'github_user_id', 'token_enc', 'refresh_token_enc',
            'token_expires_at', 'refresh_token_expires_at', 'provider',
            'auth_status', 'scopes', 'linked_at', 'updated_at',
        ],
        'github_installations' => [
            'installation_id', 'account_id', 'account_login', 'account_type',
            'repository_selection', 'status', 'token_enc', 'token_expires_at',
            'created_at', 'updated_at',
        ],
        'github_installation_repositories' => [
            'repository_id', 'installation_id', 'github_full_name', 'status',
            'created_at', 'updated_at',
        ],
        'nostr_accounts' => [
            'pubkey', 'bunker_enc', 'client_key_enc', 'status',
            'signer_name', 'linked_at', 'updated_at',
        ],
        'links' => ['login', 'pubkey', 'created_at'],
        'repos' => [
            'github_full_name', 'repo_id', 'owner_pubkey', 'relays',
            'verified', 'bridge_authorized', 'created_at', 'updated_at',
        ],
        'event_map' => [
            'github_id', 'nostr_id', 'direction', 'kind', 'author_pk',
            'signed_by', 'parent_github_id', 'meta', 'created_at',
        ],
        'jobs' => [
            'id', 'type', 'payload', 'dedupe_key', 'attempts', 'fails',
            'run_at', 'status', 'last_error', 'created_at', 'updated_at',
        ],
        'poll_cursor' => ['relay', 'last_seen', 'scan_until', 'scan_max'],
        'nostr_roots' => [
            'nostr_id', 'kind', 'pubkey', 'github_full_name',
            'event_created_at', 'discovered_at',
        ],
        'deletion_map' => [
            'deletion_nostr_id', 'target_nostr_id', 'marker_id', 'github_id',
            'parent_github_id', 'created_at',
        ],
        'oauth_states' => [
            'nonce', 'github_login', 'nostr_pubkey', 'created_at', 'expires_at',
        ],
        'github_oauth_attempts' => [
            'state', 'session_nonce', 'code_verifier', 'created_at',
            'expires_at',
        ],
        'nip46_states' => [
            'state_id', 'secret', 'client_pk', 'client_key_enc', 'bunker_pk',
            'pubkey', 'relays', 'oauth_nonce', 'status', 'error', 'created_at',
            'expires_at',
        ],
    ];
    foreach ($required as $table => $columns) {
        $actual = [];
        foreach ($db->query("PRAGMA table_info($table)") as $column) {
            $actual[$column['name']] = $column;
        }
        foreach ($columns as $column) {
            if (!isset($actual[$column])) {
                throw new RuntimeException(
                    "Unsupported bridge database: missing $table.$column"
                );
            }
        }
        $extra = array_diff(array_keys($actual), $columns);
        if ($extra) {
            throw new RuntimeException(
                "Unsupported bridge database: unexpected $table."
                . array_values($extra)[0]
            );
        }
    }

    $accountColumns = [];
    foreach ($db->query('PRAGMA table_info(github_accounts)') as $column) {
        $accountColumns[$column['name']] = $column;
    }
    if ((int)($accountColumns['provider']['notnull'] ?? 0) !== 1
        || ($accountColumns['provider']['dflt_value'] ?? null) !== null) {
        throw new RuntimeException(
            'Unsupported bridge database: github_accounts.provider shape'
        );
    }
    $attemptColumns = [];
    foreach ($db->query('PRAGMA table_info(github_oauth_attempts)') as $column) {
        $attemptColumns[$column['name']] = $column;
    }
    if ((int)($attemptColumns['code_verifier']['notnull'] ?? 0) !== 1
        || ($attemptColumns['code_verifier']['dflt_value'] ?? null) !== null) {
        throw new RuntimeException(
            'Unsupported bridge database: github_oauth_attempts.code_verifier shape'
        );
    }

    foreach ([
        [
            'github_installations',
            'github_installations_account',
            false,
            false,
            ['account_id', 'status'],
            null,
        ],
        [
            'github_installation_repositories',
            'github_installation_repo_name',
            true,
            true,
            ['github_full_name'],
            "where status='active'",
        ],
        [
            'github_accounts',
            'github_accounts_user_id',
            true,
            true,
            ['github_user_id'],
            'where github_user_id is not null',
        ],
        [
            'links',
            'links_one_pubkey_per_login',
            true,
            false,
            ['login'],
            null,
        ],
        [
            'links',
            'links_one_login_per_pubkey',
            true,
            false,
            ['pubkey'],
            null,
        ],
        [
            'repos',
            'repos_nostr_address',
            true,
            false,
            ['owner_pubkey', 'repo_id'],
            null,
        ],
        ['event_map', 'em_gh', true, false, ['github_id'], null],
        ['event_map', 'em_nos', true, false, ['nostr_id'], null],
        [
            'event_map',
            'em_parent',
            false,
            false,
            ['parent_github_id', 'kind'],
            null,
        ],
        ['jobs', 'jobs_due', false, false, ['status', 'run_at'], null],
        [
            'jobs',
            'jobs_dedupe',
            true,
            true,
            ['dedupe_key'],
            "where status='pending'",
        ],
        [
            'deletion_map',
            'deletion_marker',
            true,
            false,
            ['marker_id'],
            null,
        ],
        [
            'nip46_states',
            'nip46_one_waiting_per_session',
            true,
            true,
            ['oauth_nonce'],
            "where status='waiting'",
        ],
    ] as $index) {
        db_require_index($db, ...$index);
    }

    $hasCascade = false;
    foreach ($db->query('PRAGMA foreign_key_list(links)') as $fk) {
        if (($fk['table'] ?? '') === 'github_accounts'
            && ($fk['from'] ?? '') === 'login'
            && strtoupper((string)($fk['on_update'] ?? '')) === 'CASCADE') {
            $hasCascade = true;
            break;
        }
    }
    if (!$hasCascade) {
        throw new RuntimeException(
            'Unsupported bridge database: links must use ON UPDATE CASCADE'
        );
    }
    if ((int)$db->query(
        "SELECT COUNT(*) FROM github_accounts
         WHERE provider<>'github_app'"
    )->fetchColumn() !== 0) {
        throw new RuntimeException(
            'Unsupported bridge database: non-GitHub-App account rows remain'
        );
    }
}

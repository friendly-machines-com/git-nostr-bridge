<?php
/** Offline GitHub App authentication, refresh, and ordering tests. */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') exit(1);

define('BRIDGE_ENTRY', true);
$dbPath = sys_get_temp_dir() . '/fm-github-app-' . getmypid() . '.db';
putenv('BRIDGE_DB=' . $dbPath);
foreach ([$dbPath, "$dbPath-wal", "$dbPath-shm"] as $file) @unlink($file);

$secretDir = sys_get_temp_dir() . '/fm-github-app-secrets-' . getmypid();
@mkdir($secretDir, 0700, true);
file_put_contents(
    "$secretDir/db-crypt.php",
    "<?php return '" . bin2hex(random_bytes(32)) . "';"
);
chmod("$secretDir/db-crypt.php", 0600);
$GLOBALS['__fm_test_secrets_dir'] = $secretDir;
$GLOBALS['__fm_test_log'] = '/tmp/fm-test-github-app.log';
$GLOBALS['__fm_test_github_app'] = [
    'client_id' => 'Iv1.test-client',
    'client_secret' => 'test-client-secret',
];

$rsa = openssl_pkey_new([
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
if ($rsa === false) throw new RuntimeException('could not create test RSA key');
$pem = '';
if (!openssl_pkey_export($rsa, $pem)) {
    throw new RuntimeException('could not export test RSA key');
}
$GLOBALS['__fm_test_github_app_private_key'] = $pem;

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../lib/github_app.php';

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

function b64url_decode_test(string $value): string
{
    $padding = (4 - strlen($value) % 4) % 4;
    $decoded = base64_decode(
        strtr($value, '-_', '+/') . str_repeat('=', $padding),
        true
    );
    if ($decoded === false) throw new RuntimeException('bad test base64url');
    return $decoded;
}

echo "== GitHub App JWT ==\n";
$jwt = gh_app_jwt(1700000000);
$parts = explode('.', $jwt);
$claims = count($parts) === 3
    ? json_decode(b64url_decode_test($parts[1]), true) : null;
$details = openssl_pkey_get_details($rsa);
$verified = count($parts) === 3 && is_array($details)
    ? openssl_verify(
        $parts[0] . '.' . $parts[1],
        b64url_decode_test($parts[2]),
        $details['key'],
        OPENSSL_ALGO_SHA256
    )
    : 0;
ok(
    is_array($claims)
    && $claims['iss'] === 'Iv1.test-client'
    && $claims['iat'] === 1699999940
    && $claims['exp'] === 1700000540,
    'JWT has bounded GitHub claims'
);
ok($verified === 1, 'JWT RS256 signature verifies');

echo "== installation state and non-ordering ==\n";
$account = ['id' => 77, 'login' => 'daym', 'type' => 'User'];
$repository = [
    'id' => 8801,
    'full_name' => 'daym/personal-project',
    'owner' => $account,
];
$event = [
    'installation' => [
        'id' => 9901,
        'account' => $account,
        'repository_selection' => 'selected',
    ],
    'repository' => $repository,
];
ok(
    gh_app_bank_webhook_context($event) === '9901',
    'personal-account App installation banked'
);
$accountType = db()->query(
    "SELECT account_type FROM github_installations
     WHERE installation_id='9901'"
)->fetchColumn();
ok($accountType === 'User', 'personal account accepted without an organization');
$repoStatus = db()->query(
    "SELECT status FROM github_installation_repositories
     WHERE repository_id='8801'"
)->fetchColumn();
ok($repoStatus === 'active', 'repository access banked from signed webhook');

gh_app_mark_repositories_removed('9901', [$repository]);
gh_app_bank_webhook_context($event); // delayed ordinary content delivery
$repoStatus = db()->query(
    "SELECT status FROM github_installation_repositories
     WHERE repository_id='8801'"
)->fetchColumn();
ok(
    $repoStatus === 'removed',
    'delayed content cannot reverse repository removal'
);
gh_app_mark_installation_inactive('9901', 'deleted');
gh_app_bank_webhook_context($event); // delayed delivery from before deletion
$installationStatus = db()->query(
    "SELECT status FROM github_installations WHERE installation_id='9901'"
)->fetchColumn();
ok(
    $installationStatus === 'deleted',
    'delayed content cannot reactivate deleted installation'
);
ok(
    $installationStatus === 'deleted',
    'no independent account-authorization cache exists to reactivate'
);

$mintCalls = 0;
$GLOBALS['__fm_test_gh_request'] = static function (
    string $method,
    string $path,
    string $token
) use (&$mintCalls, $account, $repository): array {
    if ($method === 'GET'
        && $path === '/app/installations?per_page=100&page=1') {
        return [['id' => 9902], ['id' => 9901], ['id' => 9901]];
    }
    if ($method === 'GET' && $path === '/app/installations/9901') {
        return [
            'id' => 9901,
            'account' => $account,
            'repository_selection' => 'selected',
            'suspended_at' => null,
        ];
    }
    if ($method === 'POST'
        && $path === '/app/installations/9901/access_tokens') {
        $mintCalls++;
        return [
            'token' => 'ghs_test_installation',
            'expires_at' => gmdate('c', time() + 3600),
        ];
    }
    if ($method === 'GET'
        && $path === '/installation/repositories?per_page=100&page=1') {
        return ['total_count' => 1, 'repositories' => [$repository]];
    }
    throw new GhError("unexpected test request $method $path");
};
ok(
    gh_app_list_installation_ids() === ['9901', '9902'],
    'authoritative App installation discovery is a canonical ID set'
);
$result = gh_app_reconcile_installation('9901');
ok(
    $result === ['status' => 'active', 'repositories' => 1],
    'authoritative reconciliation converges after reversed deliveries'
);

// A delayed payload from another installation cannot transfer an existing
// repository row. Only an authoritative installation reconciliation may.
gh_app_bank_webhook_context([
    'installation' => [
        'id' => 9902,
        'account' => ['id' => 78, 'login' => 'other', 'type' => 'User'],
        'repository_selection' => 'selected',
    ],
    'repository' => $repository,
]);
$repoInstallation = db()->query(
    "SELECT installation_id FROM github_installation_repositories
     WHERE repository_id='8801'"
)->fetchColumn();
ok(
    $repoInstallation === '9901',
    'non-authoritative webhook cannot transfer repository ownership'
);

ok(
    gh_app_token_for_repo('daym/personal-project') === 'ghs_test_installation'
    && gh_app_token_for_repo('daym/personal-project') === 'ghs_test_installation'
    && $mintCalls === 1,
    'installation token is encrypted-cached until near expiry'
);

echo "== optional user authorization ==\n";
$initial = [
    'access_token' => 'ghu_initial',
    'refresh_token' => 'ghr_initial',
    'token_expires_at' => now() + 30,
    'refresh_token_expires_at' => now() + 86400,
];
gh_app_store_user_authorization('alice', '501', $initial);
$identityConflict = false;
try {
    gh_app_store_user_authorization('alice', '999', $initial);
} catch (GhUserIdentityConflict $error) {
    $identityConflict = true;
}
ok(
    $identityConflict,
    'a reused GitHub login cannot replace a different numeric identity'
);
$nostrPk = str_repeat('ab', 32);
db()->prepare(
    "INSERT INTO nostr_accounts
     (pubkey,bunker_enc,status,linked_at,updated_at)
     VALUES (?,?,'linked',?,?)"
)->execute([$nostrPk, 'test', now(), now()]);
db()->prepare(
    'INSERT INTO links(login,pubkey,created_at) VALUES (?,?,?)'
)->execute(['alice', $nostrPk, now()]);

$refreshCalls = 0;
$GLOBALS['__fm_test_gh_oauth_token_request'] = static function (
    array $fields
) use (&$refreshCalls): array {
    $refreshCalls++;
    if (($fields['grant_type'] ?? '') !== 'refresh_token'
        || ($fields['refresh_token'] ?? '') !== 'ghr_initial') {
        throw new GhError('unexpected refresh fields', 400);
    }
    return [
        'access_token' => 'ghu_refreshed',
        'refresh_token' => 'ghr_rotated',
        'expires_in' => 28800,
        'refresh_token_expires_in' => 15897600,
    ];
};
ok(
    gh_app_user_token('alice') === 'ghu_refreshed'
    && gh_app_user_token('alice') === 'ghu_refreshed'
    && $refreshCalls === 1,
    'expired user token refreshes once and rotated result is cached'
);
$stored = db()->query(
    "SELECT refresh_token_enc FROM github_accounts WHERE login='alice'"
)->fetchColumn();
ok(
    fm_decrypt_at_rest($stored) === 'ghr_rotated',
    'rotated refresh token is stored encrypted'
);

$renamed = [
    'access_token' => 'ghu_renamed',
    'refresh_token' => 'ghr_renamed',
    'token_expires_at' => now() + 28800,
    'refresh_token_expires_at' => now() + 15897600,
];
gh_app_store_user_authorization('alice-renamed', '501', $renamed);
$linkedLogin = db()->query(
    "SELECT login FROM links WHERE pubkey='$nostrPk'"
)->fetchColumn();
ok(
    $linkedLogin === 'alice-renamed',
    'stable GitHub user ID preserves Nostr link across login rename'
);

gh_app_store_user_authorization('revoked-user', '502', [
    'access_token' => 'ghu_expired',
    'refresh_token' => 'ghr_revoked',
    'token_expires_at' => now() - 1,
    'refresh_token_expires_at' => now() + 86400,
]);
$GLOBALS['__fm_test_gh_oauth_token_request'] = static function (): array {
    throw new GhError('bad refresh token', 400);
};
try {
    gh_app_user_token('revoked-user');
    ok(false, 'revoked authorization requests reauthorization');
} catch (GhUserAuthorizationUnavailable $error) {
    $status = db()->query(
        "SELECT auth_status FROM github_accounts
         WHERE login='revoked-user'"
    )->fetchColumn();
    ok(
        $status === 'reauthorize',
        'revoked authorization requests reauthorization'
    );
}

echo "== repository stars ==\n";
$starRequests = [];
$GLOBALS['__fm_test_gh_request'] = static function (
    string $method,
    string $path,
    string $token,
    ?array $body,
    int $timeout,
    string $accept
) use (&$starRequests): array {
    $starRequests[] = compact(
        'method',
        'path',
        'token',
        'body',
        'timeout',
        'accept'
    );
    if ($path === '/user/701') {
        return ['id' => 701, 'login' => 'target-renamed'];
    }
    if (str_contains($path, '/users/target-renamed/starred?')) {
        return [
            [
                'starred_at' => '2026-08-22T01:00:00Z',
                'repo' => ['id' => 500, 'full_name' => 'daym/other'],
            ],
            [
                'starred_at' => '2026-08-22T02:00:00Z',
                'repo' => ['id' => 600, 'full_name' => 'daym/project'],
            ],
        ];
    }
    return [];
};
$starState = gh_repository_star_state_for_user(
    'ghs_installation',
    '600',
    '701'
);
ok(
    ($starState['starred'] ?? null) === true
    && ($starState['login'] ?? null) === 'target-renamed'
    && ($starState['starred_at_timestamp'] ?? null)
        === strtotime('2026-08-22T02:00:00Z')
    && ($starRequests[0]['path'] ?? null) === '/user/701'
    && str_starts_with(
        (string)($starRequests[1]['path'] ?? ''),
        '/users/target-renamed/starred?'
    )
    && ($starRequests[1]['accept'] ?? null)
        === 'application/vnd.github.star+json',
    'star reconciliation survives login rename and matches stable IDs'
);
ok(
    gh_repository_star_state_for_user(
        'ghs_installation',
        '999',
        '701'
    )['starred'] === false,
    'complete actor collection authoritatively represents absence'
);
gh_user_set_star('ghu_user', 'daym/project', true);
gh_user_set_star('ghu_user', 'daym/project', false);
$starMethods = array_column(
    array_values(array_filter(
        $starRequests,
        fn(array $request): bool => str_starts_with(
            $request['path'],
            '/user/starred/'
        )
    )),
    'method'
);
ok(
    $starMethods === ['PUT', 'DELETE'],
    'repository star mutation uses GitHub user endpoints in both directions'
);

foreach ([$dbPath, "$dbPath-wal", "$dbPath-shm"] as $file) @unlink($file);
@unlink("$secretDir/db-crypt.php");
@rmdir($secretDir);

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);

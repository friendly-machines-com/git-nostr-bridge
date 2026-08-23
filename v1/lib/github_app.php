<?php
/**
 * GitHub App authentication and installation state.
 *
 * Long-lived operator material is limited to the App registration and RSA
 * private key. Installation tokens are minted on demand, cached encrypted,
 * and never configured by hand. User authorization uses the same GitHub App
 * with expiring access/refresh tokens.
 */
declare(strict_types=1);

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/util.php';
require_once __DIR__ . '/secrets.php';
require_once __DIR__ . '/github.php';

class GhInstallationUnavailable extends RuntimeException {}
class GhUserAuthorizationUnavailable extends RuntimeException {}
class GhUserIdentityConflict extends RuntimeException {}

function gh_base64url(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

/** Create the short-lived RS256 JWT used only to call GitHub App endpoints. */
function gh_app_jwt(?int $issuedAt = null): string
{
    $at = $issuedAt ?? now();
    $app = fm_secret_github_app();
    $header = gh_base64url(json_c(['alg' => 'RS256', 'typ' => 'JWT']));
    $claims = gh_base64url(json_c([
        'iat' => $at - 60,
        'exp' => $at + 540,
        // GitHub recommends the App's client ID as the issuer.
        'iss' => $app['client_id'],
    ]));
    $input = $header . '.' . $claims;
    $signature = '';
    if (!openssl_sign(
        $input,
        $signature,
        fm_secret_github_app_private_key(),
        OPENSSL_ALGO_SHA256
    )) {
        throw new RuntimeException('could not sign GitHub App JWT');
    }
    return $input . '.' . gh_base64url($signature);
}

/** Stable numeric identity used to recognize this App's own GitHub events. */
function gh_app_id(): string
{
    $testId = $GLOBALS['__fm_test_github_app_id'] ?? null;
    if ((is_int($testId) || is_string($testId))
        && ctype_digit((string)$testId)) {
        return (string)$testId;
    }

    static $id = null;
    if ($id !== null) return $id;

    $remote = gh_request('GET', '/app', gh_app_jwt());
    $candidate = gh_app_installation_id($remote['id'] ?? null);
    $clientId = is_string($remote['client_id'] ?? null)
        ? $remote['client_id'] : '';
    $configured = fm_secret_github_app();
    if ($candidate === null || $clientId === ''
        || !hash_equals($configured['client_id'], $clientId)) {
        throw new GhError(
            'authenticated GitHub App identity does not match configuration'
        );
    }
    $id = $candidate;
    return $id;
}

/**
 * Exchange an OAuth code or refresh token. Test seam accepts a callable and
 * prevents all network access in the offline suites.
 */
function gh_oauth_token_request(array $fields): array
{
    $test = $GLOBALS['__fm_test_gh_oauth_token_request'] ?? null;
    if (is_callable($test)) {
        $response = $test($fields);
        if (!is_array($response)) throw new GhError('test OAuth response is not an array');
        return $response;
    }

    $ch = curl_init('https://github.com/login/oauth/access_token');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($fields),
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
    ]);
    $raw = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    if ($raw === false) throw new GhError("oauth curl: $error");
    $decoded = json_decode($raw ?: 'null', true);
    if ($code < 200 || $code >= 300 || !is_array($decoded)
        || isset($decoded['error'])) {
        $message = is_array($decoded)
            ? (string)($decoded['error_description']
                ?? $decoded['error'] ?? 'invalid response')
            : 'invalid response';
        throw new GhError("github oauth $code: $message", $code);
    }
    return $decoded;
}

/** Normalize the expiring-token response configured for this App. */
function gh_app_user_token_response(array $response, ?int $issuedAt = null): array
{
    $at = $issuedAt ?? now();
    $access = $response['access_token'] ?? null;
    $refresh = $response['refresh_token'] ?? null;
    $expiresIn = filter_var(
        $response['expires_in'] ?? null,
        FILTER_VALIDATE_INT,
        ['options' => ['min_range' => 1]]
    );
    $refreshExpiresIn = filter_var(
        $response['refresh_token_expires_in'] ?? null,
        FILTER_VALIDATE_INT,
        ['options' => ['min_range' => 1]]
    );
    if (!is_string($access) || $access === ''
        || !is_string($refresh) || $refresh === ''
        || $expiresIn === false || $refreshExpiresIn === false) {
        throw new GhError(
            'GitHub App did not return expiring access and refresh tokens; '
            . 'enable "Expire user authorization tokens"'
        );
    }
    return [
        'access_token' => $access,
        'refresh_token' => $refresh,
        'token_expires_at' => $at + (int)$expiresIn,
        'refresh_token_expires_at' => $at + (int)$refreshExpiresIn,
    ];
}

function gh_app_exchange_code(
    string $code,
    string $codeVerifier,
    string $redirectUri
): array {
    $app = fm_secret_github_app();
    return gh_app_user_token_response(gh_oauth_token_request([
        'client_id' => $app['client_id'],
        'client_secret' => $app['client_secret'],
        'code' => $code,
        'redirect_uri' => $redirectUri,
        'code_verifier' => $codeVerifier,
    ]));
}

function gh_app_store_user_authorization(
    string $login,
    string $githubUserId,
    array $tokens
): void {
    if ($login === '' || $githubUserId === ''
        || !isset(
            $tokens['access_token'],
            $tokens['refresh_token'],
            $tokens['token_expires_at'],
            $tokens['refresh_token_expires_at']
        )) {
        throw new InvalidArgumentException('incomplete GitHub user authorization');
    }
    $byLogin = db()->prepare(
        'SELECT github_user_id FROM github_accounts WHERE login=?'
    );
    $byLogin->execute([$login]);
    $loginRowId = $byLogin->fetchColumn();
    if ($loginRowId !== false
        && !hash_equals((string)$loginRowId, $githubUserId)) {
        throw new GhUserIdentityConflict(
            'GitHub login is already attached to a different numeric account'
        );
    }
    $byId = db()->prepare(
        'SELECT login FROM github_accounts WHERE github_user_id=?'
    );
    $byId->execute([$githubUserId]);
    $priorLogin = $byId->fetchColumn();
    if (is_string($priorLogin) && $priorLogin !== $login) {
        $collision = db()->prepare(
            'SELECT github_user_id FROM github_accounts WHERE login=?'
        );
        $collision->execute([$login]);
        $collisionId = $collision->fetchColumn();
        if ($collisionId !== false) {
            throw new GhUserIdentityConflict(
                'GitHub login is already attached to a different account row'
            );
        }
        // links.login follows this update through ON UPDATE CASCADE.
        db()->prepare(
            'UPDATE github_accounts SET login=?,updated_at=? WHERE github_user_id=?'
        )->execute([$login, now(), $githubUserId]);
    }
    db()->prepare(
        "INSERT INTO github_accounts
         (login,github_user_id,token_enc,refresh_token_enc,
          token_expires_at,refresh_token_expires_at,provider,auth_status,
          scopes,linked_at,updated_at)
         VALUES (?,?,?,?,?,?,'github_app','active','',?,?)
         ON CONFLICT(login) DO UPDATE SET
           github_user_id=excluded.github_user_id,
           token_enc=excluded.token_enc,
           refresh_token_enc=excluded.refresh_token_enc,
           token_expires_at=excluded.token_expires_at,
           refresh_token_expires_at=excluded.refresh_token_expires_at,
           provider='github_app',auth_status='active',scopes='',
           updated_at=excluded.updated_at"
    )->execute([
        $login,
        $githubUserId,
        fm_encrypt_at_rest((string)$tokens['access_token']),
        fm_encrypt_at_rest((string)$tokens['refresh_token']),
        (int)$tokens['token_expires_at'],
        (int)$tokens['refresh_token_expires_at'],
        now(),
        now(),
    ]);
}

/**
 * Return a valid user token, refreshing it optimistically. A simultaneous
 * refresh is harmless: the loser observes the winner's newly stored token.
 */
function gh_app_user_token(string $login): string
{
    $testTokens = $GLOBALS['__fm_test_github_user_tokens'] ?? null;
    if (is_array($testTokens) && is_string($testTokens[$login] ?? null)) {
        return $testTokens[$login];
    }

    $query = db()->prepare(
        "SELECT * FROM github_accounts
         WHERE login=? AND provider='github_app' AND auth_status='active'"
    );
    $query->execute([$login]);
    $row = $query->fetch();
    if (!$row) {
        throw new GhUserAuthorizationUnavailable('GitHub user must reauthorize');
    }
    if ((int)($row['token_expires_at'] ?? 0) > now() + 60) {
        return fm_decrypt_at_rest((string)$row['token_enc']);
    }

    $refreshEnc = $row['refresh_token_enc'] ?? null;
    if (!is_string($refreshEnc) || $refreshEnc === ''
        || (int)($row['refresh_token_expires_at'] ?? 0) <= now() + 60) {
        db()->prepare(
            "UPDATE github_accounts SET auth_status='reauthorize',updated_at=?
             WHERE login=? AND provider='github_app'"
        )->execute([now(), $login]);
        throw new GhUserAuthorizationUnavailable('GitHub refresh token expired');
    }

    $app = fm_secret_github_app();
    try {
        $tokens = gh_app_user_token_response(gh_oauth_token_request([
            'client_id' => $app['client_id'],
            'client_secret' => $app['client_secret'],
            'grant_type' => 'refresh_token',
            'refresh_token' => fm_decrypt_at_rest($refreshEnc),
        ]));
    } catch (GhError $error) {
        // A concurrent worker may have rotated the single-use refresh token.
        $query->execute([$login]);
        $fresh = $query->fetch();
        if ($fresh && !hash_equals(
            $refreshEnc,
            (string)($fresh['refresh_token_enc'] ?? '')
        ) && (int)($fresh['token_expires_at'] ?? 0) > now() + 30) {
            return fm_decrypt_at_rest((string)$fresh['token_enc']);
        }
        if ($error->getCode() >= 400 && $error->getCode() < 500) {
            db()->prepare(
                "UPDATE github_accounts
                 SET auth_status='reauthorize',updated_at=?
                 WHERE login=? AND refresh_token_enc=?"
            )->execute([now(), $login, $refreshEnc]);
            throw new GhUserAuthorizationUnavailable(
                'GitHub authorization was revoked or expired',
                0,
                $error
            );
        }
        throw $error;
    }

    $accessEnc = fm_encrypt_at_rest((string)$tokens['access_token']);
    $nextRefreshEnc = fm_encrypt_at_rest((string)$tokens['refresh_token']);
    $update = db()->prepare(
        "UPDATE github_accounts SET
           token_enc=?,refresh_token_enc=?,token_expires_at=?,
           refresh_token_expires_at=?,updated_at=?
         WHERE login=? AND provider='github_app' AND auth_status='active'
           AND refresh_token_enc=?"
    );
    $update->execute([
        $accessEnc,
        $nextRefreshEnc,
        (int)$tokens['token_expires_at'],
        (int)$tokens['refresh_token_expires_at'],
        now(),
        $login,
        $refreshEnc,
    ]);
    if ($update->rowCount() === 1) return (string)$tokens['access_token'];

    // Another worker won between the refresh response and our UPDATE.
    $query->execute([$login]);
    $fresh = $query->fetch();
    if ($fresh && (int)($fresh['token_expires_at'] ?? 0) > now() + 30) {
        return fm_decrypt_at_rest((string)$fresh['token_enc']);
    }
    throw new GhError('concurrent GitHub user-token refresh did not converge');
}

function gh_app_require_user_reauthorization(string $login): void
{
    db()->prepare(
        "UPDATE github_accounts SET auth_status='reauthorize',updated_at=?
         WHERE login=? AND provider='github_app'"
    )->execute([now(), $login]);
}

function gh_app_installation_id(mixed $value): ?string
{
    if ((is_int($value) || is_string($value))
        && ctype_digit((string)$value)
        && (string)$value !== '0') {
        return (string)$value;
    }
    return null;
}

/**
 * Bank installation/repository identity from any signed App webhook. Ordinary
 * content may create unknown rows but never reactivate an explicitly removed
 * repository or inactive installation; authoritative reconciliation does.
 */
function gh_app_bank_webhook_context(array $event): ?string
{
    $installation = is_array($event['installation'] ?? null)
        ? $event['installation'] : [];
    $installationId = gh_app_installation_id($installation['id'] ?? null);
    if ($installationId === null) return null;

    $repository = is_array($event['repository'] ?? null)
        ? $event['repository'] : null;
    $account = is_array($installation['account'] ?? null)
        ? $installation['account']
        : (is_array($repository['owner'] ?? null) ? $repository['owner'] : []);
    $accountId = gh_app_installation_id($account['id'] ?? null);
    $accountLogin = is_string($account['login'] ?? null)
        ? $account['login'] : '';
    $accountType = is_string($account['type'] ?? null)
        && in_array($account['type'], ['Organization', 'User'], true)
        ? $account['type'] : '';
    if ($accountId === null || $accountLogin === '' || $accountType === '') {
        return $installationId;
    }

    $time = now();
    db()->beginTransaction();
    try {
        db()->prepare(
            "INSERT INTO github_installations
             (installation_id,account_id,account_login,account_type,
              repository_selection,status,created_at,updated_at)
             VALUES (?,?,?,?,?,'active',?,?)
             ON CONFLICT(installation_id) DO NOTHING"
        )->execute([
            $installationId,
            $accountId,
            $accountLogin,
            $accountType,
            is_string($installation['repository_selection'] ?? null)
                ? $installation['repository_selection'] : null,
            $time,
            $time,
        ]);
        if ($repository !== null) {
            gh_app_bank_repository(
                $installationId,
                $repository,
                false
            );
        }
        db()->commit();
    } catch (Throwable $error) {
        if (db()->inTransaction()) db()->rollBack();
        throw $error;
    }
    return $installationId;
}

/**
 * Insert/update repository identity. When $authoritative is false, an
 * explicitly removed repository remains removed despite a delayed payload.
 */
function gh_app_bank_repository(
    string $installationId,
    array $repository,
    bool $authoritative
): void {
    $repositoryId = gh_app_installation_id($repository['id'] ?? null);
    $fullName = is_string($repository['full_name'] ?? null)
        ? $repository['full_name'] : '';
    if ($repositoryId === null
        || !preg_match('#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $fullName)) {
        return;
    }
    $time = now();
    if ($authoritative) {
        db()->prepare(
            "UPDATE github_installation_repositories
             SET status='removed',updated_at=?
             WHERE github_full_name=? AND repository_id<>? AND status='active'"
        )->execute([$time, $fullName, $repositoryId]);
        db()->prepare(
            "INSERT INTO github_installation_repositories
             (repository_id,installation_id,github_full_name,status,created_at,updated_at)
             VALUES (?,?,?,'active',?,?)
             ON CONFLICT(repository_id) DO UPDATE SET
               installation_id=excluded.installation_id,
               github_full_name=excluded.github_full_name,
               status='active',updated_at=excluded.updated_at"
        )->execute([$repositoryId, $installationId, $fullName, $time, $time]);
        return;
    }
    db()->prepare(
        "INSERT INTO github_installation_repositories
         (repository_id,installation_id,github_full_name,status,created_at,updated_at)
         VALUES (?,?,?,'active',?,?)
         ON CONFLICT(repository_id) DO NOTHING"
    )->execute([$repositoryId, $installationId, $fullName, $time, $time]);
}

function gh_app_mark_installation_inactive(
    string $installationId,
    string $status
): void {
    if (!in_array($status, ['suspended', 'deleted'], true)) {
        throw new InvalidArgumentException('invalid installation status');
    }
    db()->beginTransaction();
    try {
        db()->prepare(
            "UPDATE github_installations
             SET status=?,token_enc=NULL,token_expires_at=NULL,updated_at=?
             WHERE installation_id=?"
        )->execute([$status, now(), $installationId]);
        db()->prepare(
            "UPDATE github_installation_repositories
             SET status='removed',updated_at=? WHERE installation_id=?"
        )->execute([now(), $installationId]);
        db()->commit();
    } catch (Throwable $error) {
        if (db()->inTransaction()) db()->rollBack();
        throw $error;
    }
}

function gh_app_mark_repositories_removed(
    string $installationId,
    array $repositories
): void {
    $update = db()->prepare(
        "UPDATE github_installation_repositories
         SET status='removed',updated_at=?
         WHERE installation_id=? AND repository_id=?"
    );
    foreach ($repositories as $repository) {
        if (!is_array($repository)) continue;
        $repositoryId = gh_app_installation_id($repository['id'] ?? null);
        if ($repositoryId !== null) {
            $update->execute([now(), $installationId, $repositoryId]);
        }
    }
}

/** Mint a new installation token using an App JWT. */
function gh_app_mint_installation_token(string $installationId): array
{
    $response = gh_request(
        'POST',
        '/app/installations/' . rawurlencode($installationId) . '/access_tokens',
        gh_app_jwt()
    );
    $token = $response['token'] ?? null;
    $expiresAt = is_string($response['expires_at'] ?? null)
        ? strtotime($response['expires_at']) : false;
    if (!is_string($token) || $token === ''
        || $expiresAt === false || $expiresAt <= now() + 60) {
        throw new GhError('invalid GitHub installation-token response');
    }
    return ['token' => $token, 'expires_at' => $expiresAt];
}

function gh_app_installation_token(
    string $installationId,
    bool $forceRefresh = false
): string {
    $query = db()->prepare(
        "SELECT status,token_enc,token_expires_at
         FROM github_installations WHERE installation_id=?"
    );
    $query->execute([$installationId]);
    $row = $query->fetch();
    if (!$row || $row['status'] !== 'active') {
        throw new GhInstallationUnavailable(
            "GitHub App installation $installationId is not active"
        );
    }
    if (!$forceRefresh
        && is_string($row['token_enc'] ?? null)
        && (int)($row['token_expires_at'] ?? 0) > now() + 60) {
        return fm_decrypt_at_rest($row['token_enc']);
    }
    $fresh = gh_app_mint_installation_token($installationId);
    $update = db()->prepare(
        "UPDATE github_installations
         SET token_enc=?,token_expires_at=?,updated_at=?
         WHERE installation_id=? AND status='active'"
    );
    $update->execute([
        fm_encrypt_at_rest($fresh['token']),
        $fresh['expires_at'],
        now(),
        $installationId,
    ]);
    if ($update->rowCount() !== 1) {
        throw new GhInstallationUnavailable(
            "GitHub App installation $installationId changed while minting"
        );
    }
    return $fresh['token'];
}

function gh_app_installation_for_repo(string $fullName): string
{
    $query = db()->prepare(
        "SELECT gi.installation_id
         FROM github_installation_repositories gir
         JOIN github_installations gi
           ON gi.installation_id=gir.installation_id
         WHERE gir.github_full_name=? AND gir.status='active'
           AND gi.status='active' AND gi.token_enc IS NOT NULL"
    );
    $query->execute([$fullName]);
    $installationId = $query->fetchColumn();
    if (!is_string($installationId) || $installationId === '') {
        throw new GhInstallationUnavailable(
            "GitHub App is not installed for $fullName"
        );
    }
    return $installationId;
}

function gh_app_token_for_repo(string $fullName): string
{
    $testTokens = $GLOBALS['__fm_test_github_installation_tokens'] ?? null;
    if (is_array($testTokens) && is_string($testTokens[$fullName] ?? null)) {
        return $testTokens[$fullName];
    }
    return gh_app_installation_token(gh_app_installation_for_repo($fullName));
}

/**
 * List the App's complete current installation-ID set. This is the bootstrap
 * and recovery path when an installation webhook was delayed or lost.
 *
 * @return list<string>
 */
function gh_app_list_installation_ids(): array
{
    $ids = [];
    $jwt = gh_app_jwt();
    for ($page = 1; $page <= 100; $page++) {
        $batch = gh_request(
            'GET',
            "/app/installations?per_page=100&page=$page",
            $jwt
        );
        if (!array_is_list($batch)) {
            throw new GhError(
                'GitHub App installation list response is not a list'
            );
        }
        foreach ($batch as $installation) {
            $id = is_array($installation)
                ? gh_app_installation_id($installation['id'] ?? null)
                : null;
            if ($id === null) {
                throw new GhError(
                    'GitHub App installation list contains an invalid identity'
                );
            }
            // GitHub IDs are opaque decimal strings. Prefix the associative
            // key so PHP cannot coerce that string identity into an integer.
            $ids['s:' . $id] = $id;
        }
        if (count($batch) < 100) break;
        if ($page === 100) {
            throw new GhError(
                'GitHub App installation pagination did not converge'
            );
        }
    }
    $result = array_values($ids);
    sort($result, SORT_STRING);
    return $result;
}

/**
 * Reconcile an installation and its complete repository set from GitHub.
 * Webhook arrival order therefore cannot decide final access state.
 */
function gh_app_reconcile_installation(string $installationId): array
{
    try {
        $remote = gh_request(
            'GET',
            '/app/installations/' . rawurlencode($installationId),
            gh_app_jwt()
        );
    } catch (GhError $error) {
        if ($error->getCode() === 404) {
            gh_app_mark_installation_inactive($installationId, 'deleted');
            return ['status' => 'deleted', 'repositories' => 0];
        }
        throw $error;
    }

    $account = is_array($remote['account'] ?? null) ? $remote['account'] : [];
    $accountId = gh_app_installation_id($account['id'] ?? null);
    $login = is_string($account['login'] ?? null) ? $account['login'] : '';
    $type = is_string($account['type'] ?? null)
        && in_array($account['type'], ['Organization', 'User'], true)
        ? $account['type'] : '';
    if ($accountId === null || $login === '' || $type === '') {
        throw new GhError('GitHub installation response has no valid account');
    }
    $status = empty($remote['suspended_at']) ? 'active' : 'suspended';
    $selection = is_string($remote['repository_selection'] ?? null)
        ? $remote['repository_selection'] : null;
    $time = now();
    db()->prepare(
        "INSERT INTO github_installations
         (installation_id,account_id,account_login,account_type,
          repository_selection,status,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,?)
         ON CONFLICT(installation_id) DO UPDATE SET
           account_id=excluded.account_id,account_login=excluded.account_login,
           account_type=excluded.account_type,
           repository_selection=excluded.repository_selection,
           status=excluded.status,updated_at=excluded.updated_at"
    )->execute([
        $installationId,
        $accountId,
        $login,
        $type,
        $selection,
        $status,
        $time,
        $time,
    ]);
    if ($status !== 'active') {
        gh_app_mark_installation_inactive($installationId, 'suspended');
        return ['status' => 'suspended', 'repositories' => 0];
    }

    $token = gh_app_installation_token($installationId, true);
    $repositories = [];
    $total = null;
    for ($page = 1; ; $page++) {
        $response = gh_request(
            'GET',
            "/installation/repositories?per_page=100&page=$page",
            $token
        );
        $pageRepos = is_array($response['repositories'] ?? null)
            ? $response['repositories'] : null;
        $pageTotal = filter_var(
            $response['total_count'] ?? null,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 0]]
        );
        if ($pageRepos === null || $pageTotal === false) {
            throw new GhError('invalid GitHub installation repository list');
        }
        $total = (int)$pageTotal;
        foreach ($pageRepos as $repository) {
            if (!is_array($repository)) continue;
            $id = gh_app_installation_id($repository['id'] ?? null);
            if ($id !== null) {
                // Preserve GitHub's opaque decimal string identity; PHP
                // otherwise coerces it to an integer associative key.
                $repositories['s:' . $id] = $repository;
            }
        }
        if (count($repositories) >= $total) break;
        if (!$pageRepos) break;
        if ($page > (int)ceil(max(1, $total) / 100) + 1) {
            throw new GhError(
                'GitHub installation repository pagination did not converge'
            );
        }
    }
    if ($total === null || count($repositories) !== $total) {
        throw new GhError(
            'GitHub installation repository pagination was incomplete'
        );
    }

    db()->beginTransaction();
    try {
        db()->prepare(
            "UPDATE github_installation_repositories
             SET status='removed',updated_at=? WHERE installation_id=?"
        )->execute([$time, $installationId]);
        foreach ($repositories as $repository) {
            gh_app_bank_repository($installationId, $repository, true);
        }
        db()->commit();
    } catch (Throwable $error) {
        if (db()->inTransaction()) db()->rollBack();
        throw $error;
    }
    return ['status' => 'active', 'repositories' => count($repositories)];
}

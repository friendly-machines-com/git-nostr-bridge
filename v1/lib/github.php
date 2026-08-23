<?php
/**
 * github.php -- GitHub REST helpers (cURL), Dir B side.
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';
require_once __DIR__ . '/secrets.php';

const GH_API = 'https://api.github.com';

class GhError extends RuntimeException {}

/**
 * Read one public-or-unlisted Gist without a GitHub user token.
 *
 * NIP-39 proof verification must not expand the GitHub App's permissions.
 * The Gist ID is validated before being appended to this fixed API origin, so
 * this helper cannot become a general unauthenticated request or SSRF path.
 */
function gh_public_gist(string $gistId, int $timeout = 4): array
{
    $gistId = strtolower($gistId);
    if (!preg_match('/^[0-9a-f]{5,64}$/D', $gistId)) {
        throw new InvalidArgumentException('invalid GitHub Gist ID');
    }
    $test = $GLOBALS['__fm_test_gh_public_gist'] ?? null;
    if (is_callable($test)) {
        $response = $test($gistId);
        if (!is_array($response)) {
            throw new GhError('test Gist response is not an array');
        }
        return $response;
    }

    $path = '/gists/' . rawurlencode($gistId);
    $ch = curl_init(GH_API . $path);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => max(1, min(10, $timeout)),
        CURLOPT_HTTPHEADER => [
            'Accept: application/vnd.github+json',
            'User-Agent: friendly-machines-bridge',
            'X-GitHub-Api-Version: 2022-11-28',
        ],
    ]);
    $raw = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    if ($raw === false) throw new GhError("gist curl: $error");
    $decoded = json_decode($raw ?: 'null', true);
    if ($code >= 400) {
        $message = is_array($decoded)
            && is_string($decoded['message'] ?? null)
            ? $decoded['message'] : '';
        throw new GhError("github $code $path: $message", $code);
    }
    if (!is_array($decoded)) {
        throw new GhError('GitHub returned an invalid Gist response');
    }
    return $decoded;
}

function gh_request(
    string $method,
    string $path,
    string $token,
    ?array $body = null,
    int $timeout = 15,
    string $accept = 'application/vnd.github+json'
): array
{
    $test = $GLOBALS['__fm_test_gh_request'] ?? null;
    if (is_callable($test)) {
        $response = $test(
            $method,
            $path,
            $token,
            $body,
            $timeout,
            $accept
        );
        if (!is_array($response)) {
            throw new GhError('test GitHub response is not an array');
        }
        return $response;
    }
    $ch = curl_init(GH_API . $path);
    $headers = [
        'Authorization: Bearer ' . $token,
        'Accept: ' . $accept,
        'User-Agent: friendly-machines-bridge',
        'X-GitHub-Api-Version: 2022-11-28',
    ];
    if ($body !== null) $headers[] = 'Content-Type: application/json';
    // GitHub's authenticated-user star endpoint explicitly requires an
    // empty PUT body with Content-Length: 0.
    if ($method === 'PUT' && $body === null) {
        $headers[] = 'Content-Length: 0';
    }
    $options = [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_HTTPHEADER     => $headers,
    ];
    if ($body !== null) $options[CURLOPT_POSTFIELDS] = json_c($body);
    curl_setopt_array($ch, $options);
    $raw = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    if ($raw === false) throw new GhError("curl: $err");
    $dec = json_decode($raw ?: 'null', true);
    if ($code >= 400) {
        $msg = is_array($dec) && is_string($dec['message'] ?? null)
            ? $dec['message'] : '';
        throw new GhError("github $code $path: $msg", $code);
    }
    return is_array($dec) ? $dec : [];
}

if (!function_exists('gh_repository_star_state_for_user')) {
/**
 * Read one stable GitHub user/repository pair without using the restricted
 * repository-wide stargazer endpoint.
 *
 * GitHub logins can change, so /user/{account_id} resolves the current login
 * from the immutable numeric ID supplied by the signed App webhook. The
 * user's starred-repository collection is then searched by immutable
 * repository ID. Only a completely consumed collection proves absence.
 *
 * @return array{
 *   starred:bool,github_user_id:string,login:string,
 *   starred_at:?string,starred_at_timestamp:?int
 * }
 */
function gh_repository_star_state_for_user(
    string $token,
    string $repositoryId,
    string $githubUserId
): array {
    if (!ctype_digit($repositoryId) || $repositoryId === '0'
        || !ctype_digit($githubUserId) || $githubUserId === '0') {
        throw new InvalidArgumentException(
            'invalid GitHub repository-star identity'
        );
    }

    $user = gh_request(
        'GET',
        '/user/' . rawurlencode($githubUserId),
        $token
    );
    $resolvedId = $user['id'] ?? null;
    $login = is_string($user['login'] ?? null)
        ? $user['login'] : '';
    if ((!is_int($resolvedId) && !is_string($resolvedId))
        || !hash_equals($githubUserId, (string)$resolvedId)
        || !preg_match('/^[A-Za-z0-9-]{1,100}$/D', $login)) {
        throw new GhError(
            'GitHub user-ID lookup returned a different or invalid identity'
        );
    }

    for ($page = 1; $page <= 1000; $page++) {
        $batch = gh_request(
            'GET',
            '/users/' . rawurlencode($login)
                . '/starred?sort=created&direction=desc'
                . "&per_page=100&page=$page",
            $token,
            null,
            15,
            'application/vnd.github.star+json'
        );
        if (!array_is_list($batch)) {
            throw new GhError(
                'GitHub starred-repository response is not a list'
            );
        }
        foreach ($batch as $entry) {
            $repository = is_array($entry)
                && is_array($entry['repo'] ?? null)
                ? $entry['repo'] : [];
            $candidateId = $repository['id'] ?? null;
            if ((!is_int($candidateId) && !is_string($candidateId))
                || !ctype_digit((string)$candidateId)
                || (string)$candidateId === '0') {
                throw new GhError(
                    'GitHub starred-repository response has an invalid identity'
                );
            }
            if (!hash_equals($repositoryId, (string)$candidateId)) {
                continue;
            }
            $starredAt = is_string($entry['starred_at'] ?? null)
                ? $entry['starred_at'] : '';
            $timestamp = $starredAt !== '' ? strtotime($starredAt) : false;
            if ($timestamp === false || $timestamp < 1) {
                throw new GhError(
                    'GitHub repository star has no usable source timestamp'
                );
            }
            return [
                'starred' => true,
                'github_user_id' => $githubUserId,
                'login' => $login,
                'starred_at' => $starredAt,
                'starred_at_timestamp' => $timestamp,
            ];
        }
        if (count($batch) < 100) {
            return [
                'starred' => false,
                'github_user_id' => $githubUserId,
                'login' => $login,
                'starred_at' => null,
                'starred_at_timestamp' => null,
            ];
        }
    }
    throw new GhError(
        'GitHub starred-repository pagination exceeded the completeness bound'
    );
}
}

if (!function_exists('gh_user_has_star')) {
/** Read the current star state belonging to a GitHub App user token. */
function gh_user_has_star(
    string $token,
    string $fullName
): bool {
    try {
        gh_request('GET', "/user/starred/$fullName", $token);
        return true;
    } catch (GhError $error) {
        if ($error->getCode() === 404) return false;
        throw $error;
    }
}
}

if (!function_exists('gh_user_set_star')) {
/** Idempotently set the token owner's repository-star state. */
function gh_user_set_star(
    string $token,
    string $fullName,
    bool $starred
): void {
    gh_request(
        $starred ? 'PUT' : 'DELETE',
        "/user/starred/$fullName",
        $token
    );
}
}

/** Post a comment as the token owner. Returns node_id.
 *  (function_exists guard = offline test seam, like relay.php) */
if (!function_exists('gh_post_issue_comment')) {
function gh_post_issue_comment(string $token, string $fullName, int $number, string $body): string
{
    // PRs use the same endpoint (issues/comments) -- GitHub PRs are issues.
    $res = gh_request('POST', "/repos/$fullName/issues/$number/comments", $token, ['body' => $body]);
    if (empty($res['node_id'])) throw new GhError('comment response missing node_id');
    return $res['node_id'];
}
}

if (!function_exists('gh_create_issue')) {
/** Create an issue as the token owner. Returns the full response. */
function gh_create_issue(string $token, string $fullName, string $title, string $body): array
{
    return gh_request('POST', "/repos/$fullName/issues", $token,
                      ['title' => $title, 'body' => $body]);
}
}

if (!function_exists('gh_set_issue_status')) {
/** Map the representable NIP-34 issue states to GitHub state reasons. */
function gh_set_issue_status(
    string $token,
    string $fullName,
    int $number,
    int $statusKind
): array {
    $body = match ($statusKind) {
        1630 => ['state' => 'open', 'state_reason' => 'reopened'],
        1631 => ['state' => 'closed', 'state_reason' => 'completed'],
        1632 => ['state' => 'closed', 'state_reason' => 'not_planned'],
        default => throw new InvalidArgumentException(
            'GitHub cannot represent this NIP-34 issue status'
        ),
    };
    return gh_request(
        'PATCH',
        "/repos/$fullName/issues/$number",
        $token,
        $body
    );
}
}

if (!function_exists('gh_issue_status_events')) {
/** Parse an exact GitHub event timestamp without depending on bridge.php. */
function gh_issue_status_timestamp(mixed $value): int
{
    if (!is_string($value) || $value === '') {
        throw new GhError('GitHub issue status event has no timestamp');
    }
    $timestamp = strtotime($value);
    if ($timestamp === false || $timestamp < 1) {
        throw new GhError('GitHub issue status event has an invalid timestamp');
    }
    return $timestamp;
}

/**
 * Return GitHub's causal close/reopen history for one issue.
 *
 * Webhook deliveries and REST issue-event arrays are not ordering
 * authorities. REST is used as a map keyed by stable event ID because it
 * exposes performed_via_github_app. The GraphQL issue timeline connection is
 * the causal sequence. Both snapshots must contain the same status-event ID
 * set; a concurrent change makes the job retry instead of publishing a
 * partial or misordered history. A logical Nostr timestamp advances at least
 * one second per transition, preserving that sequence when multiple GitHub
 * transitions share one integer second.
 *
 * @return list<array{
 *   github_id:string,kind:int,actor:string,source_created_at:int,
 *   nostr_created_at:int,performed_by_bridge:bool
 * }>
 */
function gh_issue_status_events(
    string $token,
    string $fullName,
    int $number,
    string $bridgeAppId
): array {
    if ($number < 1 || !str_contains($fullName, '/')) {
        throw new InvalidArgumentException('invalid issue status-history target');
    }

    $restEvents = [];
    for ($page = 1; $page <= 100; $page++) {
        $batch = gh_request(
            'GET',
            "/repos/$fullName/issues/$number/events?per_page=100&page=$page",
            $token
        );
        if (!array_is_list($batch)) {
            throw new GhError('GitHub issue events response is not a list');
        }
        foreach ($batch as $event) {
            if (!is_array($event)
                || !in_array($event['event'] ?? null, ['closed', 'reopened'], true)) {
                continue;
            }
            $nodeId = is_string($event['node_id'] ?? null)
                ? $event['node_id'] : '';
            if ($nodeId === ''
                || isset($restEvents[$nodeId])) {
                throw new GhError(
                    'GitHub issue status history has an invalid or duplicate identity'
                );
            }
            $performed = is_array(
                $event['performed_via_github_app'] ?? null
            ) ? $event['performed_via_github_app'] : [];
            $performedId = $performed['id'] ?? null;
            $restEvents[$nodeId] = [
                'event' => $event['event'],
                'performed_app_id' =>
                    (is_int($performedId) || is_string($performedId))
                    && ctype_digit((string)$performedId)
                    ? (string)$performedId : '',
            ];
        }
        if (count($batch) < 100) break;
        if ($page === 100) {
            throw new GhError(
                'GitHub issue status-history pagination did not converge'
            );
        }
    }
    if (!$restEvents) return [];

    [$owner, $repo] = explode('/', $fullName, 2);
    $events = [];
    $seen = [];
    $cursor = null;
    for ($page = 1; $page <= 100; $page++) {
        $response = gh_request('POST', '/graphql', $token, [
            'query' => <<<'GRAPHQL'
query FriendlyMachinesIssueStatusTimeline(
  $owner: String!,
  $repo: String!,
  $number: Int!,
  $after: String
) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      timelineItems(
        first: 100,
        after: $after,
        itemTypes: [CLOSED_EVENT, REOPENED_EVENT]
      ) {
        nodes {
          __typename
          ... on ClosedEvent {
            id
            createdAt
            stateReason
            actor { login }
          }
          ... on ReopenedEvent {
            id
            createdAt
            stateReason
            actor { login }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
GRAPHQL,
            'variables' => [
                'owner' => $owner,
                'repo' => $repo,
                'number' => $number,
                'after' => $cursor,
            ],
        ]);
        $timeline = $response['data']['repository']['issue']['timelineItems']
            ?? null;
        if (!empty($response['errors']) || !is_array($timeline)
            || !array_is_list($timeline['nodes'] ?? null)
            || !is_array($timeline['pageInfo'] ?? null)) {
            throw new GhError(
                'GitHub did not return a complete issue status timeline'
            );
        }
        foreach ($timeline['nodes'] as $node) {
            $nodeId = is_array($node)
                && is_string($node['id'] ?? null) ? $node['id'] : '';
            $type = is_array($node) ? ($node['__typename'] ?? null) : null;
            $reason = is_array($node) ? ($node['stateReason'] ?? null) : null;
            if ($nodeId === '' || isset($seen[$nodeId])
                || !isset($restEvents[$nodeId])) {
                throw new GhError('GitHub returned a malformed issue state event');
            }
            if ($type === 'ReopenedEvent') {
                $kind = 1630;
            } elseif ($type === 'ClosedEvent' && $reason === 'COMPLETED') {
                $kind = 1631;
            } elseif ($type === 'ClosedEvent'
                && in_array($reason, ['NOT_PLANNED', 'DUPLICATE'], true)) {
                $kind = 1632;
            } else {
                throw new GhError(
                    'GitHub returned an unknown issue state reason'
                );
            }
            $restEvent = $restEvents[$nodeId];
            if (($restEvent['event'] === 'reopened') !== ($kind === 1630)) {
                throw new GhError(
                    'GitHub REST and GraphQL issue histories disagree'
                );
            }
            $seen[$nodeId] = true;
            $events[] = [
                'github_id' => $nodeId,
                'kind' => $kind,
                'actor' => is_array($node['actor'] ?? null)
                    && is_string($node['actor']['login'] ?? null)
                    ? $node['actor']['login'] : '',
                'source_created_at' => gh_issue_status_timestamp(
                    $node['createdAt'] ?? null
                ),
                'performed_by_bridge' => $bridgeAppId !== ''
                    && hash_equals(
                        $bridgeAppId,
                        $restEvent['performed_app_id']
                    ),
            ];
        }
        $hasNext = $timeline['pageInfo']['hasNextPage'] ?? null;
        $endCursor = $timeline['pageInfo']['endCursor'] ?? null;
        if (!is_bool($hasNext)
            || ($hasNext && (!is_string($endCursor) || $endCursor === ''))) {
            throw new GhError('GitHub issue status timeline has invalid paging');
        }
        if (!$hasNext) break;
        if ($page === 100) {
            throw new GhError(
                'GitHub issue status timeline pagination did not converge'
            );
        }
        $cursor = $endCursor;
    }
    if (count($seen) !== count($restEvents)) {
        throw new GhError(
            'GitHub issue status history changed during reconciliation'
        );
    }

    $result = [];
    $logicalCreatedAt = 0;
    foreach ($events as $event) {
        $logicalCreatedAt = max(
            $event['source_created_at'],
            $logicalCreatedAt + 1
        );
        $result[] = [
            'github_id' => $event['github_id'],
            'kind' => $event['kind'],
            'actor' => $event['actor'],
            'source_created_at' => $event['source_created_at'],
            'nostr_created_at' => $logicalCreatedAt,
            'performed_by_bridge' => $event['performed_by_bridge'],
        ];
    }
    return $result;
}
}

if (!function_exists('gh_tombstone_issue')) {
/** GitHub issues cannot be deleted; replace their visible fields and close. */
function gh_tombstone_issue(
    string $token, string $fullName, int $number, string $body
): array {
    return gh_request('PATCH', "/repos/$fullName/issues/$number", $token, [
        'title' => '[Deleted on Nostr]',
        'body' => $body,
        'state' => 'closed',
    ]);
}
}

if (!function_exists('gh_delete_issue_comment_by_node_id')) {
/**
 * Delete a mapped issue comment using its stable GraphQL node_id.
 *
 * REST deletion needs the numeric id, so resolve it through the issue's
 * paginated comments. Absence is success: it closes the crash window where
 * GitHub deleted the comment before SQLite recorded the deletion crossing.
 */
function gh_delete_issue_comment_by_node_id(
    string $token,
    string $fullName,
    int $number,
    string $nodeId
): void {
    if ($nodeId === '') {
        throw new InvalidArgumentException('missing GitHub comment node id');
    }
    for ($page = 1; $page <= 100; $page++) {
        $comments = gh_request(
            'GET',
            "/repos/$fullName/issues/$number/comments?per_page=100&page=$page",
            $token
        );
        foreach ($comments as $comment) {
            if (($comment['node_id'] ?? null) !== $nodeId) continue;
            $id = $comment['id'] ?? null;
            if ((!is_int($id) && !is_string($id))
                || !ctype_digit((string)$id)
                || (int)$id < 1) {
                throw new GhError(
                    'GitHub comment lookup returned no numeric id'
                );
            }
            gh_request(
                'DELETE',
                "/repos/$fullName/issues/comments/" . (int)$id,
                $token
            );
            return;
        }
        if (count($comments) < 100) return;
    }
    throw new GhError('GitHub comment lookup pagination did not converge');
}
}

function gh_bridge_marker(string $nostrId): string
{
    if (!is_hex64($nostrId)) throw new InvalidArgumentException('bad nostr id for GitHub marker');
    $mac = hash_hmac(
        'sha256',
        'github-origin-v1:' . strtolower($nostrId),
        fm_secret_db_crypt_key()
    );
    return "<!-- friendly-machines-bridge:v1:"
         . strtolower($nostrId) . ":$mac -->";
}

/** Return a bridge-authenticated origin id, never a user-forgeable comment. */
function gh_bridge_marker_id(string $body): ?string
{
    if (!preg_match(
        '/<!-- friendly-machines-bridge:v1:([0-9a-f]{64}):([0-9a-f]{64}) -->/',
        $body,
        $match
    )) {
        return null;
    }
    $expected = hash_hmac(
        'sha256',
        'github-origin-v1:' . $match[1],
        fm_secret_db_crypt_key()
    );
    return hash_equals($expected, $match[2]) ? $match[1] : null;
}

function gh_body_with_marker(string $body, string $nostrId): string
{
    $suffix = "\n\n" . gh_bridge_marker($nostrId);
    $maxBodyBytes = 65536 - strlen($suffix);
    $body = rtrim(gh_utf8_prefix($body, $maxBodyBytes));
    return $body . $suffix;
}

function gh_utf8_prefix(string $value, int $maxBytes): string
{
    if (strlen($value) <= $maxBytes) return $value;
    if (function_exists('mb_strcut')) return mb_strcut($value, 0, $maxBytes, 'UTF-8');
    $cut = substr($value, 0, $maxBytes);
    while ($cut !== '' && !preg_match('//u', $cut)) $cut = substr($cut, 0, -1);
    return $cut;
}

function gh_issue_title(string $title): string
{
    if (function_exists('mb_substr')) return mb_substr($title, 0, 256, 'UTF-8');
    return gh_utf8_prefix($title, 256);
}

/**
 * Select a unique causally possible GitHub object carrying an authenticated
 * marker. The object created by this job cannot predate the durable enqueue.
 * A marker can be copied after its first publication, however, and GitHub's
 * integer-second timestamps cannot prove which of two eligible objects first
 * contained it. Ambiguity must therefore retry for explicit resolution; it
 * must never choose an event-map identity by timestamp or numeric-ID order.
 */
function gh_unique_marker_match(
    array $objects,
    string $marker,
    int $queuedAt
): ?array
{
    if ($queuedAt < 1) {
        throw new InvalidArgumentException(
            'missing durable queue timestamp for marker reconciliation'
        );
    }
    $matches = [];
    foreach ($objects as $object) {
        if (!is_array($object)
            || empty($object['node_id'])
            || !str_contains((string)($object['body'] ?? ''), $marker)) {
            continue;
        }
        $createdAt = is_string($object['created_at'] ?? null)
            ? strtotime($object['created_at']) : false;
        if ($createdAt === false) continue;
        if ($createdAt < $queuedAt) continue;
        $matches[(string)$object['node_id']] = $object;
    }
    if (!$matches) return null;
    if (count($matches) !== 1) {
        throw new GhError(
            'ambiguous GitHub marker reconciliation; multiple eligible objects'
        );
    }
    return array_values($matches)[0];
}

if (!function_exists('gh_post_issue_comment_idempotent')) {
/**
 * Reconcile before POST using a hidden event-id marker. This closes the
 * otherwise unavoidable crash window between GitHub accepting a comment
 * and SQLite recording its node_id.
 */
function gh_post_issue_comment_idempotent(
    string $token, string $fullName, int $number, string $body,
    string $nostrId, int $queuedAt
): string {
    if ($queuedAt < 1) {
        throw new InvalidArgumentException(
            'missing durable queue timestamp for comment reconciliation'
        );
    }
    $marker = gh_bridge_marker($nostrId);
    $since = rawurlencode(
        gmdate('Y-m-d\TH:i:s\Z', max(0, $queuedAt - 300))
    );
    $candidates = [];
    for ($page = 1; $page <= 100; $page++) {
        $comments = gh_request(
            'GET',
            "/repos/$fullName/issues/$number/comments"
                . "?per_page=100&page=$page&since=$since",
            $token
        );
        foreach ($comments as $comment) {
            if (str_contains((string)($comment['body'] ?? ''), $marker)
                && !empty($comment['node_id'])) {
                $candidates[] = $comment;
            }
        }
        if (count($comments) < 100) break;
        if ($page === 100) {
            throw new GhError(
                'GitHub comment reconciliation pagination did not converge'
            );
        }
    }
    $existing = gh_unique_marker_match($candidates, $marker, $queuedAt);
    if ($existing !== null) return (string)$existing['node_id'];
    return gh_post_issue_comment($token, $fullName, $number,
                                 gh_body_with_marker($body, $nostrId));
}
}

if (!function_exists('gh_create_issue_idempotent')) {
function gh_create_issue_idempotent(
    string $token, string $fullName, string $title, string $body,
    string $nostrId, int $queuedAt
): array {
    if ($queuedAt < 1) {
        throw new InvalidArgumentException(
            'missing durable queue timestamp for issue reconciliation'
        );
    }
    $marker = gh_bridge_marker($nostrId);
    $since = rawurlencode(
        gmdate('Y-m-d\TH:i:s\Z', max(0, $queuedAt - 300))
    );
    $candidates = [];
    for ($page = 1; $page <= 100; $page++) {
        $issues = gh_request(
            'GET',
            "/repos/$fullName/issues"
                . "?state=all&sort=updated&direction=asc&per_page=100"
                . "&page=$page&since=$since",
            $token
        );
        foreach ($issues as $issue) {
            if (str_contains((string)($issue['body'] ?? ''), $marker)
                && !empty($issue['node_id'])
                && !isset($issue['pull_request'])) {
                $candidates[] = $issue;
            }
        }
        if (count($issues) < 100) break;
        if ($page === 100) {
            throw new GhError(
                'GitHub issue reconciliation pagination did not converge'
            );
        }
    }
    $existing = gh_unique_marker_match($candidates, $marker, $queuedAt);
    if ($existing !== null) return $existing;
    return gh_create_issue($token, $fullName, gh_issue_title($title),
                           gh_body_with_marker($body, $nostrId));
}
}

<?php
/**
 * bridge.php -- Dir A core: build nostr events from GitHub payloads,
 * sign (remote via NIP-46 / local via bridge key) and publish.
 * GitHub webhooks enqueue durable deliveries; cron executes all work here.
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/nip44.php';
require_once __DIR__ . '/ws.php';
require_once __DIR__ . '/nip46.php';
require_once __DIR__ . '/relay.php';
require_once __DIR__ . '/repository.php';
require_once __DIR__ . '/secrets.php';
require_once __DIR__ . '/github_app.php';
require_once __DIR__ . '/linking.php';
require_once __DIR__ . '/nip39.php';

class BridgeSkip extends RuntimeException {}    // permanent skip, no retry
class BridgeRemoteSignerUnavailable extends RuntimeException {}
const NIP46_LINK_RETRY_SECS = 5;
const NIP46_REPLACE_STATE_PREFIX = 'replace-signer:';
class BridgeDefer extends RuntimeException
{
    public function __construct(string $message, public int $delaySecs = 30)
    {
        parent::__construct($message);
    }
}

/** Decode the explicit signer-replacement intent stored on a waiting state. */
function bridge_nip46_replacement_pubkey(mixed $value): ?string
{
    if (!is_string($value)
        || !str_starts_with($value, NIP46_REPLACE_STATE_PREFIX)) {
        return null;
    }
    $pubkey = strtolower(substr($value, strlen(NIP46_REPLACE_STATE_PREFIX)));
    return is_hex64($pubkey) ? $pubkey : null;
}

if (!function_exists('bridge_nip46_get_public_key')) {
function bridge_nip46_get_public_key(
    string $clientPriv,
    string $clientPk,
    string $bunkerPk,
    string $relay,
    ?callable $onAuthUrl = null,
    ?callable $onSignerError = null
): ?string {
    try {
        $gpk = nip46_rpc($clientPriv, $clientPk, $bunkerPk, $relay,
                         'get_public_key', [], 8.0, $onAuthUrl);
    } catch (WsException $error) {
        return null;
    }
    if (is_array($gpk)
        && is_string($gpk['error'] ?? null)
        && $gpk['error'] !== ''
        && $onSignerError !== null) {
        // A signer error is untrusted protocol text. Keep it bounded and
        // single-line before it reaches the private queue ledger or browser.
        $signerError = preg_replace(
            '/[\x00-\x1f\x7f]+/',
            ' ',
            $gpk['error']
        );
        $signerError = substr(trim((string)$signerError), 0, 160);
        if ($signerError !== '') $onSignerError($signerError);
    }
    $pubkey = strtolower((string)($gpk['result'] ?? ''));
    return is_hex64($pubkey) ? $pubkey : null;
}
}

if (!function_exists('bridge_nip46_connection_relays')) {
/**
 * Ask the signer for its current relay set as NIP-46 requires immediately
 * after connect. The JSON array represents a set: duplicates and order carry
 * no meaning. ws_connect independently restricts server egress to public
 * addresses, so protocol-compliant relay replacement is not an SSRF grant.
 */
function bridge_nip46_connection_relays(
    string $clientPriv,
    string $clientPk,
    string $bunkerPk,
    array $connectedRelays,
    ?callable $onAuthUrl = null
): array {
    $connectedRelays = relay_url_set($connectedRelays, 4);
    if (!$connectedRelays) return [];

    $candidateSets = [];
    foreach ($connectedRelays as $connectedRelay) {
        try {
            $response = nip46_rpc(
                $clientPriv,
                $clientPk,
                $bunkerPk,
                $connectedRelay,
                'switch_relays',
                [],
                8.0,
                $onAuthUrl
            );
        } catch (WsException $error) {
            continue;
        }
        if (!is_array($response) || !array_key_exists('result', $response)) {
            continue;
        }
        if ($response['result'] === null || $response['result'] === 'null') {
            $relays = $connectedRelays;
        } elseif (is_string($response['result'])) {
            $decoded = json_decode($response['result'], true);
            $relays = is_array($decoded) && array_is_list($decoded)
                ? relay_url_set($decoded, 4) : [];
        } else {
            $relays = [];
        }
        if ($relays) $candidateSets[json_c($relays)] = $relays;
    }
    // Relay results are sets. Conflicting successful answers are not resolved
    // by arrival order or by choosing a preferred socket.
    return count($candidateSets) === 1
        ? array_values($candidateSets)[0]
        : [];
}
}

if (!function_exists('bridge_nip46_prove_user_key')) {
/** Prove get_public_key is not merely a remote signer's unauthenticated claim. */
function bridge_nip46_prove_user_key(
    string $clientPriv,
    string $clientPk,
    string $bunkerUri,
    string $userPk,
    string $stateId,
    int $createdAt,
    ?callable $onAuthUrl = null
): bool {
    $proof = [
        'pubkey' => $userPk,
        'kind' => 1111,
        'content' => 'Friendly Machines NIP-46 identity-link proof',
        'tags' => [['challenge', $stateId]],
        'created_at' => $createdAt,
    ];
    try {
        return nip46_sign_event(
            $clientPriv,
            $clientPk,
            $bunkerUri,
            $proof,
            8.0,
            $onAuthUrl
        ) !== null;
    } catch (WsException $error) {
        return false;
    }
}
}

/**
 * Atomically validate and bank one nostrconnect response. Both the cron relay
 * scanner and the live browser relay listener use this exact transition.
 */
function bridge_accept_nip46_connect(
    string $stateId,
    array $event,
    array $observedRelays
): bool
{
    require_once __DIR__ . '/jobs.php';
    if (!preg_match('/^[0-9a-f]{32}$/', $stateId)) return false;
    $observedRelays = relay_url_set($observedRelays, 4);
    $advertised = array_fill_keys(nip46_listen_relays(), true);
    if (!$observedRelays
        || array_filter(
            $observedRelays,
            fn(string $relay): bool => !isset($advertised[$relay])
        )) {
        return false;
    }

    $query = db()->prepare(
        "SELECT * FROM nip46_states
         WHERE state_id=? AND status='waiting' AND expires_at>=?"
    );
    $query->execute([$stateId, now()]);
    $state = $query->fetch();
    if (!$state) return false;
    $keyEnc = $state['client_key_enc'] ?? null;
    if (!is_string($keyEnc) || $keyEnc === '') {
        db()->prepare(
            "UPDATE nip46_states SET status='failed',error=?
             WHERE state_id=? AND status='waiting'"
        )->execute(['missing per-connection NIP-46 client key', $stateId]);
        return false;
    }
    try {
        $clientPriv = fm_decrypt_at_rest($keyEnc);
        $clientPk = fm_pubkey_hex($clientPriv);
    } catch (Throwable $error) {
        bridge_log('nip46', 'cannot load waiting client key', [
            'state' => $stateId,
            'error' => $error->getMessage(),
        ]);
        return false;
    }
    if (!hash_equals((string)$state['client_pk'], $clientPk)) {
        db()->prepare(
            "UPDATE nip46_states SET status='failed',error=?
             WHERE state_id=? AND status='waiting'"
        )->execute(['NIP-46 client key does not match pubkey', $stateId]);
        return false;
    }
    $decoded = nip46_decode_connect_event($event, $clientPriv, $clientPk);
    if ($decoded === null) return false;
    [$bunkerPk, $secret] = $decoded;
    if (!hash_equals((string)$state['secret'], $secret)) return false;
    $replacePubkey = bridge_nip46_replacement_pubkey(
        $state['error'] ?? null
    );

    db()->beginTransaction();
    try {
        $up = db()->prepare(
            "UPDATE nip46_states
             SET status='connected',bunker_pk=?,relays=?,pubkey=NULL,
                 error=NULL,expires_at=?
             WHERE state_id=? AND status='waiting'"
        );
        $up->execute([
            $bunkerPk,
            json_c($observedRelays),
            now() + FM_PARTIAL_LINK_SESSION_SECS,
            $stateId,
        ]);
        if ($up->rowCount() !== 1) {
            db()->rollBack();
            return false;
        }
        if (is_string($state['oauth_nonce'] ?? null)
            && $state['oauth_nonce'] !== '') {
            db()->prepare(
                "UPDATE oauth_states
                 SET expires_at=MAX(expires_at, ?) WHERE nonce=?"
            )->execute([
                now() + FM_PARTIAL_LINK_SESSION_SECS,
                $state['oauth_nonce'],
            ]);
        }
        jobs_enqueue(
            'nip46_finish',
            array_filter([
                'state_id' => $stateId,
                'phase' => 'checking_relays',
                'replace_pubkey' => $replacePubkey,
            ], static fn(mixed $value): bool => $value !== null),
            'nip46finish:' . $stateId
        );
        db()->commit();
        return true;
    } catch (Throwable $error) {
        if (db()->inTransaction()) db()->rollBack();
        throw $error;
    }
}

/**
 * Cron-side backstop for nostrconnect responses. Kind 24133 is ephemeral;
 * the browser keeps live subscriptions while the approval UI is open, while
 * this scan covers browsers whose response happens during a cron window.
 */
function bridge_collect_nip46_connects(): void
{
    $query = db()->prepare(
        "SELECT state_id,client_pk,created_at FROM nip46_states
         WHERE status='waiting' AND expires_at>=?"
    );
    $query->execute([now()]);
    $states = $query->fetchAll();
    if (!$states) return;
    $byClient = [];
    $oldest = now();
    foreach ($states as $state) {
        $byClient[$state['client_pk']] = $state['state_id'];
        $oldest = min($oldest, (int)$state['created_at']);
    }
    $responses = nip46_collect_connect_events(
        array_keys($byClient),
        nip46_listen_relays(),
        max(1, $oldest - 120),
        8.0
    );
    foreach ($responses as $response) {
        $relays = $response['relays'];
        $event = $response['event'];
        // p tags are a recipient set, not a preference list. Validation and
        // NIP-44 decryption select the one actual waiting connection.
        $recipientSet = [];
        foreach ($event['tags'] ?? [] as $tag) {
            if (is_array($tag) && ($tag[0] ?? '') === 'p'
                && is_string($tag[1] ?? null)
                && isset($byClient[$tag[1]])) {
                $recipientSet[$tag[1]] = true;
            }
        }
        $clientPks = array_keys($recipientSet);
        sort($clientPks, SORT_STRING);
        foreach ($clientPks as $clientPk) {
            if (bridge_accept_nip46_connect(
                $byClient[$clientPk],
                $event,
                $relays
            )) break;
        }
    }
}

// --------------------------------------------------------------------------
// repo acceptance + nostr mapping (DESIGN §2.3)
// --------------------------------------------------------------------------

/** @return array repos row or null when the exact repository is unmapped */
function bridge_repo_row(array $repository): ?array
{
    $owner = is_array($repository['owner'] ?? null)
        && is_string($repository['owner']['login'] ?? null)
        ? $repository['owner']['login'] : '';
    $full = is_string($repository['full_name'] ?? null)
        ? $repository['full_name'] : '';
    if ($owner === '' || $full === '') return null;

    $rep = db()->prepare('SELECT * FROM repos WHERE github_full_name = ?');
    $rep->execute([$full]);
    return $rep->fetch() ?: null;
}

/**
 * Return a pre-registered, publisher-verified repository mapping or null.
 *
 * bridge_authorized is deliberately NOT a crossing gate. It records whether
 * the bridge key is a repository maintainer and is relevant only when that
 * key wants to author a status for somebody else's root.
 */
function bridge_repo_ensure(array $repository): ?array
{
    $row = bridge_repo_row($repository);
    if ($row === null || (int)$row['verified'] !== 1) return null;

    $active = db()->prepare(
        "SELECT 1
         FROM github_installation_repositories gir
         JOIN github_installations gi
           ON gi.installation_id=gir.installation_id
         WHERE gir.github_full_name=?
           AND gir.status='active' AND gi.status='active'
           AND gi.token_enc IS NOT NULL"
    );
    $active->execute([$row['github_full_name']]);
    return $active->fetchColumn() ? $row : null;
}

/**
 * Reload the durable reduced repository authority.
 *
 * Queued payload snapshots are not authority, but neither is an empty relay
 * result. Registration and the relay reducer bank signed 30617 replacements
 * and kind-5 deletion cutoffs independently; jobs consume that retained
 * state without putting relay I/O on the crossing path.
 */
function bridge_require_current_repo_mapping(string $fullName): array
{
    $query = db()->prepare(
        'SELECT * FROM repos WHERE github_full_name=? AND verified=1'
    );
    $query->execute([$fullName]);
    $repoRow = $query->fetch();
    if (!$repoRow) {
        throw new BridgeDefer(
            "repository mapping for $fullName is not currently verified",
            300
        );
    }
    if (($GLOBALS['__fm_test_repo_verification'] ?? false) === true) {
        $testAnnouncement = $GLOBALS[
            '__fm_test_repo_announcement'
        ] ?? null;
        if (is_array($testAnnouncement)) {
            $repoRow['_announcement'] = $testAnnouncement;
        }
        return $repoRow;
    }

    $active = db()->prepare(
        "SELECT 1
         FROM github_installation_repositories gir
         JOIN github_installations gi
           ON gi.installation_id=gir.installation_id
         WHERE gir.github_full_name=?
           AND gir.status='active' AND gi.status='active'
           AND gi.token_enc IS NOT NULL"
    );
    $active->execute([$fullName]);
    if (!$active->fetchColumn()) {
        throw new BridgeDefer(
            "GitHub App is not currently installed for $fullName",
            300
        );
    }

    $relays = json_decode((string)($repoRow['relays'] ?? ''), true);
    if (!is_array($relays) || !relay_url_set($relays)) {
        throw new BridgeDefer(
            'repository mapping has no valid relay set',
            300
        );
    }
    $announcement = repo_banked_announcement($repoRow);
    if (is_array($announcement)) {
        $repoRow['_announcement'] = $announcement;
    }
    return $repoRow;
}

/** Persist a discovered discussion root before any dependent event is run. */
function bridge_register_nostr_root(array $event, array $repoRow): bool
{
    $id = strtolower((string)($event['id'] ?? ''));
    $pk = strtolower((string)($event['pubkey'] ?? ''));
    $kind = (int)($event['kind'] ?? 0);
    $full = (string)($repoRow['github_full_name'] ?? '');
    $createdAt = (int)($event['created_at'] ?? 0);
    if (!is_hex64($id) || !is_hex64($pk) || $kind !== 1621
        || $full === '' || $createdAt < 1) {
        return false;
    }

    $st = db()->prepare("INSERT OR IGNORE INTO nostr_roots
                         (nostr_id,kind,pubkey,github_full_name,event_created_at,discovered_at)
                         VALUES (?,?,?,?,?,?)");
    $st->execute([$id, $kind, $pk, $full, $createdAt, now()]);
    return $st->rowCount() === 1;
}

/** Schedule bounded historical scans so replies may precede root discovery. */
function bridge_enqueue_nostr_root_backfills(array $event, array $repoRow): void
{
    require_once __DIR__ . '/jobs.php';
    $rootId = strtolower((string)($event['id'] ?? ''));
    $createdAt = (int)($event['created_at'] ?? 0);
    if (!is_hex64($rootId) || $createdAt < 1) return;

    $relays = json_decode((string)($repoRow['relays'] ?? ''), true);
    if (!is_array($relays) || !$relays) $relays = relay_defaults();
    foreach (relay_url_set($relays) as $relay) {
        foreach ([
            ['name' => 'comments', 'tag' => 'E', 'kinds' => [1111]],
            [
                'name' => 'statuses',
                'tag' => 'e',
                'kinds' => [1630, 1631, 1632, 1633],
            ],
            ['name' => 'deletions', 'tag' => 'e', 'kinds' => [5]],
        ] as $scan) {
            $until = now();
            jobs_enqueue('nostr_backfill', [
                'root_id' => $rootId,
                'relay' => $relay,
                'tag' => $scan['tag'],
                'scan_name' => $scan['name'],
                'kinds' => $scan['kinds'],
                // A reply necessarily knows the root id, but its author clock
                // is not authoritative. Scan the full root scope rather than
                // assuming reply.created_at >= root.created_at.
                'since' => 1,
                'until' => $until,
            ], "nostrbackfill:$relay:$rootId:{$scan['name']}:$until");
        }
    }
}

/** Backfill deletion requests for a newly discovered dependent event id. */
function bridge_enqueue_nostr_deletion_backfill(
    string $targetId, array $repoRow
): void {
    require_once __DIR__ . '/jobs.php';
    if (!is_hex64($targetId)) return;
    $relays = json_decode((string)($repoRow['relays'] ?? ''), true);
    if (!is_array($relays) || !$relays) $relays = relay_defaults();
    foreach (relay_url_set($relays) as $relay) {
        $until = now();
        jobs_enqueue('nostr_backfill', [
            'root_id' => strtolower($targetId),
            'relay' => $relay,
            'tag' => 'e',
            'scan_name' => 'deletions',
            'kinds' => [5],
            'since' => 1,
            'until' => $until,
        ], "nostrbackfill:$relay:$targetId:deletions:$until");
    }
}

// --------------------------------------------------------------------------
// event builders (NIP-34 / NIP-22 per DESIGN §3.1-3.3)
// --------------------------------------------------------------------------

function gh_node_id(array $object): string
{
    $nodeId = $object['node_id'] ?? null;
    if (!is_string($nodeId) || $nodeId === '' || strlen($nodeId) > 256) {
        throw new BridgeSkip('GitHub object has no stable node_id');
    }
    return $nodeId;
}

function gh_event_timestamp(mixed $value): int
{
    if (!is_string($value) || $value === '') {
        throw new BridgeSkip('GitHub object has no source timestamp');
    }
    $timestamp = strtotime($value);
    if ($timestamp === false || $timestamp < 1) {
        throw new BridgeSkip('GitHub object has an invalid source timestamp');
    }
    return $timestamp;
}

function bridge_tags_base(array $repoRow, string $full, int $number): array
{
    $a = '30617:' . $repoRow['owner_pubkey'] . ':' . $repoRow['repo_id'];
    return [
        ['a', $a],
        ['p', $repoRow['owner_pubkey']],
        ['gh', "$full#$number"],
    ];
}

/** kind 1621 issue */
function bridge_build_issue(array $repoRow, array $issue): array
{
    $full = $issue['full_name'] ?? '';
    $tags = bridge_tags_base($repoRow, $full, (int)$issue['number']);
    $tags[] = ['subject', $issue['title'] ?? ''];
    $tags[] = ['t', 'gh-' . $issue['number']];
    return [
        'kind'       => 1621,
        'content'    => (string)($issue['body'] ?? ''),
        'tags'       => $tags,
        'created_at' => gh_event_timestamp($issue['created_at'] ?? null),
    ];
}

/** kind 1630 Open / 1631 Resolved / 1632 Closed */
function bridge_build_status(array $repoRow, string $full, int $number,
                             int $statusKind, string $rootNostrId,
                             string $rootAuthorPk,
                             string|int|null $githubTimestamp = null): array
{
    $content = match ($statusKind) {
        1630 => 'Issue reopened on GitHub.',
        1631 => 'Issue resolved on GitHub.',
        1632 => 'Issue closed on GitHub.',
        default => throw new InvalidArgumentException(
            'unsupported GitHub issue status kind'
        ),
    };
    $mentioned = [$repoRow['owner_pubkey'] => true, $rootAuthorPk => true];
    $mentioned = array_keys($mentioned);
    sort($mentioned, SORT_STRING);
    $tags = [['e', $rootNostrId, '', 'root']];
    foreach ($mentioned as $pubkey) $tags[] = ['p', $pubkey];
    $tags[] = ['a', '30617:' . $repoRow['owner_pubkey'] . ':' . $repoRow['repo_id']];
    $tags[] = ['gh', "$full#$number"];
    return [
        'kind'       => $statusKind,
        'content'    => $content,
        'tags'       => $tags,
        'created_at' => is_int($githubTimestamp)
            ? $githubTimestamp
            : gh_event_timestamp($githubTimestamp),
    ];
}

/** kind 1111 comment (NIP-22 uppercase-root/lowercase-parent) */
function bridge_build_comment(array $repoRow, string $full, int $number,
                              array $comment, string $rootId, string $rootAuthorPk,
                              ?array $parent1111 = null): array
{
    $relayHint = '';
    if ($parent1111 !== null) {
        [$parent, $pk, $kind] = [$parent1111['nostr_id'], $parent1111['author_pk'], 1111];
    } else {
        [$parent, $pk, $kind] = [$rootId, $rootAuthorPk, 1621];
    }
    $tags = [
        ['E', $rootId, $relayHint, $rootAuthorPk],   // UPPERCASE root
        ['K', '1621'],
        ['P', $rootAuthorPk],
        ['e', $parent, $relayHint, $pk],             // lowercase parent
        ['k', (string)$kind],
        ['p', $pk],
        ['gh', "$full#$number (comment {$comment['id']})"],
    ];
    return [
        'kind'       => 1111,
        'content'    => (string)($comment['body'] ?? ''),
        'tags'       => $tags,
        'created_at' => gh_event_timestamp(
            $comment['created_at'] ?? null
        ),
    ];
}

/** NIP-09 deletion request for a GitHub-origin Nostr comment mirror. */
function bridge_build_deletion(
    array $repoRow,
    string $full,
    int $number,
    string $targetNostrId,
    int $targetKind,
    string $reason,
    ?string $githubTimestamp = null
): array {
    return [
        'kind' => 5,
        'content' => $reason,
        'tags' => [
            ['e', $targetNostrId],
            ['k', (string)$targetKind],
            ['p', $repoRow['owner_pubkey']],
            ['gh', "$full#$number"],
        ],
        'created_at' => gh_event_timestamp($githubTimestamp),
    ];
}

/** NIP-25 kind-7 repository star reaction. */
function bridge_build_repository_star(
    array $repoRow,
    string $full,
    array $announcement,
    int $createdAt
): array {
    $announcementId = strtolower(
        (string)($announcement['id'] ?? '')
    );
    $announcementPk = strtolower(
        (string)($announcement['pubkey'] ?? '')
    );
    $address = '30617:' . $repoRow['owner_pubkey']
        . ':' . $repoRow['repo_id'];
    if (!is_hex64($announcementId)
        || !is_hex64($announcementPk)
        || $announcementPk !== strtolower((string)$repoRow['owner_pubkey'])
        || $createdAt < 1) {
        throw new BridgeSkip(
            'current repository announcement cannot be starred'
        );
    }
    return [
        'kind' => 7,
        'content' => '⭐',
        'tags' => [
            ['e', $announcementId, '', $announcementPk],
            ['a', $address, '', $announcementPk],
            ['p', $announcementPk],
            ['k', '30617'],
            ['gh', "$full (star)"],
        ],
        'created_at' => $createdAt,
    ];
}

/** NIP-09 unstar of one concrete kind-7 reaction. */
function bridge_build_repository_unstar(
    array $repoRow,
    string $full,
    string $targetNostrId,
    int $createdAt
): array {
    if (!is_hex64(strtolower($targetNostrId)) || $createdAt < 1) {
        throw new BridgeSkip('invalid repository-star deletion target');
    }
    return [
        'kind' => 5,
        'content' => 'Repository unstarred on GitHub.',
        'tags' => [
            ['e', strtolower($targetNostrId)],
            ['k', '7'],
            ['p', $repoRow['owner_pubkey']],
            ['gh', "$full (unstar)"],
        ],
        'created_at' => $createdAt,
    ];
}

// --------------------------------------------------------------------------
// author resolution + signing + publish (DESIGN §3 job execution)
// --------------------------------------------------------------------------

/** @return array{path:'remote'|'bridge', pubkey, bunker?, client_priv?, login} */
function bridge_resolve_author(string $githubLogin): array
{
    $st = db()->prepare("
        SELECT na.pubkey, na.bunker_enc, na.client_key_enc, na.status
        FROM nostr_accounts na
        JOIN links l ON l.pubkey = na.pubkey
        WHERE l.login = ? AND na.status = 'linked'");
    $st->execute([$githubLogin]);
    $row = $st->fetch();
    if ($row) {
        if (!is_string($row['client_key_enc']) || $row['client_key_enc'] === '') {
            bridge_log('bridge', 'linked signer credentials are incomplete', [
                'login' => $githubLogin,
                'reason' => 'missing NIP-46 client key',
            ]);
            throw new BridgeDefer(
                'waiting for complete linked Nostr signer credentials',
                300
            );
        } else {
            try {
                return [
                    'path'   => 'remote',
                    'pubkey' => $row['pubkey'],
                    'bunker' => fm_decrypt_at_rest($row['bunker_enc']),
                    'client_priv' => fm_decrypt_at_rest($row['client_key_enc']),
                    'login'  => $githubLogin,
                ];
            } catch (Throwable $error) {
                bridge_log(
                    'bridge',
                    'linked signer credentials cannot be loaded',
                    ['login' => $githubLogin, 'reason' => $error->getMessage()]
                );
                throw new BridgeDefer(
                    'waiting for usable linked Nostr signer credentials',
                    300
                );
            }
        }
    }
    return ['path' => 'bridge', 'pubkey' => null, 'bunker' => null, 'login' => $githubLogin];
}

/** Resolve a GitHub actor by immutable numeric ID, surviving login renames. */
function bridge_resolve_github_user_author(
    string $githubUserId,
    string $githubLogin
): array {
    if (!ctype_digit($githubUserId) || $githubUserId === '0') {
        return [
            'path' => 'bridge',
            'pubkey' => null,
            'bunker' => null,
            'login' => $githubLogin,
        ];
    }
    $st = db()->prepare(
        "SELECT na.pubkey,na.bunker_enc,na.client_key_enc
         FROM github_accounts ga
         JOIN links l ON l.login=ga.login
         JOIN nostr_accounts na ON na.pubkey=l.pubkey
         WHERE ga.github_user_id=? AND ga.provider='github_app'
           AND ga.auth_status='active' AND na.status='linked'"
    );
    $st->execute([$githubUserId]);
    $row = $st->fetch();
    if ($row) {
        if (!is_string($row['client_key_enc'] ?? null)
            || $row['client_key_enc'] === '') {
            throw new BridgeDefer(
                'waiting for complete linked Nostr signer credentials',
                300
            );
        }
        try {
            return [
                'path' => 'remote',
                'pubkey' => $row['pubkey'],
                'bunker' => fm_decrypt_at_rest($row['bunker_enc']),
                'client_priv' => fm_decrypt_at_rest(
                    $row['client_key_enc']
                ),
                'login' => $githubLogin,
            ];
        } catch (Throwable $error) {
            bridge_log('bridge', 'linked star signer credentials cannot be loaded', [
                'github_user_id' => $githubUserId,
                'reason' => $error->getMessage(),
            ]);
            throw new BridgeDefer(
                'waiting for usable linked Nostr signer credentials',
                300
            );
        }
    }
    return [
        'path' => 'bridge',
        'pubkey' => null,
        'bunker' => null,
        'login' => $githubLogin,
    ];
}

/** Resolve a known Nostr pubkey to its durable remote signer, if available. */
function bridge_resolve_nostr_author(string $pubkey): ?array
{
    $st = db()->prepare("SELECT pubkey,bunker_enc,client_key_enc
                         FROM nostr_accounts
                         WHERE pubkey=? AND status='linked'");
    $st->execute([strtolower($pubkey)]);
    $row = $st->fetch();
    if (!$row || !is_string($row['client_key_enc'])
        || $row['client_key_enc'] === '') {
        return null;
    }
    return [
        'path' => 'remote',
        'pubkey' => $row['pubkey'],
        'bunker' => fm_decrypt_at_rest($row['bunker_enc']),
        'client_priv' => fm_decrypt_at_rest($row['client_key_enc']),
        'login' => '',
    ];
}

/** Build the exact event fields whose hash/signature are author-dependent. */
function bridge_unsigned_for_author(array $ev, array $author): array
{
    $wire = nip46_unsigned_event($ev);
    // Record where the content first appeared. This signed origin marker
    // closes the crash window in which relay publish succeeds before the
    // local event_map row is committed.
    if (!empty($ev['proxy_url'])) {
        $wire['tags'][] = ['proxy', (string)$ev['proxy_url'], 'github'];
    }

    if ($author['path'] === 'remote') {
        $wire['pubkey'] = strtolower((string)$author['pubkey']);
        return $wire;
    }
    $clientPriv = fm_secret_bridge_key();
    $wire['pubkey'] = fm_pubkey_hex($clientPriv);
    if (!empty($author['login'])) $wire['tags'][] = ['gh_user', $author['login']];
    return $wire;
}

function bridge_publish_unsigned(array $ev, array $author): array
{
    $wire = bridge_unsigned_for_author($ev, $author);
    if ($author['path'] === 'remote') {
        $clientPriv = $author['client_priv'];
        $clientPk = fm_pubkey_hex($clientPriv);
        try {
            $signed = nip46_sign_event(
                $clientPriv,
                $clientPk,
                $author['bunker'],
                $wire,
                8.0
            );
        } catch (WsException $error) {
            throw new BridgeRemoteSignerUnavailable(
                'bunker sign_event connection failed',
                0,
                $error
            );
        }
        if ($signed === null) {
            throw new BridgeRemoteSignerUnavailable(
                'bunker sign_event failed/timeout'
            );
        }
        return $signed;
    }
    $clientPriv = fm_secret_bridge_key();
    return fm_event_sign($wire, $clientPriv);
}

/**
 * A durable active link fixes signer identity. Temporary NIP-46 failure is a
 * dependency delay, never authority to publish an immutable bridge-signed
 * substitute that cannot later be upgraded without changing its event ID.
 */
function bridge_linked_signer_defer(
    array $author,
    string $githubId,
    BridgeRemoteSignerUnavailable $error
): BridgeDefer {
    bridge_log('bridge', 'linked signer unavailable; retaining user-signed crossing', [
        'login' => $author['login'] ?? '',
        'github_id' => $githubId,
        'reason' => $error->getMessage(),
    ]);
    return new BridgeDefer('waiting for linked Nostr signer', 60);
}

/** Full Dir A publish for one unit; returns nostr event id. */
function bridge_gh2nostr(
    array $repoRow,
    array $ev,
    array $author,
    string $githubId
): string
{
    $relays = json_decode($repoRow['relays'] ?? 'null', true) ?: relay_defaults();
    $actualAuthor = $author;
    $wire = bridge_unsigned_for_author($ev, $actualAuthor);
    $expectedId = fm_event_id($wire);
    $signed = relay_find_event($expectedId, $relays);
    if ($signed !== null
        && (strtolower((string)$signed['pubkey']) !== $wire['pubkey']
            || nip46_unsigned_event($signed) !== nip46_unsigned_event($wire))) {
        $signed = null;
    }
    if ($signed === null) {
        try {
            $signed = bridge_publish_unsigned($ev, $actualAuthor);
        } catch (BridgeRemoteSignerUnavailable $error) {
            throw bridge_linked_signer_defer(
                $actualAuthor,
                $githubId,
                $error
            );
        }
    }
    if (!fm_event_verify($signed)) {
        throw new RuntimeException('signer returned an invalid event');
    }
    $results = [];
    if ($signed['id'] !== $expectedId
        || strtolower((string)$signed['pubkey']) !== $wire['pubkey']
        || nip46_unsigned_event($signed) !== nip46_unsigned_event($wire)) {
        throw new RuntimeException('recovered signer event does not match request');
    }
    if (relay_find_event($signed['id'], $relays) === null) {
        $results = relay_publish($signed, $relays);
        if (!relay_publish_ok($results)) {
            throw new BridgeDefer(
                'all relays failed: ' . json_c($results),
                300
            );
        }
    }
    db()->prepare("INSERT INTO event_map
                   (github_id, nostr_id, direction, kind, author_pk, signed_by, parent_github_id, meta, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)")
       ->execute([$githubId, $signed['id'], 'gh2nostr', (int)$signed['kind'],
                  $signed['pubkey'],
                  $signed['pubkey'],
                  $ev['parent_github_id'] ?? null,
                  $ev['meta'] ?? null, now()]);
    if ((int)$signed['kind'] === 1621
        && bridge_register_nostr_root($signed, $repoRow)) {
        bridge_enqueue_nostr_root_backfills($signed, $repoRow);
    } elseif (!in_array((int)$signed['kind'], [1621, 5], true)) {
        bridge_enqueue_nostr_deletion_backfill($signed['id'], $repoRow);
    }
    // SUCCESS LOG (one line per crossing; failures log separately)
    bridge_log('bridge', 'mirrored gh->nostr', [
        'gh'      => $githubId,
        'nostr'   => $signed['id'],
        'kind'    => (int)$signed['kind'],
        'author'  => $actualAuthor['path'] === 'remote'
            ? $actualAuthor['pubkey'] : 'bridge(proxy)',
        'relays'  => $results
            ? array_keys(array_filter($results, fn($r) => $r === 'ok'))
            : ['reconciled-existing'],
    ]);
    return $signed['id'];
}

// --------------------------------------------------------------------------
// ledger helpers (shared by webhook + cron)
// --------------------------------------------------------------------------

function bridge_already_mapped(string $githubId): bool
{
    $st = db()->prepare('SELECT 1 FROM event_map WHERE github_id = ?');
    $st->execute([$githubId]);
    return (bool)$st->fetchColumn();
}

function bridge_nostr_already_mapped(string $nostrId): bool
{
    $st = db()->prepare('SELECT 1 FROM event_map WHERE nostr_id = ?');
    $st->execute([$nostrId]);
    return (bool)$st->fetchColumn();
}

/** Stable logical identity of one GitHub user's star on one repository. */
function bridge_github_star_pair(
    string $repositoryId,
    string $githubUserId
): string {
    if (!ctype_digit($repositoryId) || $repositoryId === '0'
        || !ctype_digit($githubUserId) || $githubUserId === '0') {
        throw new BridgeSkip('invalid GitHub repository-star identity');
    }
    return "star:$repositoryId:$githubUserId";
}

/**
 * Retain membership in the observed GitHub repository/user-pair set.
 *
 * schema_meta already holds operational key/value state as well as the two
 * schema markers. A primary-keyed empty value is deliberate set storage:
 * webhook duplicates and arrival order cannot change membership, and adding
 * a member changes no database shape or schema contract.
 */
function bridge_bank_github_star_pair(
    string $repositoryId,
    string $githubUserId
): void {
    bridge_github_star_pair($repositoryId, $githubUserId);
    db()->prepare(
        'INSERT OR IGNORE INTO schema_meta(k,v) VALUES (?,?)'
    )->execute([
        "github_star_pair|$repositoryId|$githubUserId",
        '',
    ]);
}

/** @return list<array> active mapped Nostr star reactions for one pair */
function bridge_active_repository_stars(string $pair): array
{
    $query = db()->prepare(
        "SELECT em.*
         FROM event_map em
         LEFT JOIN deletion_map dm ON dm.target_nostr_id=em.nostr_id
         WHERE em.parent_github_id=? AND em.kind=7
           AND dm.target_nostr_id IS NULL
         ORDER BY em.created_at,em.nostr_id"
    );
    $query->execute([$pair]);
    return $query->fetchAll();
}

/** Preserve causal star generations when GitHub timestamps share a second. */
function bridge_repository_star_created_at(
    string $pair,
    int $sourceCreatedAt
): int {
    if ($sourceCreatedAt < 1) {
        throw new BridgeSkip('GitHub star has an invalid timestamp');
    }
    $maximum = 0;
    $query = db()->prepare(
        'SELECT meta FROM event_map
         WHERE parent_github_id=? AND kind=7'
    );
    $query->execute([$pair]);
    foreach ($query->fetchAll(PDO::FETCH_COLUMN) as $json) {
        $meta = json_decode((string)$json, true);
        if (is_array($meta)) {
            $maximum = max(
                $maximum,
                (int)($meta['event_created_at'] ?? 0)
            );
        }
    }
    return max($sourceCreatedAt, $maximum + 1);
}

/**
 * Select the GitHub App user authorization corresponding to a Nostr author.
 * Installations are not GitHub users and cannot star repositories, so there
 * is deliberately no App-token fallback for this operation.
 *
 * @return array{token:string,login:string,github_user_id:string}
 */
function bridge_github_user_for_nostr_star(string $pubkey): array
{
    $query = db()->prepare(
        "SELECT ga.login,ga.github_user_id
         FROM github_accounts ga
         JOIN links l ON l.login=ga.login
         WHERE l.pubkey=? AND ga.provider='github_app'
           AND ga.auth_status='active'"
    );
    $query->execute([strtolower($pubkey)]);
    $row = $query->fetch();
    $githubUserId = is_array($row)
        ? (string)($row['github_user_id'] ?? '') : '';
    $login = is_array($row) ? (string)($row['login'] ?? '') : '';
    if ($login === '' || !ctype_digit($githubUserId)
        || $githubUserId === '0') {
        throw new BridgeDefer(
            'waiting for this Nostr author to link a GitHub user',
            3600
        );
    }
    try {
        $token = gh_app_user_token($login);
    } catch (GhUserAuthorizationUnavailable $error) {
        throw new BridgeDefer(
            'waiting for GitHub user reauthorization',
            3600
        );
    }
    return [
        'token' => $token,
        'login' => $login,
        'github_user_id' => $githubUserId,
    ];
}

function bridge_github_app_token_for_repo(string $fullName): string
{
    try {
        return gh_app_token_for_repo($fullName);
    } catch (GhInstallationUnavailable $error) {
        throw new BridgeDefer($error->getMessage(), 300);
    }
}

/**
 * Choose the GitHub identity for a Nostr-origin crossing. A valid linked
 * GitHub-App user token upgrades attribution. Otherwise the App installation
 * token guarantees the crossing under the bridge bot identity.
 *
 * @return array{token:string,path:'user'|'app',login:?string}
 */
function bridge_github_author_for_nostr(string $pubkey, string $fullName): array
{
    $pubkey = strtolower($pubkey);
    if (!is_hex64($pubkey)) throw new InvalidArgumentException('invalid nostr author');

    $st = db()->prepare("
        SELECT ga.login
        FROM github_accounts ga
        JOIN links l ON l.login=ga.login
        WHERE l.pubkey=? AND ga.provider='github_app'
          AND ga.auth_status='active'");
    $st->execute([$pubkey]);
    $row = $st->fetch();
    if ($row) {
        try {
            return [
                'token' => gh_app_user_token((string)$row['login']),
                'path' => 'user',
                'login' => $row['login'],
            ];
        } catch (Throwable $error) {
            // User authorization is only an attribution upgrade. Revocation,
            // refresh transport failure, or a damaged optional credential
            // must not gate the installed App's repository crossing.
            bridge_log('github-app', 'user authorization unavailable', [
                'login' => $row['login'],
                'reason' => $error->getMessage(),
            ]);
        }
    }
    return [
        'token' => bridge_github_app_token_for_repo($fullName),
        'path' => 'app',
        'login' => null,
    ];
}

/**
 * Prefer linked-user attribution, but authorization must never become a
 * crossing gate. A definitive user-token access failure retries the same
 * idempotent operation through the repository installation.
 *
 * @return array{result:mixed,author:array}
 */
function bridge_github_execute_for_nostr(
    string $pubkey,
    string $fullName,
    callable $operation
): array {
    $author = bridge_github_author_for_nostr($pubkey, $fullName);
    try {
        return ['result' => $operation($author), 'author' => $author];
    } catch (GhError $error) {
        if ($author['path'] !== 'user'
            || !in_array($error->getCode(), [401, 403, 404], true)) {
            throw $error;
        }
        if ($error->getCode() === 401 && is_string($author['login'])) {
            gh_app_require_user_reauthorization($author['login']);
        }
        bridge_log('github-app', 'user write fell back to installation', [
            'login' => $author['login'],
            'repo' => $fullName,
            'status' => $error->getCode(),
        ]);
        $fallback = [
            'token' => bridge_github_app_token_for_repo($fullName),
            'path' => 'app',
            'login' => null,
        ];
        return ['result' => $operation($fallback), 'author' => $fallback];
    }
}

/** Visible attribution for a Nostr author proxied through the GitHub bridge. */
function bridge_nostr_github_proxy_body(
    string $body, string $pubkey, string $nostrId
): string {
    $npub = fm_npub_encode($pubkey);
    return "_Mirrored from Nostr event `$nostrId` by `$npub` using the "
         . "Friendly Machines Nostr Bridge GitHub App._\n\n" . $body;
}

/** NIP-34 status authority: root author or any declared maintainer. */
function bridge_nostr_status_authorized(
    string $statusAuthor, string $rootAuthor, array $repoRow
): ?bool {
    if ($statusAuthor === $rootAuthor) {
        return true;
    }
    $announcement = is_array($repoRow['_announcement'] ?? null)
        ? $repoRow['_announcement']
        : repo_banked_announcement($repoRow);
    if (is_array($announcement)) {
        return repo_announcement_authorizes(
            $announcement,
            $statusAuthor
        );
    }
    if (($GLOBALS['__fm_test_repo_verification'] ?? false) !== true) {
        return null;
    }
    $relays = json_decode((string)($repoRow['relays'] ?? ''), true);
    if (!is_array($relays) || !$relays) return false;
    return relay_verify_repo_owner(
        (string)$repoRow['repo_id'],
        (string)$repoRow['owner_pubkey'],
        $relays,
        $statusAuthor,
        $relays);
}

/**
 * Latest valid Nostr status already reduced for this root.
 *
 * NIP-34 orders status by created_at. Equal timestamps use the same
 * deterministic lowest-id tie break as the client and NIP-01 replacement
 * reducers, so arrival order cannot affect GitHub state.
 *
 * @return array{nostr_id:string,kind:int,event_created_at:int}|null
 */
function bridge_latest_nostr_status(
    string $rootGithubId,
    ?string $excludeNostrId = null
): ?array
{
    $query = db()->prepare(
        "SELECT em.nostr_id,em.kind,em.meta
         FROM event_map em
         WHERE em.kind IN (1630,1631,1632,1633)
           AND em.parent_github_id=?
           AND em.nostr_id<>?
           AND NOT EXISTS (
             SELECT 1 FROM deletion_map dm
             WHERE dm.target_nostr_id=em.nostr_id
           )"
    );
    $query->execute([$rootGithubId, $excludeNostrId ?? '']);
    $latest = null;
    foreach ($query as $row) {
        $meta = json_decode((string)($row['meta'] ?? ''), true);
        $createdAt = is_array($meta)
            ? (int)($meta['event_created_at'] ?? 0) : 0;
        if ($createdAt < 1 || !is_hex64((string)$row['nostr_id'])) continue;
        if ($latest === null
            || $createdAt > $latest['event_created_at']
            || ($createdAt === $latest['event_created_at']
                && strcmp($row['nostr_id'], $latest['nostr_id']) < 0)) {
            $latest = [
                'nostr_id' => $row['nostr_id'],
                'kind' => (int)$row['kind'],
                'event_created_at' => $createdAt,
            ];
        }
    }
    return $latest;
}

function bridge_record_nostr_status(
    array $payload,
    array $rootRow,
    string $full,
    int $number,
    string $state,
    string $githubIdentity,
    bool $applied
): void {
    $nostrId = strtolower((string)$payload['nostr_id']);
    $crossingId = 'status:' . $rootRow['github_id'] . ':' . $nostrId;
    db()->prepare(
        "INSERT INTO event_map
         (github_id,nostr_id,direction,kind,author_pk,signed_by,
          parent_github_id,meta,created_at)
         VALUES (?,?,?,?,?,?,?,?,?)"
    )->execute([
        $crossingId,
        $nostrId,
        'nostr2gh',
        (int)$payload['kind'],
        $payload['pubkey'],
        $payload['pubkey'],
        $rootRow['github_id'],
        json_c([
            'full' => $full,
            'number' => $number,
            'state' => $state,
            'github_identity' => $githubIdentity,
            'event_created_at' => (int)$payload['created_at'],
            'applied_to_github' => $applied,
        ]),
        now(),
    ]);
}

/** @return [nostrId, authorPk] | null */
function bridge_root_id(string $issueGithubId): ?array
{
    $st = db()->prepare("SELECT nostr_id, author_pk FROM event_map WHERE github_id = ? AND kind = 1621");
    $st->execute([$issueGithubId]);
    $r = $st->fetch();
    return $r ? [$r['nostr_id'], $r['author_pk']] : null;
}

/**
 * Publish one human GitHub status transition from reconciled issue history.
 *
 * @param array{0:string,1:string} $root [Nostr root id, root author]
 * @param array{
 *   github_id:string,kind:int,actor:string,source_created_at:int,
 *   nostr_created_at:int,performed_by_bridge:bool
 * } $transition
 */
function bridge_cross_github_status(
    array $repoRow,
    string $full,
    int $number,
    string $issueGithubId,
    array $root,
    array $transition
): void {
    $githubEventId = (string)($transition['github_id'] ?? '');
    $statusKind = (int)($transition['kind'] ?? 0);
    $createdAt = (int)($transition['nostr_created_at'] ?? 0);
    if ($githubEventId === ''
        || !in_array($statusKind, [1630, 1631, 1632], true)
        || $createdAt < 1) {
        throw new BridgeSkip('invalid reconciled GitHub status event');
    }
    if (bridge_already_mapped($githubEventId)) return;

    $ev = bridge_build_status(
        $repoRow,
        $full,
        $number,
        $statusKind,
        $root[0],
        $root[1],
        $createdAt
    );
    $ev['proxy_url'] = "https://github.com/$full/issues/$number";
    $ev['parent_github_id'] = $issueGithubId;
    $ev['meta'] = json_c([
        'full' => $full,
        'number' => $number,
        'state' => match ($statusKind) {
            1630 => 'open',
            1631 => 'resolved',
            1632 => 'closed',
        },
        'event_created_at' => $createdAt,
        'github_source_created_at' =>
            (int)($transition['source_created_at'] ?? 0),
        'source' => 'github-issue-event-history',
    ]);
    $githubActor = is_string($transition['actor'] ?? null)
        ? $transition['actor'] : '';

    // NIP-34 accepts status from the root author or a maintainer. The bridge
    // key may sign only when it has that authority; otherwise the linked root
    // author must sign and no bridge-key fallback is legal.
    $bridgePk = fm_pubkey_hex(fm_secret_bridge_key());
    $bridgeAuthorized = $root[1] === $bridgePk;
    if (!$bridgeAuthorized) {
        $announcement = is_array($repoRow['_announcement'] ?? null)
            ? $repoRow['_announcement']
            : repo_banked_announcement($repoRow);
        if (is_array($announcement)) {
            $bridgeAuthorized = repo_announcement_authorizes(
                $announcement,
                $bridgePk
            );
        } elseif (($GLOBALS['__fm_test_repo_verification'] ?? false)
                  === true) {
            $bridgeAuthorized =
                (int)$repoRow['bridge_authorized'] === 1;
        } else {
            throw new BridgeDefer(
                'waiting for banked bridge maintainer authorization',
                300
            );
        }
    }
    if ($bridgeAuthorized) {
        $author = [
            'path' => 'bridge',
            'pubkey' => null,
            'bunker' => null,
            'login' => $githubActor,
        ];
    } else {
        $author = bridge_resolve_nostr_author($root[1]);
        if ($author === null) {
            throw new BridgeDefer(
                'waiting for an authoritative status signer',
                300
            );
        }
        if ($githubActor !== '') $ev['tags'][] = ['gh_user', $githubActor];
    }

    bridge_gh2nostr(
        $repoRow,
        $ev,
        $author,
        $githubEventId
    );
}

/** Queue the root from any GitHub issue payload, not only an opened delivery. */
function bridge_enqueue_github_issue_root(
    array $repoRow, string $full, array $issue, string $author
): string {
    $number = is_int($issue['number'] ?? null) ? $issue['number'] : 0;
    $githubId = gh_node_id($issue);
    if (!bridge_already_mapped($githubId)) {
        jobs_enqueue('gh2nostr_issue_open', [
            'repo' => $repoRow,
            'issue' => [
                'number' => $number,
                'title' => $issue['title'] ?? '',
                'body' => $issue['body'] ?? '',
                'node_id' => $githubId,
                'created_at' => $issue['created_at'] ?? null,
                'full_name' => $full,
            ],
            'author' => $author,
        ], "gh:$githubId");
    }
    return $githubId;
}

function bridge_github_body_nostr_origin(array $object): ?string
{
    $body = is_string($object['body'] ?? null) ? $object['body'] : '';
    return gh_bridge_marker_id($body);
}

function bridge_nostr_origin_github_id(string $nostrOrMarkerId): ?string
{
    $mapped = db()->prepare(
        'SELECT github_id FROM event_map WHERE nostr_id=? LIMIT 1'
    );
    $mapped->execute([$nostrOrMarkerId]);
    $githubId = $mapped->fetchColumn();
    if (is_string($githubId) && $githubId !== '') return $githubId;

    $st = db()->prepare("SELECT github_id FROM deletion_map
                         WHERE deletion_nostr_id=? OR marker_id=? LIMIT 1");
    $st->execute([$nostrOrMarkerId, $nostrOrMarkerId]);
    $githubId = $st->fetchColumn();
    return is_string($githubId) && $githubId !== '' ? $githubId : null;
}

/** @return array{target_nostr_id:string,marker_id:string,author_pk:string}|null */
function bridge_github_issue_nostr_deletion(string $issueGithubId): ?array
{
    $query = db()->prepare(
        "SELECT dm.target_nostr_id,dm.marker_id,em.author_pk
         FROM event_map em
         JOIN deletion_map dm ON dm.target_nostr_id=em.nostr_id
         WHERE em.github_id=? AND em.kind=1621
         ORDER BY dm.created_at ASC LIMIT 1"
    );
    $query->execute([$issueGithubId]);
    $row = $query->fetch();
    return $row ?: null;
}

// --------------------------------------------------------------------------
// durable job execution
// --------------------------------------------------------------------------

/**
 * Persist user-visible progress before each potentially slow NIP-46 phase.
 * The queue payload is the resumable job's own state, so a page reload or a
 * different cron process reports the real phase rather than guessing from an
 * old error string.
 */
function bridge_nip46_job_phase(array &$job, string $phase): void
{
    if (!in_array($phase, [
        'checking_relays',
        'identifying_account',
        'verifying_signer',
        'saving_link',
    ], true)) {
        throw new InvalidArgumentException('invalid NIP-46 job phase');
    }
    $payload = is_array($job['payload_arr'] ?? null)
        ? $job['payload_arr'] : [];
    $payload['phase'] = $phase;
    db()->prepare(
        "UPDATE jobs SET payload=?,updated_at=?
         WHERE id=? AND status='pending'"
    )->execute([
        json_c($payload),
        now(),
        (int)$job['id'],
    ]);
    $job['payload_arr'] = $payload;
}

function bridge_run_due_jobs(int $limit = 25): void
{
    // Lease immediately before execution. Claiming a whole batch up front
    // lets later leases expire while earlier network jobs are still running.
    for ($i = 0; $i < $limit; $i++) {
        $claimed = jobs_claim_due(1);
        if (!$claimed) break;
        bridge_process_claimed_job($claimed[0]);
    }
}

/** Apply the common durable retry policy to one already leased job. */
function bridge_process_claimed_job(array $job): void
{
    try {
        $err = bridge_execute_job($job);
        jobs_finish((int)$job['id'], $err === null, $err ?? '');
    } catch (BridgeDefer $e) {
        jobs_defer((int)$job['id'], $e->delaySecs, $e->getMessage());
    } catch (BridgeSkip $e) {
        bridge_log('jobs', 'permanent skip', [
            'id' => (int)$job['id'], 'reason' => $e->getMessage(),
        ]);
        jobs_finish((int)$job['id'], true);
    } catch (GhError $e) {
        $code = $e->getCode();
        if ($code === 0
            || in_array($code, [401, 403, 404, 408, 409, 425, 429], true)
            || $code >= 500) {
            $attempt = min(6, max(0, (int)$job['attempts'] - 1));
            jobs_defer(
                (int)$job['id'],
                min(3600, 60 * (2 ** $attempt)),
                $e->getMessage()
            );
        } else {
            jobs_finish((int)$job['id'], false, $e->getMessage());
        }
    } catch (Throwable $e) {
        jobs_finish((int)$job['id'], false, $e->getMessage());
    }
}

/** Browser latency helper; cron remains the authoritative retry backstop. */
function bridge_run_job_id(int $id): bool
{
    $job = jobs_claim_id($id);
    if ($job === null) return false;
    bridge_process_claimed_job($job);
    return true;
}

/** Reflect completion-job failure/corruption back into connected UI state. */
function bridge_reconcile_nip46_finish_jobs(): void
{
    foreach (db()->query("SELECT state_id FROM nip46_states WHERE status='connected'") as $row) {
        $key = 'nip46finish:' . $row['state_id'];
        $job = db()->prepare("SELECT status,last_error FROM jobs
                              WHERE dedupe_key=? ORDER BY id DESC LIMIT 1");
        $job->execute([$key]);
        $existing = $job->fetch();
        if ($existing && $existing['status'] === 'pending') continue;
        if ($existing && $existing['status'] === 'dead') {
            db()->prepare("UPDATE nip46_states SET status='failed',error=? WHERE state_id=?")
               ->execute([
                   'Nostr link completion failed; see the private server log',
                   $row['state_id'],
               ]);
            continue;
        }
        db()->prepare("UPDATE nip46_states SET status='failed',error=?
                       WHERE state_id=? AND status='connected'")
           ->execute(['completion job invariant violated', $row['state_id']]);
    }
}

/** Turn one durable raw GitHub delivery into crossing jobs. */
function bridge_ingest_github_delivery(array $p): ?string
{
    $event = $p['event'] ?? [];
    if (!is_array($event)) return 'malformed GitHub delivery';
    $ghEvent = is_string($p['event_name'] ?? null) ? $p['event_name'] : '';
    $action = is_string($event['action'] ?? null) ? $event['action'] : '';
    $delivery = is_string($p['delivery'] ?? null) ? $p['delivery'] : '';
    $isPR = isset($event['issue']['pull_request']);

    if ($ghEvent === 'github_app_authorization') {
        if ($action !== 'revoked') return null;
        $sender = is_array($event['sender'] ?? null) ? $event['sender'] : [];
        $userId = gh_app_installation_id($sender['id'] ?? null);
        $login = is_string($sender['login'] ?? null)
            ? $sender['login'] : '';
        if ($userId === null || $login === '') {
            return 'malformed GitHub App authorization revocation';
        }
        jobs_enqueue(
            'github_user_authorization_reconcile',
            ['github_user_id' => $userId, 'login' => $login],
            'ghuserauth:' . $userId
        );
        return null;
    }

    $installationId = gh_app_bank_webhook_context($event);
    if ($installationId === null) {
        throw new BridgeSkip('GitHub delivery has no App installation');
    }
    jobs_enqueue(
        'github_installation_reconcile',
        ['installation_id' => $installationId],
        'ghinstall:' . $installationId
    );

    // Access lifecycle deliveries are state, not collaboration content.
    // Apply restrictive transitions immediately, then let the reconciliation
    // job query GitHub's current truth so delivery order cannot reverse them.
    if ($ghEvent === 'installation') {
        if ($action === 'deleted') {
            gh_app_mark_installation_inactive($installationId, 'deleted');
        } elseif ($action === 'suspend') {
            gh_app_mark_installation_inactive($installationId, 'suspended');
        }
        foreach (($event['repositories'] ?? []) as $repository) {
            if (is_array($repository)) {
                gh_app_bank_repository($installationId, $repository, false);
            }
        }
        return null;
    }
    if ($ghEvent === 'installation_repositories') {
        foreach (($event['repositories_added'] ?? []) as $repository) {
            if (is_array($repository)) {
                gh_app_bank_repository($installationId, $repository, false);
            }
        }
        $removed = is_array($event['repositories_removed'] ?? null)
            ? $event['repositories_removed'] : [];
        gh_app_mark_repositories_removed($installationId, $removed);
        return null;
    }
    if ($ghEvent === 'installation_target' || $ghEvent === 'repository') {
        return null;
    }

    if ($ghEvent === 'star'
        && in_array($action, ['created', 'deleted'], true)) {
        $repository = is_array($event['repository'] ?? null)
            ? $event['repository'] : [];
        $repoRow = bridge_repo_ensure($repository);
        if ($repoRow === null) {
            throw new BridgeDefer(
                'repository mapping or authoritative App installation is not ready',
                300
            );
        }
        $repositoryId = gh_app_installation_id(
            $repository['id'] ?? null
        );
        $sender = is_array($event['sender'] ?? null)
            ? $event['sender'] : [];
        $githubUserId = gh_app_installation_id($sender['id'] ?? null);
        $login = is_string($sender['login'] ?? null)
            ? $sender['login'] : '';
        $full = is_string($repository['full_name'] ?? null)
            ? $repository['full_name'] : '';
        if ($repositoryId === null || $githubUserId === null
            || $login === '' || $full === '') {
            return 'malformed GitHub star delivery';
        }
        $pair = bridge_github_star_pair(
            $repositoryId,
            $githubUserId
        );
        bridge_bank_github_star_pair(
            $repositoryId,
            $githubUserId
        );
        // A webhook is only a wake-up signal, but every delivery retains its
        // own durable wake-up. Coalescing by pair could lose a delete that
        // arrives while an earlier reconciliation job is already leased.
        // Execution order remains irrelevant because every job reads current
        // GitHub state.
        $wakeId = $delivery !== ''
            ? $delivery
            : hash('sha256', $ghEvent . json_c($event));
        jobs_enqueue('gh2nostr_star_reconcile', [
            'repo' => $repoRow,
            'full' => $full,
            'repository_id' => $repositoryId,
            'github_user_id' => $githubUserId,
            'login' => $login,
            'pair' => $pair,
            'observed_at' => now(),
        ], "gh:star-reconcile:$pair:$wakeId");
        return null;
    }

    $what = null;
    if ($ghEvent === 'issues'
        && in_array(
            $action,
            ['opened', 'closed', 'reopened', 'edited', 'deleted'],
            true
        )
        && !$isPR) {
        $what = $action === 'opened' ? 'issue_open'
              : ($action === 'closed' ? 'issue_close'
              : ($action === 'reopened' ? 'issue_reopen'
              : ($action === 'deleted' ? 'issue_deleted' : 'issue_edit')));
    } elseif ($ghEvent === 'issue_comment'
              && in_array($action, ['created', 'edited', 'deleted'], true)
              && !$isPR) {
        $what = $action === 'created' ? 'comment' : 'comment_' . $action;
    }
    if ($what === null) return null;

    $repository = $event['repository'] ?? [];
    if (!is_array($repository)) return 'malformed GitHub repository';
    $repoRow = bridge_repo_ensure($repository);
    if ($repoRow === null) {
        throw new BridgeDefer(
            'repository mapping or authoritative App installation is not ready',
            300
        );
    }

    $issue = $event['issue'] ?? [];
    if (!is_array($issue)) return 'malformed GitHub issue';
    $number = is_int($issue['number'] ?? null) ? $issue['number'] : 0;
    $full = is_string($repository['full_name'] ?? null)
        ? $repository['full_name'] : '';
    if ($number < 1 || $full === '') return 'malformed GitHub delivery';
    $sender = is_array($event['sender'] ?? null)
        && is_string($event['sender']['login'] ?? null)
        ? $event['sender']['login']
        : (is_array($issue['user'] ?? null)
            && is_string($issue['user']['login'] ?? null)
            ? $issue['user']['login'] : '');
    $repoRow['_full'] = $full;
    $deliveryKey = $delivery !== '' ? $delivery : hash('sha256', $ghEvent . json_c($event));

    // Only create deliveries are API echoes. Markers remain in an issue or
    // comment body after later edits/state changes; suppressing those later
    // deliveries would lose real user actions.
    $originObject = $what === 'comment'
        ? ($event['comment'] ?? [])
        : ($what === 'issue_open' ? $issue : null);
    if (is_array($originObject)) {
        $originNostrId = bridge_github_body_nostr_origin($originObject);
        if ($originNostrId !== null) {
            $objectId = gh_node_id($originObject);
            $mappedId = bridge_nostr_origin_github_id($originNostrId);
            if ($mappedId !== null) {
                if (hash_equals($mappedId, $objectId)) return null;
                bridge_log('bridge', 'ignored replayed GitHub origin marker', [
                    'origin' => $originNostrId,
                    'mapped_github_id' => $mappedId,
                    'delivery_github_id' => $objectId,
                ]);
            } else {
                throw new BridgeDefer(
                    'waiting for Nostr-origin GitHub crossing ledger'
                );
            }
        }
    }

    if (str_starts_with($what, 'issue_') && $what !== 'issue_open') {
        $issueGithubId = gh_node_id($issue);
        $rootDeletion = bridge_github_issue_nostr_deletion($issueGithubId);
        if ($rootDeletion !== null) {
            if ($what === 'issue_deleted') return null;
            $bodyMarker = bridge_github_body_nostr_origin($issue);
            if ($what === 'issue_close'
                || $bodyMarker === $rootDeletion['marker_id']) {
                return null;
            }
            $enforceId = "enforce-delete:$issueGithubId:$deliveryKey";
            jobs_enqueue('enforce_github_issue_tombstone', [
                'repo' => $repoRow,
                'full' => $full,
                'number' => $number,
                'issue_github_id' => $issueGithubId,
                'target_nostr_id' => $rootDeletion['target_nostr_id'],
                'marker_id' => $rootDeletion['marker_id'],
                'pubkey' => $rootDeletion['author_pk'],
            ], "gh:$enforceId");
            return null;
        }
    }

    if ($what === 'issue_open') {
        bridge_enqueue_github_issue_root($repoRow, $full, $issue, $sender);
    } elseif ($what === 'issue_deleted') {
        $githubId = bridge_enqueue_github_issue_root(
            $repoRow,
            $full,
            $issue,
            is_array($issue['user'] ?? null)
                ? (string)($issue['user']['login'] ?? $sender) : $sender
        );
        $crossingId = "delete:$githubId:$deliveryKey";
        jobs_enqueue('gh2nostr_source_delete', [
            'repo' => $repoRow,
            'full' => $full,
            'number' => $number,
            'issue_node_id' => $githubId,
            'target_github_id' => $githubId,
            'target_kind' => 1621,
            'crossing_id' => $crossingId,
            'author' => $sender,
            'created_at' => $issue['updated_at'] ?? null,
            'proxy_url' => "https://github.com/$full/issues/$number",
        ], "gh:$crossingId");
    } elseif ($what === 'issue_edit') {
        $githubId = bridge_enqueue_github_issue_root(
            $repoRow, $full, $issue,
            is_array($issue['user'] ?? null)
                ? (string)($issue['user']['login'] ?? $sender) : $sender);
        $changes = is_array($event['changes'] ?? null) ? $event['changes'] : [];
        $parts = ["Issue edited on GitHub."];
        if (array_key_exists('title', $changes)) {
            $parts[] = "**New title:** " . (string)($issue['title'] ?? '');
        }
        if (array_key_exists('body', $changes)) {
            $parts[] = "**New description:**\n\n" . (string)($issue['body'] ?? '');
        }
        if (count($parts) === 1) return null;
        $crossingId = "edit:$githubId:$deliveryKey";
        jobs_enqueue('gh2nostr_notice', [
            'repo' => $repoRow,
            'full' => $full,
            'number' => $number,
            'issue_node_id' => $githubId,
            'crossing_id' => $crossingId,
            'body' => implode("\n\n", $parts),
            'author' => $sender,
            'created_at' => $issue['updated_at'] ?? null,
            'proxy_url' => "https://github.com/$full/issues/$number",
        ], "gh:$crossingId");
    } elseif ($what === 'issue_close' || $what === 'issue_reopen') {
        // GitHub does not promise webhook order. A close/reopen delivery is
        // only a wake-up signal. The executor reads GitHub's ordered issue
        // event history, which supplies stable transition identities and
        // lets it suppress transitions performed by this bridge App.
        $githubId = bridge_enqueue_github_issue_root(
            $repoRow, $full, $issue,
            is_array($issue['user'] ?? null)
                ? (string)($issue['user']['login'] ?? $sender) : $sender);
        jobs_enqueue('gh2nostr_status_reconcile', [
            'repo' => $repoRow, 'full' => $full, 'number' => $number,
            'issue_github_id' => $githubId,
        ], "gh:status-reconcile:$githubId:$deliveryKey");
    } else {
        $comment = $event['comment'] ?? [];
        if (!is_array($comment)) return 'malformed GitHub comment';
        $issueGithubId = bridge_enqueue_github_issue_root(
            $repoRow, $full, $issue,
            is_array($issue['user'] ?? null)
                ? (string)($issue['user']['login'] ?? $sender) : $sender);
        $githubId = gh_node_id($comment);
        $commentLogin = is_array($comment['user'] ?? null)
            && is_string($comment['user']['login'] ?? null)
            ? $comment['user']['login'] : $sender;
        $deleted = $what === 'comment_deleted';
        if ($deleted) {
            $echo = db()->prepare(
                'SELECT 1 FROM deletion_map WHERE github_id=? LIMIT 1'
            );
            $echo->execute([$githubId]);
            if ($echo->fetchColumn()) return null;
        }

        // Edited/deleted can arrive without Created. Bank a deterministic
        // base comment from the payload first so the dependent operation has
        // an immutable Nostr target instead of waiting forever.
        if ($what === 'comment' || !bridge_already_mapped($githubId)) {
            jobs_enqueue('gh2nostr_comment', [
                'repo' => $repoRow, 'full' => $full, 'number' => $number,
                'issue_node_id' => $issueGithubId,
                'comment' => [
                    'id' => $comment['id'] ?? 0, 'node_id' => $githubId,
                    'body' => $comment['body'] ?? '',
                    'created_at' => $comment['created_at'] ?? null,
                    'login' => $commentLogin,
                ],
            ], "gh:$githubId");
        }
        if ($what === 'comment') {
            return null;
        }

        if ($deleted) {
            $crossingId = 'delete:' . $githubId . ':' . $deliveryKey;
            jobs_enqueue('gh2nostr_source_delete', [
                'repo' => $repoRow,
                'full' => $full,
                'number' => $number,
                'issue_node_id' => $issueGithubId,
                'target_github_id' => $githubId,
                'target_kind' => 1111,
                'crossing_id' => $crossingId,
                'author' => $sender,
                'created_at' => $comment['updated_at']
                    ?? $comment['created_at'] ?? null,
                'proxy_url' => "https://github.com/$full/issues/$number",
            ], "gh:$crossingId");
        } else {
            $crossingId = ($deleted ? 'delete:' : 'edit:')
                . $githubId . ':' . $deliveryKey;
            $body = "A GitHub issue comment was edited.\n\n"
                  . (string)($comment['body'] ?? '');
            jobs_enqueue('gh2nostr_notice', [
                'repo' => $repoRow,
                'full' => $full,
                'number' => $number,
                'issue_node_id' => $issueGithubId,
                'crossing_id' => $crossingId,
                'body' => $body,
                'author' => $sender,
                'created_at' => $comment['updated_at']
                    ?? $comment['created_at'] ?? null,
                'proxy_url' => "https://github.com/$full/issues/$number",
            ], "gh:$crossingId");
        }
    }
    return null;
}

function bridge_nip39_link_is_active(string $login, string $pubkey): bool
{
    $query = db()->prepare(
        "SELECT 1
         FROM links l
         JOIN github_accounts ga ON ga.login=l.login
         JOIN nostr_accounts na ON na.pubkey=l.pubkey
         WHERE l.login=? AND l.pubkey=?
           AND ga.provider='github_app' AND ga.auth_status='active'
           AND na.status='linked'"
    );
    $query->execute([$login, strtolower($pubkey)]);
    return (bool)$query->fetchColumn();
}

function bridge_nip39_save_payload(
    array &$job,
    array $payload,
    string $phase
): void {
    $payload['phase'] = $phase;
    jobs_update_payload((int)$job['id'], $payload);
    $job['payload_arr'] = $payload;
}

function bridge_nip39_fail(
    array &$job,
    array $payload,
    string $message
): ?string {
    $payload['error'] = substr($message, 0, 300);
    unset($payload['auth_url']);
    bridge_nip39_save_payload($job, $payload, 'failed');
    return null;
}

if (!function_exists('bridge_nip39_sign_event')) {
function bridge_nip39_sign_event(
    array $author,
    array $proposal,
    ?callable $onAuthUrl = null,
    ?callable $onSignerError = null
): ?array {
    return nip46_sign_event(
        (string)$author['client_priv'],
        fm_pubkey_hex((string)$author['client_priv']),
        (string)$author['bunker'],
        $proposal,
        8.0,
        $onAuthUrl,
        $onSignerError
    );
}
}

/** Build and persist a proposal preview from the latest observed head. */
function bridge_nip39_prepare(
    array &$job,
    array $payload,
    bool $reconfirmation
): ?string {
    $login = (string)($payload['github_login'] ?? '');
    $pubkey = strtolower((string)($payload['pubkey'] ?? ''));
    $action = (string)($payload['action'] ?? '');
    $gistId = $payload['gist_id'] ?? null;
    if (!nip39_github_login_valid($login)
        || !is_hex64($pubkey)
        || !in_array($action, ['add', 'remove'], true)
        || ($action === 'add'
            && (!is_string($gistId)
                || !preg_match('/^[0-9a-f]{5,64}$/D', $gistId)))
        || ($action === 'remove' && $gistId !== null)) {
        return bridge_nip39_fail(
            $job,
            $payload,
            'The identity-publication request is malformed.'
        );
    }
    if (!bridge_nip39_link_is_active($login, $pubkey)) {
        return bridge_nip39_fail(
            $job,
            $payload,
            'The GitHub and Nostr identities are no longer fully linked.'
        );
    }
    if ($action === 'add') {
        try {
            nip39_verify_github_gist($login, $pubkey, $gistId);
            $payload['gist_verified_at'] = now();
        } catch (Nip39ProofError $error) {
            return bridge_nip39_fail($job, $payload, $error->getMessage());
        }
    }

    bridge_nip39_save_payload(
        $job,
        $payload,
        $reconfirmation ? 'checking_current' : 'reading_current'
    );
    try {
        $context = nip39_discover_context($pubkey);
    } catch (Nip39RelayUnavailable $error) {
        throw new BridgeDefer($error->getMessage(), 30);
    }
    $current = $context['current'];
    $proposal = nip39_build_proposal(
        $current,
        $pubkey,
        $login,
        $action === 'add' ? $gistId : null
    );
    $payload['base_event_id'] = is_array($current)
        ? strtolower((string)$current['id']) : null;
    $payload['proposed_event'] = $proposal;
    $payload['identities'] = nip39_identity_preview($proposal['tags']);
    $payload['target_relays'] = $context['relays'];
    $payload['observed_relays'] = $context['complete_relays'];
    $payload['error'] = null;
    unset($payload['auth_url'], $payload['confirmed_base_event_id']);

    if (!nip39_managed_claim_changed(
        $current,
        $login,
        $action === 'add' ? $gistId : null
    )) {
        bridge_nip39_save_payload(
            $job,
            $payload,
            $action === 'add' ? 'already_current' : 'nothing_to_remove'
        );
        return null;
    }

    if ($reconfirmation) {
        $payload['notice'] =
            'The current Nostr identity snapshot changed before signing. '
            . 'Review the refreshed complete set.';
    } else {
        unset($payload['notice']);
    }
    bridge_nip39_save_payload(
        $job,
        $payload,
        'awaiting_confirmation'
    );
    throw new BridgeDefer(
        'waiting for explicit NIP-39 publication confirmation',
        86400
    );
}

function bridge_nip39_execute_identity(array &$job): ?string
{
    $payload = is_array($job['payload_arr'] ?? null)
        ? $job['payload_arr'] : [];
    $phase = (string)($payload['phase'] ?? 'preparing');
    if (in_array($phase, ['preparing', 'reading_current'], true)) {
        return bridge_nip39_prepare($job, $payload, false);
    }
    if ($phase === 'awaiting_confirmation') {
        throw new BridgeDefer(
            'waiting for explicit NIP-39 publication confirmation',
            86400
        );
    }
    if (in_array($phase, [
        'ready_to_sign',
        'checking_current',
        'awaiting_signature',
    ], true)) {
        $login = (string)($payload['github_login'] ?? '');
        $pubkey = strtolower((string)($payload['pubkey'] ?? ''));
        $action = (string)($payload['action'] ?? '');
        $gistId = $payload['gist_id'] ?? null;
        if (!bridge_nip39_link_is_active($login, $pubkey)) {
            return bridge_nip39_fail(
                $job,
                $payload,
                'The GitHub and Nostr identities are no longer fully linked.'
            );
        }
        if ($action === 'add'
            && (int)($payload['gist_verified_at'] ?? 0) < now() - 60) {
            try {
                nip39_verify_github_gist(
                    $login,
                    $pubkey,
                    (string)$gistId
                );
                $payload['gist_verified_at'] = now();
            } catch (Nip39ProofError $error) {
                return bridge_nip39_fail(
                    $job,
                    $payload,
                    $error->getMessage()
                );
            }
        }

        bridge_nip39_save_payload(
            $job,
            $payload,
            'checking_current'
        );
        try {
            $context = nip39_discover_context($pubkey);
        } catch (Nip39RelayUnavailable $error) {
            throw new BridgeDefer($error->getMessage(), 30);
        }
        $currentId = is_array($context['current'])
            ? strtolower((string)$context['current']['id']) : null;
        $confirmedBase = $payload['confirmed_base_event_id'] ?? null;
        if ($confirmedBase !== $currentId) {
            return bridge_nip39_prepare($job, $payload, true);
        }
        $proposal = nip39_build_proposal(
            $context['current'],
            $pubkey,
            $login,
            $action === 'add' ? (string)$gistId : null
        );
        $payload['proposed_event'] = $proposal;
        $payload['target_relays'] = $context['relays'];
        $payload['observed_relays'] = $context['complete_relays'];
        $payload['error'] = null;
        bridge_nip39_save_payload(
            $job,
            $payload,
            'awaiting_signature'
        );

        $author = bridge_resolve_nostr_author($pubkey);
        if ($author === null || ($author['path'] ?? '') !== 'remote') {
            return bridge_nip39_fail(
                $job,
                $payload,
                'The linked remote Nostr signer is unavailable.'
            );
        }
        $authUrl = null;
        $signerError = null;
        $onAuthUrl = static function (string $url) use (
            &$authUrl,
            &$job,
            &$payload
        ): void {
            $authUrl = $url;
            $payload['auth_url'] = $url;
            bridge_nip39_save_payload(
                $job,
                $payload,
                'awaiting_signature'
            );
        };
        $onSignerError = static function (string $message) use (
            &$signerError
        ): void {
            $signerError = $message;
        };
        try {
            $signed = bridge_nip39_sign_event(
                $author,
                $proposal,
                $onAuthUrl,
                $onSignerError
            );
        } catch (WsException $error) {
            throw new BridgeDefer(
                'waiting for the linked Nostr signer',
                15
            );
        }
        if ($signed === null) {
            if ($signerError !== null) {
                return bridge_nip39_fail(
                    $job,
                    $payload,
                    'The signer rejected the identity update: '
                    . $signerError
                    . '. In Amber, allow optional kind 10011 for the '
                    . 'friendly-machines bridge connection, then try again.'
                );
            }
            throw new BridgeDefer(
                $authUrl !== null
                    ? 'waiting for signer authorization'
                    : 'waiting for the linked Nostr signer',
                15
            );
        }
        if (!nip46_signed_event_matches(
            $signed,
            nip46_unsigned_event($proposal),
            $pubkey
        )) {
            return bridge_nip39_fail(
                $job,
                $payload,
                'The signer returned a mismatched identity event.'
            );
        }

        /*
         * Persist the complete signed event before any relay I/O. Every retry
         * below uses this exact signature and can never ask Amber to sign the
         * same confirmed intent again.
         */
        $payload['signed_event'] = nip46_wire_event($signed);
        unset($payload['auth_url']);
        bridge_nip39_save_payload($job, $payload, 'signed');
        return bridge_nip39_enqueue_publications($job, $payload);
    }
    if ($phase === 'signed') {
        return bridge_nip39_enqueue_publications($job, $payload);
    }
    if (in_array($phase, [
        'failed',
        'already_current',
        'nothing_to_remove',
        'publishing',
    ], true)) {
        return null;
    }
    return bridge_nip39_fail(
        $job,
        $payload,
        'The identity-publication job has an invalid phase.'
    );
}

/**
 * Enqueue every per-relay publication from an already durable signed event.
 * Re-entering this phase after a crash is safe because every child has a
 * stable dedupe key.
 */
function bridge_nip39_enqueue_publications(
    array &$job,
    array $payload
): ?string {
    $signed = $payload['signed_event'] ?? null;
    $pubkey = strtolower((string)($payload['pubkey'] ?? ''));
    if (!is_array($signed)
        || !fm_event_verify($signed)
        || (int)($signed['kind'] ?? -1) !== NIP39_KIND
        || strtolower((string)($signed['pubkey'] ?? '')) !== $pubkey) {
        return bridge_nip39_fail(
            $job,
            $payload,
            'The durable signed identity event is invalid.'
        );
    }
    $publicationJobs = [];
    foreach (relay_url_set($payload['target_relays'] ?? [], 12) as $relay) {
        $dedupe = 'nip39relay:' . $signed['id'] . ':'
            . substr(hash('sha256', $relay), 0, 16);
        if (!jobs_dedupe_terminal($dedupe)) {
            jobs_enqueue(
                'nip39_publish_relay',
                [
                    'event' => $signed,
                    'relay' => $relay,
                    'pubkey' => $pubkey,
                ],
                $dedupe
            );
        }
        $publicationJobs[$relay] = $dedupe;
    }
    if (!$publicationJobs) {
        return bridge_nip39_fail(
            $job,
            $payload,
            'No secure Nostr publication relay is configured.'
        );
    }
    ksort($publicationJobs, SORT_STRING);
    $payload['publication_jobs'] = $publicationJobs;
    bridge_nip39_save_payload($job, $payload, 'publishing');
    return null;
}

/** @return null on success/skip, string error otherwise. */
function bridge_execute_job(array $job): ?string
{
    require_once __DIR__ . '/jobs.php';
    $p = $job['payload_arr'];
    $repoRow = $p['repo'] ?? null;
    if (is_array($repoRow)
        && is_string($repoRow['github_full_name'] ?? null)) {
        $repoRow = bridge_require_current_repo_mapping(
            $repoRow['github_full_name']
        );
    }

    switch ($job['type']) {
        case 'nip39_identity':
            return bridge_nip39_execute_identity($job);

        case 'nip39_publish_relay': {
            $event = $p['event'] ?? null;
            $relay = is_string($p['relay'] ?? null) ? $p['relay'] : '';
            $pubkey = strtolower((string)($p['pubkey'] ?? ''));
            if (!is_array($event)
                || !fm_event_verify($event)
                || (int)($event['kind'] ?? -1) !== NIP39_KIND
                || strtolower((string)($event['pubkey'] ?? '')) !== $pubkey
                || !is_hex64($pubkey)
                || relay_url_set([$relay]) !== [$relay]) {
                throw new BridgeSkip(
                    'invalid NIP-39 relay-publication payload'
                );
            }
            if (relay_find_event((string)$event['id'], [$relay]) !== null) {
                return null;
            }
            $results = relay_publish($event, [$relay], 5.0);
            if (relay_publish_ok($results)) return null;
            $result = (string)($results[$relay] ?? 'error: no response');
            if (str_starts_with($result, 'rejected:')) {
                return $result;
            }
            throw new BridgeDefer(
                'relay publication pending: ' . $result,
                300
            );
        }

        case 'github_delivery':
            return bridge_ingest_github_delivery($p);

        case 'github_installation_reconcile': {
            $installationId = gh_app_installation_id(
                $p['installation_id'] ?? null
            );
            if ($installationId === null) {
                throw new BridgeSkip('invalid GitHub installation id');
            }
            $result = gh_app_reconcile_installation($installationId);
            bridge_log('github-app', 'installation reconciled', [
                'installation' => $installationId,
                'status' => $result['status'],
                'repositories' => $result['repositories'],
            ]);
            return null;
        }

        case 'github_user_authorization_reconcile': {
            $githubUserId = gh_app_installation_id(
                $p['github_user_id'] ?? null
            );
            $login = is_string($p['login'] ?? null) ? $p['login'] : '';
            if ($githubUserId === null || $login === '') {
                throw new BridgeSkip('invalid GitHub user revocation payload');
            }
            $account = db()->prepare(
                "SELECT * FROM github_accounts
                 WHERE provider='github_app'
                   AND (github_user_id=? OR login=?)
                 ORDER BY github_user_id=? DESC LIMIT 1"
            );
            $account->execute([$githubUserId, $login, $githubUserId]);
            $row = $account->fetch();
            if (!$row) return null;
            if ($row['auth_status'] !== 'active') return null;
            try {
                $token = gh_app_user_token((string)$row['login']);
                $remote = gh_request('GET', '/user', $token);
            } catch (GhUserAuthorizationUnavailable $error) {
                return null; // refresh failure already marked reauthorization
            } catch (GhError $error) {
                if ($error->getCode() === 401) {
                    gh_app_require_user_reauthorization(
                        (string)$row['login']
                    );
                    return null;
                }
                throw $error;
            }
            if ((string)($remote['id'] ?? '') !== $githubUserId) {
                gh_app_require_user_reauthorization((string)$row['login']);
                throw new BridgeSkip(
                    'GitHub user token identity no longer matches authorization'
                );
            }
            // The stored token is current and valid: this was a delayed
            // revocation delivery from before a later reauthorization.
            return null;
        }

        case 'enforce_github_issue_tombstone': {
            if ($repoRow === null) return 'missing repo row';
            $targetNostrId = strtolower(
                (string)($p['target_nostr_id'] ?? '')
            );
            $markerId = strtolower((string)($p['marker_id'] ?? ''));
            $pubkey = strtolower((string)($p['pubkey'] ?? ''));
            if (!is_hex64($targetNostrId)
                || !is_hex64($markerId)
                || !is_hex64($pubkey)) {
                throw new BridgeSkip('invalid tombstone enforcement payload');
            }
            $stillDeleted = db()->prepare(
                "SELECT 1 FROM deletion_map
                 WHERE target_nostr_id=? AND marker_id=?"
            );
            $stillDeleted->execute([$targetNostrId, $markerId]);
            if (!$stillDeleted->fetchColumn()) return null;

            $notice = "This issue remains tombstoned because its Nostr source "
                . "event `$targetNostrId` has a valid, permanent NIP-09 "
                . "deletion request.";
            bridge_github_execute_for_nostr(
                $pubkey,
                (string)$p['full'],
                fn(array $author): array => gh_tombstone_issue(
                    $author['token'],
                    (string)$p['full'],
                    (int)$p['number'],
                    gh_body_with_marker($notice, $markerId)
                )
            );
            bridge_log('bridge', 'restored permanent Nostr tombstone', [
                'nostr' => $targetNostrId,
                'gh' => $p['full'] . '#' . (int)$p['number'],
            ]);
            return null;
        }

        case 'nip46_finish': {
            $stateId = (string)($p['state_id'] ?? '');
            $replacePubkey = $p['replace_pubkey'] ?? null;
            if ($replacePubkey !== null
                && (!is_string($replacePubkey)
                    || !is_hex64($replacePubkey))) {
                return 'nip46 replacement intent is malformed';
            }
            $st = db()->prepare('SELECT * FROM nip46_states WHERE state_id = ?');
            $st->execute([$stateId]);
            $state = $st->fetch();
            // The signer RPCs below are network I/O. Release this SQLite read
            // snapshot first so a concurrent browser status poll cannot make
            // the later relay/state write fail with SQLITE_BUSY_SNAPSHOT.
            $st->closeCursor();
            if (!$state) return 'nip46 state is missing';
            if ($state['status'] === 'done') return null;
            if ($state['status'] !== 'connected') return 'nip46 state is not connected';
            if ((int)$state['expires_at'] < now()) {
                db()->prepare(
                    "UPDATE nip46_states SET status='failed',error=?
                     WHERE state_id=? AND status='connected'"
                )->execute([
                    'Nostr link completion expired after 30 days',
                    $stateId,
                ]);
                throw new BridgeSkip(
                    'NIP-46 completion expired after its 30-day retry window'
                );
            }

            $bunkerPk = strtolower((string)($state['bunker_pk'] ?? ''));
            $connectedRelays = json_decode(
                (string)($state['relays'] ?? ''),
                true
            );
            if (!is_hex64($bunkerPk)
                || !is_array($connectedRelays)
                || !array_is_list($connectedRelays)
                || relay_url_set($connectedRelays, 4) !== $connectedRelays
                || !$connectedRelays) {
                return 'nip46 connected state is incomplete';
            }
            $clientKeyEnc = $state['client_key_enc'] ?? null;
            if (!is_string($clientKeyEnc) || $clientKeyEnc === '') {
                db()->prepare("UPDATE nip46_states SET status='failed',error=?
                               WHERE state_id=?")
                   ->execute(['missing per-connection NIP-46 client key', $stateId]);
                throw new BridgeSkip('missing per-connection NIP-46 client key');
            }
            $clientPriv = fm_decrypt_at_rest($clientKeyEnc);
            $clientPk = fm_pubkey_hex($clientPriv);
            if (!hash_equals($clientPk, (string)$state['client_pk'])) {
                db()->prepare("UPDATE nip46_states SET status='failed',error=?
                               WHERE state_id=?")
                   ->execute(['NIP-46 client key does not match pubkey', $stateId]);
                throw new BridgeSkip('NIP-46 client key does not match pubkey');
            }

            bridge_nip46_job_phase($job, 'checking_relays');
            $authRequired = false;
            $onAuthUrl = static function (string $url) use (
                $stateId,
                &$authRequired
            ): void {
                $authRequired = true;
                db()->prepare(
                    "UPDATE nip46_states SET error=?
                     WHERE state_id=? AND status='connected'"
                )->execute([
                    NIP46_AUTH_STATE_PREFIX . $url,
                    $stateId,
                ]);
            };
            $updatedRelays = bridge_nip46_connection_relays(
                $clientPriv,
                $clientPk,
                $bunkerPk,
                $connectedRelays,
                $onAuthUrl
            );
            if (!$updatedRelays && $authRequired) {
                throw new BridgeDefer(
                    'waiting for signer authorization',
                    NIP46_LINK_RETRY_SECS
                );
            }
            if ($updatedRelays) {
                $connectionRelays = $updatedRelays;
                /*
                 * switch_relays changes durable connection state immediately.
                 * Persist it before get_public_key: if the signer moves its
                 * subscription and that next ephemeral request is missed, a
                 * retry must resume on the negotiated relays rather than
                 * restart forever from the obsolete connect-response relay.
                 */
                db()->prepare(
                    "UPDATE nip46_states SET relays=?
                     WHERE state_id=? AND status='connected'"
                )->execute([json_c($connectionRelays), $stateId]);
            } else {
                /*
                 * A missing switch_relays response does not invalidate the
                 * current durable relay set. It may already be the set returned
                 * by an earlier successful switch whose following ephemeral
                 * RPC was lost. Continue there; requiring another switch reply
                 * first makes that resumable state impossible to use.
                 */
                $connectionRelays = $connectedRelays;
            }

            // Some remote signers publish the switch_relays response before
            // their replacement relay subscriptions have finished updating.
            // Give that handoff a bounded moment; durable retries use the
            // newly persisted set if the first request is still missed.
            usleep(500000);

            bridge_nip46_job_phase($job, 'identifying_account');
            /*
             * The nostrconnect URI explicitly authorized the bootstrap relays.
             * Keep them as transport fallbacks after switch_relays. Older
             * signers have been observed publishing a new relay set before
             * their subscription has actually moved; kind 24133 is ephemeral,
             * so using only the announced set can lose every follow-up RPC.
             * Results still must agree, independent of relay arrival order.
             */
            $requestRelays = relay_url_set(array_merge(
                $connectionRelays,
                nip46_listen_relays()
            ), 6);
            $userPks = [];
            $responsiveRelays = [];
            $signerErrors = [];
            foreach ($requestRelays as $connectionRelay) {
                $candidatePk = bridge_nip46_get_public_key(
                    $clientPriv,
                    $clientPk,
                    $bunkerPk,
                    $connectionRelay,
                    $onAuthUrl,
                    static function (string $error) use (
                        &$signerErrors
                    ): void {
                        $signerErrors[$error] = true;
                    }
                );
                if ($candidatePk !== null) {
                    $userPks[$candidatePk] = true;
                    $responsiveRelays[$connectionRelay] = true;
                }
            }
            if (count($userPks) !== 1) {
                throw new BridgeDefer(
                    $authRequired
                        ? 'waiting for signer authorization'
                        : ($userPks
                        ? 'get_public_key disagreed across signer relays'
                        : ($signerErrors
                          ? 'get_public_key rejected by signer: '
                            . implode('; ', array_keys($signerErrors))
                          : 'get_public_key received no valid response on '
                            . json_c($requestRelays))),
                    NIP46_LINK_RETRY_SECS
                );
            }
            $userPk = (string)array_key_first($userPks);
            if ($replacePubkey !== null
                && !hash_equals($replacePubkey, $userPk)) {
                db()->prepare(
                    "UPDATE nip46_states SET status='failed',error=?
                     WHERE state_id=? AND status='connected'"
                )->execute([
                    'Replacement signer controls a different Nostr account',
                    $stateId,
                ]);
                throw new BridgeSkip(
                    'replacement signer controls a different Nostr account'
                );
            }
            // A correctly signed/encrypted response is stronger liveness
            // evidence than a prior switch_relays announcement. Retain every
            // such transport in the durable set so the proof and future
            // signing do not discard the only relay where this signer is
            // demonstrably answering.
            $connectionRelays = relay_url_set(array_merge(
                $connectionRelays,
                array_keys($responsiveRelays)
            ), 6);
            db()->prepare(
                "UPDATE nip46_states SET relays=?
                 WHERE state_id=? AND status='connected'"
            )->execute([json_c($connectionRelays), $stateId]);

            bridge_nip46_job_phase($job, 'verifying_signer');
            $bunkerUri = 'bunker://' . $bunkerPk;
            foreach ($connectionRelays as $index => $connectionRelay) {
                $bunkerUri .= ($index === 0 ? '?' : '&')
                    . 'relay=' . rawurlencode($connectionRelay);
            }
            if (!bridge_nip46_prove_user_key(
                $clientPriv,
                $clientPk,
                $bunkerUri,
                $userPk,
                $stateId,
                now(),
                $onAuthUrl
            )) {
                throw new BridgeDefer(
                    $authRequired
                        ? 'waiting for signer authorization'
                        : 'NIP-46 signer did not prove control of get_public_key',
                    NIP46_LINK_RETRY_SECS
                );
            }
            bridge_nip46_job_phase($job, 'saving_link');
            $bunkerEnc = fm_encrypt_at_rest($bunkerUri);
            $oauthNonce = (string)($state['oauth_nonce'] ?? '');
            $signerDisposition = 'created';

            db()->beginTransaction();
            try {
                $existingSigner = db()->prepare(
                    'SELECT status FROM nostr_accounts WHERE pubkey=?'
                );
                $existingSigner->execute([$userPk]);
                $existingSignerStatus = $existingSigner->fetchColumn();
                if ($existingSignerStatus === false) {
                    if ($replacePubkey !== null) {
                        throw new IdentityLinkConflict(
                            'Signer replacement target no longer exists'
                        );
                    }
                    db()->prepare(
                        'INSERT INTO nostr_accounts
                         (pubkey,bunker_enc,client_key_enc,status,
                          linked_at,updated_at)
                         VALUES (?,?,?,?,?,?)'
                    )->execute([
                        $userPk,
                        $bunkerEnc,
                        $clientKeyEnc,
                        'linked',
                        now(),
                        now(),
                    ]);
                } elseif ($replacePubkey !== null) {
                    db()->prepare(
                        "UPDATE nostr_accounts
                         SET bunker_enc=?,client_key_enc=?,status='linked',
                             updated_at=?
                         WHERE pubkey=?"
                    )->execute([
                        $bunkerEnc,
                        $clientKeyEnc,
                        now(),
                        $userPk,
                    ]);
                    $signerDisposition = 'replaced';
                } elseif ($existingSignerStatus === 'linked') {
                    /*
                     * A user who cleared cookies may repeat the NIP-46 proof
                     * merely to sign this browser back in. Preserve the
                     * already-authorized remote signer connection. Replacing
                     * it requires the separately marked replacement flow.
                     */
                    $signerDisposition = 'session-recovered';
                } else {
                    throw new IdentityLinkConflict(
                        'Existing Nostr signer must be explicitly replaced'
                    );
                }

                $login = null;
                if ($oauthNonce !== '') {
                    db()->prepare("UPDATE oauth_states
                                   SET nostr_pubkey=?, expires_at=MAX(expires_at, ?)
                                   WHERE nonce=?")
                       ->execute([
                           $userPk,
                           now() + FM_PARTIAL_LINK_SESSION_SECS,
                           $oauthNonce,
                       ]);
                    $os = db()->prepare(
                        "SELECT os.github_login
                         FROM oauth_states os
                         JOIN github_accounts ga
                           ON ga.login=os.github_login
                         WHERE os.nonce=? AND ga.provider='github_app'
                           AND ga.auth_status='active'"
                    );
                    $os->execute([$oauthNonce]);
                    $login = $os->fetchColumn() ?: null;
                }
                if ($login !== null) {
                    fm_link_identities($login, $userPk);
                }
                db()->prepare("UPDATE nip46_states
                               SET status='done', pubkey=?, error=NULL, expires_at=?
                               WHERE state_id=?")
                   ->execute([
                       $userPk,
                       now() + FM_PARTIAL_LINK_SESSION_SECS,
                       $stateId,
                   ]);
                db()->commit();
            } catch (IdentityLinkConflict $e) {
                if (db()->inTransaction()) db()->rollBack();
                db()->prepare("UPDATE nip46_states SET status='failed',error=? WHERE state_id=?")
                   ->execute([$e->getMessage(), $stateId]);
                throw new BridgeSkip($e->getMessage(), 0, $e);
            } catch (Throwable $e) {
                if (db()->inTransaction()) db()->rollBack();
                throw $e;
            }
            bridge_log('nip46', 'finish job completed', [
                'state' => $stateId, 'pubkey' => substr($userPk, 0, 8),
                'linked' => $login,
                'signer' => $signerDisposition,
            ]);
            return null;
        }

        case 'gh2nostr_issue_open': {
            if ($repoRow === null) return 'missing repo row';
            $githubId = $p['issue']['node_id'];
            if (bridge_already_mapped($githubId)) return null;
            $ev = bridge_build_issue($repoRow, $p['issue']);
            $ev['proxy_url'] = "https://github.com/{$p['issue']['full_name']}/issues/{$p['issue']['number']}";
            $ev['meta'] = json_c(['full' => $p['issue']['full_name'], 'number' => $p['issue']['number'],
                                  'title' => $p['issue']['title'] ?? '']);
            $author = bridge_resolve_author($p['author']);
            bridge_gh2nostr($repoRow, $ev, $author, $githubId);
            return null;
        }
        case 'gh2nostr_repository_stars_reconcile': {
            $full = (string)($p['full'] ?? '');
            $repositoryId = (string)($p['repository_id'] ?? '');
            $scanAt = (int)($p['scan_at'] ?? 0);
            if (!ctype_digit($repositoryId)
                || $repositoryId === '0'
                || $scanAt < 1) {
                throw new BridgeSkip(
                    'invalid repository-star reconciliation payload'
                );
            }
            $currentRepo = bridge_require_current_repo_mapping($full);
            // GitHub no longer exposes a repository's complete stargazer
            // collection to an ordinary App installation. Every signed Star
            // webhook therefore adds its immutable repository/user identity
            // to an explicit primary-keyed set. Mapped Nostr reactions are a
            // second source of known pairs. Reduce those independent
            // collections by numeric user ID, then reconcile each pair from
            // that user's current starred-repository collection. This
            // remains correct when unstar arrives before star.
            $actors = [];
            $knownPairs = db()->prepare(
                "SELECT k FROM schema_meta
                 WHERE k LIKE ?
                 ORDER BY k"
            );
            $knownPairs->execute([
                "github_star_pair|$repositoryId|%",
            ]);
            foreach ($knownPairs->fetchAll(PDO::FETCH_COLUMN) as $key) {
                if (preg_match(
                    '/^github_star_pair\|'
                    . preg_quote($repositoryId, '/')
                    . '\|([1-9][0-9]*)$/',
                    (string)$key,
                    $match
                )) {
                    $actors[$match[1]] = '';
                }
            }
            $known = db()->prepare(
                "SELECT DISTINCT parent_github_id,meta
                 FROM event_map
                 WHERE kind=7 AND parent_github_id LIKE ?"
            );
            $known->execute(["star:$repositoryId:%"]);
            foreach ($known->fetchAll() as $row) {
                $pair = (string)$row['parent_github_id'];
                if (!preg_match(
                    '/^star:' . preg_quote($repositoryId, '/')
                    . ':([1-9][0-9]*)$/',
                    $pair,
                    $match
                )) {
                    continue;
                }
                $githubUserId = $match[1];
                $meta = json_decode((string)($row['meta'] ?? ''), true);
                $login = is_array($meta)
                    ? (string)($meta['github_login'] ?? '') : '';
                if (!isset($actors[$githubUserId]) || $login !== '') {
                    $actors[$githubUserId] = $login;
                }
            }
            ksort($actors, SORT_STRING);
            foreach ($actors as $githubUserId => $login) {
                // PHP coerces decimal-string array keys to integers. GitHub
                // IDs are opaque decimal strings, so restore that type at
                // the map boundary before identity construction.
                $githubUserId = (string)$githubUserId;
                $pair = bridge_github_star_pair(
                    $repositoryId,
                    $githubUserId
                );
                jobs_enqueue('gh2nostr_star_reconcile', [
                    'repo' => $currentRepo,
                    'full' => $full,
                    'repository_id' => $repositoryId,
                    'github_user_id' => $githubUserId,
                    'login' => $login,
                    'pair' => $pair,
                    'observed_at' => $scanAt,
                ], "gh:star-reconcile:$pair:scan:$scanAt");
            }
            return null;
        }
        case 'gh2nostr_star_reconcile': {
            if ($repoRow === null) return 'missing repo row';
            require_once __DIR__ . '/github.php';
            $full = (string)($p['full'] ?? '');
            $repositoryId = (string)($p['repository_id'] ?? '');
            $githubUserId = (string)($p['github_user_id'] ?? '');
            $pair = bridge_github_star_pair(
                $repositoryId,
                $githubUserId
            );
            if (!hash_equals($pair, (string)($p['pair'] ?? ''))) {
                throw new BridgeSkip('GitHub star pair changed in queue');
            }
            $token = bridge_github_app_token_for_repo($full);
            $starState = gh_repository_star_state_for_user(
                $token,
                $repositoryId,
                $githubUserId
            );
            $active = bridge_active_repository_stars($pair);
            if ($starState['starred']) {
                if ($active) return null;
                $createdAt = bridge_repository_star_created_at(
                    $pair,
                    (int)$starState['starred_at_timestamp']
                );
                $announcement = is_array(
                    $repoRow['_announcement'] ?? null
                ) ? $repoRow['_announcement'] : null;
                if ($announcement === null) {
                    throw new BridgeDefer(
                        'waiting for current repository announcement identity',
                        300
                    );
                }
                $baseGithubId = $pair . ':'
                    . (int)$starState['starred_at_timestamp'];
                $githubId = $baseGithubId;
                for ($generation = 2;
                     bridge_already_mapped($githubId);
                     $generation++) {
                    $githubId = $baseGithubId . ':' . $generation;
                }
                $event = bridge_build_repository_star(
                    $repoRow,
                    $full,
                    $announcement,
                    $createdAt
                );
                $event['proxy_url'] = "https://github.com/$full";
                $event['parent_github_id'] = $pair;
                $event['meta'] = json_c([
                    'full' => $full,
                    'repository_id' => $repositoryId,
                    'github_user_id' => $githubUserId,
                    'github_login' => $starState['login'],
                    'github_starred_at' => $starState['starred_at'],
                    'github_source_created_at' =>
                        (int)$starState['starred_at_timestamp'],
                    'event_created_at' => $createdAt,
                    'source' => 'github-star-reconciliation',
                ]);
                $author = bridge_resolve_github_user_author(
                    $githubUserId,
                    (string)$starState['login']
                );
                bridge_gh2nostr(
                    $repoRow,
                    $event,
                    $author,
                    $githubId
                );
                return null;
            }

            foreach ($active as $targetRow) {
                $targetNostrId = strtolower(
                    (string)$targetRow['nostr_id']
                );
                $crossingId = 'unstar:' . $targetNostrId;
                $existing = db()->prepare(
                    'SELECT nostr_id FROM event_map
                     WHERE github_id=? AND kind=5'
                );
                $existing->execute([$crossingId]);
                $deletionNostrId = $existing->fetchColumn();
                $targetMeta = json_decode(
                    (string)($targetRow['meta'] ?? ''),
                    true
                );
                $targetCreatedAt = is_array($targetMeta)
                    ? (int)($targetMeta['event_created_at'] ?? 0) : 0;
                $deletionCreatedAt = max(
                    (int)($p['observed_at'] ?? 0),
                    $targetCreatedAt + 1
                );
                if (!is_string($deletionNostrId)
                    || !is_hex64($deletionNostrId)) {
                    $signerPk = strtolower(
                        (string)($targetRow['signed_by'] ?? '')
                    );
                    $bridgePk = fm_pubkey_hex(fm_secret_bridge_key());
                    if ($signerPk === $bridgePk) {
                        $author = [
                            'path' => 'bridge',
                            'pubkey' => null,
                            'bunker' => null,
                            'login' => (string)$starState['login'],
                        ];
                    } else {
                        $author = bridge_resolve_nostr_author($signerPk);
                        if ($author === null) {
                            throw new BridgeDefer(
                                'waiting for repository-star signer to unstar',
                                300
                            );
                        }
                    }
                    $event = bridge_build_repository_unstar(
                        $repoRow,
                        $full,
                        $targetNostrId,
                        $deletionCreatedAt
                    );
                    if ($author['path'] === 'remote'
                        && (string)$starState['login'] !== '') {
                        $event['tags'][] = [
                            'gh_user',
                            (string)$starState['login'],
                        ];
                    }
                    $event['proxy_url'] = "https://github.com/$full";
                    $event['parent_github_id'] = $pair;
                    $event['meta'] = json_c([
                        'full' => $full,
                        'repository_id' => $repositoryId,
                        'github_user_id' => $githubUserId,
                        'target_nostr_id' => $targetNostrId,
                        'event_created_at' => $deletionCreatedAt,
                        'source' => 'github-star-reconciliation',
                    ]);
                    $deletionNostrId = bridge_gh2nostr(
                        $repoRow,
                        $event,
                        $author,
                        $crossingId
                    );
                }
                $markerId = hash(
                    'sha256',
                    $deletionNostrId . ':' . $targetNostrId
                );
                db()->prepare(
                    "INSERT OR IGNORE INTO deletion_map
                     (deletion_nostr_id,target_nostr_id,marker_id,github_id,
                      parent_github_id,created_at)
                     VALUES (?,?,?,?,?,?)"
                )->execute([
                    $deletionNostrId,
                    $targetNostrId,
                    $markerId,
                    (string)$targetRow['github_id'],
                    $pair,
                    now(),
                ]);
            }
            return null;
        }
        case 'gh2nostr_status_reconcile': {
            if ($repoRow === null) return 'missing repo row';
            require_once __DIR__ . '/github.php';
            $issueGithubId = (string)($p['issue_github_id'] ?? '');
            $root = bridge_root_id($issueGithubId);
            if ($root === null) {
                throw new BridgeDefer('waiting for GitHub issue root mapping');
            }
            $full = (string)($p['full'] ?? '');
            $number = (int)($p['number'] ?? 0);
            bridge_require_current_repo_mapping($full);
            $token = gh_app_token_for_repo($full);
            $history = gh_issue_status_events(
                $token,
                $full,
                $number,
                gh_app_id()
            );
            foreach ($history as $transition) {
                if ($transition['performed_by_bridge']
                    || bridge_already_mapped($transition['github_id'])) {
                    continue;
                }
                bridge_cross_github_status(
                    $repoRow,
                    $full,
                    $number,
                    $issueGithubId,
                    $root,
                    $transition
                );
            }
            return null;
        }
        case 'gh2nostr_comment': {
            if ($repoRow === null) return 'missing repo row';
            $githubId = $p['comment']['node_id'];
            if (bridge_already_mapped($githubId)) return null;
            $root = bridge_root_id($p['issue_node_id']);
            if ($root === null) {
                throw new BridgeDefer('waiting for GitHub issue root mapping');
            }
            [$rootId, $rootAuthorPk] = $root;
            $ev = bridge_build_comment($repoRow, $p['full'], $p['number'], $p['comment'],
                                       $rootId, $rootAuthorPk, null);
            $ev['proxy_url'] = "https://github.com/{$p['full']}/issues/{$p['number']}#issuecomment-{$p['comment']['id']}";
            $ev['parent_github_id'] = $p['issue_node_id'];
            $author = bridge_resolve_author($p['comment']['login']);
            bridge_gh2nostr($repoRow, $ev, $author, $githubId);
            return null;
        }
        case 'gh2nostr_source_delete': {
            if ($repoRow === null) return 'missing repo row';
            $crossingId = (string)($p['crossing_id'] ?? '');
            if ($crossingId === '') return 'missing deletion crossing id';

            $targetKind = (int)($p['target_kind'] ?? 0);
            if (!in_array($targetKind, [1111, 1621], true)) {
                throw new BridgeSkip('invalid GitHub deletion target kind');
            }
            $target = db()->prepare(
                'SELECT * FROM event_map WHERE github_id=? AND kind=?'
            );
            $target->execute([
                (string)($p['target_github_id'] ?? ''),
                $targetKind,
            ]);
            $targetRow = $target->fetch();
            if (!$targetRow) {
                throw new BridgeDefer(
                    'waiting for GitHub deletion target Nostr mapping'
                );
            }
            if ($targetRow['direction'] !== 'gh2nostr') {
                // Deleting the GitHub mirror is not authority to delete an
                // independently authored Nostr source event. Record the
                // missing GitHub target so later out-of-order Nostr
                // dependants do not retry an impossible crossing forever.
                $meta = json_decode(
                    (string)($targetRow['meta'] ?? ''),
                    true
                );
                if (!is_array($meta)) $meta = [];
                $meta['github_deleted'] = true;
                $meta['github_deleted_at'] = gh_event_timestamp(
                    is_string($p['created_at'] ?? null)
                        ? $p['created_at'] : null
                );
                db()->prepare(
                    'UPDATE event_map SET meta=? WHERE github_id=?'
                )->execute([
                    json_c($meta),
                    (string)$targetRow['github_id'],
                ]);
                return null;
            }

            $existingDeletion = db()->prepare(
                'SELECT nostr_id FROM event_map WHERE github_id=? AND kind=5'
            );
            $existingDeletion->execute([$crossingId]);
            $deletionNostrId = $existingDeletion->fetchColumn();

            if (!is_string($deletionNostrId)
                || !is_hex64($deletionNostrId)) {
                $signerPk = strtolower(
                    (string)($targetRow['signed_by'] ?? '')
                );
                $bridgePk = fm_pubkey_hex(fm_secret_bridge_key());
                if (!is_hex64($signerPk)) {
                    throw new BridgeSkip(
                        'source mapping has no valid signer'
                    );
                }
                $githubActor = is_string($p['author'] ?? null)
                    ? $p['author'] : '';
                if ($signerPk === $bridgePk) {
                    $author = [
                        'path' => 'bridge',
                        'pubkey' => null,
                        'bunker' => null,
                        'login' => $githubActor,
                    ];
                } else {
                    $author = bridge_resolve_nostr_author($signerPk);
                    if ($author === null) {
                        throw new BridgeDefer(
                            'waiting for original source signer to delete mirror',
                            300
                        );
                    }
                }
                $ev = bridge_build_deletion(
                    $repoRow,
                    (string)$p['full'],
                    (int)$p['number'],
                    (string)$targetRow['nostr_id'],
                    $targetKind,
                    $targetKind === 1111
                        ? 'The source GitHub issue comment was deleted.'
                        : 'The source GitHub issue was deleted.',
                    is_string($p['created_at'] ?? null)
                        ? $p['created_at'] : null
                );
                if ($author['path'] === 'remote' && $githubActor !== '') {
                    $ev['tags'][] = ['gh_user', $githubActor];
                }
                $ev['proxy_url'] = (string)($p['proxy_url'] ?? '');
                $ev['parent_github_id'] = (string)$p['issue_node_id'];
                $ev['meta'] = json_c([
                    'full' => $p['full'],
                    'number' => (int)$p['number'],
                    'target_nostr_id' => $targetRow['nostr_id'],
                    'source' => 'github',
                ]);
                $deletionNostrId = bridge_gh2nostr(
                    $repoRow,
                    $ev,
                    $author,
                    $crossingId
                );
            }

            $targetNostrId = strtolower((string)$targetRow['nostr_id']);
            $markerId = hash(
                'sha256',
                $deletionNostrId . ':' . $targetNostrId
            );
            db()->prepare(
                "INSERT OR IGNORE INTO deletion_map
                 (deletion_nostr_id,target_nostr_id,marker_id,github_id,
                  parent_github_id,created_at)
                 VALUES (?,?,?,?,?,?)"
            )->execute([
                $deletionNostrId,
                $targetNostrId,
                $markerId,
                (string)$p['target_github_id'],
                (string)$p['issue_node_id'],
                now(),
            ]);
            return null;
        }
        case 'gh2nostr_notice': {
            if ($repoRow === null) return 'missing repo row';
            $crossingId = (string)($p['crossing_id'] ?? '');
            if ($crossingId === '') return 'missing notice crossing id';
            if (bridge_already_mapped($crossingId)) return null;
            $root = bridge_root_id((string)$p['issue_node_id']);
            if ($root === null) {
                throw new BridgeDefer('waiting for GitHub issue root mapping');
            }
            [$rootId, $rootAuthorPk] = $root;
            $notice = [
                'id' => $crossingId,
                'body' => (string)($p['body'] ?? ''),
                'created_at' => $p['created_at'] ?? null,
            ];
            $ev = bridge_build_comment(
                $repoRow,
                (string)$p['full'],
                (int)$p['number'],
                $notice,
                $rootId,
                $rootAuthorPk,
                null);
            $ev['proxy_url'] = (string)($p['proxy_url'] ?? '');
            $ev['parent_github_id'] = (string)$p['issue_node_id'];
            $author = bridge_resolve_author((string)($p['author'] ?? ''));
            bridge_gh2nostr($repoRow, $ev, $author, $crossingId);
            return null;
        }
        case 'nostr2gh_star': {
            require_once __DIR__ . '/github.php';
            $nostrId = strtolower((string)($p['nostr_id'] ?? ''));
            $pubkey = strtolower((string)($p['pubkey'] ?? ''));
            $full = (string)($p['full'] ?? '');
            $repositoryId = (string)($p['repository_id'] ?? '');
            $announcementId = strtolower(
                (string)($p['announcement_nostr_id'] ?? '')
            );
            if (!is_hex64($nostrId) || !is_hex64($pubkey)
                || !ctype_digit($repositoryId)
                || $repositoryId === '0'
                || !is_hex64($announcementId)) {
                throw new BridgeSkip('invalid Nostr repository-star payload');
            }
            if (bridge_nostr_already_mapped($nostrId)) return null;
            if ($repoRow === null) return 'missing repo row';
            if (($GLOBALS['__fm_test_repo_verification'] ?? false) !== true) {
                $relays = json_decode(
                    (string)($repoRow['relays'] ?? ''),
                    true
                );
                $announcement = relay_find_event(
                    $announcementId,
                    is_array($relays) ? $relays : []
                );
                if (!is_array($announcement)) {
                    throw new BridgeDefer(
                        'waiting for referenced repository announcement',
                        300
                    );
                }
                if ((int)($announcement['kind'] ?? 0) !== 30617
                    || strtolower((string)($announcement['pubkey'] ?? ''))
                        !== strtolower((string)$repoRow['owner_pubkey'])
                    || relay_unique_tag_value($announcement, 'd')
                        !== (string)$repoRow['repo_id']) {
                    throw new BridgeSkip(
                        'Nostr star references a different repository event'
                    );
                }
            }
            $github = bridge_github_user_for_nostr_star($pubkey);
            $pair = bridge_github_star_pair(
                $repositoryId,
                $github['github_user_id']
            );
            bridge_bank_github_star_pair(
                $repositoryId,
                $github['github_user_id']
            );
            try {
                if (!gh_user_has_star($github['token'], $full)) {
                    gh_user_set_star($github['token'], $full, true);
                }
            } catch (GhError $error) {
                if (in_array($error->getCode(), [401, 403], true)) {
                    gh_app_require_user_reauthorization($github['login']);
                    throw new BridgeDefer(
                        'waiting for GitHub Starring permission reauthorization',
                        3600
                    );
                }
                throw $error;
            }
            db()->prepare(
                "INSERT OR IGNORE INTO event_map
                 (github_id,nostr_id,direction,kind,author_pk,signed_by,
                  parent_github_id,meta,created_at)
                 VALUES (?,?,?,?,?,?,?,?,?)"
            )->execute([
                'nostr-star:' . $nostrId,
                $nostrId,
                'nostr2gh',
                7,
                $pubkey,
                $pubkey,
                $pair,
                json_c([
                    'full' => $full,
                    'repository_id' => $repositoryId,
                    'github_user_id' => $github['github_user_id'],
                    'github_login' => $github['login'],
                    'announcement_nostr_id' => $announcementId,
                    'event_created_at' => (int)($p['created_at'] ?? 0),
                    'source' => 'nostr-star',
                ]),
                now(),
            ]);
            bridge_log('bridge', 'mirrored nostr->gh repository star', [
                'nostr' => $nostrId,
                'gh' => $full,
                'identity' => $github['login'],
            ]);
            return null;
        }
        case 'nostr2gh_comment': {
            require_once __DIR__ . '/github.php';
            if (bridge_nostr_already_mapped($p['nostr_id'])) return null;

            $rootId = strtolower((string)($p['root_nostr_id'] ?? ''));
            $root = db()->prepare("SELECT github_id,meta,author_pk
                                   FROM event_map
                                   WHERE nostr_id=? AND kind=1621");
            $root->execute([$rootId]);
            $rootRow = $root->fetch();
            if (!$rootRow) {
                throw new BridgeDefer('waiting for Nostr issue root crossing');
            }
            $rootDeleted = db()->prepare(
                'SELECT 1 FROM deletion_map WHERE target_nostr_id=? LIMIT 1'
            );
            $rootDeleted->execute([$rootId]);
            if ($rootDeleted->fetchColumn()) {
                throw new BridgeSkip(
                    'comment root has a valid Nostr deletion request'
                );
            }
            if (($p['root_pubkey'] ?? null) !== $rootRow['author_pk']) {
                throw new BridgeSkip('comment P tag does not match root author');
            }
            $parentId = strtolower((string)($p['parent_nostr_id'] ?? ''));
            if ($parentId === $rootId) {
                if (($p['parent_kind'] ?? null) !== '1621'
                    || ($p['parent_pubkey'] ?? null) !== $rootRow['author_pk']) {
                    throw new BridgeSkip('comment root-parent tags are inconsistent');
                }
            } else {
                $parent = db()->prepare("SELECT author_pk,parent_github_id
                                         FROM event_map
                                         WHERE nostr_id=? AND kind=1111");
                $parent->execute([$parentId]);
                $parentRow = $parent->fetch();
                if (!$parentRow) {
                    throw new BridgeDefer('waiting for parent Nostr comment crossing');
                }
                $parentAuthor = $parentRow['author_pk'];
                if (!hash_equals(
                    (string)$rootRow['github_id'],
                    (string)$parentRow['parent_github_id']
                )) {
                    throw new BridgeSkip(
                        'comment parent belongs to a different root'
                    );
                }
                if (($p['parent_kind'] ?? null) !== '1111'
                    || ($p['parent_pubkey'] ?? null) !== $parentAuthor) {
                    throw new BridgeSkip('comment reply tags do not match parent');
                }
            }

            $meta = json_decode((string)($rootRow['meta'] ?? ''), true);
            $full = is_array($meta) ? (string)($meta['full'] ?? '') : '';
            $number = is_array($meta) ? (int)($meta['number'] ?? 0) : 0;
            if (($meta['github_deleted'] ?? false) === true) {
                throw new BridgeSkip(
                    'GitHub issue mirror was deleted'
                );
            }
            if ($full === '' || $number < 1) {
                throw new BridgeDefer('Nostr issue root has no GitHub coordinates');
            }
            bridge_require_current_repo_mapping($full);
            $performed = bridge_github_execute_for_nostr(
                $p['pubkey'],
                $full,
                function (array $author) use ($p, $full, $number): string {
                    $body = (string)$p['body'];
                    if ($author['path'] === 'app') {
                        $body = bridge_nostr_github_proxy_body(
                            $body,
                            $p['pubkey'],
                            $p['nostr_id']
                        );
                    }
                    return gh_post_issue_comment_idempotent(
                        $author['token'],
                        $full,
                        $number,
                        $body,
                        $p['nostr_id'],
                        (int)$p['queued_at']
                    );
                }
            );
            $nodeId = $performed['result'];
            $author = $performed['author'];
            db()->prepare("INSERT INTO event_map
                           (github_id,nostr_id,direction,kind,author_pk,signed_by,
                            parent_github_id,meta,created_at)
                           VALUES (?,?,?,?,?,?,?,?,?)")
               ->execute([$nodeId, $p['nostr_id'], 'nostr2gh', 1111,
                          $p['pubkey'], $p['pubkey'], $rootRow['github_id'],
                          json_c([
                              'full' => $full,
                              'number' => $number,
                              'github_identity' => $author['path'],
                              'parent_nostr_id' => $parentId,
                          ]),
                          now()]);
            bridge_log('bridge', 'mirrored nostr->gh', [
                'nostr' => $p['nostr_id'], 'gh' => $nodeId,
                'kind'  => 1111, 'as' => "$full#$number",
                'identity' => $author['path'],
            ]);
            return null;
        }
        case 'nostr2gh_issue': {
            require_once __DIR__ . '/github.php';
            if (bridge_nostr_already_mapped($p['nostr_id'])) return null;
            bridge_require_current_repo_mapping((string)$p['full']);
            $performed = bridge_github_execute_for_nostr(
                $p['pubkey'],
                (string)$p['full'],
                function (array $author) use ($p): array {
                    $body = (string)$p['body'];
                    if ($author['path'] === 'app') {
                        $body = bridge_nostr_github_proxy_body(
                            $body,
                            $p['pubkey'],
                            $p['nostr_id']
                        );
                    }
                    return gh_create_issue_idempotent(
                        $author['token'],
                        $p['full'],
                        $p['title'],
                        $body,
                        $p['nostr_id'],
                        (int)$p['queued_at']
                    );
                }
            );
            $res = $performed['result'];
            $author = $performed['author'];
            $githubId = gh_node_id($res);
            $githubNumber = filter_var(
                $res['number'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );
            if ($githubNumber === false) {
                throw new GhError('issue response missing numeric number');
            }
            db()->prepare("INSERT INTO event_map
                           (github_id, nostr_id, direction, kind, author_pk, signed_by, meta, created_at)
                           VALUES (?,?,?,?,?,?,?,?)")
               ->execute([$githubId, $p['nostr_id'], 'nostr2gh', 1621,
                          $p['pubkey'], $p['pubkey'],
                          json_c(['full' => $p['full'], 'number' => $githubNumber,
                                  'title' => $p['title'],
                                  'github_identity' => $author['path']]), now()]);
            bridge_log('bridge', 'mirrored nostr->gh', [
                'nostr' => $p['nostr_id'], 'gh' => $githubId,
                'kind'  => 1621, 'as' => $p['full'] . '#' . $githubNumber,
                'identity' => $author['path'],
            ]);
            return null;
        }
        case 'nostr2gh_status': {
            require_once __DIR__ . '/github.php';
            if (bridge_nostr_already_mapped($p['nostr_id'])) return null;
            $kind = (int)($p['kind'] ?? 0);
            $eventCreatedAt = (int)($p['created_at'] ?? 0);
            if (!in_array($kind, [1630, 1631, 1632, 1633], true)
                || $eventCreatedAt < 1
                || !is_hex64(strtolower((string)($p['nostr_id'] ?? '')))) {
                throw new BridgeSkip('invalid Nostr status payload');
            }

            $root = db()->prepare("SELECT github_id,meta,author_pk
                                   FROM event_map
                                   WHERE nostr_id=? AND kind=1621");
            $root->execute([strtolower((string)$p['root_nostr_id'])]);
            $rootRow = $root->fetch();
            if (!$rootRow) {
                throw new BridgeDefer('waiting for Nostr status root crossing');
            }
            $rootDeleted = db()->prepare(
                'SELECT 1 FROM deletion_map WHERE target_nostr_id=? LIMIT 1'
            );
            $rootDeleted->execute([
                strtolower((string)$p['root_nostr_id'])
            ]);
            if ($rootDeleted->fetchColumn()) {
                throw new BridgeSkip(
                    'status root has a valid Nostr deletion request'
                );
            }
            $meta = json_decode((string)($rootRow['meta'] ?? ''), true);
            $full = is_array($meta) ? (string)($meta['full'] ?? '') : '';
            $number = is_array($meta) ? (int)($meta['number'] ?? 0) : 0;
            if (($meta['github_deleted'] ?? false) === true) {
                throw new BridgeSkip(
                    'GitHub issue mirror was deleted'
                );
            }
            if ($full === '' || $number < 1) {
                throw new BridgeDefer('Nostr status root has no GitHub coordinates');
            }
            $repoRow = bridge_require_current_repo_mapping($full);
            $authorized = bridge_nostr_status_authorized(
                $p['pubkey'],
                $rootRow['author_pk'],
                $repoRow
            );
            if ($authorized === null) {
                throw new BridgeDefer(
                    'waiting to verify Nostr repository maintainer state',
                    300
                );
            }
            if (!$authorized) {
                throw new BridgeSkip('Nostr status author is not authoritative');
            }
            $mentionedPubkeys = is_array($p['mentioned_pubkeys'] ?? null)
                ? $p['mentioned_pubkeys'] : [];
            if (!in_array($repoRow['owner_pubkey'], $mentionedPubkeys, true)
                || !in_array($rootRow['author_pk'], $mentionedPubkeys, true)) {
                throw new BridgeSkip(
                    'Nostr status is missing repository/root author p tags'
                );
            }

            $states = [
                1630 => 'open',
                1631 => 'resolved',
                1632 => 'closed',
                1633 => 'draft',
            ];
            $latest = bridge_latest_nostr_status(
                (string)$rootRow['github_id']
            );
            if ($latest !== null
                && ($latest['event_created_at'] > $eventCreatedAt
                    || ($latest['event_created_at'] === $eventCreatedAt
                        && strcmp(
                            $latest['nostr_id'],
                            strtolower((string)$p['nostr_id'])
                        ) < 0))) {
                bridge_record_nostr_status(
                    $p,
                    $rootRow,
                    $full,
                    $number,
                    $states[$kind],
                    'superseded',
                    false
                );
                return null;
            }

            // GitHub issues have no Draft state. Bank the valid NIP-34 head
            // so an older arriving Open/Closed event cannot overwrite it,
            // but do not invent a GitHub label/comment as fake state.
            if ($kind === 1633) {
                bridge_record_nostr_status(
                    $p,
                    $rootRow,
                    $full,
                    $number,
                    'draft',
                    'not-representable',
                    false
                );
                return null;
            }

            $performed = bridge_github_execute_for_nostr(
                $p['pubkey'],
                $full,
                fn(array $author): array => gh_set_issue_status(
                    $author['token'],
                    $full,
                    $number,
                    $kind
                )
            );
            $author = $performed['author'];
            bridge_record_nostr_status(
                $p,
                $rootRow,
                $full,
                $number,
                $states[$kind],
                $author['path'],
                true
            );
            bridge_log('bridge', 'mirrored nostr->gh status', [
                'nostr' => $p['nostr_id'],
                'gh' => "$full#$number",
                'state' => $states[$kind],
                'identity' => $author['path'],
            ]);
            return null;
        }
        case 'nostr2gh_deletion': {
            require_once __DIR__ . '/github.php';
            $deletionId = strtolower((string)($p['nostr_id'] ?? ''));
            $targetId = strtolower((string)($p['target_nostr_id'] ?? ''));
            $done = db()->prepare("SELECT 1 FROM deletion_map
                                   WHERE deletion_nostr_id=? AND target_nostr_id=?");
            $done->execute([$deletionId, $targetId]);
            if ($done->fetchColumn()) return null;

            $target = db()->prepare("SELECT * FROM event_map WHERE nostr_id=?");
            $target->execute([$targetId]);
            $targetRow = $target->fetch();
            if (!$targetRow) {
                throw new BridgeDefer('waiting for Nostr deletion target crossing');
            }
            if (!hash_equals(
                strtolower((string)$targetRow['author_pk']),
                strtolower((string)$p['pubkey']))) {
                throw new BridgeSkip('Nostr deletion author does not own target');
            }
            if ((int)$targetRow['kind'] === 5) {
                throw new BridgeSkip(
                    'deleting a Nostr deletion request has no effect'
                );
            }

            if ((int)$targetRow['kind'] === 7) {
                $targetMeta = json_decode(
                    (string)($targetRow['meta'] ?? ''),
                    true
                );
                $full = is_array($targetMeta)
                    ? (string)($targetMeta['full'] ?? '') : '';
                $repositoryId = is_array($targetMeta)
                    ? (string)($targetMeta['repository_id'] ?? '') : '';
                if ($full === '' || !ctype_digit($repositoryId)
                    || $repositoryId === '0') {
                    throw new BridgeDefer(
                        'repository star has no GitHub coordinates'
                    );
                }
                bridge_require_current_repo_mapping($full);
                $github = bridge_github_user_for_nostr_star(
                    (string)$p['pubkey']
                );
                $pair = bridge_github_star_pair(
                    $repositoryId,
                    $github['github_user_id']
                );
                if (!hash_equals(
                    $pair,
                    (string)$targetRow['parent_github_id']
                )) {
                    throw new BridgeSkip(
                        'repository star belongs to another GitHub identity'
                    );
                }
                $other = db()->prepare(
                    "SELECT 1
                     FROM event_map em
                     LEFT JOIN deletion_map dm
                       ON dm.target_nostr_id=em.nostr_id
                     WHERE em.parent_github_id=? AND em.kind=7
                       AND em.nostr_id<>?
                       AND dm.target_nostr_id IS NULL
                     LIMIT 1"
                );
                $other->execute([$pair, $targetId]);
                $githubChanged = false;
                if (!$other->fetchColumn()) {
                    try {
                        if (gh_user_has_star($github['token'], $full)) {
                            gh_user_set_star(
                                $github['token'],
                                $full,
                                false
                            );
                            $githubChanged = true;
                        }
                    } catch (GhError $error) {
                        if (in_array(
                            $error->getCode(),
                            [401, 403],
                            true
                        )) {
                            gh_app_require_user_reauthorization(
                                $github['login']
                            );
                            throw new BridgeDefer(
                                'waiting for GitHub Starring permission reauthorization',
                                3600
                            );
                        }
                        throw $error;
                    }
                }
                $markerId = hash(
                    'sha256',
                    "$deletionId:$targetId"
                );
                db()->prepare(
                    "INSERT INTO deletion_map
                     (deletion_nostr_id,target_nostr_id,marker_id,github_id,
                      parent_github_id,created_at)
                     VALUES (?,?,?,?,?,?)"
                )->execute([
                    $deletionId,
                    $targetId,
                    $markerId,
                    'star-delete:' . $deletionId . ':' . $targetId,
                    $pair,
                    now(),
                ]);
                bridge_log('bridge', 'mirrored nostr->gh repository unstar', [
                    'nostr' => $deletionId,
                    'target' => $targetId,
                    'gh' => $full,
                    'github_changed' => $githubChanged,
                    'identity' => $github['login'],
                ]);
                return null;
            }

            $rootRow = $targetRow;
            if ((int)$targetRow['kind'] !== 1621) {
                $root = db()->prepare("SELECT * FROM event_map
                                       WHERE github_id=? AND kind=1621");
                $root->execute([(string)$targetRow['parent_github_id']]);
                $rootRow = $root->fetch();
                if (!$rootRow) {
                    throw new BridgeDefer('waiting for deletion target root crossing');
                }
            }
            $meta = json_decode((string)($rootRow['meta'] ?? ''), true);
            $targetMeta = json_decode(
                (string)($targetRow['meta'] ?? ''),
                true
            );
            $full = is_array($meta) ? (string)($meta['full'] ?? '') : '';
            $number = is_array($meta) ? (int)($meta['number'] ?? 0) : 0;
            $githubAlreadyDeleted = (
                is_array($meta)
                && ($meta['github_deleted'] ?? false) === true
            ) || (
                is_array($targetMeta)
                && ($targetMeta['github_deleted'] ?? false) === true
            );
            if ($full === '' || $number < 1) {
                throw new BridgeDefer('deletion target has no GitHub coordinates');
            }

            $markerId = hash('sha256', "$deletionId:$targetId");
            $parentGithubId = (string)$rootRow['github_id'];

            if (in_array(
                (int)$targetRow['kind'],
                [1630, 1631, 1632, 1633],
                true
            )) {
                $current = bridge_latest_nostr_status($parentGithubId);
                $wasHead = $current !== null
                    && hash_equals($current['nostr_id'], $targetId);
                $githubIdentity = 'not-current';
                $effectiveState = 'unchanged';

                if ($wasHead) {
                    $next = bridge_latest_nostr_status(
                        $parentGithubId,
                        $targetId
                    );
                    $nextKind = $next['kind'] ?? 1630;
                    $stateNames = [
                        1630 => 'open',
                        1631 => 'resolved',
                        1632 => 'closed',
                        1633 => 'draft',
                    ];
                    $effectiveState = $stateNames[$nextKind];
                    if ($nextKind === 1633) {
                        // GitHub Issues has no Draft state. The Nostr Draft
                        // remains the effective head while GitHub is left
                        // unchanged; do not invent a label or comment state.
                        $githubIdentity = 'not-representable';
                    } elseif ($githubAlreadyDeleted) {
                        // A delayed Nostr status deletion still changes the
                        // reduced Nostr head, but there is no GitHub issue left
                        // to mutate. Record it without waiting for App access.
                        $githubIdentity = 'already-deleted';
                    } else {
                        bridge_require_current_repo_mapping($full);
                        $performed = bridge_github_execute_for_nostr(
                            $p['pubkey'],
                            $full,
                            fn(array $author): array => gh_set_issue_status(
                                $author['token'],
                                $full,
                                $number,
                                $nextKind
                            )
                        );
                        $githubIdentity = $performed['author']['path'];
                    }
                }

                $githubId = 'status-delete:' . $parentGithubId
                    . ':' . $deletionId . ':' . $targetId;
                db()->prepare(
                    "INSERT INTO deletion_map
                     (deletion_nostr_id,target_nostr_id,marker_id,github_id,
                      parent_github_id,created_at)
                     VALUES (?,?,?,?,?,?)"
                )->execute([
                    $deletionId,
                    $targetId,
                    $markerId,
                    $githubId,
                    $parentGithubId,
                    now(),
                ]);
                bridge_log('bridge', 'mirrored Nostr status deletion', [
                    'nostr' => $deletionId,
                    'target' => $targetId,
                    'gh' => "$full#$number",
                    'effective_state' => $effectiveState,
                    'identity' => $githubIdentity,
                ]);
                return null;
            }

            $reason = trim((string)($p['reason'] ?? ''));
            $notice = "Deletion requested on Nostr by `"
                . fm_npub_encode($p['pubkey']) . "`.\n\n"
                . "Deletion event: `$deletionId`.\n\n"
                . ($reason !== '' ? "Reason: $reason" : 'No reason supplied.');
            if ($githubAlreadyDeleted) {
                $githubId = (string)$targetRow['github_id'];
                $author = ['path' => 'already-deleted'];
            } else {
                bridge_require_current_repo_mapping($full);
                $performed = bridge_github_execute_for_nostr(
                    $p['pubkey'],
                    $full,
                    function (array $author) use (
                        $targetRow,
                        $notice,
                        $markerId,
                        $full,
                        $number
                    ): string {
                        if ((int)$targetRow['kind'] === 1621) {
                            $body = gh_body_with_marker($notice, $markerId);
                            $response = gh_tombstone_issue(
                                $author['token'],
                                $full,
                                $number,
                                $body
                            );
                            return (string)($response['node_id']
                                ?? ('deleted:' . $targetRow['github_id']));
                        }
                        gh_delete_issue_comment_by_node_id(
                            $author['token'],
                            $full,
                            $number,
                            (string)$targetRow['github_id']
                        );
                        return (string)$targetRow['github_id'];
                    }
                );
                $githubId = $performed['result'];
                $author = $performed['author'];
            }
            db()->prepare("INSERT INTO deletion_map
                           (deletion_nostr_id,target_nostr_id,marker_id,github_id,
                            parent_github_id,created_at)
                           VALUES (?,?,?,?,?,?)")
               ->execute([
                   $deletionId,
                   $targetId,
                   $markerId,
                   $githubId,
                   $parentGithubId,
                   now(),
               ]);
            bridge_log('bridge', 'mirrored nostr->gh deletion', [
                'nostr' => $deletionId,
                'target' => $targetId,
                'gh' => "$full#$number",
                'identity' => $author['path'],
            ]);
            return null;
        }
        case 'nostr_backfill': {
            require_once __DIR__ . '/../cron_handler.php';
            $rootId = strtolower((string)($p['root_id'] ?? ''));
            $relay = (string)($p['relay'] ?? '');
            $tag = (string)($p['tag'] ?? '');
            $kinds = $p['kinds'] ?? [];
            $since = max(1, (int)($p['since'] ?? 1));
            $until = max($since, (int)($p['until'] ?? now()));
            if (!is_hex64($rootId) || !relay_url_valid($relay)
                || !in_array($tag, ['E', 'e'], true)
                || !is_array($kinds) || !$kinds) {
                throw new BridgeSkip('invalid Nostr root backfill payload');
            }
            $limit = 1000;
            [$events, $complete] = relay_query([
                'kinds' => array_values(array_map('intval', $kinds)),
                '#' . $tag => [$rootId],
                'since' => $since,
                'until' => $until,
                'limit' => $limit,
            ], [$relay], 8.0);
            if (!$complete) {
                throw new BridgeDefer(
                    'Nostr root backfill did not reach EOSE',
                    300
                );
            }

            $created = [];
            foreach ($events as $event) {
                $ts = (int)($event['created_at'] ?? 0);
                if ($ts > 0) $created[] = $ts;
                cron_handle_nostr_event($event);
            }
            if (count($events) >= $limit && $created) {
                $nextUntil = min($created) - 1;
                if ($nextUntil >= $since) {
                    $name = (string)($p['scan_name']
                        ?? ($tag === 'E' ? 'comments' : 'statuses'));
                    jobs_enqueue('nostr_backfill', [
                        'root_id' => $rootId,
                        'relay' => $relay,
                        'tag' => $tag,
                        'scan_name' => $name,
                        'kinds' => $kinds,
                        'since' => $since,
                        'until' => $nextUntil,
                    ], "nostrbackfill:$relay:$rootId:$name:$nextUntil");
                }
            }
            return null;
        }
    }
    return 'unknown job type ' . $job['type'];
}

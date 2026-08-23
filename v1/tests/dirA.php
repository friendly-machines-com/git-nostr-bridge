<?php
/**
 * tests/dirA.php -- OFFLINE Direction A replay.
 * Relay layer stubbed via relay.php's function_exists seam (no network).
 * Exercises: classification inputs, event building (1621/1111), thread
 * parenting, proxy tags on the bridge path, event_map ledger, job dedupe.
 *
 * Usage: BRIDGE_DB=/tmp/x.db php tests/dirA.php
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') exit(1);

define('BRIDGE_ENTRY', true);
if (!getenv('BRIDGE_DB')) putenv('BRIDGE_DB=/tmp/fm-dirA.db');
@unlink(getenv('BRIDGE_DB'));

// self-contained throwaway secrets for this run (never the real ones)
$ts = sys_get_temp_dir() . '/fm-secrets-' . getmypid();
@mkdir($ts, 0700, true);
file_put_contents("$ts/db-crypt.php", "<?php return \"" . bin2hex(random_bytes(32)) . "\";");
file_put_contents("$ts/bridge-key.php", "<?php return \"" . bin2hex(random_bytes(32)) . "\";");
chmod("$ts/db-crypt.php", 0600);
chmod("$ts/bridge-key.php", 0600);
$GLOBALS['__fm_test_secrets_dir'] = $ts;
$GLOBALS['__fm_test_log'] = '/tmp/fm-test-dirA.log';   // keep test noise out of the real log
$GLOBALS['__fm_test_repo_verification'] = true;
$GLOBALS['__fm_test_github_app'] = [
    'client_id' => 'Iv1.test-bridge',
    'client_secret' => 'test-secret',
];
$GLOBALS['__fm_test_github_app_id'] = '4242';

// --- stub the relay seam BEFORE lib/relay.php loads -------------------------
$GLOBALS['__published'] = [];
$GLOBALS['__relay_found_event'] = null;
$GLOBALS['__relay_query_events'] = [];
function observe_nip46_job_phase(string $operation): void
{
    $payload = db()->query(
        "SELECT payload FROM jobs WHERE type='nip46_finish'
         ORDER BY id DESC LIMIT 1"
    )->fetchColumn();
    $decoded = json_decode((string)$payload, true);
    $phase = is_array($decoded) ? ($decoded['phase'] ?? null) : null;
    if (is_string($phase)) {
        $GLOBALS['__nip46_observed_phases'][$operation][$phase] = true;
    }
}
function relay_defaults(): array { return ['wss://relay.damus.io', 'wss://nos.lol']; }
function relay_publish(array $event, array $relays, float $t = 6.0): array {
    $GLOBALS['__published'][] = $event;
    return [($relays[0] ?? 'r') => 'ok'];
}
function relay_query(array $f, array $r, float $t = 4.0): array {
    return [$GLOBALS['__relay_query_events'], true];
}
function relay_find_event(string $id, array $relays): ?array {
    $event = $GLOBALS['__relay_found_event'];
    return is_array($event) && ($event['id'] ?? '') === $id ? $event : null;
}
function nip46_collect_connect_events(
    array $clientPks,
    array $relays,
    int $since,
    float $timeoutSecs = 8.0
): array {
    return array_map(
        fn($event) => [
            'relays' => ['wss://relay.damus.io'],
            'event' => $event,
        ],
        $GLOBALS['__relay_query_events']
    );
}
function bridge_nip46_get_public_key(
    string $clientPriv,
    string $clientPk,
    string $bunkerPk,
    string $relay,
    ?callable $onAuthUrl = null
): ?string {
    observe_nip46_job_phase('get_public_key');
    $GLOBALS['__nip46_get_public_key_relays'][] = $relay;
    if (is_array($GLOBALS['__nip46_user_pk_by_relay'] ?? null)) {
        return $GLOBALS['__nip46_user_pk_by_relay'][$relay] ?? null;
    }
    return $GLOBALS['__nip46_user_pk'] ?? null;
}
function bridge_nip46_connection_relays(
    string $clientPriv,
    string $clientPk,
    string $bunkerPk,
    array $connectedRelays,
    ?callable $onAuthUrl = null
): array {
    observe_nip46_job_phase('switch_relays');
    if (($GLOBALS['__nip46_interleave_db_write'] ?? false) === true) {
        $GLOBALS['__nip46_interleave_db_write'] = false;
        $other = new PDO('sqlite:' . getenv('BRIDGE_DB'));
        $other->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $other->exec('PRAGMA busy_timeout=1000');
        $other->exec(
            "INSERT INTO schema_meta(k,v) VALUES "
            . "('test_concurrent_web_poll','committed') "
            . "ON CONFLICT(k) DO UPDATE SET v=excluded.v"
        );
        $other = null;
    }
    return $GLOBALS['__nip46_connection_relays'] ?? $connectedRelays;
}
function bridge_nip46_prove_user_key(
    string $clientPriv,
    string $clientPk,
    string $bunkerUri,
    string $userPk,
    string $stateId,
    int $createdAt,
    ?callable $onAuthUrl = null
): bool {
    observe_nip46_job_phase('sign_challenge');
    $GLOBALS['__nip46_proof'] = compact(
        'bunkerUri',
        'userPk',
        'stateId',
        'createdAt'
    );
    return ($GLOBALS['__nip46_proof_result'] ?? true) === true;
}
function gh_issue_status_events(
    string $token,
    string $fullName,
    int $number,
    string $bridgeClientId
): array {
    return $GLOBALS['__gh_status_history'] ?? [];
}
function gh_repository_star_state_for_user(
    string $token,
    string $repositoryId,
    string $githubUserId
): array {
    return $GLOBALS['__gh_repository_star_state'];
}

require __DIR__ . '/../db.php';
require_once __DIR__ . '/../lib/util.php';
require_once __DIR__ . '/../lib/secrets.php';
require_once __DIR__ . '/../lib/crypto.php';
require_once __DIR__ . '/../lib/jobs.php';
require_once __DIR__ . '/../lib/bridge.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $n): void { global $pass, $fail; if ($c) { $pass++; echo "  ok  $n\n"; } else { $fail++; echo "FAIL  $n\n"; } }

// real captured shapes (2026-08-20, friendly-machines-com/dummy)
$issue = ['id' => 5198711839, 'node_id' => 'I_kwDOT-FXI88AAAABNd4MHw', 'number' => 1,
  'title' => 'x', 'body' => null, 'user' => ['login' => 'daym'], 'state' => 'open',
  'created_at' => '2026-08-20T01:30:31Z',
  'updated_at' => '2026-08-20T01:30:31Z'];
$repo = ['id' => 1340167971, 'name' => 'dummy', 'full_name' => 'friendly-machines-com/dummy',
  'owner' => ['id' => 7001, 'login' => 'friendly-machines-com',
              'type' => 'Organization']];
$installation = ['id' => 42001, 'account' => $repo['owner'],
                 'repository_selection' => 'selected'];
$comment = ['id' => 5350111927, 'node_id' => 'IC_kwDOT-FXI88AAAABPuQ6tw', 'body' => 'zz5',
  'user' => ['login' => 'daym'], 'created_at' => '2026-08-20T01:36:05Z'];

// Any signed App webhook banks its organization or personal installation.
gh_app_bank_webhook_context([
    'installation' => $installation,
    'repository' => $repo,
]);
db()->prepare(
    "UPDATE github_installations
     SET token_enc=?,token_expires_at=? WHERE installation_id=?"
)->execute([
    fm_encrypt_at_rest('ghs_authoritatively_reconciled'),
    now() + 3600,
    (string)$installation['id'],
]);
$st = db()->prepare(
    "SELECT 1 FROM github_installations
     WHERE account_login=? AND account_type='Organization' AND status='active'"
);
$st->execute(['friendly-machines-com']);
ok((bool)$st->fetchColumn(), 'installed organization accepted');

// map the repo (simulating verified 30617 lookup)
db()->prepare("INSERT INTO repos (github_full_name, repo_id, owner_pubkey, relays,
               verified,bridge_authorized,created_at,updated_at)
               VALUES (?,?,?,?,1,1,?,?)")
   ->execute([$repo['full_name'], 'dummy', str_repeat('aa', 32),
              json_encode(['wss://relay.damus.io']), now(), now()]);
$repoRow = bridge_repo_row($repo);
$GLOBALS['__fm_test_repo_announcement'] = [
    'id' => str_repeat('bc', 32),
    'pubkey' => str_repeat('aa', 32),
    'kind' => 30617,
    'created_at' => now() - 1000,
    'tags' => [['d', 'dummy']],
    'content' => '',
];
ok($repoRow !== null && (int)$repoRow['verified'] === 1, 'repo row resolved');
ok(bridge_repo_row(['full_name' => 'evil/other', 'owner' => ['login' => 'evil']]) === null,
   'unmapped repository rejected');
db()->prepare('UPDATE repos SET bridge_authorized=0 WHERE github_full_name=?')
   ->execute([$repo['full_name']]);
ok(bridge_repo_ensure($repo) !== null,
   'verified repo crosses even when bridge key is not a maintainer');
$repoRow = bridge_repo_row($repo);

// 1. issue opened -> 1621 (bridge path: author unlinked)
$ev = bridge_build_issue($repoRow, ['number' => 1, 'title' => 'x', 'body' => 'issue body',
    'node_id' => $issue['node_id'], 'created_at' => $issue['created_at'],
    'full_name' => $repo['full_name']]);
$ev['proxy_url'] = "https://github.com/{$repo['full_name']}/issues/1";
$author = bridge_resolve_author('daym');
ok($author['path'] === 'bridge', 'unlinked author -> bridge path');
$id1 = bridge_gh2nostr($repoRow, $ev, $author, $issue['node_id']);
$sig1 = $GLOBALS['__published'][0];
ok($sig1['kind'] === 1621, 'kind 1621');
ok(fm_event_verify($sig1), '1621 signature verifies');
ok(in_array(['a', '30617:' . str_repeat('aa', 32) . ':dummy'], $sig1['tags']), 'a-tag -> 30617');
ok(in_array(['p', str_repeat('aa', 32)], $sig1['tags']), 'p-tag owner');
ok(in_array(['subject', 'x'], $sig1['tags']), 'subject tag');
ok(in_array(['t', 'gh-1'], $sig1['tags']), 't gh-1 label');
ok(in_array(['gh', 'friendly-machines-com/dummy#1'], $sig1['tags']), 'gh tag');
ok(in_array(['proxy', "https://github.com/{$repo['full_name']}/issues/1", 'github'], $sig1['tags']),
   'proxy tag (honest origin)');
ok(in_array(['gh_user', 'daym'], $sig1['tags']), 'gh_user tag');

// 2. first comment -> 1111 rooted at the 1621
$root = bridge_root_id($issue['node_id']);
ok($root !== null && $root[0] === $id1, 'root lookup by node_id');
$parent = null; // GitHub issue comments are flat/top-level, not reply-to chains
ok($parent === null, 'first GitHub comment is top-level');
$ev2 = bridge_build_comment($repoRow, $repo['full_name'], 1, $comment, $root[0], $root[1], $parent);
$ev2['proxy_url'] = "https://github.com/{$repo['full_name']}/issues/1#issuecomment-{$comment['id']}";
$ev2['parent_github_id'] = $issue['node_id'];
$id2 = bridge_gh2nostr($repoRow, $ev2, bridge_resolve_author('daym'), $comment['node_id']);
$sig2 = $GLOBALS['__published'][1];
ok($sig2['kind'] === 1111, 'kind 1111');
ok(fm_event_verify($sig2), '1111 signature verifies');
// root author for tags = the 1621's SIGNER (bridge key on bridge path)
$bridgePk = fm_pubkey_hex(fm_secret_bridge_key());
ok($sig2['tags'][0] === ['E', $id1, '', $bridgePk], 'E root -> 1621 id + signer');
ok($sig2['tags'][1] === ['K', '1621'], 'K root kind');
ok($sig2['tags'][2] === ['P', $bridgePk], 'P root author (signer)');
ok($sig2['tags'][3] === ['e', $id1, '', $bridgePk], 'e parent = root (top-level)');
ok($sig2['tags'][4] === ['k', '1621'], 'k parent kind');
ok(in_array(['gh_user', 'daym'], $sig2['tags']), 'proxy/gh_user on comment too');

// Repository registration accepts only an owner-signed announcement that
// authorizes the bridge and declares exactly the registered relay set.
$announcementOwnerSec = random_hex(32);
$announcementOwnerPk = fm_pubkey_hex($announcementOwnerSec);
$announcement = fm_event_sign([
    'kind' => 30617, 'pubkey' => $announcementOwnerPk, 'created_at' => now(),
    'content' => '', 'tags' => [
        ['d', 'registered-repo'],
        ['maintainers', $bridgePk],
        ['relays', 'wss://relay.damus.io'],
    ],
], $announcementOwnerSec);
$GLOBALS['__relay_query_events'] = [$announcement];
ok(relay_verify_repo_owner(
    'registered-repo', $announcementOwnerPk, ['wss://relay.damus.io'],
    $bridgePk, ['wss://relay.damus.io']),
   '30617 owner, maintainer, and declared relay verified');
ok(!relay_verify_repo_owner(
    'registered-repo', $announcementOwnerPk, ['wss://relay.damus.io'],
    fm_pubkey_hex(random_hex(32)), ['wss://relay.damus.io']),
   '30617 missing bridge maintainer rejected');
ok(!relay_verify_repo_owner(
    'registered-repo', $announcementOwnerPk, ['wss://relay.damus.io'],
    $bridgePk, ['wss://other.example']),
   '30617 undeclared registration relay rejected');
$twoRelayAnnouncement = $announcement;
$twoRelayAnnouncement['created_at'] = now() + 1;
$twoRelayAnnouncement['tags'] = [
    ['d', 'registered-repo'],
    ['maintainers', $bridgePk],
    ['relays', 'wss://z.example', 'wss://relay.damus.io'],
    ['relays', 'wss://z.example'],
];
$twoRelayAnnouncement = fm_event_sign(
    $twoRelayAnnouncement,
    $announcementOwnerSec
);
$GLOBALS['__relay_query_events'] = [$twoRelayAnnouncement];
ok(!relay_verify_repo_owner(
    'registered-repo',
    $announcementOwnerPk,
    ['wss://relay.damus.io'],
    $bridgePk,
    ['wss://relay.damus.io']
), '30617 additional declared relay cannot be omitted from registration');
ok(relay_verify_repo_owner(
    'registered-repo',
    $announcementOwnerPk,
    ['wss://z.example', 'wss://relay.damus.io', 'wss://z.example'],
    $bridgePk,
    ['wss://relay.damus.io', 'wss://z.example']
), '30617 relay verification is invariant under order and duplicates');
$invalidRelayAnnouncement = $twoRelayAnnouncement;
$invalidRelayAnnouncement['created_at'] = now() + 2;
$invalidRelayAnnouncement['tags'][2][] = 'http://not-a-nostr-relay.example';
$invalidRelayAnnouncement = fm_event_sign(
    $invalidRelayAnnouncement,
    $announcementOwnerSec
);
$GLOBALS['__relay_query_events'] = [$invalidRelayAnnouncement];
ok(!relay_verify_repo_owner(
    'registered-repo',
    $announcementOwnerPk,
    ['wss://z.example', 'wss://relay.damus.io'],
    $bridgePk,
    ['wss://relay.damus.io', 'wss://z.example']
), '30617 invalid extra relay cannot disappear during set normalization');
$conflictingIdentifier = $announcement;
$conflictingIdentifier['created_at'] = now() + 3;
$conflictingIdentifier['tags'][] = ['d', 'other-repo'];
$conflictingIdentifier = fm_event_sign(
    $conflictingIdentifier,
    $announcementOwnerSec
);
$GLOBALS['__relay_query_events'] = [$conflictingIdentifier];
ok(!relay_verify_repo_owner(
    'registered-repo',
    $announcementOwnerPk,
    ['wss://relay.damus.io'],
    $bridgePk,
    ['wss://relay.damus.io']
), 'conflicting scalar d tags cannot select a repository by tag order');

// A 30617 publisher normally is an implicit maintainer, but NIP-34 removes
// that implication when the announcement contains a subordinate-fork u tag.
$subordinateAnnouncement = $announcement;
$subordinateAnnouncement['created_at'] = now() + 1;
$subordinateAnnouncement['tags'] = [
    ['d', 'registered-repo'],
    [
        'u',
        '30617:' . fm_pubkey_hex(random_hex(32)) . ':upstream',
        'wss://relay.damus.io',
        fm_pubkey_hex(random_hex(32)),
    ],
    ['relays', 'wss://relay.damus.io'],
];
$subordinateAnnouncement = fm_event_sign(
    $subordinateAnnouncement,
    $announcementOwnerSec
);
$GLOBALS['__relay_query_events'] = [$subordinateAnnouncement];
ok(!relay_verify_repo_owner(
    'registered-repo',
    $announcementOwnerPk,
    ['wss://relay.damus.io'],
    $announcementOwnerPk,
    ['wss://relay.damus.io']
), 'subordinate-fork publisher is not an implicit maintainer');
ok(bridge_nostr_status_authorized(
    $announcementOwnerPk,
    fm_pubkey_hex(random_hex(32)),
    [
        'repo_id' => 'registered-repo',
        'owner_pubkey' => $announcementOwnerPk,
        'relays' => '["wss://relay.damus.io"]',
    ]
) === false, 'subordinate-fork publisher cannot authorize issue status');

// Addressable repository announcements reduce by source time, never relay
// delivery order. A newer version that removes authorization wins.
$staleAnnouncement = $announcement;
$staleAnnouncement['created_at'] = now() - 10;
$staleAnnouncement = fm_event_sign($staleAnnouncement, $announcementOwnerSec);
$currentAnnouncement = $announcement;
$currentAnnouncement['created_at'] = now();
$currentAnnouncement['tags'] = [
    ['d', 'registered-repo'],
    ['relays', 'wss://relay.damus.io'],
];
$currentAnnouncement = fm_event_sign(
    $currentAnnouncement,
    $announcementOwnerSec
);
$GLOBALS['__relay_query_events'] = [
    $staleAnnouncement,
    $currentAnnouncement,
];
ok(!relay_verify_repo_owner(
    'registered-repo', $announcementOwnerPk, ['wss://relay.damus.io'],
    $bridgePk, ['wss://relay.damus.io']),
   'newest 30617 wins even when stale authorization arrives first');
$GLOBALS['__relay_query_events'] = [];

// A verified announcement is a durable input, not a cache of one relay's
// latest response. Empty reads cannot erase it; replacement and deletion
// events reduce correctly in either arrival order.
$ledgerSec = random_hex(32);
$ledgerPk = fm_pubkey_hex($ledgerSec);
$ledgerFull = 'friendly-machines-com/ledger-repo';
$ledgerRow = [
    'github_full_name' => $ledgerFull,
    'repo_id' => 'ledger-repo',
    'owner_pubkey' => $ledgerPk,
    'relays' => json_c(['wss://relay.damus.io']),
    'verified' => 1,
    'bridge_authorized' => 0,
    'created_at' => now(),
    'updated_at' => now(),
];
db()->prepare(
    "INSERT INTO repos
     (github_full_name,repo_id,owner_pubkey,relays,verified,
      bridge_authorized,created_at,updated_at)
     VALUES (?,?,?,?,?,?,?,?)"
)->execute(array_values($ledgerRow));
db()->prepare(
    "INSERT INTO github_installation_repositories
     (repository_id,installation_id,github_full_name,status,created_at,updated_at)
     VALUES ('ledger-repository-id','42001',?,'active',?,?)"
)->execute([$ledgerFull, now(), now()]);
$ledgerBase = now() - 100;
$bankedAnnouncement = fm_event_sign([
    'kind' => 30617,
    'pubkey' => $ledgerPk,
    'created_at' => $ledgerBase,
    'content' => '',
    'tags' => [
        ['d', 'ledger-repo'],
        ['relays', 'wss://relay.damus.io'],
    ],
], $ledgerSec);
ok(
    repo_bank_announcement($ledgerRow, $bankedAnnouncement, $bridgePk),
    'verified repository announcement is banked durably'
);
$GLOBALS['__fm_test_repo_verification'] = false;
$requiredLedger = bridge_require_current_repo_mapping($ledgerFull);
$GLOBALS['__fm_test_repo_verification'] = true;
ok(
    (int)$requiredLedger['verified'] === 1
    && ($requiredLedger['_announcement']['id'] ?? null)
        === $bankedAnnouncement['id'],
    'empty relay observation cannot erase banked repository authority'
);

$ledgerAddress = "30617:$ledgerPk:ledger-repo";
$commentDeletionTemplate = bridge_build_deletion(
    $ledgerRow,
    $ledgerFull,
    7,
    str_repeat('ab', 32),
    1111,
    'comment deleted',
    gmdate('c', $ledgerBase + 10)
);
$commentDeletion = fm_event_sign([
    ...$commentDeletionTemplate,
    'pubkey' => $ledgerPk,
], $ledgerSec);
ok(
    !in_array($ledgerAddress, array_column(
        $commentDeletion['tags'],
        1
    ), true)
    && repo_reduce_announcement_deletion_event($commentDeletion) === 0
    && (int)db()->query(
        "SELECT verified FROM repos
         WHERE github_full_name='$ledgerFull'"
    )->fetchColumn() === 1,
    'content deletion never emits a repository-address deletion target'
);

$addressDeletion = fm_event_sign([
    'kind' => 5,
    'pubkey' => $ledgerPk,
    'created_at' => $ledgerBase + 20,
    'content' => 'repository announcement deleted',
    'tags' => [['a', $ledgerAddress], ['k', '30617']],
], $ledgerSec);
ok(
    repo_reduce_announcement_deletion_event($addressDeletion) === 1
    && (int)db()->query(
        "SELECT verified FROM repos
         WHERE github_full_name='$ledgerFull'"
    )->fetchColumn() === 0,
    'same-author address deletion tombstones a banked announcement'
);

$replacementAfterDeletion = fm_event_sign([
    'kind' => 30617,
    'pubkey' => $ledgerPk,
    'created_at' => $ledgerBase + 30,
    'content' => '',
    'tags' => [
        ['d', 'ledger-repo'],
        ['relays', 'wss://relay.damus.io', 'wss://z.example'],
    ],
], $ledgerSec);
ok(
    repo_reduce_announcement_event(
        $replacementAfterDeletion,
        $bridgePk
    ) === 1
    && (int)db()->query(
        "SELECT verified FROM repos
         WHERE github_full_name='$ledgerFull'"
    )->fetchColumn() === 1,
    'replacement newer than deletion restores repository in either order'
);

$lateOlderDeletion = fm_event_sign([
    'kind' => 5,
    'pubkey' => $ledgerPk,
    'created_at' => $ledgerBase + 25,
    'content' => '',
    'tags' => [['a', $ledgerAddress], ['k', '30617']],
], $ledgerSec);
repo_reduce_announcement_deletion_event($lateOlderDeletion);
ok(
    (int)db()->query(
        "SELECT verified FROM repos
         WHERE github_full_name='$ledgerFull'"
    )->fetchColumn() === 1,
    'late older deletion cannot erase a newer announcement'
);

$attackerDeletionSec = random_hex(32);
$attackerDeletion = fm_event_sign([
    'kind' => 5,
    'pubkey' => fm_pubkey_hex($attackerDeletionSec),
    'created_at' => $ledgerBase + 40,
    'content' => '',
    'tags' => [['a', $ledgerAddress], ['k', '30617']],
], $attackerDeletionSec);
ok(
    repo_reduce_announcement_deletion_event($attackerDeletion) === 0
    && (int)db()->query(
        "SELECT verified FROM repos
         WHERE github_full_name='$ledgerFull'"
    )->fetchColumn() === 1,
    'another author cannot delete repository authority'
);

// 3. second GitHub comment is also top-level (GitHub supplies no reply target)
$parent2 = null;
$comment2 = $comment;
$comment2['id'] = 5350111999; $comment2['node_id'] = 'IC_second0000000000000000000000'; $comment2['body'] = 'reply';
$ev3 = bridge_build_comment($repoRow, $repo['full_name'], 1, $comment2, $root[0], $root[1], $parent2);
$ev3['proxy_url'] = 'https://github.com/x/y';
$ev3['parent_github_id'] = $issue['node_id'];
$id3 = bridge_gh2nostr($repoRow, $ev3, bridge_resolve_author('daym'), $comment2['node_id']);
$sig3 = $GLOBALS['__published'][2];
ok($sig3['tags'][3][1] === $id1, 'e parent stays issue root for flat GitHub comment');
ok($sig3['tags'][4] === ['k', '1621'], 'k parent kind stays 1621');
ok($sig3['tags'][0][1] === $id1, 'E root stays the 1621');

// 4. status event
$ev4 = bridge_build_status(
    $repoRow,
    $repo['full_name'],
    1,
    1632,
    $id1,
    $root[1],
    '2026-08-20T01:40:00Z'
);
$ev4['proxy_url'] = 'https://github.com/x';
$id4 = bridge_gh2nostr($repoRow, $ev4, bridge_resolve_author('daym'),
    'status:' . $issue['node_id'] . ':closed');
$sig4 = $GLOBALS['__published'][3];
ok($sig4['kind'] === 1632, 'closed -> 1632');
ok($sig4['tags'][0] === ['e', $id1, '', 'root'], 'status e+root marker');

// 5. ledger integrity
ok((int)db()->query('SELECT COUNT(*) FROM event_map')->fetchColumn() === 4, '4 crossings in ledger');
try {
    db()->prepare('INSERT INTO event_map (github_id,nostr_id,direction,kind,created_at) VALUES (?,?,?,?,?)')
       ->execute([$issue['node_id'], str_repeat('ff', 32), 'gh2nostr', 1621, time()]);
    ok(false, 'duplicate github_id rejected');
} catch (PDOException $e) { ok(true, 'duplicate github_id rejected'); }
try {
    db()->prepare('INSERT INTO event_map (github_id,nostr_id,direction,kind,created_at) VALUES (?,?,?,?,?)')
       ->execute(['other:id', $id2, 'gh2nostr', 1111, time()]);
    ok(false, 'duplicate nostr_id rejected (loop-kill)');
} catch (PDOException $e) { ok(true, 'duplicate nostr_id rejected (loop-kill)'); }

// GitHub star deliveries are wake-up signals. Reconciliation reads current
// state, and an unstar/re-star within one GitHub timestamp second still
// produces distinct, causally ordered Nostr events.
$starDelivery = [
    'delivery' => 'star-created-delivery',
    'event_name' => 'star',
    'event' => [
        'action' => 'created',
        'installation' => $installation,
        'repository' => $repo,
        'sender' => ['id' => 8080, 'login' => 'stargazer'],
        'starred_at' => '2026-08-20T01:50:00Z',
    ],
];
ok(
    bridge_ingest_github_delivery($starDelivery) === null
    && (bool)db()->query(
        "SELECT 1 FROM schema_meta
         WHERE k='github_star_pair|1340167971|8080'"
    )->fetchColumn(),
    'GitHub star delivery retains its pair and queues reconciliation'
);
$deleteWakeDelivery = $starDelivery;
$deleteWakeDelivery['delivery'] = 'star-deleted-delivery';
$deleteWakeDelivery['event']['action'] = 'deleted';
$deleteWakeDelivery['event']['starred_at'] = null;
bridge_ingest_github_delivery($deleteWakeDelivery);
ok(
    (int)db()->query(
        "SELECT COUNT(*) FROM jobs
         WHERE type='gh2nostr_star_reconcile' AND status='pending'"
    )->fetchColumn() === 2,
    'star delivery arriving during a pending reconcile retains its wake-up'
);
$starJobQuery = db()->prepare(
    "SELECT payload FROM jobs
     WHERE type='gh2nostr_star_reconcile'
     ORDER BY id DESC LIMIT 1"
);
$starJobQuery->execute();
$starPayload = json_decode((string)$starJobQuery->fetchColumn(), true);
$GLOBALS['__gh_repository_star_state'] = [
    'starred' => true,
    'github_user_id' => '8080',
    'login' => 'stargazer',
    'starred_at' => '2026-08-20T01:50:00Z',
    'starred_at_timestamp' => strtotime('2026-08-20T01:50:00Z'),
];
$publishedBeforeStar = count($GLOBALS['__published']);
bridge_execute_job([
    'type' => 'gh2nostr_star_reconcile',
    'payload_arr' => $starPayload,
]);
$firstStar = $GLOBALS['__published'][$publishedBeforeStar] ?? null;
ok(
    is_array($firstStar)
    && $firstStar['kind'] === 7
    && $firstStar['content'] === '⭐'
    && in_array(['e', str_repeat('bc', 32), '', str_repeat('aa', 32)], $firstStar['tags'], true)
    && in_array(['a', '30617:' . str_repeat('aa', 32) . ':dummy', '', str_repeat('aa', 32)], $firstStar['tags'], true)
    && in_array(['k', '30617'], $firstStar['tags'], true),
    'GitHub star becomes a complete NIP-25 repository reaction'
);

$GLOBALS['__gh_repository_star_state'] = [
    'starred' => false,
    'github_user_id' => '8080',
    'login' => 'stargazer',
    'starred_at' => null,
    'starred_at_timestamp' => null,
];
$starPayload['observed_at']++;
bridge_execute_job([
    'type' => 'gh2nostr_star_reconcile',
    'payload_arr' => $starPayload,
]);
$unstar = end($GLOBALS['__published']);
$starDeleted = db()->prepare(
    'SELECT 1 FROM deletion_map WHERE target_nostr_id=?'
);
$starDeleted->execute([$firstStar['id']]);
ok(
    is_array($unstar)
    && $unstar['kind'] === 5
    && in_array(['e', $firstStar['id']], $unstar['tags'], true)
    && !in_array(
        '30617:' . str_repeat('aa', 32) . ':dummy',
        array_column($unstar['tags'], 1),
        true
    )
    && (bool)$starDeleted->fetchColumn(),
    'GitHub unstar deletes only the concrete reaction, not its repository'
);

$GLOBALS['__gh_repository_star_state'] = [
    'starred' => true,
    'github_user_id' => '8080',
    'login' => 'stargazer',
    'starred_at' => '2026-08-20T01:50:00Z',
    'starred_at_timestamp' => strtotime('2026-08-20T01:50:00Z'),
];
bridge_execute_job([
    'type' => 'gh2nostr_star_reconcile',
    'payload_arr' => $starPayload,
]);
$secondStar = end($GLOBALS['__published']);
ok(
    is_array($secondStar)
    && $secondStar['kind'] === 7
    && $secondStar['id'] !== $firstStar['id']
    && $secondStar['created_at'] === $firstStar['created_at'] + 1,
    'same-second GitHub restar gets a distinct monotonic Nostr generation'
);
$publishedAfterRestar = count($GLOBALS['__published']);
bridge_execute_job([
    'type' => 'gh2nostr_star_reconcile',
    'payload_arr' => $starPayload,
]);
ok(
    count($GLOBALS['__published']) === $publishedAfterRestar,
    'delayed star wake-up cannot duplicate current repository-star state'
);
$starScanAt = now();
$unstarFirstDelivery = $deleteWakeDelivery;
$unstarFirstDelivery['delivery'] = 'unknown-pair-unstar-delivery';
$unstarFirstDelivery['event']['sender'] = [
    'id' => 9090,
    'login' => 'unstar-first-user',
];
bridge_ingest_github_delivery($unstarFirstDelivery);
bridge_execute_job([
    'type' => 'gh2nostr_repository_stars_reconcile',
    'payload_arr' => [
        'full' => $repo['full_name'],
        'repository_id' => (string)$repo['id'],
        'scan_at' => $starScanAt,
    ],
]);
$scanActors = [];
$scanJobs = db()->prepare(
    "SELECT payload FROM jobs
     WHERE type='gh2nostr_star_reconcile'
       AND dedupe_key LIKE ?"
);
$scanJobs->execute(['%:scan:' . $starScanAt]);
foreach ($scanJobs->fetchAll(PDO::FETCH_COLUMN) as $payload) {
    $decoded = json_decode((string)$payload, true);
    $scanActors[] = (string)($decoded['github_user_id'] ?? '');
}
sort($scanActors, SORT_STRING);
ok(
    $scanActors === ['8080', '9090'],
    'periodic set reduction retains mapped and unstar-before-star pairs'
);

// A retry after relay acceptance reconciles the deterministic event id
// instead of publishing it again.
$publishedBefore = count($GLOBALS['__published']);
$evReconciled = bridge_build_status(
    $repoRow,
    $repo['full_name'],
    1,
    1630,
    $id1,
    $root[1],
    '2026-08-20T01:45:00Z'
);
$evReconciled['proxy_url'] = 'https://github.com/friendly-machines-com/dummy/issues/1';
$reconcileAuthor = bridge_resolve_author('daym');
$GLOBALS['__relay_found_event'] = fm_event_sign(
    bridge_unsigned_for_author($evReconciled, $reconcileAuthor),
    fm_secret_bridge_key()
);
bridge_gh2nostr($repoRow, $evReconciled, $reconcileAuthor,
    'status:' . $issue['node_id'] . ':reconciled');
$GLOBALS['__relay_found_event'] = null;
ok(count($GLOBALS['__published']) === $publishedBefore,
   'relay reconciliation closes publish-before-ledger crash window');

// A linked crossing has exactly one permitted signer. Crash recovery accepts
// the deterministic user-signed event and never looks for a bridge substitute.
$remoteSec = fm_private_key_generate();
$remoteAuthor = [
    'path' => 'remote',
    'pubkey' => fm_pubkey_hex($remoteSec),
    'bunker' => 'bunker://' . str_repeat('12', 32)
        . '?relay=' . rawurlencode('wss://relay.damus.io'),
    'client_priv' => fm_private_key_generate(),
    'login' => 'linked-user',
];
$remoteRecovery = bridge_build_comment(
    $repoRow,
    $repo['full_name'],
    1,
    [
        'id' => 777,
        'body' => 'linked signer crash recovery',
        'created_at' => '2026-08-20T01:46:00Z',
    ],
    $id1,
    $root[1]
);
$remoteRecovery['proxy_url'] =
    'https://github.com/friendly-machines-com/dummy/issues/1#issuecomment-777';
$remoteRecovery['parent_github_id'] = $issue['node_id'];
$GLOBALS['__relay_found_event'] = fm_event_sign(
    bridge_unsigned_for_author($remoteRecovery, $remoteAuthor),
    $remoteSec
);
$publishedBefore = count($GLOBALS['__published']);
bridge_gh2nostr(
    $repoRow,
    $remoteRecovery,
    $remoteAuthor,
    'IC_remote_recovery'
);
$GLOBALS['__relay_found_event'] = null;
ok(
    count($GLOBALS['__published']) === $publishedBefore
    && db()->query(
        "SELECT signed_by FROM event_map
         WHERE github_id='IC_remote_recovery'"
    )->fetchColumn() === $remoteAuthor['pubkey'],
    'retry recovers only the accepted linked-user signature'
);
$linkedSignerDelay = bridge_linked_signer_defer(
    $remoteAuthor,
    'IC_remote_unavailable',
    new BridgeRemoteSignerUnavailable('test timeout')
);
ok(
    $linkedSignerDelay->delaySecs === 60
    && str_contains($linkedSignerDelay->getMessage(), 'linked Nostr signer'),
    'temporary linked-signer failure remains a durable dependency'
);

// 6. jobs dedupe + claim/finish/backoff
db()->exec(
    "UPDATE jobs SET status='done'
     WHERE type IN (
       'nostr_backfill',
       'gh2nostr_star_reconcile',
       'github_installation_reconcile'
     )"
);
$i1 = jobs_enqueue('gh2nostr_issue_open', ['x' => 1], 'gh:I_test');
$i2 = jobs_enqueue('gh2nostr_issue_open', ['x' => 1], 'gh:I_test');
ok($i1 > 0 && $i2 === 0, 'job enqueue dedupe_key unique');
$claimed = jobs_claim_due(5);
ok(count($claimed) === 1 && (int)$claimed[0]['attempts'] === 1, 'claim due, attempts=1');
jobs_finish($i1, false, 'test error');
$job = db()->query('SELECT run_at, last_error FROM jobs WHERE id=' . $i1)->fetch();
ok((int)$job['run_at'] > now() && $job['last_error'] === 'test error', 'backoff scheduled + error kept');
for ($k = 0; $k < 7; $k++) { jobs_finish($i1, false, 'x'); }   // 8 fails total
$dead = db()->query('SELECT status FROM jobs WHERE id=' . $i1)->fetchColumn();
ok($dead === 'dead', 'dead-letter after 8 failed executions');
ok(
    jobs_dedupe_terminal('gh:I_test'),
    'dead immutable input cannot silently receive a fresh failure budget'
);

// 7. durable NIP-46 completion: cron observes connect -> queues finish -> done
$userSec = random_hex(32);
$userPk = fm_pubkey_hex($userSec);
$GLOBALS['__nip46_observed_phases'] = [];
$GLOBALS['__nip46_user_pk'] = null;
$GLOBALS['__nip46_connection_relays'] = [
    'wss://one.example',
    'wss://two.example',
];
$oauthNonce = random_hex(32);
db()->prepare('INSERT INTO oauth_states
               (nonce,github_login,created_at,expires_at) VALUES (?,?,?,?)')
   ->execute([$oauthNonce, 'alice', now(), now() + 3600]);
db()->prepare("INSERT INTO github_accounts
               (login,github_user_id,token_enc,provider,auth_status,
                linked_at,updated_at)
               VALUES (?,?,?,'github_app','active',?,?)")
   ->execute(['alice', '9001', fm_encrypt_at_rest('ghu_alice'), now(), now()]);
$stateId = random_hex(16);
$connectSecret = random_hex(16);
$nipClientSec = fm_private_key_generate();
$nipClientPk = fm_pubkey_hex($nipClientSec);
db()->prepare("INSERT INTO nip46_states
               (state_id,secret,client_pk,client_key_enc,oauth_nonce,
                status,created_at,expires_at)
               VALUES (?,?,?,?,?,'waiting',?,?)")
   ->execute([$stateId, $connectSecret, $nipClientPk,
              fm_encrypt_at_rest($nipClientSec), $oauthNonce,
              now(), now() + 3600]);
$signerSec = random_hex(32);
$signerPk = fm_pubkey_hex($signerSec);
$decoyNonce = random_hex(32);
$decoyStateId = random_hex(16);
$decoyClientSec = fm_private_key_generate();
$decoyClientPk = fm_pubkey_hex($decoyClientSec);
db()->prepare(
    'INSERT INTO oauth_states (nonce,created_at,expires_at) VALUES (?,?,?)'
)->execute([$decoyNonce, now(), now() + 3600]);
db()->prepare("INSERT INTO nip46_states
               (state_id,secret,client_pk,client_key_enc,oauth_nonce,
                status,created_at,expires_at)
               VALUES (?,?,?,?,?,'waiting',?,?)")
   ->execute([
       $decoyStateId,
       random_hex(16),
       $decoyClientPk,
       fm_encrypt_at_rest($decoyClientSec),
       $decoyNonce,
       now(),
       now() + 3600,
   ]);
$connectEvent = [
    'kind' => 24133, 'pubkey' => $signerPk, 'created_at' => now(),
    // Recipients are a set. The encrypted recipient is deliberately second;
    // tag position must not select the waiting session.
    'tags' => [['p', $decoyClientPk], ['p', $nipClientPk]],
    'content' => nip44_encrypt(
        $signerSec, $nipClientPk,
        json_c(['id' => 'connect-test', 'result' => $connectSecret])),
];
$GLOBALS['__relay_query_events'] = [fm_event_sign($connectEvent, $signerSec)];
bridge_collect_nip46_connects();
$GLOBALS['__relay_query_events'] = [];
$recipientStates = db()->prepare(
    'SELECT state_id,status FROM nip46_states WHERE state_id IN (?,?)'
);
$recipientStates->execute([$stateId, $decoyStateId]);
$recipientStates = array_column(
    $recipientStates->fetchAll(),
    'status',
    'state_id'
);
ok(
    ($recipientStates[$stateId] ?? null) === 'connected'
    && ($recipientStates[$decoyStateId] ?? null) === 'waiting',
    'NIP-46 recipient set is selected by decryption, not p-tag order'
);
db()->prepare('DELETE FROM nip46_states WHERE state_id=?')
   ->execute([$decoyStateId]);
db()->prepare('DELETE FROM oauth_states WHERE nonce=?')
   ->execute([$decoyNonce]);
$bankedSessionExpiry = db()->prepare(
    'SELECT expires_at FROM oauth_states WHERE nonce=?'
);
$bankedSessionExpiry->execute([$oauthNonce]);
ok(
    (int)$bankedSessionExpiry->fetchColumn()
        > now() + FM_PARTIAL_LINK_SESSION_SECS - 60,
    'banked signer approval extends its resumable link session'
);
$bankedSessionExpiry->closeCursor();
$finishIdQuery = db()->query("SELECT id FROM jobs
                              WHERE dedupe_key='nip46finish:$stateId'");
$finishId = (int)$finishIdQuery->fetchColumn();
$finishIdQuery->closeCursor();
$finishJobQuery = db()->query("SELECT * FROM jobs WHERE id=$finishId");
$finishJob = $finishJobQuery->fetch();
$finishJobQuery->closeCursor();
$finishJob['payload_arr'] = json_decode($finishJob['payload'], true);
// Earlier assertions deliberately keep local statement variables for
// readability. End any of their snapshots so this interleaving isolates the
// cursor owned by bridge_execute_job itself.
foreach (get_defined_vars() as $testLocal) {
    if ($testLocal instanceof PDOStatement) $testLocal->closeCursor();
}
$GLOBALS['__nip46_interleave_db_write'] = true;
$deferredForUserKey = false;
try {
    bridge_execute_job($finishJob);
} catch (BridgeDefer $error) {
    $deferredForUserKey = str_contains(
        $error->getMessage(),
        'get_public_key received no valid response'
    );
}
$negotiatedWhileIncomplete = db()->prepare(
    'SELECT status,relays FROM nip46_states WHERE state_id=?'
);
$negotiatedWhileIncomplete->execute([$stateId]);
$negotiatedWhileIncomplete = $negotiatedWhileIncomplete->fetch();
ok(
    $deferredForUserKey
    && $negotiatedWhileIncomplete['status'] === 'connected'
    && json_decode($negotiatedWhileIncomplete['relays'], true)
       === ['wss://one.example', 'wss://two.example'],
    'failed post-switch RPC resumes from the durable negotiated relay set'
);
ok(
    db()->query(
        "SELECT v FROM schema_meta WHERE k='test_concurrent_web_poll'"
    )->fetchColumn() === 'committed',
    'NIP-46 job releases its read snapshot across concurrent web writes'
);
$GLOBALS['__nip46_user_pk'] = null;
$GLOBALS['__nip46_user_pk_by_relay'] = ['wss://nos.lol' => $userPk];
$GLOBALS['__nip46_get_public_key_relays'] = [];
$GLOBALS['__nip46_connection_relays'] = [];
$GLOBALS['__nip46_proof_result'] = false;
$shortProofRetry = false;
try {
    bridge_execute_job($finishJob);
} catch (BridgeDefer $error) {
    $shortProofRetry = $error->delaySecs === NIP46_LINK_RETRY_SECS
        && $error->delaySecs < 60
        && str_contains($error->getMessage(), 'prove control');
}
ok(
    $shortProofRetry,
    'failed signer proof retries on the next cron tick, not after five minutes'
);
$GLOBALS['__nip46_proof_result'] = true;
bridge_run_due_jobs(5);
$finishState = db()->prepare('SELECT status,pubkey FROM nip46_states WHERE state_id=?');
$finishState->execute([$stateId]);
$finishRow = $finishState->fetch();
ok($finishId > 0 && $finishRow['status'] === 'done' && $finishRow['pubkey'] === $userPk,
   'nip46 retry uses its durable relay set without requiring another switch');
$finishedPayload = json_decode(
    (string)db()->query(
        "SELECT payload FROM jobs WHERE id=$finishId"
    )->fetchColumn(),
    true
);
ok(
    isset(
        $GLOBALS['__nip46_observed_phases']['switch_relays']['checking_relays'],
        $GLOBALS['__nip46_observed_phases']['get_public_key']['identifying_account'],
        $GLOBALS['__nip46_observed_phases']['sign_challenge']['verifying_signer']
    )
    && ($finishedPayload['phase'] ?? null) === 'saving_link',
    'durable NIP-46 job reports each user-visible phase'
);
ok(
    in_array(
        'wss://nos.lol',
        $GLOBALS['__nip46_get_public_key_relays'],
        true
    ),
    'NIP-46 RPC retries an approved bootstrap relay after relay handoff'
);
$link = db()->prepare('SELECT 1 FROM links WHERE login=? AND pubkey=?');
$link->execute(['alice', $userPk]);
ok((bool)$link->fetchColumn(), 'nip46 finish joins server-side OAuth session');
$storedClient = db()->prepare('SELECT client_key_enc FROM nostr_accounts WHERE pubkey=?');
$storedClient->execute([$userPk]);
ok(fm_decrypt_at_rest($storedClient->fetchColumn()) === $nipClientSec,
   'per-link NIP-46 client key survives durable completion');
$storedBunker = db()->prepare(
    'SELECT bunker_enc FROM nostr_accounts WHERE pubkey=?'
);
$storedBunker->execute([$userPk]);
ok(
    nip46_bunker_relays(
        parse_url(
            fm_decrypt_at_rest($storedBunker->fetchColumn()),
            PHP_URL_QUERY
        ) ?: ''
    ) === [
        'wss://nos.lol',
        'wss://one.example',
        'wss://two.example',
    ],
    'negotiated and demonstrably responsive NIP-46 relays survive completion'
);
ok(
    ($GLOBALS['__nip46_proof']['userPk'] ?? null) === $userPk
    && ($GLOBALS['__nip46_proof']['stateId'] ?? null) === $stateId,
    'NIP-46 signer proves control of the claimed user key'
);
ok(
    nip46_bunker_relays(
        parse_url(
            (string)($GLOBALS['__nip46_proof']['bunkerUri'] ?? ''),
            PHP_URL_QUERY
        ) ?: ''
    )[0] === 'wss://nos.lol',
    'identity proof retains the relay that answered get_public_key'
);

// Clearing cookies and repeating the NIP-46 proof signs the new browser
// session in, but must not silently replace the durable signer connection.
$originalSigner = db()->prepare(
    'SELECT bunker_enc,client_key_enc FROM nostr_accounts WHERE pubkey=?'
);
$originalSigner->execute([$userPk]);
$originalSigner = $originalSigner->fetch();
$linksBeforeSignerRecovery = (int)db()->query(
    'SELECT COUNT(*) FROM links'
)->fetchColumn();
$recoveryNonce = random_hex(32);
db()->prepare(
    'INSERT INTO oauth_states(nonce,created_at,expires_at) VALUES (?,?,?)'
)->execute([$recoveryNonce, now(), now() + 3600]);
$recoveryStateId = random_hex(16);
$recoveryClientSec = fm_private_key_generate();
$recoveryClientPk = fm_pubkey_hex($recoveryClientSec);
$recoveryBunkerPk = fm_pubkey_hex(fm_private_key_generate());
db()->prepare(
    "INSERT INTO nip46_states
     (state_id,secret,client_pk,client_key_enc,bunker_pk,relays,
      oauth_nonce,status,created_at,expires_at)
     VALUES (?,?,?,?,?,?,?,'connected',?,?)"
)->execute([
    $recoveryStateId,
    random_hex(16),
    $recoveryClientPk,
    fm_encrypt_at_rest($recoveryClientSec),
    $recoveryBunkerPk,
    json_c(['wss://nos.lol']),
    $recoveryNonce,
    now(),
    now() + 3600,
]);
$recoveryJobId = jobs_enqueue(
    'nip46_finish',
    ['state_id' => $recoveryStateId, 'phase' => 'checking_relays'],
    'nip46finish:' . $recoveryStateId
);
$recoveryJob = db()->query(
    "SELECT * FROM jobs WHERE id=$recoveryJobId"
)->fetch();
$recoveryJob['payload_arr'] = json_decode(
    $recoveryJob['payload'],
    true
);
$GLOBALS['__nip46_user_pk_by_relay'] = ['wss://nos.lol' => $userPk];
$GLOBALS['__nip46_connection_relays'] = [];
$GLOBALS['__nip46_proof_result'] = true;
bridge_execute_job($recoveryJob);
$recoveredBrowser = db()->prepare(
    'SELECT nostr_pubkey FROM oauth_states WHERE nonce=?'
);
$recoveredBrowser->execute([$recoveryNonce]);
$signerAfterRecovery = db()->prepare(
    'SELECT bunker_enc,client_key_enc FROM nostr_accounts WHERE pubkey=?'
);
$signerAfterRecovery->execute([$userPk]);
$signerAfterRecovery = $signerAfterRecovery->fetch();
ok(
    $recoveredBrowser->fetchColumn() === $userPk
    && $signerAfterRecovery === $originalSigner
    && (int)db()->query('SELECT COUNT(*) FROM links')->fetchColumn()
        === $linksBeforeSignerRecovery,
    'repeated NIP-46 proof restores session without replacing signer or link'
);

// The separately marked replacement path may rotate those credentials, but
// only for the exact durable pubkey authorized by the existing browser.
$replacementNonce = random_hex(32);
db()->prepare(
    'INSERT INTO oauth_states
     (nonce,nostr_pubkey,created_at,expires_at) VALUES (?,?,?,?)'
)->execute([$replacementNonce, $userPk, now(), now() + 3600]);
$replacementStateId = random_hex(16);
$replacementClientSec = fm_private_key_generate();
$replacementClientPk = fm_pubkey_hex($replacementClientSec);
$replacementBunkerPk = fm_pubkey_hex(fm_private_key_generate());
db()->prepare(
    "INSERT INTO nip46_states
     (state_id,secret,client_pk,client_key_enc,bunker_pk,relays,
      oauth_nonce,status,created_at,expires_at)
     VALUES (?,?,?,?,?,?,?,'connected',?,?)"
)->execute([
    $replacementStateId,
    random_hex(16),
    $replacementClientPk,
    fm_encrypt_at_rest($replacementClientSec),
    $replacementBunkerPk,
    json_c(['wss://nos.lol']),
    $replacementNonce,
    now(),
    now() + 3600,
]);
$replacementJobId = jobs_enqueue(
    'nip46_finish',
    [
        'state_id' => $replacementStateId,
        'phase' => 'checking_relays',
        'replace_pubkey' => $userPk,
    ],
    'nip46finish:' . $replacementStateId
);
$replacementJob = db()->query(
    "SELECT * FROM jobs WHERE id=$replacementJobId"
)->fetch();
$replacementJob['payload_arr'] = json_decode(
    $replacementJob['payload'],
    true
);
bridge_execute_job($replacementJob);
$signerAfterReplacement = db()->prepare(
    'SELECT bunker_enc,client_key_enc FROM nostr_accounts WHERE pubkey=?'
);
$signerAfterReplacement->execute([$userPk]);
$signerAfterReplacement = $signerAfterReplacement->fetch();
ok(
    fm_decrypt_at_rest($signerAfterReplacement['client_key_enc'])
        === $replacementClientSec
    && str_starts_with(
        fm_decrypt_at_rest($signerAfterReplacement['bunker_enc']),
        'bunker://' . $replacementBunkerPk
    )
    && (int)db()->query('SELECT COUNT(*) FROM links')->fetchColumn()
        === $linksBeforeSignerRecovery,
    'explicit exact-key replacement rotates signer credentials without relinking'
);

$mismatchNonce = random_hex(32);
db()->prepare(
    'INSERT INTO oauth_states
     (nonce,nostr_pubkey,created_at,expires_at) VALUES (?,?,?,?)'
)->execute([$mismatchNonce, $userPk, now(), now() + 3600]);
$mismatchStateId = random_hex(16);
$mismatchClientSec = fm_private_key_generate();
db()->prepare(
    "INSERT INTO nip46_states
     (state_id,secret,client_pk,client_key_enc,bunker_pk,relays,
      oauth_nonce,status,created_at,expires_at)
     VALUES (?,?,?,?,?,?,?,'connected',?,?)"
)->execute([
    $mismatchStateId,
    random_hex(16),
    fm_pubkey_hex($mismatchClientSec),
    fm_encrypt_at_rest($mismatchClientSec),
    fm_pubkey_hex(fm_private_key_generate()),
    json_c(['wss://nos.lol']),
    $mismatchNonce,
    now(),
    now() + 3600,
]);
$mismatchJobId = jobs_enqueue(
    'nip46_finish',
    [
        'state_id' => $mismatchStateId,
        'phase' => 'checking_relays',
        'replace_pubkey' => $userPk,
    ],
    'nip46finish:' . $mismatchStateId
);
$mismatchJob = db()->query(
    "SELECT * FROM jobs WHERE id=$mismatchJobId"
)->fetch();
$mismatchJob['payload_arr'] = json_decode(
    $mismatchJob['payload'],
    true
);
$mismatchPk = fm_pubkey_hex(fm_private_key_generate());
$GLOBALS['__nip46_user_pk_by_relay'] = [
    'wss://nos.lol' => $mismatchPk,
];
$mismatchRejected = false;
try {
    bridge_execute_job($mismatchJob);
} catch (BridgeSkip $error) {
    $mismatchRejected = str_contains(
        $error->getMessage(),
        'different Nostr account'
    );
}
$mismatchState = db()->prepare(
    'SELECT status FROM nip46_states WHERE state_id=?'
);
$mismatchState->execute([$mismatchStateId]);
ok(
    $mismatchRejected
    && $mismatchState->fetchColumn() === 'failed',
    'explicit signer replacement cannot switch to a different Nostr identity'
);
$GLOBALS['__nip46_user_pk_by_relay'] = ['wss://nos.lol' => $userPk];

$otherPk = fm_pubkey_hex(random_hex(32));
db()->prepare("INSERT INTO nostr_accounts
               (pubkey,bunker_enc,status,linked_at,updated_at)
               VALUES (?,?,'linked',?,?)")
   ->execute([$otherPk, fm_encrypt_at_rest('bunker://' . str_repeat('ab', 32)
              . '?relay=wss%3A%2F%2Frelay.example'), now(), now()]);
db()->prepare("INSERT INTO github_accounts
               (login,github_user_id,token_enc,provider,auth_status,
                linked_at,updated_at)
               VALUES (?,?,?,'github_app','active',?,?)")
   ->execute([
       'incomplete-signer',
       '99002',
       fm_encrypt_at_rest('ghu_incomplete'),
       now(),
       now(),
   ]);
db()->prepare(
    'INSERT INTO links(login,pubkey,created_at) VALUES (?,?,?)'
)->execute(['incomplete-signer', $otherPk, now()]);
$incompleteSignerDeferred = false;
try {
    bridge_resolve_author('incomplete-signer');
} catch (BridgeDefer $error) {
    $incompleteSignerDeferred = str_contains(
        $error->getMessage(),
        'linked Nostr signer'
    );
}
ok(
    $incompleteSignerDeferred,
    'incomplete active link defers instead of changing to the bridge key'
);
try {
    fm_link_identities('alice', $otherPk);
    ok(false, 'one GitHub identity cannot bind a second Nostr identity');
} catch (IdentityLinkConflict $e) {
    ok(true, 'one GitHub identity cannot bind a second Nostr identity');
}

// User authorization revocation is not installation-scoped. It is still
// durably reconciled so a delayed revoke cannot override a later reauth.
$revocation = [
    'delivery' => 'delivery-user-revocation',
    'event_name' => 'github_app_authorization',
    'event' => [
        'action' => 'revoked',
        'sender' => ['id' => 9001, 'login' => 'alice'],
    ],
];
ok(
    bridge_ingest_github_delivery($revocation) === null
    && (int)db()->query(
        "SELECT COUNT(*) FROM jobs
         WHERE type='github_user_authorization_reconcile'
           AND status='pending'"
    )->fetchColumn() === 1,
    'GitHub App user revocation is durably reconciled'
);

// 8. durable raw GitHub delivery -> child crossing job
$deliveryIssue = $issue;
$deliveryIssue['node_id'] = 'I_delivery_test';
$deliveryIssue['number'] = 7;
$delivery = [
    'delivery' => 'delivery-guid-1',
    'event_name' => 'issues',
    'event' => [
        'action' => 'opened', 'issue' => $deliveryIssue,
        'repository' => $repo, 'installation' => $installation,
        'sender' => ['login' => 'daym'],
    ],
];
ok(bridge_ingest_github_delivery($delivery) === null,
   'raw GitHub delivery classified');
$child = db()->prepare("SELECT COUNT(*) FROM jobs
                        WHERE type='gh2nostr_issue_open' AND status='pending'");
$child->execute();
ok((int)$child->fetchColumn() === 1, 'raw delivery durably creates crossing job');
bridge_ingest_github_delivery($delivery);
$child->execute();
ok((int)$child->fetchColumn() === 1, 'raw delivery child enqueue is idempotent while pending');

// Hidden API-origin markers are authenticated. Even a valid marker copied
// from another object cannot suppress the copied-to object's creation.
$validMarker = gh_bridge_marker($id1);
ok(
    gh_bridge_marker_id($validMarker) === $id1
    && gh_bridge_marker_id(
        "<!-- friendly-machines-bridge:$id1 -->"
    ) === null,
    'GitHub origin markers require a valid bridge MAC'
);
$originalMarkerObject = [
    'id' => 100,
    'node_id' => 'I_original_marker',
    'body' => $validMarker,
    'created_at' => '2026-08-20T02:00:00Z',
    // A later ordinary edit must not let a copied marker take ownership.
    'updated_at' => '2026-08-21T02:00:00Z',
];
$editedOldMarkerCopy = [
    'id' => 50,
    'node_id' => 'I_edited_old_copy',
    'body' => $validMarker,
    'created_at' => '2026-08-19T02:00:00Z',
    'updated_at' => '2026-08-20T02:00:01Z',
];
$newMarkerCopy = [
    'id' => 101,
    'node_id' => 'I_new_copy',
    'body' => $validMarker,
    'created_at' => '2026-08-20T02:00:01Z',
    'updated_at' => '2026-08-20T02:00:01Z',
];
try {
    gh_unique_marker_match(
        [$newMarkerCopy, $editedOldMarkerCopy, $originalMarkerObject],
        $validMarker,
        strtotime('2026-08-20T02:00:00Z')
    );
    ok(false, 'crash recovery rejects ambiguous copied markers');
} catch (GhError $error) {
    ok(
        str_contains($error->getMessage(), 'ambiguous'),
        'crash recovery rejects ambiguous copied markers'
    );
}
ok(
    gh_unique_marker_match(
        [$editedOldMarkerCopy, $originalMarkerObject],
        $validMarker,
        strtotime('2026-08-20T02:00:00Z')
    )['node_id'] === 'I_original_marker',
    'objects created before durable enqueue cannot own a crossing'
);
$copiedMarkerIssue = $issue;
$copiedMarkerIssue['node_id'] = 'I_copied_marker';
$copiedMarkerIssue['number'] = 71;
$copiedMarkerIssue['body'] = "copied body\n\n$validMarker";
$copiedMarkerDelivery = [
    'delivery' => 'delivery-copied-marker',
    'event_name' => 'issues',
    'event' => [
        'action' => 'opened',
        'issue' => $copiedMarkerIssue,
        'repository' => $repo,
        'installation' => $installation,
        'sender' => ['login' => 'daym'],
    ],
];
ok(
    bridge_ingest_github_delivery($copiedMarkerDelivery) === null
    && (bool)db()->query(
        "SELECT 1 FROM jobs
         WHERE dedupe_key='gh:I_copied_marker' AND status='pending'"
    )->fetchColumn(),
    'replayed valid marker cannot suppress a different GitHub object'
);

// 9. GitHub comment delivery may arrive and execute before its issue root.
$ooIssue = $issue;
$ooIssue['node_id'] = 'I_out_of_order';
$ooIssue['number'] = 8;
$ooIssue['title'] = 'root delivered late';
$ooComment = $comment;
$ooComment['node_id'] = 'IC_out_of_order';
$ooComment['id'] = 8001;
$ooDelivery = [
    'delivery' => 'delivery-comment-first',
    'event_name' => 'issue_comment',
    'event' => [
        'action' => 'created',
        'issue' => $ooIssue,
        'comment' => $ooComment,
        'repository' => $repo,
        'installation' => $installation,
        'sender' => ['login' => 'daym'],
    ],
];
ok(bridge_ingest_github_delivery($ooDelivery) === null,
   'comment-first delivery queues its root and comment');
$ooCommentJob = db()->prepare("SELECT payload FROM jobs
                               WHERE type='gh2nostr_comment' AND dedupe_key=?");
$ooCommentJob->execute(['gh:' . $ooComment['node_id']]);
$ooCommentPayload = json_decode($ooCommentJob->fetchColumn(), true);
try {
    bridge_execute_job(['type' => 'gh2nostr_comment', 'payload_arr' => $ooCommentPayload]);
    ok(false, 'GitHub comment-before-root defers');
} catch (BridgeDefer $e) {
    ok(true, 'GitHub comment-before-root defers');
}
$ooRootJob = db()->prepare("SELECT payload FROM jobs
                            WHERE type='gh2nostr_issue_open' AND dedupe_key=?");
$ooRootJob->execute(['gh:' . $ooIssue['node_id']]);
$ooRootPayload = json_decode($ooRootJob->fetchColumn(), true);
bridge_execute_job(['type' => 'gh2nostr_issue_open', 'payload_arr' => $ooRootPayload]);
bridge_execute_job(['type' => 'gh2nostr_comment', 'payload_arr' => $ooCommentPayload]);
$ooMapped = db()->prepare('SELECT kind FROM event_map WHERE github_id=?');
$ooMapped->execute([$ooComment['node_id']]);
ok((int)$ooMapped->fetchColumn() === 1111,
   'GitHub comment-before-root converges after root crossing');

// 10. Immutable NIP-34 issues cannot be replaced in place; GitHub edits are
// preserved as ordinary, interoperable NIP-22 notices on the existing root.
$editedIssue = $issue;
$editedIssue['body'] = 'new issue description';
$editedIssue['updated_at'] = '2026-08-20T02:00:00Z';
$editDelivery = [
    'delivery' => 'delivery-issue-edit',
    'event_name' => 'issues',
    'event' => [
        'action' => 'edited',
        'changes' => ['body' => ['from' => 'issue body']],
        'issue' => $editedIssue,
        'repository' => $repo,
        'installation' => $installation,
        'sender' => ['login' => 'daym'],
    ],
];
ok(bridge_ingest_github_delivery($editDelivery) === null,
   'GitHub issue edit classified');
$editJob = db()->prepare("SELECT payload FROM jobs
                          WHERE type='gh2nostr_notice' AND dedupe_key LIKE ?");
$editJob->execute(['gh:edit:' . $issue['node_id'] . ':%']);
$editPayload = json_decode($editJob->fetchColumn(), true);
bridge_execute_job(['type' => 'gh2nostr_notice', 'payload_arr' => $editPayload]);
$editEvent = end($GLOBALS['__published']);
ok($editEvent['kind'] === 1111
   && str_contains($editEvent['content'], 'new issue description')
   && $editEvent['tags'][0][1] === $id1,
   'GitHub issue edit preserved as NIP-22 notice on original root');

// Close/reopen webhooks are unordered wake-ups. Reconcile GitHub's causal
// issue-event list, skip this App's own Nostr->GitHub echo, and allocate
// distinct Nostr timestamps to human transitions in the same second.
$sameSecond = strtotime('2026-08-20T02:01:00Z');
$appEchoStatusId = 'ISE_app_echo';
$humanCloseStatusId = 'ISE_human_close';
$humanReopenStatusId = 'ISE_human_reopen';
$GLOBALS['__gh_status_history'] = [
    [
        'github_id' => $appEchoStatusId,
        'kind' => 1632,
        'actor' => 'friendly-machines-bridge[bot]',
        'source_created_at' => $sameSecond,
        'nostr_created_at' => $sameSecond,
        'performed_by_bridge' => true,
    ],
    [
        'github_id' => $humanCloseStatusId,
        'kind' => 1631,
        'actor' => 'daym',
        'source_created_at' => $sameSecond,
        'nostr_created_at' => $sameSecond + 1,
        'performed_by_bridge' => false,
    ],
    [
        'github_id' => $humanReopenStatusId,
        'kind' => 1630,
        'actor' => 'daym',
        'source_created_at' => $sameSecond,
        'nostr_created_at' => $sameSecond + 2,
        'performed_by_bridge' => false,
    ],
];
$closeIssue = $issue;
$closeIssue['state'] = 'closed';
$closeIssue['state_reason'] = 'completed';
$closeIssue['updated_at'] = '2026-08-20T02:01:00Z';
$reopenIssue = $closeIssue;
$reopenIssue['state'] = 'open';
$reopenIssue['state_reason'] = 'reopened';
$statusDelivery = [
    'event_name' => 'issues',
    'event' => [
        'repository' => $repo,
        'installation' => $installation,
        'sender' => ['login' => 'daym'],
    ],
];
$reopenDelivery = $statusDelivery;
$reopenDelivery['delivery'] = 'delivery-reopen-first';
$reopenDelivery['event']['action'] = 'reopened';
$reopenDelivery['event']['issue'] = $reopenIssue;
$closeDelivery = $statusDelivery;
$closeDelivery['delivery'] = 'delivery-close-second';
$closeDelivery['event']['action'] = 'closed';
$closeDelivery['event']['issue'] = $closeIssue;
ok(
    bridge_ingest_github_delivery($reopenDelivery) === null
    && bridge_ingest_github_delivery($closeDelivery) === null,
    'reversed GitHub status webhooks queue causal reconciliation'
);
$statusJobs = db()->query(
    "SELECT payload FROM jobs
     WHERE type='gh2nostr_status_reconcile' ORDER BY id"
)->fetchAll(PDO::FETCH_COLUMN);
$publishedBeforeStatusReconcile = count($GLOBALS['__published']);
foreach ($statusJobs as $payload) {
    bridge_execute_job([
        'type' => 'gh2nostr_status_reconcile',
        'payload_arr' => json_decode($payload, true),
    ]);
}
$statusPublications = array_slice(
    $GLOBALS['__published'],
    $publishedBeforeStatusReconcile
);
ok(
    array_column($statusPublications, 'kind') === [1631, 1630]
    && array_column($statusPublications, 'created_at')
        === [$sameSecond + 1, $sameSecond + 2],
    'same-second GitHub transitions preserve causal order'
);
ok(
    !bridge_already_mapped($appEchoStatusId)
    && bridge_already_mapped($humanCloseStatusId)
    && bridge_already_mapped($humanReopenStatusId),
    'GitHub App status echo is suppressed by issue-event provenance'
);
$GLOBALS['__gh_status_history'] = [];

// GitHub comment deletion becomes a same-signer NIP-09 request, not another
// discussion comment.
$deleteCommentDelivery = [
    'delivery' => 'delivery-comment-delete',
    'event_name' => 'issue_comment',
    'event' => [
        'action' => 'deleted',
        'issue' => $issue,
        'comment' => $comment,
        'repository' => $repo,
        'installation' => $installation,
        'sender' => ['login' => 'daym'],
    ],
];
ok(
    bridge_ingest_github_delivery($deleteCommentDelivery) === null,
    'GitHub comment deletion queued'
);
$deleteCommentJob = db()->prepare(
    "SELECT payload FROM jobs
     WHERE type='gh2nostr_source_delete' AND status='pending'"
);
$deleteCommentJob->execute();
$publishedBeforeDelete = count($GLOBALS['__published']);
$deleteCommentPayload = json_decode(
    $deleteCommentJob->fetchColumn(),
    true
);
bridge_execute_job([
    'type' => 'gh2nostr_source_delete',
    'payload_arr' => $deleteCommentPayload,
]);
$deleteEvent = $GLOBALS['__published'][$publishedBeforeDelete] ?? null;
ok(
    is_array($deleteEvent)
    && $deleteEvent['kind'] === 5
    && in_array(['e', $id2], $deleteEvent['tags'], true)
    && $deleteEvent['pubkey'] === $sig2['pubkey'],
    'GitHub deletion publishes same-signer NIP-09 target'
);
$storedDeletion = db()->prepare(
    'SELECT deletion_nostr_id FROM deletion_map WHERE target_nostr_id=?'
);
$storedDeletion->execute([$id2]);
ok(
    $storedDeletion->fetchColumn() === $deleteEvent['id'],
    'GitHub-origin NIP-09 target is durable in the deletion ledger'
);
db()->prepare('DELETE FROM deletion_map WHERE target_nostr_id=?')
   ->execute([$id2]);
$publishedBeforeDeletionRecovery = count($GLOBALS['__published']);
bridge_execute_job([
    'type' => 'gh2nostr_source_delete',
    'payload_arr' => $deleteCommentPayload,
]);
$storedDeletion->execute([$id2]);
ok(
    count($GLOBALS['__published']) === $publishedBeforeDeletionRecovery
    && $storedDeletion->fetchColumn() === $deleteEvent['id'],
    'published deletion repairs a missing ledger row without republishing'
);

$deleteIssueDelivery = [
    'delivery' => 'delivery-issue-delete',
    'event_name' => 'issues',
    'event' => [
        'action' => 'deleted',
        'issue' => $issue,
        'repository' => $repo,
        'installation' => $installation,
        'sender' => ['login' => 'daym'],
    ],
];
ok(
    bridge_ingest_github_delivery($deleteIssueDelivery) === null,
    'GitHub issue deletion queued'
);
$deleteIssueJob = db()->prepare(
    "SELECT payload FROM jobs
     WHERE type='gh2nostr_source_delete'
       AND dedupe_key LIKE 'gh:delete:I_kwDOT-FXI88AAAABNd4MHw:%'
       AND status='pending'"
);
$deleteIssueJob->execute();
$publishedBeforeIssueDelete = count($GLOBALS['__published']);
bridge_execute_job([
    'type' => 'gh2nostr_source_delete',
    'payload_arr' => json_decode($deleteIssueJob->fetchColumn(), true),
]);
$deleteIssueEvent =
    $GLOBALS['__published'][$publishedBeforeIssueDelete] ?? null;
ok(
    is_array($deleteIssueEvent)
    && $deleteIssueEvent['kind'] === 5
    && in_array(['e', $id1], $deleteIssueEvent['tags'], true)
    && in_array(['k', '1621'], $deleteIssueEvent['tags'], true),
    'GitHub issue deletion publishes NIP-09 for the mirrored root'
);

// A Nostr root deletion is permanent. Later GitHub edits queue tombstone
// enforcement, while the enforcement webhook carrying its valid marker is
// consumed without creating another job.
$permanentDeletion = db()->prepare(
    "SELECT deletion_nostr_id,marker_id FROM deletion_map
     WHERE target_nostr_id=?
     ORDER BY created_at,deletion_nostr_id LIMIT 1"
);
$permanentDeletion->execute([$id1]);
$permanentDeletionRow = $permanentDeletion->fetch();
$permanentDeletionId = $permanentDeletionRow['deletion_nostr_id'];
$permanentMarkerId = $permanentDeletionRow['marker_id'];
$resurrectionIssue = $editedIssue;
$resurrectionIssue['body'] = 'trying to resurrect deleted source';
$resurrectionDelivery = $editDelivery;
$resurrectionDelivery['delivery'] = 'delivery-resurrection-edit';
$resurrectionDelivery['event']['issue'] = $resurrectionIssue;
ok(
    bridge_ingest_github_delivery($resurrectionDelivery) === null
    && (bool)db()->query(
        "SELECT 1 FROM jobs
         WHERE type='enforce_github_issue_tombstone' AND status='pending'"
    )->fetchColumn(),
    'GitHub edit cannot resurrect a Nostr-deleted issue'
);
$pendingEnforcementBefore = (int)db()->query(
    "SELECT COUNT(*) FROM jobs
     WHERE type='enforce_github_issue_tombstone' AND status='pending'"
)->fetchColumn();
$enforcementEcho = $resurrectionDelivery;
$enforcementEcho['delivery'] = 'delivery-tombstone-echo';
$enforcementEcho['event']['issue']['body'] = gh_body_with_marker(
    'permanent tombstone',
    $permanentMarkerId
);
bridge_ingest_github_delivery($enforcementEcho);
$pendingEnforcementAfter = (int)db()->query(
    "SELECT COUNT(*) FROM jobs
     WHERE type='enforce_github_issue_tombstone' AND status='pending'"
)->fetchColumn();
ok(
    $pendingEnforcementAfter === $pendingEnforcementBefore,
    'tombstone enforcement webhook does not loop'
);

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);

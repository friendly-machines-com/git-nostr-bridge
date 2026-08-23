<?php
/**
 * tests/dirB.php -- OFFLINE Direction B tests: feed crafted nostr events
 * through the cron handler with relays + GitHub stubbed (no network).
 *
 * Verifies: signature gate, event_map loop-kill, optional attribution,
 * root-scope check, meta resolution, enqueue shape, and executor ledger writes
 * (with gh_post_issue_comment stubbed to a fake node_id).
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') exit(1);

define('BRIDGE_ENTRY', true);
if (!getenv('BRIDGE_DB')) putenv('BRIDGE_DB=/tmp/fm-dirB.db');
@unlink(getenv('BRIDGE_DB'));

// self-contained throwaway secrets for this run (never the real ones)
$ts = sys_get_temp_dir() . '/fm-secrets-' . getmypid();
@mkdir($ts, 0700, true);
file_put_contents("$ts/db-crypt.php", "<?php return \"" . bin2hex(random_bytes(32)) . "\";");
file_put_contents("$ts/bridge-key.php", "<?php return \"" . bin2hex(random_bytes(32)) . "\";");
chmod("$ts/db-crypt.php", 0600);
chmod("$ts/bridge-key.php", 0600);
$GLOBALS['__fm_test_secrets_dir'] = $ts;
$GLOBALS['__fm_test_log'] = '/tmp/fm-test-dirB.log';   // keep test noise out of the real log
$GLOBALS['__fm_test_repo_verification'] = true;
$GLOBALS['__fm_test_github_installation_tokens'] = [
    'friendly-machines-com/dummy' => 'ghs_bridge_app',
];
$GLOBALS['__fm_test_github_user_tokens'] = ['alice' => 'ghu_alice'];

// relay seam stubs (must exist before lib/relay.php)
function relay_defaults(): array { return ['wss://relay.damus.io']; }
function relay_publish(array $e, array $r, float $t = 6.0): array { return ['r' => 'ok']; }
function relay_query(array $f, array $r, float $t = 4.0): array { return [[], true]; }
function relay_has_event(string $id, array $relays): bool { return false; }

require __DIR__ . '/../db.php';
require_once __DIR__ . '/../lib/util.php';
require_once __DIR__ . '/../lib/secrets.php';
require_once __DIR__ . '/../lib/crypto.php';
require_once __DIR__ . '/../lib/jobs.php';
require_once __DIR__ . '/../lib/bridge.php';

// stub GitHub REST (must exist before executor runs)
$GLOBALS['__gh_comments'] = [];
function gh_post_issue_comment(string $token, string $full, int $number, string $body): string {
    $GLOBALS['__gh_comments'][] = compact('token', 'full', 'number', 'body');
    return 'IC_fake' . count($GLOBALS['__gh_comments']);
}
function gh_create_issue(string $token, string $full, string $title, string $body): array {
    $GLOBALS['__gh_comments'][] = ['token' => $token, 'full' => $full, 'title' => $title, 'body' => $body];
    $n = count($GLOBALS['__gh_comments']);
    return ['node_id' => 'I_fake_new_' . $n, 'number' => 8 + $n];
}
function gh_set_issue_status(
    string $token, string $full, int $number, int $statusKind
): array {
    $closed = $statusKind !== 1630;
    $GLOBALS['__gh_comments'][] = compact(
        'token', 'full', 'number', 'closed', 'statusKind'
    );
    return ['node_id' => 'I_state'];
}
function gh_tombstone_issue(string $token, string $full, int $number, string $body): array {
    $GLOBALS['__gh_comments'][] = compact('token', 'full', 'number', 'body');
    return ['node_id' => 'I_tombstone'];
}
function gh_delete_issue_comment_by_node_id(
    string $token, string $full, int $number, string $nodeId
): void {
    $GLOBALS['__gh_comments'][] = compact(
        'token', 'full', 'number', 'nodeId'
    );
}
function gh_get_issue(string $token, string $full, int $number): array {
    $GLOBALS['__gh_comments'][] = compact('token', 'full', 'number');
    return ['node_id' => 'I_reconciled_' . $number, 'number' => $number];
}
function gh_get_issue_comment(string $token, string $full, int $commentId): array {
    $GLOBALS['__gh_comments'][] = compact('token', 'full', 'commentId');
    return ['node_id' => 'IC_reconciled_' . $commentId, 'id' => $commentId];
}
function gh_post_issue_comment_idempotent(
    string $token, string $full, int $number, string $body,
    string $nostrId, int $createdAt
): string {
    return gh_post_issue_comment($token, $full, $number, $body);
}
function gh_create_issue_idempotent(
    string $token, string $full, string $title, string $body,
    string $nostrId, int $createdAt
): array {
    return gh_create_issue($token, $full, $title, $body);
}
function gh_user_has_star(string $token, string $full): bool {
    $GLOBALS['__gh_star_calls'][] = [
        'operation' => 'check',
        'token' => $token,
        'full' => $full,
    ];
    return ($GLOBALS['__gh_starred'] ?? false) === true;
}
function gh_user_set_star(string $token, string $full, bool $starred): void {
    $GLOBALS['__gh_star_calls'][] = [
        'operation' => $starred ? 'star' : 'unstar',
        'token' => $token,
        'full' => $full,
    ];
    $GLOBALS['__gh_starred'] = $starred;
}

// extract the cron handler without running the tick: include the file's
// functions via a namespace trick is overkill; instead copy the handler
// invocation by requiring cron.php with a guard.
// Simplest: define the guard here.
define('CRON_TEST_NO_TICK', true);
if (!defined('CRON_TICK_SECS')) define('CRON_TICK_SECS', 0);

$pass = 0; $fail = 0;
function ok(bool $c, string $n): void { global $pass, $fail; if ($c) { $pass++; echo "  ok  $n\n"; } else { $fail++; echo "FAIL  $n\n"; } }

// ---- fixtures --------------------------------------------------------------
$bridgeKey = fm_secret_bridge_key();
$aliceSec  = random_hex(32);            // linked nostr user
$alicePk   = fm_pubkey_hex($aliceSec);
$bobSec    = random_hex(32);            // NOT linked
$bobPk     = fm_pubkey_hex($bobSec);

db()->prepare("INSERT INTO nostr_accounts (pubkey,bunker_enc,status,linked_at,updated_at)
               VALUES (?,?, 'linked', ?, ?)")
   ->execute([$alicePk, fm_encrypt_at_rest('bunker://' . str_repeat('ee', 32) . '?relay=wss%3A%2F%2Fr'), now(), now()]);
db()->prepare("INSERT INTO github_accounts
               (login,github_user_id,token_enc,provider,auth_status,
                linked_at,updated_at)
               VALUES (?,?,?,'github_app','active',?,?)")
   ->execute(['alice', '9001', fm_encrypt_at_rest('ghu_alice'), now(), now()]);
db()->prepare("INSERT INTO links (login,pubkey,created_at) VALUES (?,?,?)")
   ->execute(['alice', $alicePk, now()]);

// a mirrored repo + mirrored issue (as if Dir A ran earlier)
db()->prepare("INSERT INTO repos (github_full_name,repo_id,owner_pubkey,relays,
               verified,bridge_authorized,created_at,updated_at)
               VALUES (?,?,?,?,1,1,?,?)")
   ->execute(['friendly-machines-com/dummy', 'dummy', str_repeat('aa', 32), '["wss://relay.damus.io"]', now(), now()]);
db()->prepare(
    "INSERT INTO github_installations
     (installation_id,account_id,account_login,account_type,status,token_enc,
      token_expires_at,created_at,updated_at)
     VALUES ('42001','7001','friendly-machines-com','Organization','active',
             ?,?,?,?)"
)->execute([
    fm_encrypt_at_rest('ghs_bridge_app'),
    now() + 3600,
    now(),
    now(),
]);
db()->prepare(
    "INSERT INTO github_installation_repositories
     (repository_id,installation_id,github_full_name,status,created_at,updated_at)
     VALUES ('1340167971','42001','friendly-machines-com/dummy','active',?,?)"
)->execute([now(), now()]);
$rootEv = ['kind' => 1621, 'content' => 'issue body',
           'tags' => [['a', '30617:' . str_repeat('aa', 32) . ':dummy'], ['p', str_repeat('aa', 32)],
                      ['subject', 'x'], ['t', 'gh-1'], ['gh', 'friendly-machines-com/dummy#1']],
           'pubkey' => fm_pubkey_hex($bridgeKey), 'created_at' => now() - 500];
$rootSigned = fm_event_sign($rootEv, $bridgeKey);
db()->prepare("INSERT INTO event_map (github_id,nostr_id,direction,kind,author_pk,signed_by,meta,created_at)
               VALUES (?,?,?,?,?,?,?,?)")
   ->execute(['I_kwDOT_root', $rootSigned['id'], 'gh2nostr', 1621,
              $rootSigned['pubkey'], $rootSigned['pubkey'],
              json_c(['full' => 'friendly-machines-com/dummy', 'number' => 1, 'title' => 'x']), now() - 500]);

function mk1111(string $sec, string $rootId, string $rootAuthorPk, string $body, int $ts): array
{
    $pk = fm_pubkey_hex($sec);
    return fm_event_sign([
        'kind' => 1111, 'content' => $body, 'pubkey' => $pk, 'created_at' => $ts,
        'tags' => [
            ['E', $rootId, '', $rootAuthorPk], ['K', '1621'], ['P', $rootAuthorPk],
            ['e', $rootId, '', $rootAuthorPk], ['k', '1621'], ['p', $rootAuthorPk],
        ],
    ], $sec);
}

// replicate cron handler decision logic by calling it directly
require_once __DIR__ . '/../cron_handler.php';   // pure functions, no tick

// A linked user's repository-specific authorization failure must degrade
// attribution, never stop the crossing.
$credentialAttempts = [];
$fallback = bridge_github_execute_for_nostr(
    $alicePk,
    'friendly-machines-com/dummy',
    function (array $author) use (&$credentialAttempts): string {
        $credentialAttempts[] = $author['token'];
        if ($author['path'] === 'user') {
            throw new GhError('user lacks repository access', 403);
        }
        return 'crossed';
    }
);
ok(
    $credentialAttempts === ['ghu_alice', 'ghs_bridge_app']
    && $fallback['result'] === 'crossed'
    && $fallback['author']['path'] === 'app',
    'user authorization failure falls back to App without dropping crossing'
);

// 1. valid alice comment threads correctly -> queued
$c1 = mk1111($aliceSec, $rootSigned['id'], $rootSigned['pubkey'], 'hello from nostr', now() - 60);
cron_handle_nostr_event($c1);
$pending = db()->query("SELECT * FROM jobs WHERE status='pending' AND type='nostr2gh_comment'")->fetchAll();
ok(count($pending) === 1, 'valid linked comment queued');
$p = json_decode($pending[0]['payload'], true);
ok($p['root_nostr_id'] === $rootSigned['id'], 'job retains unresolved root id');
ok($p['nostr_id'] === $c1['id'], 'job carries nostr id for loop-kill');

// 2. loop-kill: same event again -> nothing new
cron_handle_nostr_event($c1);
ok(count(db()->query("SELECT 1 FROM jobs WHERE type='nostr2gh_comment'")->fetchAll()) === 1,
   'duplicate nostr id not requeued');

// The signed GitHub-origin marker closes the loop even if event_map was not
// committed after relay publication.
$origin = mk1111($aliceSec, $rootSigned['id'], $rootSigned['pubkey'],
                 'came from github', now() - 55);
$origin['tags'][] = ['proxy', 'https://github.com/friendly-machines-com/dummy/issues/1',
                     'github'];
$origin = fm_event_sign($origin, $aliceSec);
cron_handle_nostr_event($origin);
ok(count(db()->query("SELECT 1 FROM jobs WHERE type='nostr2gh_comment'")->fetchAll()) === 1,
   'signed GitHub origin marker prevents crash-window loop');

// 3. unlinked author (bob) is still bridged through the App installation
$c3 = mk1111($bobSec, $rootSigned['id'], $rootSigned['pubkey'], 'i am bob', now() - 50);
cron_handle_nostr_event($c3);
$jobs3 = db()->query("SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_comment'")->fetchColumn();
ok((int)$jobs3 === 2, 'unlinked author queued through bridge identity');

// 4. forged signature -> dropped + logged
$c4 = mk1111($aliceSec, $rootSigned['id'], $rootSigned['pubkey'], 'forged', now() - 40);
$c4['sig'] = str_repeat('f', 128);    // break sig
$c4['id']  = fm_event_id($c4);        // recompute id so only sig is wrong
cron_handle_nostr_event($c4);
ok((int)db()->query("SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_comment'")->fetchColumn() === 2,
   'forged signature dropped');

// The handler is also called by reference-specific backfills, not only by the
// main cursor path, so it must independently reject far-future timestamps.
$future = mk1111(
    $aliceSec,
    $rootSigned['id'],
    $rootSigned['pubkey'],
    'from the future',
    // Pure-PHP signing can cross a wall-clock second on a slow host. Keep
    // this comfortably beyond the five-minute acceptance boundary so the
    // assertion cannot become timing-dependent.
    now() + 3600
);
cron_handle_nostr_event($future);
ok(
    (int)db()->query(
        "SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_comment'"
    )->fetchColumn() === 2,
    'backfill handler rejects far-future events'
);

// 5. E-root not mirrored yet -> durably queued, not dropped
$c5 = mk1111($aliceSec, str_repeat('99', 32), $rootSigned['pubkey'], 'orphan', now() - 30);
cron_handle_nostr_event($c5);
ok((int)db()->query("SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_comment'")->fetchColumn() === 3,
   'unresolved root comment queued');

// Mandatory lowercase parent tags must also be structurally valid.
$badParent = mk1111(
    $aliceSec, $rootSigned['id'], $rootSigned['pubkey'], 'bad parent', now() - 25);
$badParent['tags'] = array_values(array_filter(
    $badParent['tags'], fn($tag) => ($tag[0] ?? '') !== 'k'));
$badParent = fm_event_sign($badParent, $aliceSec);
cron_handle_nostr_event($badParent);
ok((int)db()->query("SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_comment'")->fetchColumn() === 3,
   'malformed NIP-22 parent tags dropped');

// 6. executor: run the queued job -> github stub + ledger write
bridge_run_due_jobs(5);
$gh = $GLOBALS['__gh_comments'];
ok(count($gh) === 2, 'linked and unlinked GH comments posted');
ok($gh[0]['token'] === 'ghu_alice' && $gh[0]['body'] === 'hello from nostr',
   'posted with alice token, nostr body');
ok($gh[1]['token'] === 'ghs_bridge_app'
   && str_contains($gh[1]['body'], $c3['id'])
   && str_contains($gh[1]['body'], 'npub1')
   && str_contains($gh[1]['body'], 'i am bob'),
   'unlinked author posted with App token and visible attribution');
$em = db()->query("SELECT github_id, direction FROM event_map WHERE nostr_id = " . db()->quote($c1['id']))->fetch();
ok($em && $em['direction'] === 'nostr2gh' && $em['github_id'] === 'IC_fake1', 'nostr2gh ledger row written');
bridge_execute_job(['type' => 'nostr2gh_comment', 'payload_arr' => $p]);
ok(count($GLOBALS['__gh_comments']) === 2, 'retry with ledger row does not repost to GitHub');
$orphanJob = db()->query("SELECT * FROM jobs
                          WHERE dedupe_key='nostr:{$c5['id']}'")->fetch();
ok($orphanJob['status'] === 'pending' && (int)$orphanJob['fails'] === 0,
   'unresolved root defers without consuming failure budget');

// The same dependent may have been queued before its root. Seeing it again
// after root discovery must still schedule its deletion backfill.
db()->prepare(
    "INSERT INTO nostr_roots
     (nostr_id,kind,pubkey,github_full_name,event_created_at,discovered_at)
     VALUES (?,1621,?,?,?,?)"
)->execute([
    str_repeat('99', 32),
    $rootSigned['pubkey'],
    'friendly-machines-com/dummy',
    now() - 100,
    now(),
]);
cron_handle_nostr_event($c5);
ok(
    (bool)db()->query(
        "SELECT 1 FROM jobs
         WHERE type='nostr_backfill'
           AND dedupe_key LIKE '%:{$c5['id']}:deletions:%'"
    )->fetchColumn(),
    'already-queued dependent still schedules deletion backfill'
);

// 7. the loop-closing check: feeding the bridge's OWN publish of that GH
//    comment back through Dir A would hit event_map via nostr_id = c1.id
$st = db()->prepare('SELECT 1 FROM event_map WHERE nostr_id = ?');
$st->execute([$c1['id']]);
ok((bool)$st->fetchColumn(), 'A->B->A loop terminates (nostr_id present)');

// Repository stars use one immutable NIP-25 reaction and a same-author
// NIP-09 deletion. GitHub's user endpoint is idempotent, and a deletion may
// be banked before its target arrives.
$GLOBALS['__gh_starred'] = false;
$GLOBALS['__gh_star_calls'] = [];
$star = fm_event_sign([
    'kind' => 7,
    'content' => '⭐',
    'pubkey' => $alicePk,
    'created_at' => now() - 22,
    'tags' => [
        ['e', str_repeat('bc', 32), '', str_repeat('aa', 32)],
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['p', str_repeat('aa', 32)],
        ['k', '30617'],
    ],
], $aliceSec);
cron_handle_nostr_event($star);
$starJob = db()->prepare(
    'SELECT * FROM jobs WHERE dedupe_key=?'
);
$starJob->execute(['nostr:' . $star['id']]);
$starJobRow = $starJob->fetch();
$starPayload = json_decode((string)$starJobRow['payload'], true);
bridge_execute_job([
    'type' => 'nostr2gh_star',
    'payload_arr' => $starPayload,
]);
jobs_finish((int)$starJobRow['id'], true);
$starMap = db()->prepare(
    'SELECT kind,parent_github_id FROM event_map WHERE nostr_id=?'
);
$starMap->execute([$star['id']]);
$starMapRow = $starMap->fetch();
ok(
    ($GLOBALS['__gh_starred'] ?? false) === true
    && ($starMapRow['kind'] ?? null) === 7
    && ($starMapRow['parent_github_id'] ?? null)
        === 'star:1340167971:9001',
    'linked Nostr repository star crosses with stable GitHub pair identity'
);

$unstar = fm_event_sign([
    'kind' => 5,
    'content' => 'unstar',
    'pubkey' => $alicePk,
    'created_at' => now() - 21,
    'tags' => [
        ['e', $star['id']],
        ['k', '7'],
    ],
], $aliceSec);
cron_handle_nostr_event($unstar);
$unstarJob = db()->prepare(
    'SELECT * FROM jobs WHERE dedupe_key=?'
);
$unstarJob->execute([
    'nostr-delete:' . $unstar['id'] . ':' . $star['id'],
]);
$unstarJobRow = $unstarJob->fetch();
bridge_execute_job([
    'type' => 'nostr2gh_deletion',
    'payload_arr' => json_decode(
        (string)$unstarJobRow['payload'],
        true
    ),
]);
jobs_finish((int)$unstarJobRow['id'], true);
$starDeletion = db()->prepare(
    'SELECT 1 FROM deletion_map
     WHERE deletion_nostr_id=? AND target_nostr_id=?'
);
$starDeletion->execute([$unstar['id'], $star['id']]);
ok(
    ($GLOBALS['__gh_starred'] ?? true) === false
    && (bool)$starDeletion->fetchColumn(),
    'same-author Nostr star deletion unstars GitHub and banks tombstone'
);

$lateStar = fm_event_sign([
    'kind' => 7,
    'content' => '⭐',
    'pubkey' => $alicePk,
    'created_at' => now() - 20,
    'tags' => [
        ['e', str_repeat('bc', 32), '', str_repeat('aa', 32)],
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['p', str_repeat('aa', 32)],
        ['k', '30617'],
    ],
], $aliceSec);
$earlyUnstar = fm_event_sign([
    'kind' => 5,
    'content' => 'arrived before star',
    'pubkey' => $alicePk,
    'created_at' => now() - 19,
    'tags' => [['e', $lateStar['id']], ['k', '7']],
], $aliceSec);
cron_handle_nostr_event($earlyUnstar);
$earlyUnstarJob = db()->prepare(
    'SELECT * FROM jobs WHERE dedupe_key=?'
);
$earlyUnstarJob->execute([
    'nostr-delete:' . $earlyUnstar['id'] . ':' . $lateStar['id'],
]);
$earlyUnstarJobRow = $earlyUnstarJob->fetch();
try {
    bridge_execute_job([
        'type' => 'nostr2gh_deletion',
        'payload_arr' => json_decode(
            (string)$earlyUnstarJobRow['payload'],
            true
        ),
    ]);
    ok(false, 'unstar-before-star defers for its target');
} catch (BridgeDefer $error) {
    ok(true, 'unstar-before-star defers for its target');
}
cron_handle_nostr_event($lateStar);
$lateStarJob = db()->prepare(
    'SELECT * FROM jobs WHERE dedupe_key=?'
);
$lateStarJob->execute(['nostr:' . $lateStar['id']]);
$lateStarJobRow = $lateStarJob->fetch();
bridge_execute_job([
    'type' => 'nostr2gh_star',
    'payload_arr' => json_decode(
        (string)$lateStarJobRow['payload'],
        true
    ),
]);
bridge_execute_job([
    'type' => 'nostr2gh_deletion',
    'payload_arr' => json_decode(
        (string)$earlyUnstarJobRow['payload'],
        true
    ),
]);
jobs_finish((int)$lateStarJobRow['id'], true);
jobs_finish((int)$earlyUnstarJobRow['id'], true);
$earlyDeletion = db()->prepare(
    'SELECT 1 FROM deletion_map
     WHERE deletion_nostr_id=? AND target_nostr_id=?'
);
$earlyDeletion->execute([$earlyUnstar['id'], $lateStar['id']]);
ok(
    ($GLOBALS['__gh_starred'] ?? true) === false
    && (bool)$earlyDeletion->fetchColumn(),
    'unstar-before-star converges after the target crossing arrives'
);

// 8. nostr-native 1621 on mapped repo -> queued as issue creation
$i8 = fm_event_sign([
    'kind' => 1621, 'content' => 'brand new issue', 'pubkey' => $bobPk, 'created_at' => now() - 20,
    'tags' => [
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['p', str_repeat('aa', 32)], ['subject', 'from nostr'],
    ],
], $bobSec);
cron_handle_nostr_event($i8);
$jobs8 = db()->query("SELECT COUNT(*) c FROM jobs WHERE type='nostr2gh_issue'")->fetch();
ok((int)$jobs8['c'] === 1, 'nostr 1621 on mapped repo queued as issue');

// A comment may arrive and execute before its Nostr-native root has crossed.
$early = mk1111($aliceSec, $i8['id'], $bobPk, 'arrived first', now() - 19);
cron_handle_nostr_event($early);
$earlyJob = db()->prepare("SELECT payload FROM jobs WHERE dedupe_key=?");
$earlyJob->execute(['nostr:' . $early['id']]);
$earlyPayload = json_decode($earlyJob->fetchColumn(), true);
try {
    bridge_execute_job(['type' => 'nostr2gh_comment', 'payload_arr' => $earlyPayload]);
    ok(false, 'comment-before-root defers');
} catch (BridgeDefer $e) {
    ok(true, 'comment-before-root defers');
}
$rootJob = db()->prepare("SELECT payload FROM jobs
                          WHERE type='nostr2gh_issue' AND dedupe_key=?");
$rootJob->execute(['nostr:' . $i8['id']]);
$rootPayload = json_decode($rootJob->fetchColumn(), true);
bridge_execute_job(['type' => 'nostr2gh_issue', 'payload_arr' => $rootPayload]);
bridge_execute_job(['type' => 'nostr2gh_comment', 'payload_arr' => $earlyPayload]);
$earlyMapped = db()->prepare('SELECT 1 FROM event_map WHERE nostr_id=?');
$earlyMapped->execute([$early['id']]);
ok((bool)$earlyMapped->fetchColumn(), 'comment-before-root converges after root crossing');
$created = array_values(array_filter(
    $GLOBALS['__gh_comments'], fn($call) => isset($call['title'])));
ok(count($created) === 1
   && $created[0]['token'] === 'ghs_bridge_app'
   && str_contains($created[0]['body'], $i8['id']),
   'unlinked Nostr issue uses App token with attribution');

// A reply parent must belong to the same immutable root, not merely exist
// somewhere in the event ledger.
$crossRootReply = mk1111(
    $aliceSec,
    $rootSigned['id'],
    $rootSigned['pubkey'],
    'invalid cross-root reply',
    now() - 18
);
$crossRootReply['tags'][3] = ['e', $early['id'], '', $alicePk];
$crossRootReply['tags'][4] = ['k', '1111'];
$crossRootReply['tags'][5] = ['p', $alicePk];
$crossRootReply = fm_event_sign($crossRootReply, $aliceSec);
cron_handle_nostr_event($crossRootReply);
$crossRootJob = db()->prepare('SELECT payload FROM jobs WHERE dedupe_key=?');
$crossRootJob->execute(['nostr:' . $crossRootReply['id']]);
$crossRootPayload = json_decode($crossRootJob->fetchColumn(), true);
try {
    bridge_execute_job([
        'type' => 'nostr2gh_comment',
        'payload_arr' => $crossRootPayload,
    ]);
    ok(false, 'cross-root comment parent rejected');
} catch (BridgeSkip $error) {
    ok(true, 'cross-root comment parent rejected');
}

// A close status may arrive before its root and must converge in either order.
$lateRoot = fm_event_sign([
    'kind' => 1621,
    'content' => 'status root',
    'pubkey' => $bobPk,
    'created_at' => now() - 15,
    'tags' => [
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['p', str_repeat('aa', 32)],
        ['subject', 'status root'],
    ],
], $bobSec);
$earlyStatus = fm_event_sign([
    'kind' => 1632,
    'content' => 'closed before root was collected',
    'pubkey' => $bobPk,
    'created_at' => now() - 14,
    'tags' => [
        ['e', $lateRoot['id'], '', 'root'],
        ['p', str_repeat('aa', 32)],
        ['p', $bobPk],
    ],
], $bobSec);
cron_handle_nostr_event($earlyStatus);
$statusJob = db()->prepare("SELECT payload FROM jobs WHERE dedupe_key=?");
$statusJob->execute(['nostr:' . $earlyStatus['id']]);
$statusPayload = json_decode($statusJob->fetchColumn(), true);
try {
    bridge_execute_job(['type' => 'nostr2gh_status', 'payload_arr' => $statusPayload]);
    ok(false, 'status-before-root defers');
} catch (BridgeDefer $e) {
    ok(true, 'status-before-root defers');
}
cron_handle_nostr_event($lateRoot);
$lateRootJob = db()->prepare("SELECT payload FROM jobs WHERE dedupe_key=?");
$lateRootJob->execute(['nostr:' . $lateRoot['id']]);
$lateRootPayload = json_decode($lateRootJob->fetchColumn(), true);
bridge_execute_job(['type' => 'nostr2gh_issue', 'payload_arr' => $lateRootPayload]);
bridge_execute_job(['type' => 'nostr2gh_status', 'payload_arr' => $statusPayload]);
$statusMapped = db()->prepare('SELECT kind FROM event_map WHERE nostr_id=?');
$statusMapped->execute([$earlyStatus['id']]);
ok((int)$statusMapped->fetchColumn() === 1632,
   'status-before-root converges after root crossing');
$stateCalls = array_values(array_filter(
    $GLOBALS['__gh_comments'], fn($call) => array_key_exists('closed', $call)));
ok(count($stateCalls) === 1
   && $stateCalls[0]['token'] === 'ghs_bridge_app'
   && $stateCalls[0]['closed'] === true,
   'unlinked Nostr close uses App token');

// Status authority is not enough by itself: the NIP-34 status form also
// identifies the repository publisher and root author with p tags.
$missingOwnerTag = fm_event_sign([
    'kind' => 1630,
    'content' => 'malformed open',
    'pubkey' => $bobPk,
    'created_at' => now() - 13,
    'tags' => [
        ['e', $lateRoot['id'], '', 'root'],
        ['p', $bobPk],
    ],
], $bobSec);
cron_handle_nostr_event($missingOwnerTag);
$missingOwnerJob = db()->prepare(
    'SELECT payload FROM jobs WHERE dedupe_key=?'
);
$missingOwnerJob->execute(['nostr:' . $missingOwnerTag['id']]);
try {
    bridge_execute_job([
        'type' => 'nostr2gh_status',
        'payload_arr' => json_decode(
            $missingOwnerJob->fetchColumn(),
            true
        ),
    ]);
    ok(false, 'status missing repository publisher p tag rejected');
} catch (BridgeSkip $error) {
    ok(true, 'status missing repository publisher p tag rejected');
}

// NIP-34 state is source-time ordered. Process newest first, then older:
// the older delivery is banked but must not mutate GitHub.
$statusBase = now() - 8;
$newOpen = fm_event_sign([
    'kind' => 1630,
    'content' => 'newest open',
    'pubkey' => $bobPk,
    'created_at' => $statusBase + 3,
    'tags' => [
        ['e', $lateRoot['id'], '', 'root'],
        ['p', str_repeat('aa', 32)],
        ['p', $bobPk],
    ],
], $bobSec);
cron_handle_nostr_event($newOpen);
$statusLookup = db()->prepare('SELECT payload FROM jobs WHERE dedupe_key=?');
$statusLookup->execute(['nostr:' . $newOpen['id']]);
bridge_execute_job([
    'type' => 'nostr2gh_status',
    'payload_arr' => json_decode($statusLookup->fetchColumn(), true),
]);
$afterOpen = count(array_filter(
    $GLOBALS['__gh_comments'],
    fn($call) => array_key_exists('closed', $call)
));

$olderClose = fm_event_sign([
    'kind' => 1632,
    'content' => 'older close delivered later',
    'pubkey' => $bobPk,
    'created_at' => $statusBase + 1,
    'tags' => [
        ['e', $lateRoot['id'], '', 'root'],
        ['p', str_repeat('aa', 32)],
        ['p', $bobPk],
    ],
], $bobSec);
cron_handle_nostr_event($olderClose);
$statusLookup->execute(['nostr:' . $olderClose['id']]);
bridge_execute_job([
    'type' => 'nostr2gh_status',
    'payload_arr' => json_decode($statusLookup->fetchColumn(), true),
]);
$afterOlder = count(array_filter(
    $GLOBALS['__gh_comments'],
    fn($call) => array_key_exists('closed', $call)
));
ok(
    $afterOpen === $afterOlder
    && bridge_nostr_already_mapped($olderClose['id']),
    'older NIP-34 status cannot overwrite newer GitHub state'
);

$resolved = fm_event_sign([
    'kind' => 1631,
    'content' => 'resolved',
    'pubkey' => $bobPk,
    'created_at' => $statusBase + 4,
    'tags' => [
        ['e', $lateRoot['id'], '', 'root'],
        ['p', str_repeat('aa', 32)],
        ['p', $bobPk],
    ],
], $bobSec);
cron_handle_nostr_event($resolved);
$statusLookup->execute(['nostr:' . $resolved['id']]);
bridge_execute_job([
    'type' => 'nostr2gh_status',
    'payload_arr' => json_decode($statusLookup->fetchColumn(), true),
]);
$resolvedCalls = array_values(array_filter(
    $GLOBALS['__gh_comments'],
    fn($call) => array_key_exists('closed', $call)
));
ok(
    end($resolvedCalls)['closed'] === true
    && end($resolvedCalls)['statusKind'] === 1631,
    'NIP-34 Resolved maps to GitHub completed'
);

$draft = fm_event_sign([
    'kind' => 1633,
    'content' => 'draft',
    'pubkey' => $bobPk,
    'created_at' => $statusBase + 5,
    'tags' => [
        ['e', $lateRoot['id'], '', 'root'],
        ['p', str_repeat('aa', 32)],
        ['p', $bobPk],
    ],
], $bobSec);
$beforeDraft = count($resolvedCalls);
cron_handle_nostr_event($draft);
$statusLookup->execute(['nostr:' . $draft['id']]);
bridge_execute_job([
    'type' => 'nostr2gh_status',
    'payload_arr' => json_decode($statusLookup->fetchColumn(), true),
]);
$afterDraft = count(array_filter(
    $GLOBALS['__gh_comments'],
    fn($call) => array_key_exists('closed', $call)
));
$lateRootMap = db()->prepare(
    'SELECT github_id FROM event_map WHERE nostr_id=?'
);
$lateRootMap->execute([$lateRoot['id']]);
$latestStatus = bridge_latest_nostr_status($lateRootMap->fetchColumn());
ok(
    $afterDraft === $beforeDraft
    && $latestStatus !== null
    && $latestStatus['nostr_id'] === $draft['id'],
    'NIP-34 Draft becomes the head without inventing GitHub state'
);

// Deleting the current Draft exposes the prior Resolved status and applies
// that effective state to GitHub. It is state reduction, not a new comment.
$deleteDraft = fm_event_sign([
    'kind' => 5,
    'content' => 'draft was accidental',
    'pubkey' => $bobPk,
    'created_at' => $statusBase + 6,
    'tags' => [['e', $draft['id']], ['k', '1633']],
], $bobSec);
cron_handle_nostr_event($deleteDraft);
$deleteDraftJob = db()->prepare(
    'SELECT payload FROM jobs WHERE dedupe_key=?'
);
$deleteDraftJob->execute([
    'nostr-delete:' . $deleteDraft['id'] . ':' . $draft['id'],
]);
$beforeStatusDeleteCalls = count($GLOBALS['__gh_comments']);
$beforeStatusDeleteComments = count(array_filter(
    $GLOBALS['__gh_comments'],
    fn($call) => isset($call['body'])
));
bridge_execute_job([
    'type' => 'nostr2gh_deletion',
    'payload_arr' => json_decode($deleteDraftJob->fetchColumn(), true),
]);
$afterStatusDeleteComments = count(array_filter(
    $GLOBALS['__gh_comments'],
    fn($call) => isset($call['body'])
));
$lateRootMap->execute([$lateRoot['id']]);
$latestAfterDelete = bridge_latest_nostr_status(
    (string)$lateRootMap->fetchColumn()
);
ok(
    count($GLOBALS['__gh_comments']) === $beforeStatusDeleteCalls + 1
    && $afterStatusDeleteComments === $beforeStatusDeleteComments
    && $latestAfterDelete !== null
    && $latestAfterDelete['nostr_id'] === $resolved['id'],
    'deleting current status exposes and applies the previous status'
);

// A NIP-09 request may arrive before the target. It remains durable, then
// tombstones the GitHub issue only after the same-author target is mapped.
$deleteTarget = fm_event_sign([
    'kind' => 1621,
    'content' => 'delete me later',
    'pubkey' => $bobPk,
    'created_at' => now() - 12,
    'tags' => [
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['p', str_repeat('aa', 32)],
        ['subject', 'delete target'],
    ],
], $bobSec);
$deleteFirst = fm_event_sign([
    'kind' => 5,
    'content' => 'published accidentally',
    'pubkey' => $bobPk,
    'created_at' => now() - 11,
    'tags' => [
        ['e', $deleteTarget['id']],
        ['k', '1621'],
    ],
], $bobSec);
cron_handle_nostr_event($deleteFirst);
$deleteJob = db()->prepare("SELECT payload FROM jobs WHERE dedupe_key=?");
$deleteJob->execute(['nostr-delete:' . $deleteFirst['id'] . ':' . $deleteTarget['id']]);
$deletePayload = json_decode($deleteJob->fetchColumn(), true);
try {
    bridge_execute_job(['type' => 'nostr2gh_deletion', 'payload_arr' => $deletePayload]);
    ok(false, 'deletion-before-target defers');
} catch (BridgeDefer $e) {
    ok(true, 'deletion-before-target defers');
}
cron_handle_nostr_event($deleteTarget);
$deleteTargetJob = db()->prepare("SELECT payload FROM jobs WHERE dedupe_key=?");
$deleteTargetJob->execute(['nostr:' . $deleteTarget['id']]);
$deleteTargetPayload = json_decode($deleteTargetJob->fetchColumn(), true);
bridge_execute_job(['type' => 'nostr2gh_issue', 'payload_arr' => $deleteTargetPayload]);
bridge_execute_job(['type' => 'nostr2gh_deletion', 'payload_arr' => $deletePayload]);
$deleted = db()->prepare("SELECT 1 FROM deletion_map
                          WHERE deletion_nostr_id=? AND target_nostr_id=?");
$deleted->execute([$deleteFirst['id'], $deleteTarget['id']]);
ok((bool)$deleted->fetchColumn(),
   'deletion-before-target converges after target crossing');
$tombstones = array_values(array_filter(
    $GLOBALS['__gh_comments'],
    fn($call) => isset($call['body'])
        && str_contains($call['body'], 'Deletion requested on Nostr')));
ok(count($tombstones) === 1
   && $tombstones[0]['token'] === 'ghs_bridge_app',
   'unlinked Nostr deletion uses App token and visible attribution');

// A Nostr deletion of a mapped comment uses GitHub's actual comment DELETE
// path. It must not append a second "deletion notice" comment.
$deleteComment = fm_event_sign([
    'kind' => 5,
    'content' => 'remove my comment',
    'pubkey' => $alicePk,
    'created_at' => now() - 10,
    'tags' => [['e', $c1['id']], ['k', '1111']],
], $aliceSec);
cron_handle_nostr_event($deleteComment);
$deleteCommentJob = db()->prepare(
    'SELECT payload FROM jobs WHERE dedupe_key=?'
);
$deleteCommentJob->execute([
    'nostr-delete:' . $deleteComment['id'] . ':' . $c1['id'],
]);
$commentsBeforeDelete = count($GLOBALS['__gh_comments']);
bridge_execute_job([
    'type' => 'nostr2gh_deletion',
    'payload_arr' => json_decode($deleteCommentJob->fetchColumn(), true),
]);
$deleteCall = $GLOBALS['__gh_comments'][$commentsBeforeDelete] ?? null;
ok(
    is_array($deleteCall)
    && ($deleteCall['nodeId'] ?? null) === 'IC_fake1'
    && !array_key_exists('body', $deleteCall),
    'Nostr comment deletion removes the mapped GitHub comment'
);

// If GitHub deleted its mirror first, that fact lives on the target comment,
// not the still-existing issue root. A later same-author Nostr deletion must
// close locally without requiring another impossible GitHub DELETE.
db()->prepare('UPDATE event_map SET meta=? WHERE nostr_id=?')
   ->execute([
       json_c([
           'full' => 'friendly-machines-com/dummy',
           'number' => 1,
           'github_deleted' => true,
       ]),
       $c3['id'],
   ]);
$deleteAlreadyGoneComment = fm_event_sign([
    'kind' => 5,
    'content' => 'confirm deleted comment',
    'pubkey' => $bobPk,
    'created_at' => now() - 9,
    'tags' => [['e', $c3['id']], ['k', '1111']],
], $bobSec);
cron_handle_nostr_event($deleteAlreadyGoneComment);
$alreadyGoneJob = db()->prepare(
    'SELECT payload FROM jobs WHERE dedupe_key=?'
);
$alreadyGoneJob->execute([
    'nostr-delete:' . $deleteAlreadyGoneComment['id'] . ':' . $c3['id'],
]);
$beforeAlreadyGone = count($GLOBALS['__gh_comments']);
bridge_execute_job([
    'type' => 'nostr2gh_deletion',
    'payload_arr' => json_decode($alreadyGoneJob->fetchColumn(), true),
]);
$alreadyGoneMapped = db()->prepare(
    'SELECT 1 FROM deletion_map
     WHERE deletion_nostr_id=? AND target_nostr_id=?'
);
$alreadyGoneMapped->execute([
    $deleteAlreadyGoneComment['id'],
    $c3['id'],
]);
ok(
    count($GLOBALS['__gh_comments']) === $beforeAlreadyGone
    && (bool)$alreadyGoneMapped->fetchColumn(),
    'comment deletion converges after its GitHub mirror was already deleted'
);

$deletionTarget = fm_event_sign([
    'kind' => 5,
    'content' => 'original deletion request',
    'pubkey' => $bobPk,
    'created_at' => now() - 10,
    'tags' => [['e', $deleteTarget['id']], ['k', '1621']],
], $bobSec);
db()->prepare(
    "INSERT INTO event_map
     (github_id,nostr_id,direction,kind,author_pk,signed_by,
      parent_github_id,meta,created_at)
     VALUES (?,?,?,?,?,?,?,?,?)"
)->execute([
    'delete-crossing-for-test',
    $deletionTarget['id'],
    'gh2nostr',
    5,
    $bobPk,
    $bobPk,
    'I_kwDOT_root',
    json_c(['full' => 'friendly-machines-com/dummy', 'number' => 1]),
    now(),
]);
$deleteDeletion = fm_event_sign([
    'kind' => 5,
    'content' => 'try to undo deletion',
    'pubkey' => $bobPk,
    'created_at' => now() - 9,
    'tags' => [['e', $deletionTarget['id']], ['k', '5']],
], $bobSec);
cron_handle_nostr_event($deleteDeletion);
$deleteDeletionJob = db()->prepare(
    'SELECT payload FROM jobs WHERE dedupe_key=?'
);
$deleteDeletionJob->execute([
    'nostr-delete:' . $deleteDeletion['id'] . ':' . $deletionTarget['id'],
]);
try {
    bridge_execute_job([
        'type' => 'nostr2gh_deletion',
        'payload_arr' => json_decode(
            $deleteDeletionJob->fetchColumn(),
            true
        ),
    ]);
    ok(false, 'deleting a deletion request has no effect');
} catch (BridgeSkip $error) {
    ok(true, 'deleting a deletion request has no effect');
}

$forgedDelete = fm_event_sign([
    'kind' => 5,
    'content' => 'not mine',
    'pubkey' => $alicePk,
    'created_at' => now() - 10,
    'tags' => [['e', $deleteTarget['id']], ['k', '1621']],
], $aliceSec);
cron_handle_nostr_event($forgedDelete);
$forgedDeleteJob = db()->prepare("SELECT payload FROM jobs WHERE dedupe_key=?");
$forgedDeleteJob->execute([
    'nostr-delete:' . $forgedDelete['id'] . ':' . $deleteTarget['id'],
]);
$forgedDeletePayload = json_decode($forgedDeleteJob->fetchColumn(), true);
try {
    bridge_execute_job([
        'type' => 'nostr2gh_deletion',
        'payload_arr' => $forgedDeletePayload,
    ]);
    ok(false, 'different-author deletion rejected');
} catch (BridgeSkip $e) {
    ok(true, 'different-author deletion rejected');
}

// GitHub may delete its mirror before a later Nostr status-deletion request is
// processed. The Nostr reduction must still be recorded without retrying an
// impossible GitHub mutation or waiting for App access.
$goneRoot = fm_event_sign([
    'kind' => 1621,
    'content' => 'already gone from GitHub',
    'pubkey' => $bobPk,
    'created_at' => now() - 8,
    'tags' => [
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['p', str_repeat('aa', 32)],
        ['subject', 'gone'],
    ],
], $bobSec);
db()->prepare(
    "INSERT INTO event_map
     (github_id,nostr_id,direction,kind,author_pk,signed_by,meta,created_at)
     VALUES (?,?,?,?,?,?,?,?)"
)->execute([
    'I_github_deleted',
    $goneRoot['id'],
    'nostr2gh',
    1621,
    $bobPk,
    $bobPk,
    json_c([
        'full' => 'friendly-machines-com/dummy',
        'number' => 99,
        'github_deleted' => true,
    ]),
    now(),
]);
$goneStatus = fm_event_sign([
    'kind' => 1632,
    'content' => 'closed',
    'pubkey' => $bobPk,
    'created_at' => now() - 7,
    'tags' => [
        ['e', $goneRoot['id'], '', 'root'],
        ['p', $bobPk],
    ],
], $bobSec);
bridge_record_nostr_status(
    [
        'nostr_id' => $goneStatus['id'],
        'kind' => 1632,
        'pubkey' => $bobPk,
        'created_at' => $goneStatus['created_at'],
    ],
    [
        'github_id' => 'I_github_deleted',
        'author_pk' => $bobPk,
    ],
    'friendly-machines-com/dummy',
    99,
    'closed',
    'app',
    true
);
$deleteGoneStatus = fm_event_sign([
    'kind' => 5,
    'content' => 'remove stale status',
    'pubkey' => $bobPk,
    'created_at' => now() - 6,
    'tags' => [['e', $goneStatus['id']], ['k', '1632']],
], $bobSec);
cron_handle_nostr_event($deleteGoneStatus);
$deleteGoneJob = db()->prepare(
    'SELECT payload FROM jobs WHERE dedupe_key=?'
);
$deleteGoneJob->execute([
    'nostr-delete:' . $deleteGoneStatus['id'] . ':' . $goneStatus['id'],
]);
$githubCallsBeforeGoneDelete = count($GLOBALS['__gh_comments']);
bridge_execute_job([
    'type' => 'nostr2gh_deletion',
    'payload_arr' => json_decode($deleteGoneJob->fetchColumn(), true),
]);
$goneDeletion = db()->prepare(
    'SELECT 1 FROM deletion_map
     WHERE deletion_nostr_id=? AND target_nostr_id=?'
);
$goneDeletion->execute([$deleteGoneStatus['id'], $goneStatus['id']]);
ok(
    count($GLOBALS['__gh_comments']) === $githubCallsBeforeGoneDelete
    && (bool)$goneDeletion->fetchColumn(),
    'status deletion converges after its GitHub mirror was already deleted'
);

// A proxy tag is an origin claim, not authority to reconstruct a ledger row.
// Durable GitHub jobs perform deterministic relay recovery themselves.
$proxyRoot = fm_event_sign([
    'kind' => 1621,
    'content' => 'already exists on GitHub',
    'pubkey' => fm_pubkey_hex($bridgeKey),
    'created_at' => now() - 9,
    'tags' => [
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['p', str_repeat('aa', 32)],
        ['subject', 'recover me'],
        ['gh', 'friendly-machines-com/dummy#33'],
        ['proxy', 'https://github.com/friendly-machines-com/dummy/issues/33', 'github'],
    ],
], $bridgeKey);
cron_handle_nostr_event($proxyRoot);
$reconciled = db()->prepare('SELECT github_id FROM event_map WHERE nostr_id=?');
$reconciled->execute([$proxyRoot['id']]);
ok($reconciled->fetchColumn() === false
   && (int)db()->query(
       "SELECT COUNT(*) FROM jobs
        WHERE type LIKE 'reconcile_github_%'"
   )->fetchColumn() === 0,
   'self-labelled proxy root cannot poison the crossing ledger');
$proxyComment = mk1111(
    $bridgeKey,
    $proxyRoot['id'],
    $proxyRoot['pubkey'],
    'existing GitHub comment',
    now() - 8);
$proxyComment['tags'][] = [
    'proxy',
    'https://github.com/friendly-machines-com/dummy/issues/33#issuecomment-3301',
    'github',
];
$proxyComment = fm_event_sign($proxyComment, $bridgeKey);
cron_handle_nostr_event($proxyComment);
$reconciledComment = db()->prepare(
    'SELECT github_id FROM event_map WHERE nostr_id=?');
$reconciledComment->execute([$proxyComment['id']]);
ok($reconciledComment->fetchColumn() === false,
   'self-labelled proxy comment cannot poison the crossing ledger');

// 9. wrong-repo 1621 -> dropped
$i9 = fm_event_sign([
    'kind' => 1621, 'content' => 'x', 'pubkey' => $alicePk, 'created_at' => now() - 10,
    'tags' => [
        ['a', '30617:' . str_repeat('bb', 32) . ':other'],
        ['p', str_repeat('bb', 32)],
    ],
], $aliceSec);
cron_handle_nostr_event($i9);
ok((int)db()->query("SELECT COUNT(*) c FROM jobs WHERE type='nostr2gh_issue'")->fetchColumn() === 3,
   '1621 for unmapped repo dropped');

// Collection semantics: identical scalar duplicates collapse; conflicting
// values are ambiguous and are rejected under every tag permutation.
$issueCount = (int)db()->query(
    "SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_issue'"
)->fetchColumn();
$duplicateAddress = fm_event_sign([
    'kind' => 1621,
    'content' => 'duplicate scalar',
    'pubkey' => $bobPk,
    'created_at' => now() - 7,
    'tags' => [
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['subject', 'same'],
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['subject', 'same'],
        ['p', str_repeat('aa', 32)],
    ],
], $bobSec);
cron_handle_nostr_event($duplicateAddress);
ok(
    (int)db()->query(
        "SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_issue'"
    )->fetchColumn() === $issueCount + 1,
    'identical issue scalar duplicates collapse'
);

$issueCount++;
foreach ([false, true] as $reverse) {
    $tags = [
        ['a', '30617:' . str_repeat('aa', 32) . ':dummy'],
        ['a', '30617:' . str_repeat('aa', 32) . ':other'],
        ['p', str_repeat('aa', 32)],
    ];
    if ($reverse) $tags = array_reverse($tags);
    cron_handle_nostr_event(fm_event_sign([
        'kind' => 1621,
        'content' => 'ambiguous destination',
        'pubkey' => $bobPk,
        'created_at' => now() - ($reverse ? 5 : 6),
        'tags' => $tags,
    ], $bobSec));
}
ok(
    (int)db()->query(
        "SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_issue'"
    )->fetchColumn() === $issueCount,
    'conflicting issue destinations are rejected in every tag order'
);

$commentCount = (int)db()->query(
    "SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_comment'"
)->fetchColumn();
foreach ([false, true] as $reverse) {
    $tags = [
        ['E', $rootSigned['id'], '', $rootSigned['pubkey']],
        ['E', str_repeat('77', 32), '', $rootSigned['pubkey']],
        ['K', '1621'],
        ['P', $rootSigned['pubkey']],
        ['e', $rootSigned['id'], '', $rootSigned['pubkey']],
        ['k', '1621'],
        ['p', $rootSigned['pubkey']],
    ];
    if ($reverse) $tags = array_reverse($tags);
    cron_handle_nostr_event(fm_event_sign([
        'kind' => 1111,
        'content' => 'ambiguous root',
        'pubkey' => $alicePk,
        'created_at' => now() - ($reverse ? 3 : 4),
        'tags' => $tags,
    ], $aliceSec));
}
ok(
    (int)db()->query(
        "SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_comment'"
    )->fetchColumn() === $commentCount,
    'conflicting NIP-22 roots are rejected in every tag order'
);

$statusCount = (int)db()->query(
    "SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_status'"
)->fetchColumn();
foreach ([false, true] as $reverse) {
    $tags = [
        ['e', $lateRoot['id'], '', 'root'],
        ['e', str_repeat('66', 32), '', 'root'],
        ['p', str_repeat('aa', 32)],
        ['p', $bobPk],
    ];
    if ($reverse) $tags = array_reverse($tags);
    cron_handle_nostr_event(fm_event_sign([
        'kind' => 1632,
        'content' => 'ambiguous status root',
        'pubkey' => $bobPk,
        'created_at' => now() - ($reverse ? 1 : 2),
        'tags' => $tags,
    ], $bobSec));
}
ok(
    (int)db()->query(
        "SELECT COUNT(*) FROM jobs WHERE type='nostr2gh_status'"
    )->fetchColumn() === $statusCount,
    'conflicting status roots are rejected in every tag order'
);

$targetA = str_repeat('44', 32);
$targetB = str_repeat('55', 32);
$deleteSet = fm_event_sign([
    'kind' => 5,
    'content' => '',
    'pubkey' => $bobPk,
    'created_at' => now(),
    'tags' => [
        ['e', $targetB],
        ['e', $targetA],
        ['e', $targetB],
    ],
], $bobSec);
cron_handle_nostr_event($deleteSet);
$deleteTargets = db()->prepare(
    "SELECT payload FROM jobs
     WHERE dedupe_key LIKE ?
     ORDER BY id"
);
$deleteTargets->execute(['nostr-delete:' . $deleteSet['id'] . ':%']);
$queuedTargets = array_map(
    fn($payload) => json_decode($payload, true)['target_nostr_id'] ?? null,
    $deleteTargets->fetchAll(PDO::FETCH_COLUMN)
);
ok(
    $queuedTargets === [$targetA, $targetB],
    'deletion targets are a sorted set rather than tag order'
);

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);

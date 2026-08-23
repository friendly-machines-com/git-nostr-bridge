<?php
/**
 * cron.php -- Direction B (Nostr -> GitHub) + retries. CLI ONLY.
 * No daemon; bounded job batches and short relay sockets. Slow external
 * services can make a tick exceed the cron interval, so flock guards overlap.
 *
 *   1. drain due jobs (Dir A retries + Dir B posts)
 *   2. recheck known GitHub star pairs and discover every repository-scoped
 *      Nostr kind 7 / 1621 event
 *   3. query comments and all four NIP-34 statuses by immutable root IDs
 *   4. verify -> durable enqueue; unresolved dependencies defer, never drop
 *   5. advance per-relay cursor (with 120s lag window)
 *   6. GC expired oauth/nip46 states
 *
 * Cron (every minute):
 *   * * * * * php /home/dh_4nnf3n/auth.friendly-machines.com/v1/cron.php \
 *     >> /home/dh_4nnf3n/bridge-cron.log 2>&1
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib/util.php';
require_once __DIR__ . '/lib/secrets.php';
require_once __DIR__ . '/lib/crypto.php';
require_once __DIR__ . '/lib/jobs.php';
require_once __DIR__ . '/lib/bridge.php';
require_once __DIR__ . '/lib/relay.php';

const CRON_TICK_SECS   = 12;    // relay read window
const CURSOR_LAG_SECS  = 120;   // clock-skew safety (DESIGN §11)
const CRON_PAGE_LIMIT  = 1000;
const CRON_FULL_RESCAN_SECS = 3600;
const GITHUB_INSTALLATION_DISCOVERY_SECS = 3600;

function cron_event_matches_filter(array $event, array $filter): bool
{
    return relay_event_matches_filter($event, $filter);
}

// --- overlap guard ----------------------------------------------------------
$dbFile = getenv('BRIDGE_DB') ?: __DIR__ . '/bridge.db';
db(); // initialize the selected database before creating its adjacent lock
$lockFp = fopen($dbFile . '.cron.lock', 'c');
if ($lockFp) chmod($dbFile . '.cron.lock', 0600);
if (!$lockFp || !flock($lockFp, LOCK_EX | LOCK_NB)) {
    echo date('c'), " another tick is running; exiting\n";
    exit(0);
}

require_once __DIR__ . '/cron_handler.php';

/**
 * Run one resumable, backwards-paginated filter. Cursor names are separate
 * from relay URLs so roots/comments/statuses can advance independently.
 *
 * @return array events accepted from this page (also sent to the handler)
 */
function cron_poll_relay_filter(
    string $relay, string $cursorName, array $filter, int $initialSince = 1
): array
{
    $db = db();
    $cur = $db->prepare('SELECT * FROM poll_cursor WHERE relay = ?');
    $cur->execute([$cursorName]);
    $cursor = $cur->fetch();
    // Do not retain a SQLite read snapshot across relay I/O. A web request may
    // commit while the socket is open; attempting to upgrade that stale WAL
    // snapshot for the cursor write then fails with SQLITE_BUSY_SNAPSHOT
    // ("database is locked"), which busy_timeout cannot resolve.
    $cur->closeCursor();
    $lastSeen = (int)($cursor['last_seen'] ?? $initialSince);
    $scanUntil = isset($cursor['scan_until']) ? (int)$cursor['scan_until'] : null;

    // Relay arrival order and event created_at are independent. Incremental
    // cursors are only a latency optimization; hourly full sweeps guarantee
    // eventual discovery of events published later with old timestamps.
    $fullScanKey = 'nostr_full_scan|' . $cursorName;
    if ($cursor && $scanUntil === null && $lastSeen > $initialSince) {
        $full = $db->prepare('SELECT v FROM schema_meta WHERE k=?');
        $full->execute([$fullScanKey]);
        $lastFullScan = (int)($full->fetchColumn() ?: 0);
        $full->closeCursor();
        if ($lastFullScan < now() - CRON_FULL_RESCAN_SECS) {
            $db->prepare('UPDATE poll_cursor SET last_seen=? WHERE relay=?')
               ->execute([$initialSince, $cursorName]);
            $lastSeen = $initialSince;
        }
    }
    $since = max(1, $lastSeen - CURSOR_LAG_SECS);
    $queryUntil = $scanUntil ?? now();
    $scanMax = isset($cursor['scan_max']) ? (int)$cursor['scan_max'] : $queryUntil;

    $fp = ws_connect_safe($relay);
    if ($fp === null) return [];
    $subId = 'b' . bin2hex(random_bytes(4));
    $filters = array_is_list($filter) ? $filter : [$filter];
    foreach ($filters as &$queryFilter) {
        if (!is_array($queryFilter)) {
            throw new InvalidArgumentException('invalid relay filter set');
        }
        $queryFilter['since'] = $since;
        $queryFilter['until'] = $queryUntil;
        $queryFilter['limit'] = CRON_PAGE_LIMIT;
    }
    unset($queryFilter);
    $events = [];
    $pageCreatedAts = [];
    $eose = false;
    try {
        ws_send_text($fp, json_c([
            'REQ',
            $subId,
            ...$filters,
        ]));
        $deadline = microtime(true) + CRON_TICK_SECS;
        while (microtime(true) < $deadline) {
            $left = $deadline - microtime(true);
            stream_set_timeout($fp, (int)$left, (int)(fmod($left, 1) * 1e6));
            $raw = ws_read_message($fp);
            if ($raw === null) break;
            $dec = json_decode($raw, true);
            if (!is_array($dec)) continue;
            if (($dec[0] ?? '') === 'EOSE') { $eose = true; break; }
            if (($dec[0] ?? '') !== 'EVENT' || !is_array($dec[2] ?? null)) continue;
            $event = $dec[2];
            $matches = false;
            foreach ($filters as $queryFilter) {
                if (cron_event_matches_filter($event, $queryFilter)) {
                    $matches = true;
                    break;
                }
            }
            if (!fm_event_verify($event) || !$matches) {
                bridge_log('cron', 'dropped: invalid relay query result', [
                    'id' => $event['id'] ?? '?',
                    'relay' => $relay,
                ]);
                continue;
            }
            $createdAt = (int)$event['created_at'];
            if ($createdAt > now() + 300) {
                bridge_log('cron', 'dropped: event timestamp too far in future', [
                    'id' => $event['id'], 'relay' => $relay,
                ]);
                continue;
            }
            $pageCreatedAts[] = $createdAt;
            $events[$event['id']] = $event;
        }
    } catch (WsException $e) {
        bridge_log('cron', 'relay read failed', [
            'relay' => $relay, 'error' => $e->getMessage(),
        ]);
        ws_send_close($fp);
        return [];
    }
    ws_send_close($fp);

    foreach ($events as $event) cron_handle_nostr_event($event);
    if (!$eose) return array_values($events);

    $pageMin = $pageCreatedAts ? min($pageCreatedAts) : $since;
    if ($pageCreatedAts && $pageMin > $since) {
        $db->prepare("INSERT INTO poll_cursor
                      (relay,last_seen,scan_until,scan_max) VALUES (?,?,?,?)
                      ON CONFLICT(relay) DO UPDATE SET
                        scan_until=excluded.scan_until,
                        scan_max=excluded.scan_max")
           ->execute([$cursorName, $lastSeen, $pageMin - 1, $scanMax]);
    } else {
        $db->prepare("INSERT INTO poll_cursor
                      (relay,last_seen,scan_until,scan_max) VALUES (?,?,NULL,NULL)
                      ON CONFLICT(relay) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        scan_until=NULL, scan_max=NULL")
           ->execute([$cursorName, max($lastSeen, $scanMax)]);
        if ($lastSeen <= $initialSince) {
            $db->prepare(
                "INSERT INTO schema_meta(k,v) VALUES (?,?)
                 ON CONFLICT(k) DO UPDATE SET v=excluded.v"
            )->execute([$fullScanKey, (string)now()]);
        }
    }
    return array_values($events);
}

function cron_poll_relays(): void
{
    $db = db();
    $allAddresses = [];
    $ownerPubkeys = [];
    $relays = [];
    foreach ($db->query(
        "SELECT DISTINCT r.*
         FROM repos r
         JOIN github_installation_repositories gir
           ON gir.github_full_name=r.github_full_name
          AND gir.status='active'
         JOIN github_installations gi
           ON gi.installation_id=gir.installation_id
          AND gi.status='active'
          AND gi.token_enc IS NOT NULL
         ORDER BY r.github_full_name"
    ) as $repo) {
        $allAddresses[] = '30617:' . $repo['owner_pubkey']
            . ':' . $repo['repo_id'];
        $ownerPubkeys[] = $repo['owner_pubkey'];
        foreach (json_decode($repo['relays'] ?? '[]', true) ?: [] as $url) {
            if (is_string($url) && relay_url_valid($url)) $relays[$url] = true;
        }
    }
    if (!$allAddresses) return;
    foreach (relay_defaults() as $url) $relays[$url] = true;

    $allAddresses = array_values(array_unique($allAddresses));
    $ownerPubkeys = array_values(array_unique($ownerPubkeys));
    sort($allAddresses, SORT_STRING);
    sort($ownerPubkeys, SORT_STRING);
    foreach (relay_url_set(array_keys($relays)) as $relay) {
        // Repository announcements and their NIP-09 address tombstones are
        // independent retained input sets. Reduce them before discussions;
        // empty EOSE responses never erase a banked announcement. One filter
        // deliberately retains every kind-5 by a registered owner: each a/e
        // target is validated by the reducer, and this also catches a
        // deletion published before its discussion target is known.
        cron_poll_relay_filter($relay, "repo-metadata|$relay", [
            'kinds' => [5, 30617],
            'authors' => $ownerPubkeys,
        ]);

        $addresses = [];
        foreach ($db->query(
            'SELECT owner_pubkey,repo_id FROM repos WHERE verified=1'
        ) as $repo) {
            $addresses[] = '30617:' . $repo['owner_pubkey']
                . ':' . $repo['repo_id'];
        }
        $addresses = array_values(array_unique($addresses));
        sort($addresses, SORT_STRING);
        if (!$addresses) continue;

        // Roots first. The handler records them synchronously, before comment
        // filters are built, so same-tick delivery order cannot matter.
        cron_poll_relay_filter($relay, "roots-stars|$relay", [
            [
                'kinds' => [1621],
                '#a' => $addresses,
            ],
            [
                'kinds' => [7],
                '#a' => $addresses,
            ],
        ]);

        $rootIds = $db->query('SELECT nostr_id FROM nostr_roots ORDER BY nostr_id')
                      ->fetchAll(PDO::FETCH_COLUMN);
        $dependentFilters = [];
        if ($rootIds) {
            $dependentFilters[] = [
                'kinds' => [1111],
                '#E' => $rootIds,
            ];
            $dependentFilters[] = [
                'kinds' => [1630, 1631, 1632, 1633],
                '#e' => $rootIds,
            ];
        }
        $knownEventIds = $db->query(
            "SELECT nostr_id FROM event_map
             UNION SELECT nostr_id FROM nostr_roots
             ORDER BY nostr_id")->fetchAll(PDO::FETCH_COLUMN);
        // An unlinked Nostr author cannot yet be represented by GitHub's
        // authenticated-user star API. Keep that pending source ID in the
        // deletion watch set so an unstar published days later is still
        // discovered before the user eventually links GitHub.
        foreach ($db->query(
            "SELECT payload FROM jobs
             WHERE type='nostr2gh_star' AND status='pending'"
        )->fetchAll(PDO::FETCH_COLUMN) as $payload) {
            $decoded = json_decode((string)$payload, true);
            $starId = is_array($decoded)
                ? strtolower((string)($decoded['nostr_id'] ?? '')) : '';
            if (is_hex64($starId)) $knownEventIds[] = $starId;
        }
        $knownEventIds = array_values(array_unique($knownEventIds));
        sort($knownEventIds, SORT_STRING);
        if ($knownEventIds) {
            $dependentFilters[] = [
                'kinds' => [5],
                '#e' => $knownEventIds,
            ];
        }
        if ($dependentFilters) {
            cron_poll_relay_filter(
                $relay,
                "discussion-dependents|$relay",
                $dependentFilters
            );
        }
    }
}

function ws_connect_safe(string $relay)
{
    try { return ws_connect($relay, 6.0); } catch (WsException $e) { return null; }
}

/**
 * Hourly App installation discovery is the recovery path for a missing
 * installation webhook. Reconcile both the remote set and every local row:
 * remote-only IDs are bootstrapped, while local-only IDs converge through
 * the reconcile job's authoritative 404/deletion handling.
 */
function cron_enqueue_github_installation_reconciliation(): void
{
    $key = 'github_installations_discovered_at';
    $query = db()->prepare('SELECT v FROM schema_meta WHERE k=?');
    $query->execute([$key]);
    $last = (int)($query->fetchColumn() ?: 0);
    if ($last >= now() - GITHUB_INSTALLATION_DISCOVERY_SECS) return;

    try {
        $ids = gh_app_list_installation_ids();
    } catch (Throwable $error) {
        bridge_log('github-app', 'installation discovery failed', [
            'error' => $error->getMessage(),
        ]);
        return;
    }
    foreach (db()->query(
        'SELECT installation_id FROM github_installations'
    )->fetchAll(PDO::FETCH_COLUMN) as $localId) {
        if (is_string($localId) && $localId !== '') $ids[] = $localId;
    }
    $ids = array_values(array_unique($ids));
    sort($ids, SORT_STRING);
    foreach ($ids as $installationId) {
        jobs_enqueue(
            'github_installation_reconcile',
            ['installation_id' => $installationId],
            'ghinstall:' . $installationId
        );
    }
    db()->prepare(
        "INSERT INTO schema_meta(k,v) VALUES (?,?)
         ON CONFLICT(k) DO UPDATE SET v=excluded.v"
    )->execute([$key, (string)now()]);
}

/**
 * Hourly star reconciliation rechecks every stable repository/user pair
 * already retained in the durable pair set/event ledger. GitHub's July 2026
 * API restriction prevents an ordinary App installation from enumerating a
 * repository's complete stargazer set; new pairs therefore enter through
 * signed, durably banked Star webhooks, while this pass repairs missed or
 * reordered state transitions for every pair the bridge has observed.
 */
function cron_enqueue_github_star_reconciliation(): void
{
    $query = db()->query(
        "SELECT gir.repository_id,gir.github_full_name
         FROM github_installation_repositories gir
         JOIN github_installations gi
           ON gi.installation_id=gir.installation_id
          AND gi.status='active' AND gi.token_enc IS NOT NULL
         JOIN repos r
           ON r.github_full_name=gir.github_full_name AND r.verified=1
         WHERE gir.status='active'
         ORDER BY gir.repository_id"
    );
    foreach ($query as $repository) {
        $repositoryId = (string)$repository['repository_id'];
        $key = 'github_star_scan|' . $repositoryId;
        $lastQuery = db()->prepare(
            'SELECT v FROM schema_meta WHERE k=?'
        );
        $lastQuery->execute([$key]);
        $last = (int)($lastQuery->fetchColumn() ?: 0);
        if ($last >= now() - CRON_FULL_RESCAN_SECS) continue;
        $scanAt = now();
        jobs_enqueue(
            'gh2nostr_repository_stars_reconcile',
            [
                'full' => $repository['github_full_name'],
                'repository_id' => $repositoryId,
                'scan_at' => $scanAt,
            ],
            "gh:repository-stars:$repositoryId:$scanAt"
        );
        db()->prepare(
            "INSERT INTO schema_meta(k,v) VALUES (?,?)
             ON CONFLICT(k) DO UPDATE SET v=excluded.v"
        )->execute([$key, (string)$scanAt]);
    }
}

// --- run -------------------------------------------------------------------
//echo date('c'), " cron tick\n";
bridge_collect_nip46_connects();    // signer approvals, browser-independent
bridge_reconcile_nip46_finish_jobs();
cron_enqueue_github_installation_reconciliation();
cron_enqueue_github_star_reconciliation();
bridge_run_due_jobs(25);          // 1. retries + queued Dir B posts
cron_poll_relays();               // 2-4. poll + enqueue
bridge_run_due_jobs(25);          //     immediate drain of new enqueues
db()->prepare('DELETE FROM oauth_states WHERE expires_at < ?')->execute([now() - 300]);
db()->prepare('DELETE FROM github_oauth_attempts WHERE expires_at < ?')->execute([now() - 300]);
db()->prepare("DELETE FROM nip46_states
               WHERE status IN ('waiting','failed','done') AND expires_at < ?")
    ->execute([now() - 300]);
//echo date('c'), " cron done\n";

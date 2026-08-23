<?php
/**
 * cron_handler.php -- Direction B event-handling logic (pure functions,
 * shared by cron.php tick and tests/dirB.php; no side effects on include).
 */
declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib/util.php';
require_once __DIR__ . '/lib/secrets.php';
require_once __DIR__ . '/lib/crypto.php';
require_once __DIR__ . '/lib/jobs.php';
require_once __DIR__ . '/lib/bridge.php';
require_once __DIR__ . '/lib/relay.php';

if (!defined('CURSOR_LAG_SECS')) define('CURSOR_LAG_SECS', 120);

/**
 * Feed one nostr event through the Dir B decision pipeline.
 * Authentication only selects the crossing identity. It is never an intake
 * gate: every valid, in-scope event is durably queued.
 */
function cron_handle_nostr_event(array $ev): void
{
    $id = $ev['id'] ?? '';
    if (!is_hex64($id)) return;

    // 1. cryptographic gate -- forged events die here
    if (!fm_event_verify($ev)) {
        bridge_log('cron', 'dropped: bad signature', ['id' => $id]);
        return;
    }
    if ($ev['created_at'] < 1 || $ev['created_at'] > now() + 300) {
        bridge_log('cron', 'dropped: invalid event timestamp', [
            'id' => $id,
            'created_at' => $ev['created_at'],
        ]);
        return;
    }
    $pk = $ev['pubkey'];
    $kind = (int)$ev['kind'];

    // Repository metadata is its own durable reducer. Process it before the
    // crossing ledger: a kind-5 event can simultaneously tombstone an issue
    // and the addressable 30617, and either observation may arrive first.
    if ($kind === 30617) {
        $reduced = repo_reduce_announcement_event(
            $ev,
            fm_pubkey_hex(fm_secret_bridge_key())
        );
        if ($reduced > 0) {
            bridge_log('cron', 'reduced repository announcement', [
                'id' => $id,
                'repositories' => $reduced,
            ]);
        }
        return;
    }
    if ($kind === 5) {
        $reduced = repo_reduce_announcement_deletion_event($ev);
        if ($reduced > 0) {
            bridge_log('cron', 'reduced repository deletion', [
                'id' => $id,
                'repositories' => $reduced,
            ]);
        }
    }

    // 2. Loop-kill independent of the local ledger. A process may die after
    // relay acceptance but before event_map is committed; GitHub-origin
    // events carry this signed standard proxy tag for that crash window.
    $githubOrigin = false;
    foreach ($ev['tags'] as $tag) {
        if (($tag[0] ?? '') === 'proxy'
            && ($tag[2] ?? '') === 'github'
            && str_starts_with($tag[1] ?? '', 'https://github.com/')) {
            $githubOrigin = true;
        }
    }

    // 3. durable ledger dedupe
    $st = db()->prepare('SELECT 1 FROM event_map WHERE nostr_id = ?');
    $st->execute([$id]);
    if ($st->fetchColumn()) return;

    if ($githubOrigin) {
        // A proxy tag is an origin claim, not authority to create ledger
        // mappings. The original durable GitHub job deterministically
        // recovers any publish-before-ledger crash from the relay event ID.
        // Ignoring a third party's self-labelled event cannot poison state.
        return;
    }

    if ($kind === 1111) {
        if (jobs_dedupe_terminal("nostr:$id")) return;
        // Queue by immutable E-root even when the root crossing has not
        // completed. The executor validates and resolves it later.
        $rootReference = cron_nip22_event_reference($ev, 'E');
        if ($rootReference === null) return;
        [$rootId, $rootAuthor] = $rootReference;
        if (!is_hex64($rootId) || !is_hex64($rootAuthor)
            || !cron_tag_has($ev, 'P', $rootAuthor)
            || cron_tag_val($ev, 'K') !== '1621') {
            bridge_log('cron', 'dropped: invalid NIP-22 root tags', ['id' => $id]);
            return;
        }
        $rootId = strtolower($rootId);
        $rootAuthor = strtolower($rootAuthor);
        $parentReference = cron_nip22_event_reference($ev, 'e');
        if ($parentReference === null) {
            bridge_log('cron', 'dropped: invalid NIP-22 parent tags', ['id' => $id]);
            return;
        }
        [$parentId, $parentAuthor] = $parentReference;
        $parentKind = cron_tag_val($ev, 'k');
        $validParent = cron_tag_has($ev, 'p', $parentAuthor)
            && (($parentId === $rootId && $parentKind === '1621')
                || ($parentId !== $rootId && $parentKind === '1111'));
        if (!$validParent) {
            bridge_log('cron', 'dropped: invalid NIP-22 parent tags', ['id' => $id]);
            return;
        }
        $parentId = strtolower($parentId);
        $parentAuthor = strtolower($parentAuthor);
        $body = $ev['content'] ?? '';
        if ($body === '') return;

        jobs_enqueue('nostr2gh_comment', [
            'body'      => $body,
            'pubkey'    => $pk,
            'nostr_id'  => $id,
            'root_nostr_id' => $rootId,
            'root_pubkey' => strtolower($rootAuthor),
            'parent_nostr_id' => $parentId,
            'parent_pubkey' => strtolower($parentAuthor),
            'parent_kind' => $parentKind,
            'created_at' => (int)$ev['created_at'],
            'queued_at' => now(),
        ], "nostr:$id");
        $rootRepo = db()->prepare("
            SELECT r.* FROM nostr_roots nr
            JOIN repos r ON r.github_full_name=nr.github_full_name
            WHERE nr.nostr_id=?");
        $rootRepo->execute([$rootId]);
        $rootRepoRow = $rootRepo->fetch();
        if ($rootRepoRow) {
            bridge_enqueue_nostr_deletion_backfill($id, $rootRepoRow);
        }
        bridge_log('cron', 'queued nostr->gh comment', [
            'id' => $id, 'root' => $rootId,
        ]);
        return;
    }

    if ($kind === 7) {
        if (jobs_dedupe_terminal("nostr:$id")) return;
        // Repository stars are explicit NIP-25 star reactions, not every
        // generic like. The e/a/p/k references are sets/scalars validated
        // independently of tag order.
        if (($ev['content'] ?? '') !== '⭐') return;
        $address = cron_tag_val($ev, 'a');
        $announcementId = cron_tag_val($ev, 'e');
        if ($address === null || !is_hex64((string)$announcementId)
            || cron_tag_val($ev, 'k') !== '30617') {
            return;
        }
        $parts = explode(':', $address, 3);
        if (count($parts) !== 3 || $parts[0] !== '30617') return;
        [, $ownerPk, $repoId] = $parts;
        $ownerPk = strtolower($ownerPk);
        if (!is_hex64($ownerPk) || !cron_tag_has($ev, 'p', $ownerPk)) {
            return;
        }
        $repo = db()->prepare(
            "SELECT r.*,gir.repository_id
             FROM repos r
             JOIN github_installation_repositories gir
               ON gir.github_full_name=r.github_full_name
              AND gir.status='active'
             JOIN github_installations gi
               ON gi.installation_id=gir.installation_id
              AND gi.status='active' AND gi.token_enc IS NOT NULL
             WHERE r.repo_id=? AND r.owner_pubkey=? AND r.verified=1"
        );
        $repo->execute([$repoId, $ownerPk]);
        $destinations = $repo->fetchAll();
        if (count($destinations) !== 1) {
            if (count($destinations) > 1) {
                bridge_log('cron', 'dropped: star repository is ambiguous', [
                    'id' => $id,
                    'address' => $address,
                ]);
            }
            return;
        }
        $repoRow = $destinations[0];
        jobs_enqueue('nostr2gh_star', [
            'repo' => $repoRow,
            'full' => $repoRow['github_full_name'],
            'repository_id' => (string)$repoRow['repository_id'],
            'pubkey' => $pk,
            'nostr_id' => $id,
            'announcement_nostr_id' => strtolower($announcementId),
            'created_at' => (int)$ev['created_at'],
        ], "nostr:$id");
        bridge_enqueue_nostr_deletion_backfill($id, $repoRow);
        bridge_log('cron', 'queued nostr->gh repository star', [
            'id' => $id,
            'gh' => $repoRow['github_full_name'],
        ]);
        return;
    }

    if ($kind === 1621) {
        if (jobs_dedupe_terminal("nostr:$id")) return;
        // A NIP-34 issue has one repository address. Repeating the identical
        // a value is harmless; distinct values are ambiguous and must not let
        // tag order choose a GitHub destination.
        $address = cron_tag_val($ev, 'a');
        if ($address === null) return;
        // NIP-01 address values split only twice; the d identifier is the
        // entire remainder and may itself contain colons.
        $parts = explode(':', $address, 3);
        if (count($parts) !== 3 || $parts[0] !== '30617') return;
        [, $ownerPk, $repoId] = $parts;
        if (!cron_tag_has($ev, 'p', $ownerPk)) return;
        $subjects = cron_tag_values($ev, 'subject');
        if (count($subjects) > 1) {
            bridge_log('cron', 'dropped: issue has conflicting subject tags', [
                'id' => $id,
            ]);
            return;
        }
        $rep = db()->prepare('SELECT github_full_name FROM repos
                              WHERE repo_id = ? AND owner_pubkey = ?
                                AND verified = 1
                              ORDER BY github_full_name');
        $rep->execute([$repoId, $ownerPk]);
        $destinations = $rep->fetchAll(PDO::FETCH_COLUMN);
        if (count($destinations) !== 1) {
            if (count($destinations) > 1) {
                bridge_log('cron', 'dropped: repository address is ambiguous', [
                    'id' => $id,
                    'address' => $address,
                ]);
            }
            return;
        }
        $full = $destinations[0];

        $repo = db()->prepare('SELECT * FROM repos WHERE github_full_name=?');
        $repo->execute([$full]);
        $repoRow = $repo->fetch();
        if (!$repoRow) return;
        $isNewRoot = bridge_register_nostr_root($ev, $repoRow);
        jobs_enqueue('nostr2gh_issue', [
            'full'      => $full,
            'title'     => $subjects[0] ?? '(no title)',
            'body'      => $ev['content'] ?? '',
            'pubkey'    => $pk,
            'nostr_id'  => $id,
            'created_at' => (int)$ev['created_at'],
            'queued_at' => now(),
        ], "nostr:$id");
        if ($isNewRoot) bridge_enqueue_nostr_root_backfills($ev, $repoRow);
        bridge_log('cron', 'queued nostr->gh issue', ['id' => $id, 'gh' => $full]);
        return;
    }

    if (in_array($kind, [1630, 1631, 1632, 1633], true)) {
        if (jobs_dedupe_terminal("nostr:$id")) return;
        $rootIds = [];
        $mentionedPubkeys = [];
        foreach ($ev['tags'] as $tag) {
            if (($tag[0] ?? '') === 'e'
                && ($tag[3] ?? '') === 'root') {
                if (!is_string($tag[1] ?? null) || !is_hex64($tag[1])) {
                    $rootIds = [];
                    break;
                }
                $rootIds[strtolower($tag[1])] = true;
            }
            if (($tag[0] ?? '') === 'p'
                && is_string($tag[1] ?? null)
                && is_hex64($tag[1])) {
                $mentionedPubkeys[strtolower($tag[1])] = true;
            }
        }
        if (count($rootIds) !== 1) {
            bridge_log('cron', 'dropped: status root marker is missing or ambiguous', [
                'id' => $id,
            ]);
            return;
        }
        $rootId = (string)array_key_first($rootIds);
        $mentionedPubkeys = array_keys($mentionedPubkeys);
        sort($mentionedPubkeys, SORT_STRING);
        jobs_enqueue('nostr2gh_status', [
            'nostr_id' => $id,
            'root_nostr_id' => $rootId,
            'pubkey' => $pk,
            'kind' => $kind,
            'content' => (string)($ev['content'] ?? ''),
            'created_at' => (int)$ev['created_at'],
            'mentioned_pubkeys' => $mentionedPubkeys,
        ], "nostr:$id");
        $rootRepo = db()->prepare("
            SELECT r.* FROM nostr_roots nr
            JOIN repos r ON r.github_full_name=nr.github_full_name
            WHERE nr.nostr_id=?");
        $rootRepo->execute([$rootId]);
        $rootRepoRow = $rootRepo->fetch();
        if ($rootRepoRow) {
            bridge_enqueue_nostr_deletion_backfill($id, $rootRepoRow);
        }
        bridge_log('cron', 'queued nostr->gh status', [
            'id' => $id, 'root' => $rootId, 'kind' => $kind,
        ]);
        return;
    }

    if ($kind === 5) {
        $targets = [];
        foreach ($ev['tags'] as $tag) {
            if (($tag[0] ?? '') === 'e'
                && is_string($tag[1] ?? null)
                && is_hex64($tag[1])) {
                $targets[strtolower($tag[1])] = true;
            }
        }
        $targetIds = array_keys($targets);
        sort($targetIds, SORT_STRING);
        foreach ($targetIds as $targetId) {
            if (jobs_dedupe_terminal("nostr-delete:$id:$targetId")) {
                continue;
            }
            jobs_enqueue('nostr2gh_deletion', [
                'nostr_id' => $id,
                'target_nostr_id' => $targetId,
                'pubkey' => $pk,
                'reason' => (string)($ev['content'] ?? ''),
                'created_at' => (int)$ev['created_at'],
            ], "nostr-delete:$id:$targetId");
        }
        if ($targets) {
            bridge_log('cron', 'queued nostr->gh deletion', [
                'id' => $id, 'targets' => $targetIds,
            ]);
        }
    }
}

/** Return the sorted semantic set of slot-1 values for a tag name. */
function cron_tag_values(array $ev, string $name): array
{
    $values = [];
    foreach ($ev['tags'] as $t) {
        if (($t[0] ?? '') === $name && is_string($t[1] ?? null)) {
            // Prefix the associative key: PHP otherwise coerces a value such
            // as "1621" to an integer key, violating the string-set contract.
            $values['s:' . $t[1]] = $t[1];
        }
    }
    $result = array_values($values);
    sort($result, SORT_STRING);
    return $result;
}

/**
 * Scalar tags may be repeated identically. Missing or conflicting values are
 * both unusable; callers decide whether absence is permitted.
 */
function cron_tag_val(array $ev, string $name): ?string
{
    $values = cron_tag_values($ev, $name);
    return count($values) === 1 ? $values[0] : null;
}

/** Return one unambiguous NIP-22 [event-id, author] reference. */
function cron_nip22_event_reference(array $ev, string $name): ?array
{
    $references = [];
    $seen = false;
    foreach ($ev['tags'] as $tag) {
        if (($tag[0] ?? '') !== $name) continue;
        $seen = true;
        $eventId = $tag[1] ?? null;
        $author = $tag[3] ?? null;
        if (!is_string($eventId) || !is_hex64($eventId)
            || !is_string($author) || !is_hex64($author)) {
            return null;
        }
        $eventId = strtolower($eventId);
        $author = strtolower($author);
        $references["$eventId:$author"] = [$eventId, $author];
    }
    return $seen && count($references) === 1
        ? array_values($references)[0]
        : null;
}

function cron_tag_has(array $ev, string $name, string $value): bool
{
    foreach ($ev['tags'] as $tag) {
        if (($tag[0] ?? '') === $name && ($tag[1] ?? '') === $value) return true;
    }
    return false;
}

function cron_tag_has_hex(array $ev, string $name): bool
{
    foreach ($ev['tags'] as $tag) {
        if (($tag[0] ?? '') === $name
            && is_string($tag[1] ?? null)
            && is_hex64($tag[1])) return true;
    }
    return false;
}

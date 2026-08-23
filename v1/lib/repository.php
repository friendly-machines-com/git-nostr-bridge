<?php
/**
 * repository.php -- durable reduction of NIP-34 repository authority.
 *
 * Relay queries are observations, never authoritative snapshots. Once an
 * operator has bound a GitHub repository to a verified kind-30617 address,
 * an empty or unavailable relay response cannot erase that banked state.
 * Only a newer valid replacement or a same-author kind-5 address deletion
 * changes the reduced state. Both inputs are retained in schema_meta so
 * replacement/deletion arrival order cannot affect the result.
 */
declare(strict_types=1);

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/relay.php';

const REPO_ANNOUNCEMENT_META_PREFIX = 'repo_announcement|';
const REPO_ANNOUNCEMENT_DELETE_META_PREFIX =
    'repo_announcement_delete|';

function repo_announcement_address(array $repoRow): string
{
    return '30617:' . strtolower((string)$repoRow['owner_pubkey'])
        . ':' . (string)$repoRow['repo_id'];
}

function repo_announcement_meta_key(array $repoRow): string
{
    return REPO_ANNOUNCEMENT_META_PREFIX
        . (string)$repoRow['github_full_name'];
}

function repo_announcement_delete_meta_key(array $repoRow): string
{
    return REPO_ANNOUNCEMENT_DELETE_META_PREFIX
        . (string)$repoRow['github_full_name'];
}

/** @return list<string>|null */
function repo_announcement_relays(array $event): ?array
{
    $declared = [];
    $sawTag = false;
    foreach (($event['tags'] ?? []) as $tag) {
        if (!is_array($tag) || ($tag[0] ?? null) !== 'relays') {
            continue;
        }
        $sawTag = true;
        foreach (array_slice($tag, 1) as $relay) {
            if (!is_string($relay) || !relay_url_valid($relay)) {
                return null;
            }
            $declared[] = $relay;
        }
    }
    $relays = relay_url_set($declared);
    return $sawTag && $relays && count($relays) <= 4 ? $relays : null;
}

function repo_event_is_newer(array $candidate, array $current): bool
{
    $candidateTime = (int)($candidate['created_at'] ?? 0);
    $currentTime = (int)($current['created_at'] ?? 0);
    if ($candidateTime !== $currentTime) {
        return $candidateTime > $currentTime;
    }
    return strcmp(
        strtolower((string)($candidate['id'] ?? '')),
        strtolower((string)($current['id'] ?? ''))
    ) < 0;
}

function repo_announcement_matches(
    array $event,
    array $repoRow
): bool {
    return (int)($event['kind'] ?? 0) === 30617
        && strtolower((string)($event['pubkey'] ?? ''))
            === strtolower((string)$repoRow['owner_pubkey'])
        && relay_unique_tag_value($event, 'd')
            === (string)$repoRow['repo_id']
        && is_hex64(strtolower((string)($event['id'] ?? '')))
        && fm_event_verify($event)
        && repo_announcement_relays($event) !== null;
}

function repo_deletion_matches(array $event, array $repoRow): bool
{
    if ((int)($event['kind'] ?? 0) !== 5
        || strtolower((string)($event['pubkey'] ?? ''))
            !== strtolower((string)$repoRow['owner_pubkey'])
        || !is_hex64(strtolower((string)($event['id'] ?? '')))
        || !fm_event_verify($event)) {
        return false;
    }
    $address = repo_announcement_address($repoRow);
    foreach (($event['tags'] ?? []) as $tag) {
        if (is_array($tag)
            && ($tag[0] ?? null) === 'a'
            && ($tag[1] ?? null) === $address) {
            return true;
        }
    }
    return false;
}

function repo_load_banked_event(string $key): ?array
{
    $query = db()->prepare('SELECT v FROM schema_meta WHERE k=?');
    $query->execute([$key]);
    $event = json_decode((string)($query->fetchColumn() ?: ''), true);
    return is_array($event) ? $event : null;
}

function repo_banked_announcement(array $repoRow): ?array
{
    if (!is_string($repoRow['github_full_name'] ?? null)
        || $repoRow['github_full_name'] === ''
        || !is_string($repoRow['repo_id'] ?? null)
        || !is_string($repoRow['owner_pubkey'] ?? null)) {
        return null;
    }
    $event = repo_load_banked_event(
        repo_announcement_meta_key($repoRow)
    );
    return is_array($event)
        && repo_announcement_matches($event, $repoRow)
        ? $event : null;
}

function repo_banked_announcement_deletion(array $repoRow): ?array
{
    if (!is_string($repoRow['github_full_name'] ?? null)
        || $repoRow['github_full_name'] === ''
        || !is_string($repoRow['repo_id'] ?? null)
        || !is_string($repoRow['owner_pubkey'] ?? null)) {
        return null;
    }
    $event = repo_load_banked_event(
        repo_announcement_delete_meta_key($repoRow)
    );
    return is_array($event) && repo_deletion_matches($event, $repoRow)
        ? $event : null;
}

/** NIP-34 publisher authority plus the explicit maintainers set. */
function repo_announcement_authorizes(
    array $announcement,
    string $pubkey
): bool {
    $pubkey = strtolower($pubkey);
    if (!is_hex64($pubkey)) return false;
    $publisher = strtolower((string)($announcement['pubkey'] ?? ''));
    $subordinate = false;
    $maintainers = [];
    foreach (($announcement['tags'] ?? []) as $tag) {
        if (!is_array($tag)) continue;
        if (($tag[0] ?? null) === 'u') $subordinate = true;
        if (($tag[0] ?? null) === 'maintainers') {
            foreach (array_slice($tag, 1) as $maintainer) {
                if (is_string($maintainer) && is_hex64($maintainer)) {
                    $maintainers[strtolower($maintainer)] = true;
                }
            }
        }
    }
    return isset($maintainers[$pubkey])
        || (!$subordinate && $publisher === $pubkey);
}

function repo_announcement_is_deleted(
    array $announcement,
    ?array $deletion
): bool {
    return is_array($deletion)
        && (int)($announcement['created_at'] ?? 0)
            <= (int)($deletion['created_at'] ?? 0);
}

/**
 * Bank one verified replacement and reduce it against any prior deletion.
 * Returns true when this event is the retained addressable head.
 */
function repo_bank_announcement(
    array $repoRow,
    array $event,
    string $bridgePubkey
): bool {
    if (!repo_announcement_matches($event, $repoRow)) return false;
    $current = repo_banked_announcement($repoRow);
    if (is_array($current)
        && ($current['id'] ?? null) !== ($event['id'] ?? null)
        && !repo_event_is_newer($event, $current)) {
        return false;
    }

    $relays = repo_announcement_relays($event);
    if ($relays === null) return false;
    $deletion = repo_banked_announcement_deletion($repoRow);
    $verified = repo_announcement_is_deleted($event, $deletion) ? 0 : 1;
    $bridgeAuthorized = repo_announcement_authorizes(
        $event,
        $bridgePubkey
    ) ? 1 : 0;
    $database = db();
    $ownTransaction = !$database->inTransaction();
    if ($ownTransaction) $database->beginTransaction();
    try {
        $database->prepare(
            "INSERT INTO schema_meta(k,v) VALUES (?,?)
             ON CONFLICT(k) DO UPDATE SET v=excluded.v"
        )->execute([
            repo_announcement_meta_key($repoRow),
            json_c($event),
        ]);
        $database->prepare(
            "UPDATE repos
             SET relays=?,verified=?,bridge_authorized=?,updated_at=?
             WHERE github_full_name=? AND repo_id=? AND owner_pubkey=?"
        )->execute([
            json_c($relays),
            $verified,
            $bridgeAuthorized,
            now(),
            $repoRow['github_full_name'],
            $repoRow['repo_id'],
            $repoRow['owner_pubkey'],
        ]);
        if ($ownTransaction) $database->commit();
    } catch (Throwable $error) {
        if ($ownTransaction && $database->inTransaction()) {
            $database->rollBack();
        }
        throw $error;
    }
    return true;
}

/** Reduce a kind-30617 observation against every exact registered address. */
function repo_reduce_announcement_event(
    array $event,
    string $bridgePubkey
): int {
    if ((int)($event['kind'] ?? 0) !== 30617
        || !is_hex64(strtolower((string)($event['pubkey'] ?? '')))
        || !fm_event_verify($event)) {
        return 0;
    }
    $repoId = relay_unique_tag_value($event, 'd');
    if (!is_string($repoId) || $repoId === '') return 0;
    $query = db()->prepare(
        'SELECT * FROM repos WHERE owner_pubkey=? AND repo_id=?'
    );
    $query->execute([
        strtolower((string)$event['pubkey']),
        $repoId,
    ]);
    $accepted = 0;
    foreach ($query->fetchAll() as $repoRow) {
        if (repo_bank_announcement($repoRow, $event, $bridgePubkey)) {
            $accepted++;
        }
    }
    return $accepted;
}

/**
 * Bank a same-author NIP-09 address deletion. A later 30617 replacement
 * automatically restores the address when its created_at exceeds the cutoff.
 */
function repo_reduce_announcement_deletion_event(array $event): int
{
    if ((int)($event['kind'] ?? 0) !== 5
        || !is_hex64(strtolower((string)($event['pubkey'] ?? '')))
        || !fm_event_verify($event)) {
        return 0;
    }
    $addresses = [];
    foreach (($event['tags'] ?? []) as $tag) {
        if (is_array($tag)
            && ($tag[0] ?? null) === 'a'
            && is_string($tag[1] ?? null)) {
            $addresses[$tag[1]] = true;
        }
    }
    $reduced = 0;
    foreach (array_keys($addresses) as $address) {
        $parts = explode(':', $address, 3);
        if (count($parts) !== 3 || $parts[0] !== '30617') continue;
        [, $ownerPubkey, $repoId] = $parts;
        if (strtolower($ownerPubkey)
            !== strtolower((string)$event['pubkey'])) {
            continue;
        }
        $query = db()->prepare(
            'SELECT * FROM repos WHERE owner_pubkey=? AND repo_id=?'
        );
        $query->execute([strtolower($ownerPubkey), $repoId]);
        foreach ($query->fetchAll() as $repoRow) {
            if (!repo_deletion_matches($event, $repoRow)) continue;
            $current = repo_banked_announcement_deletion($repoRow);
            if (is_array($current)
                && ($current['id'] ?? null) !== ($event['id'] ?? null)
                && !repo_event_is_newer($event, $current)) {
                continue;
            }
            $database = db();
            $ownTransaction = !$database->inTransaction();
            if ($ownTransaction) $database->beginTransaction();
            try {
                $database->prepare(
                    "INSERT INTO schema_meta(k,v) VALUES (?,?)
                     ON CONFLICT(k) DO UPDATE SET v=excluded.v"
                )->execute([
                    repo_announcement_delete_meta_key($repoRow),
                    json_c($event),
                ]);
                $announcement = repo_banked_announcement($repoRow);
                if ($announcement === null
                    || repo_announcement_is_deleted(
                        $announcement,
                        $event
                    )) {
                    $database->prepare(
                        "UPDATE repos SET verified=0,updated_at=?
                         WHERE github_full_name=?"
                    )->execute([
                        now(),
                        $repoRow['github_full_name'],
                    ]);
                }
                if ($ownTransaction) $database->commit();
            } catch (Throwable $error) {
                if ($ownTransaction && $database->inTransaction()) {
                    $database->rollBack();
                }
                throw $error;
            }
            $reduced++;
        }
    }
    return $reduced;
}

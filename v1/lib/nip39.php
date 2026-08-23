<?php
/**
 * Optional NIP-39 GitHub identity assertion support.
 *
 * This module manages public presentation metadata only. None of these
 * helpers create a bridge identity link, authorize a crossing, or select a
 * GitHub credential. A kind-10011 event is a complete regular-replaceable
 * snapshot, so reducers select one head before applying deletion and proposal
 * builders preserve every tag outside the one explicitly managed claim.
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/relay.php';
require_once __DIR__ . '/github.php';

const NIP39_KIND = 10011;
const NIP39_RELAY_LIST_KIND = 10002;
const NIP39_QUERY_TIMEOUT_SECS = 1.5;
const NIP39_MAX_CURRENT_EVENTS = 100;

class Nip39ProofError extends RuntimeException {}
class Nip39RelayUnavailable extends RuntimeException {}

function nip39_github_login_valid(string $login): bool
{
    return (bool)preg_match(
        '/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/D',
        $login
    );
}

function nip39_proof_text(string $pubkey): string
{
    if (!is_hex64($pubkey)) {
        throw new InvalidArgumentException('invalid Nostr public key');
    }
    return 'Verifying that I control the following Nostr public key: '
        . fm_npub_encode(strtolower($pubkey));
}

/**
 * Accept only a canonical Gist page belonging to the linked GitHub login.
 *
 * @return array{id:string,url:string}
 */
function nip39_parse_gist_url(string $url, string $login): array
{
    if (!nip39_github_login_valid($login)
        || $url === '' || strlen($url) > 500
        || preg_match('/[\x00-\x20\x7f]/', $url)) {
        throw new InvalidArgumentException('invalid GitHub Gist URL');
    }
    $parts = parse_url($url);
    if (!is_array($parts)
        || ($parts['scheme'] ?? '') !== 'https'
        || strtolower((string)($parts['host'] ?? '')) !== 'gist.github.com'
        || isset($parts['user'], $parts['pass'], $parts['port'])
        || isset($parts['query'], $parts['fragment'])) {
        throw new InvalidArgumentException('invalid GitHub Gist URL');
    }
    $segments = explode('/', trim((string)($parts['path'] ?? ''), '/'));
    if (count($segments) !== 2
        || strcasecmp($segments[0], $login) !== 0
        || !preg_match('/^[0-9a-f]{5,64}$/Di', $segments[1])) {
        throw new InvalidArgumentException(
            'Gist URL must belong to the linked GitHub account'
        );
    }
    $gistId = strtolower($segments[1]);
    return [
        'id' => $gistId,
        'url' => 'https://gist.github.com/'
            . rawurlencode($login) . '/' . $gistId,
    ];
}

function nip39_verify_github_gist(
    string $login,
    string $pubkey,
    string $gistId
): void {
    try {
        $gist = gh_public_gist($gistId);
    } catch (GhError $error) {
        if ($error->getCode() === 404) {
            throw new Nip39ProofError(
                'GitHub could not find that Gist',
                0,
                $error
            );
        }
        throw $error;
    }
    $owner = is_array($gist['owner'] ?? null)
        ? $gist['owner'] : [];
    $returnedId = is_string($gist['id'] ?? null)
        ? strtolower($gist['id']) : '';
    $ownerLogin = is_string($owner['login'] ?? null)
        ? $owner['login'] : '';
    $files = $gist['files'] ?? null;
    if (!hash_equals(strtolower($gistId), $returnedId)
        || strcasecmp($ownerLogin, $login) !== 0
        || !is_array($files)
        || array_is_list($files)
        || count($files) !== 1) {
        throw new Nip39ProofError(
            'The Gist must belong to the linked GitHub account and contain exactly one file'
        );
    }
    $file = array_values($files)[0] ?? null;
    if (!is_array($file)
        || ($file['truncated'] ?? false) === true
        || !is_string($file['content'] ?? null)
        || $file['content'] !== nip39_proof_text($pubkey)) {
        throw new Nip39ProofError(
            'The Gist file does not contain the exact NIP-39 proof text'
        );
    }
}

/** @return list<string> */
function nip39_base_relays(): array
{
    /*
     * These are the deployment's collaboration-discovery defaults. Per-repo
     * relay sets are intentionally not unioned here: a global user profile
     * must not fan out to every repository ever registered with the bridge.
     * NIP-65 adds the user's own write relays below.
     */
    return relay_url_set(
        array_merge(relay_defaults(), ['wss://relay.nostr.band'])
    );
}

/**
 * Query relays independently. One unavailable store cannot suppress complete
 * results from another, and response/arrival order never becomes precedence.
 *
 * @return array{events:list<array>,complete_relays:list<string>}
 */
function nip39_query_relay_set(array $filter, array $relays): array
{
    $events = [];
    $complete = [];
    foreach (relay_url_set($relays, 12) as $relay) {
        [$found, $finished] = relay_query(
            $filter,
            [$relay],
            NIP39_QUERY_TIMEOUT_SECS
        );
        if ($finished) $complete[] = $relay;
        foreach ($found as $event) {
            if (is_array($event) && is_hex64((string)($event['id'] ?? ''))) {
                $events[strtolower($event['id'])] = $event;
            }
        }
    }
    ksort($events, SORT_STRING);
    sort($complete, SORT_STRING);
    return [
        'events' => array_values($events),
        'complete_relays' => $complete,
    ];
}

function nip39_latest_replaceable(
    array $events,
    string $pubkey,
    int $kind
): ?array {
    $pubkey = strtolower($pubkey);
    $candidates = array_values(array_filter(
        $events,
        static fn(mixed $event): bool =>
            is_array($event)
            && (int)($event['kind'] ?? -1) === $kind
            && strtolower((string)($event['pubkey'] ?? '')) === $pubkey
            && fm_event_verify($event)
    ));
    usort($candidates, static function (array $a, array $b): int {
        $time = (int)$b['created_at'] <=> (int)$a['created_at'];
        return $time !== 0 ? $time : strcmp($a['id'], $b['id']);
    });
    return $candidates[0] ?? null;
}

function nip39_event_deleted(array $event, array $deletions): bool
{
    $author = strtolower((string)($event['pubkey'] ?? ''));
    $id = strtolower((string)($event['id'] ?? ''));
    foreach ($deletions as $deletion) {
        if (!is_array($deletion)
            || (int)($deletion['kind'] ?? -1) !== 5
            || strtolower((string)($deletion['pubkey'] ?? '')) !== $author
            || !fm_event_verify($deletion)) {
            continue;
        }
        foreach (($deletion['tags'] ?? []) as $tag) {
            if (is_array($tag)
                && ($tag[0] ?? null) === 'e'
                && strtolower((string)($tag[1] ?? '')) === $id) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Select the replaceable head before deletion. Deleting the winner never
 * resurrects a superseded older snapshot.
 */
function nip39_active_replaceable(
    array $events,
    array $deletions,
    string $pubkey,
    int $kind
): ?array {
    $head = nip39_latest_replaceable($events, $pubkey, $kind);
    return $head !== null && !nip39_event_deleted($head, $deletions)
        ? $head : null;
}

/** @return list<string> */
function nip39_write_relays(?array $relayList): array
{
    if ($relayList === null) return [];
    $relays = [];
    foreach (($relayList['tags'] ?? []) as $tag) {
        if (!is_array($tag) || ($tag[0] ?? null) !== 'r'
            || !is_string($tag[1] ?? null)) {
            continue;
        }
        $marker = $tag[2] ?? null;
        if ($marker !== null && $marker !== 'write') continue;
        $relays[] = $tag[1];
    }
    return relay_url_set($relays, 4);
}

/**
 * Find current relay-list and external-identity heads without assuming which
 * one arrived first or that every relay is available.
 *
 * @return array{
 *   current:?array,relays:list<string>,write_relays:list<string>,
 *   complete_relays:list<string>
 * }
 */
function nip39_discover_context(string $pubkey): array
{
    $pubkey = strtolower($pubkey);
    if (!is_hex64($pubkey)) {
        throw new InvalidArgumentException('invalid Nostr public key');
    }
    $base = nip39_base_relays();
    $relayLists = nip39_query_relay_set([
        'kinds' => [NIP39_RELAY_LIST_KIND],
        'authors' => [$pubkey],
        'limit' => NIP39_MAX_CURRENT_EVENTS,
    ], $base);
    $relayListIds = array_column($relayLists['events'], 'id');
    $relayListDeletionResult = $relayListIds
        ? nip39_query_relay_set([
            'kinds' => [5],
            '#e' => $relayListIds,
            'limit' => NIP39_MAX_CURRENT_EVENTS,
        ], $base)
        : ['events' => [], 'complete_relays' => []];
    if ($relayListIds && !$relayListDeletionResult['complete_relays']) {
        throw new Nip39RelayUnavailable(
            'No Nostr relay completed the relay-list deletion query'
        );
    }
    $relayListDeletes = $relayListDeletionResult['events'];
    $relayList = nip39_active_replaceable(
        $relayLists['events'],
        $relayListDeletes,
        $pubkey,
        NIP39_RELAY_LIST_KIND
    );
    $writeRelays = nip39_write_relays($relayList);
    $identityRelays = relay_url_set(array_merge($base, $writeRelays), 12);
    $identities = nip39_query_relay_set([
        'kinds' => [NIP39_KIND],
        'authors' => [$pubkey],
        'limit' => NIP39_MAX_CURRENT_EVENTS,
    ], $identityRelays);
    if (!$identities['complete_relays']) {
        throw new Nip39RelayUnavailable(
            'No Nostr relay completed the external-identity query'
        );
    }
    $identityIds = array_column($identities['events'], 'id');
    $deletionResult = $identityIds
        ? nip39_query_relay_set([
            'kinds' => [5],
            '#e' => $identityIds,
            'limit' => NIP39_MAX_CURRENT_EVENTS,
        ], $identityRelays)
        : ['events' => [], 'complete_relays' => []];
    if ($identityIds && !$deletionResult['complete_relays']) {
        throw new Nip39RelayUnavailable(
            'No Nostr relay completed the identity-deletion query'
        );
    }
    $deletions = $deletionResult['events'];
    return [
        'current' => nip39_active_replaceable(
            $identities['events'],
            $deletions,
            $pubkey,
            NIP39_KIND
        ),
        'relays' => $identityRelays,
        'write_relays' => $writeRelays,
        'complete_relays' => $identities['complete_relays'],
    ];
}

/**
 * Build one complete replacement while changing only this linked GitHub
 * claim. Existing wire order and duplicates outside that managed claim are
 * retained verbatim: future tag extensions may define order-sensitive
 * semantics, and this workflow has no authority to rewrite them.
 */
function nip39_build_proposal(
    ?array $current,
    string $pubkey,
    string $login,
    ?string $gistId
): array {
    $pubkey = strtolower($pubkey);
    if (!is_hex64($pubkey) || !nip39_github_login_valid($login)
        || ($gistId !== null
            && !preg_match('/^[0-9a-f]{5,64}$/D', $gistId))) {
        throw new InvalidArgumentException('invalid NIP-39 proposal');
    }
    $managedIdentity = 'github:' . strtolower($login);
    $tags = [];
    foreach (($current['tags'] ?? []) as $tag) {
        if (!is_array($tag) || !$tag
            || !array_is_list($tag)
            || array_filter($tag, 'is_string') !== $tag) {
            continue;
        }
        if (($tag[0] ?? null) === 'i'
            && is_string($tag[1] ?? null)
            && strtolower($tag[1]) === $managedIdentity) {
            continue;
        }
        $tags[] = array_values($tag);
    }
    if ($gistId !== null) {
        $tags[] = [
            'i',
            'github:' . strtolower($login),
            strtolower($gistId),
        ];
    }
    $currentCreatedAt = (int)($current['created_at'] ?? 0);
    if ($currentCreatedAt > now() + 300) {
        throw new RuntimeException(
            'Current identity event is too far in the future to replace safely'
        );
    }
    return [
        'kind' => NIP39_KIND,
        'pubkey' => $pubkey,
        'created_at' => max(now(), $currentCreatedAt + 1),
        'tags' => $tags,
        'content' => is_string($current['content'] ?? null)
            ? $current['content'] : '',
    ];
}

function nip39_managed_claim_changed(
    ?array $current,
    string $login,
    ?string $gistId
): bool {
    $managed = 'github:' . strtolower($login);
    $claims = [];
    foreach (($current['tags'] ?? []) as $tag) {
        if (is_array($tag)
            && ($tag[0] ?? null) === 'i'
            && is_string($tag[1] ?? null)
            && strtolower($tag[1]) === $managed) {
            $claims[json_c(array_values($tag))] = true;
        }
    }
    $expected = $gistId === null
        ? []
        : [json_c([
            'i',
            'github:' . strtolower($login),
            strtolower($gistId),
        ]) => true];
    ksort($claims, SORT_STRING);
    ksort($expected, SORT_STRING);
    return array_keys($claims) !== array_keys($expected);
}

/** @return list<array{identity:string,proof:string}> */
function nip39_identity_preview(array $tags): array
{
    $identities = [];
    foreach ($tags as $tag) {
        if (is_array($tag) && ($tag[0] ?? null) === 'i'
            && is_string($tag[1] ?? null)
            && is_string($tag[2] ?? null)) {
            $identities[json_c(array_values($tag))] = [
                'identity' => $tag[1],
                'proof' => $tag[2],
            ];
        }
    }
    ksort($identities, SORT_STRING);
    return array_values($identities);
}

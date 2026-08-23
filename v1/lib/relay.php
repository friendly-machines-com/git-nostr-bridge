<?php
/**
 * relay.php -- short-lived relay publish/query over lib/ws.
 * All connections live at most a few seconds; no daemons (DESIGN §0).
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';
require_once __DIR__ . '/ws.php';
require_once __DIR__ . '/crypto.php';

/**
 * NOTE: publish/query are declared with function_exists guards as an
 * offline-test seam (tests define stubs BEFORE including this file).
 */
if (!function_exists('relay_defaults')) {
function relay_defaults(): array
{
    return ['wss://relay.damus.io', 'wss://nos.lol'];
}
}

/**
 * Relay collections are semantic sets. Normalize before applying a resource
 * cap so duplicates and input order cannot decide which distinct endpoints
 * are contacted.
 *
 * @return list<string>
 */
function relay_url_set(array $values, int $limit = 0): array
{
    $set = [];
    foreach ($values as $value) {
        if (is_string($value) && relay_url_valid($value)) {
            $set[$value] = true;
        }
    }
    $urls = array_keys($set);
    sort($urls, SORT_STRING);
    return $limit > 0 ? array_slice($urls, 0, $limit) : $urls;
}

/** A scalar tag may be repeated identically, but conflicting values are invalid. */
function relay_unique_tag_value(array $event, string $name): ?string
{
    $values = [];
    foreach (($event['tags'] ?? []) as $tag) {
        if (is_array($tag) && ($tag[0] ?? null) === $name
            && is_string($tag[1] ?? null)) {
            // Keep the original string as the value; PHP coerces numeric
            // string array keys and must not change scalar tag types.
            $values['s:' . $tag[1]] = $tag[1];
        }
    }
    return count($values) === 1 ? array_values($values)[0] : null;
}

if (!function_exists('relay_publish')) {
function relay_publish(array $event, array $relays, float $timeoutSecs = 6.0): array
{
    $results = [];
    foreach (relay_url_set($relays, 4) as $url) {   // cap distinct fan-out
        try {
            $fp = ws_connect($url, $timeoutSecs);
        } catch (WsException $e) {
            $results[$url] = 'error: connect ' . $e->getMessage();
            continue;
        }
        try {
            $resp = ws_rpc($fp, ['EVENT', $event], function ($m) use ($event) {
                // match OK/CLOSED for OUR event id on any sub
                if (($m[0] ?? '') === 'OK' && ($m[1] ?? '') === $event['id']) return true;
                if (($m[0] ?? '') === 'CLOSED' || ($m[0] ?? '') === 'ERROR') return true;
                return false;
            }, $timeoutSecs);
            ws_send_close($fp);
            if ($resp === null) {
                $results[$url] = 'error: timeout';
            } elseif (($resp[0] ?? '') === 'OK') {
                // NIP-01: the boolean is the verdict. false = REJECTED
                // (blocked, rate-limited, invalid...), with the reason in
                // the 4th field. Only true means stored.
                $results[$url] = $resp[2]
                    ? 'ok'
                    : 'rejected: ' . substr((string)($resp[3] ?? 'no reason'), 0, 100);
            } else {
                $results[$url] = 'error: ' . substr(json_c($resp), 0, 120);
            }
        } catch (WsException $e) {
            $results[$url] = 'error: ' . $e->getMessage();
        }
    }
    return $results;
}
}

function relay_publish_ok(array $results): bool
{
    // Only an explicit relay "OK true" counts as published. Rejections
    // (blocked/rate-limited/invalid) must fail the job so cron retries.
    foreach ($results as $r) {
        if ($r === 'ok') return true;
    }
    return false;
}

function relay_url_valid(string $url): bool
{
    if ($url === '' || strlen($url) > 500
        || preg_match('/[\x00-\x20\x7f]/', $url)) {
        return false;
    }
    $parts = parse_url($url);
    return is_array($parts)
        && ($parts['scheme'] ?? '') === 'wss'
        && !empty($parts['host'])
        && !isset($parts['user'], $parts['pass'])
        && !isset($parts['fragment'])
        && (!isset($parts['port'])
            || ((int)$parts['port'] >= 1 && (int)$parts['port'] <= 65535));
}

/** Independently enforce the exact NIP-01 filter on an untrusted relay result. */
function relay_event_matches_filter(array $event, array $filter): bool
{
    foreach (['ids' => 'id', 'authors' => 'pubkey'] as $list => $field) {
        if (isset($filter[$list])
            && (!is_array($filter[$list])
                || !in_array($event[$field] ?? null, $filter[$list], true))) {
            return false;
        }
    }
    if (isset($filter['kinds'])
        && (!is_array($filter['kinds'])
            || !in_array((int)($event['kind'] ?? -1), $filter['kinds'], true))) {
        return false;
    }
    $createdAt = (int)($event['created_at'] ?? 0);
    if (isset($filter['since']) && $createdAt < (int)$filter['since']) {
        return false;
    }
    if (isset($filter['until']) && $createdAt > (int)$filter['until']) {
        return false;
    }
    foreach ($filter as $name => $values) {
        if (!is_string($name) || !str_starts_with($name, '#')) continue;
        if (!is_array($values)) return false;
        $tagName = substr($name, 1);
        $matched = false;
        foreach (($event['tags'] ?? []) as $tag) {
            if (is_array($tag) && ($tag[0] ?? null) === $tagName
                && in_array($tag[1] ?? null, $values, true)) {
                $matched = true;
                break;
            }
        }
        if (!$matched) return false;
    }
    return true;
}

if (!function_exists('relay_query')) {
/**
 * Query every relay in the endpoint set and merge verified matches by event ID.
 * The completeness flag is true only if every requested relay reached EOSE.
 */
function relay_query(array $filter, array $relays, float $timeoutSecs = 4.0): array
{
    $events = [];
    $requestedSet = relay_url_set($relays);
    $relaySet = array_slice($requestedSet, 0, 3);
    // More than three distinct relays exceeds this short-query resource cap.
    // Query the deterministic subset, but never report the omitted set as a
    // complete historical answer.
    $allComplete = (bool)$relaySet
        && count($relaySet) === count($requestedSet);
    $subId = 'q' . bin2hex(random_bytes(4));
    foreach ($relaySet as $url) {
        $relayComplete = false;
        try {
            $fp = ws_connect($url, $timeoutSecs);
        } catch (WsException $e) {
            $allComplete = false;
            continue;
        }
        try {
            ws_send_text($fp, json_c(['REQ', $subId, $filter]));
            $deadline = microtime(true) + $timeoutSecs;
            while (microtime(true) < $deadline) {
                $left = $deadline - microtime(true);
                stream_set_timeout($fp, (int)$left, (int)(fmod($left, 1) * 1e6));
                $raw = ws_read_message($fp);
                if ($raw === null) break;
                $dec = json_decode($raw, true);
                if (!is_array($dec)) continue;
                if (($dec[0] ?? '') === 'EOSE') {
                    $relayComplete = true;
                    break;
                }
                if (($dec[0] ?? '') === 'EVENT' && is_array($dec[2] ?? null)) {
                    $event = $dec[2];
                    if (!fm_event_verify($event)
                        || !relay_event_matches_filter($event, $filter)) {
                        continue;
                    }
                    $eventId = $event['id'];
                    $events[$eventId] = $event;
                }
            }
        } catch (WsException $e) {
            $relayComplete = false;
        } finally {
            try { ws_send_close($fp); } catch (WsException $e) {}
        }
        if (!$relayComplete) $allComplete = false;
    }
    ksort($events, SORT_STRING);
    return [array_values($events), $allComplete];
}
}

if (!function_exists('relay_has_event')) {
/** True only when a relay returns a valid event with the exact requested id. */
function relay_has_event(string $eventId, array $relays): bool
{
    return relay_find_event($eventId, $relays) !== null;
}
}

if (!function_exists('relay_find_event')) {
/** Return an exact, valid event from any configured relay. */
function relay_find_event(string $eventId, array $relays): ?array
{
    if (!is_hex64($eventId)) return null;
    foreach (relay_url_set($relays, 4) as $relay) {
        [$events] = relay_query(
            ['ids' => [$eventId], 'limit' => 1],
            [$relay],
            4.0
        );
        foreach ($events as $event) {
            if (($event['id'] ?? '') === $eventId
                && fm_event_verify($event)) {
                return $event;
            }
        }
    }
    return null;
}
}

/**
 * Verify the latest addressable 30617 published by a specific owner.
 *
 * Results from every declared relay are reduced together. A stale version on
 * one relay must not override a newer version on another; equal timestamps
 * use NIP-01's lowest-event-id rule.
 */
function relay_verify_repo_owner(
    string $repoId, string $ownerPk, array $relays,
    ?string $requiredMaintainer = null,
    array $requiredRelays = [],
    ?array &$winningEvent = null
): ?bool {
    $winningEvent = null;
    if (!is_hex64($ownerPk) || $repoId === '') return false;
    if ($requiredMaintainer !== null && !is_hex64($requiredMaintainer)) return false;
    $candidates = [];
    $queried = 0;
    foreach (relay_url_set($relays, 4) as $relay) {
        $queried++;
        [$events, $complete] = relay_query([
            'kinds' => [30617], 'authors' => [$ownerPk],
            '#d' => [$repoId], 'limit' => 20,
        ], [$relay], 5.0);
        if (!$complete) return null;
        foreach ($events as $event) {
            if (($event['pubkey'] ?? '') !== $ownerPk || !fm_event_verify($event)) continue;
            if (relay_unique_tag_value($event, 'd') !== $repoId) continue;
            $candidates[$event['id']] = $event;
        }
    }
    if ($queried === 0) return false;
    if (!$candidates) return false;
    usort($candidates, static function (array $a, array $b): int {
        $time = (int)$b['created_at'] <=> (int)$a['created_at'];
        return $time !== 0 ? $time : strcmp($a['id'], $b['id']);
    });
    $event = $candidates[0];
    $winningEvent = $event;

    $maintainerAuthorized = $requiredMaintainer === null;
    $subordinateFork = false;
    $declaredRelays = [];
    $declaredRelaysValid = true;
    foreach ($event['tags'] as $tag) {
        if (($tag[0] ?? '') === 'u') {
            $subordinateFork = true;
        }
        if (($tag[0] ?? '') === 'maintainers'
            && $requiredMaintainer !== null
            && in_array($requiredMaintainer, array_slice($tag, 1), true)) {
            $maintainerAuthorized = true;
        }
        if (($tag[0] ?? '') === 'relays') {
            foreach (array_slice($tag, 1) as $declared) {
                if (!is_string($declared) || !relay_url_valid($declared)) {
                    $declaredRelaysValid = false;
                    continue;
                }
                $declaredRelays[$declared] = true;
            }
        }
    }
    // NIP-34: publishing 30617 asserts maintainer authority unless the
    // announcement includes a u tag identifying it as a subordinate fork.
    if ($requiredMaintainer === $ownerPk && !$subordinateFork) {
        $maintainerAuthorized = true;
    }
    if ($requiredRelays) {
        if (!$declaredRelaysValid) return false;
        $expectedRelays = relay_url_set($requiredRelays);
        $actualRelays = array_keys($declaredRelays);
        sort($actualRelays, SORT_STRING);
        if ($actualRelays !== $expectedRelays) return false;
    }
    return $maintainerAuthorized;
}

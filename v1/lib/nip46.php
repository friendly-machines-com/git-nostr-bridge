<?php
/**
 * nip46.php -- NIP-46 client (nostrconnect:// flow) over lib/ws + lib/nip44.
 *
 * PROTOCOL MODEL: the nostrconnect:// flow is two one-way letterboxes on
 * shared relays, not request/response over one socket:
 *
 *   - REQUESTS  travel on events tagged  p = <signer pubkey>
 *               (we publish; the signer subscribes to its own name)
 *   - RESPONSES travel on events tagged  p = <client pubkey>
 *               (the signer publishes; we subscribe to our own name)
 *
 * The client never receives a "connect request": the URI carried it to the
 * signer out-of-band. The signer's connect ANSWER is the first event we
 * ever receive: a kind 24133 tagged to our key whose NIP-44 payload
 * decrypts (with our private key + the signer's pubkey) to
 * {"id":..,"result":"<secret>"}. The secret match is the authentication:
 * only a signer that saw our nostrconnect URI can know it, and only we
 * can decrypt the envelope.
 *
 * Design constraints that follow:
 *   1. Subscription filter is #p=[our key] (the response letterbox).
 *      Filtering by the signer's key would match our own requests.
 *   2. No authors filter: the signer's key is unknown until its first
 *      event arrives; we learn it from the event's author field.
 *   3. A NIP-44 envelope that fails to decrypt was not addressed to us;
 *      treat as not-ours and skip.
 *   4. PHP note: named-argument labels must match the DECLARED parameter
 *      names, not merely describe them. A mismatch throws at call time.
 *
 * All skip paths log: a handshake over public relays can fail in many
 * ways that are invisible from the outside (unreachable relay, signer
 * answering on a different relay, stale attempt), so each decision leaves
 * a trace in the log.
 *
 * Methods used: connect (answer side), switch_relays, get_public_key,
 * sign_event, ping.
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/nip44.php';
require_once __DIR__ . '/ws.php';
require_once __DIR__ . '/relay.php';

const NIP46_AUTH_STATE_PREFIX = 'nip46-auth-url:';

/** Accept only bounded HTTPS challenges suitable for showing to the user. */
function nip46_auth_challenge_url(mixed $value): ?string
{
    if (!is_string($value) || $value === '' || strlen($value) > 2048
        || preg_match('/[\x00-\x20\x7f]/', $value)) {
        return null;
    }
    $parts = parse_url($value);
    if (!is_array($parts)
        || strtolower((string)($parts['scheme'] ?? '')) !== 'https'
        || !is_string($parts['host'] ?? null)
        || $parts['host'] === ''
        || isset($parts['user'])
        || isset($parts['pass'])) {
        return null;
    }
    return $value;
}

/** Decode the temporary auth challenge stored on a connected link state. */
function nip46_state_auth_url(mixed $value): ?string
{
    if (!is_string($value)
        || !str_starts_with($value, NIP46_AUTH_STATE_PREFIX)) {
        return null;
    }
    return nip46_auth_challenge_url(
        substr($value, strlen(NIP46_AUTH_STATE_PREFIX))
    );
}

/** Relays advertised in nostrconnect:// and scanned by cron. */
function nip46_listen_relays(): array
{
    return relay_url_set(['wss://nos.lol', 'wss://relay.damus.io']);
}

/** Preserve repeated relay= parameters; parse_str would keep only the last. */
function nip46_bunker_relays(string $query): array
{
    $relays = [];
    foreach (explode('&', $query) as $part) {
        if ($part === '') continue;
        [$rawKey, $rawValue] = array_pad(explode('=', $part, 2), 2, '');
        if (rawurldecode($rawKey) !== 'relay') continue;
        $relay = rawurldecode($rawValue);
        if (relay_url_valid($relay)) $relays[] = $relay;
    }
    return relay_url_set($relays);
}

if (!function_exists('nip46_collect_connect_events')) {
/**
 * Keep every advertised client-response mailbox live for the whole scan.
 * Kind 24133 is ephemeral, so stopping at historical EOSE would miss an
 * approval that arrives while cron is running.
 *
 * @return array<int,array{relays:list<string>,event:array}>
 */
function nip46_collect_connect_events(
    array $clientPks,
    array $relays,
    int $since,
    float $timeoutSecs = 8.0
): array {
    $clientPks = array_values(array_unique(array_filter(
        $clientPks,
        fn($pubkey) => is_string($pubkey) && is_hex64($pubkey)
    )));
    sort($clientPks, SORT_STRING);
    if (!$clientPks) return [];

    $sockets = [];
    foreach (relay_url_set($relays, 4) as $relay) {
        try {
            $fp = ws_connect($relay, min(3.0, $timeoutSecs));
            $subId = 'c' . bin2hex(random_bytes(4));
            ws_send_text($fp, json_c(['REQ', $subId, [
                'kinds' => [24133],
                '#p' => $clientPks,
                'since' => max(1, $since),
                'limit' => 500,
            ]]));
            $sockets[(int)$fp] = [
                'fp' => $fp,
                'relay' => $relay,
            ];
        } catch (WsException $error) {
            bridge_log('nip46', 'connect scan relay unavailable', [
                'relay' => $relay,
                'error' => $error->getMessage(),
            ]);
        }
    }
    if (!$sockets) return [];

    $events = [];
    $deadline = microtime(true) + $timeoutSecs;
    while ($sockets && microtime(true) < $deadline) {
        $left = max(0.0, $deadline - microtime(true));
        $read = array_map(fn($entry) => $entry['fp'], $sockets);
        $write = null;
        $except = null;
        $ready = @stream_select(
            $read,
            $write,
            $except,
            (int)$left,
            (int)(fmod($left, 1.0) * 1e6)
        );
        if ($ready === false) break;
        if ($ready === 0) continue;

        foreach ($read as $fp) {
            $key = (int)$fp;
            if (!isset($sockets[$key])) continue;
            try {
                stream_set_timeout($fp, 2);
                $raw = ws_read_message($fp);
                if ($raw === null) {
                    ws_send_close($fp);
                    unset($sockets[$key]);
                    continue;
                }
                $message = json_decode($raw, true);
                if (($message[0] ?? '') === 'CLOSED') {
                    ws_send_close($fp);
                    unset($sockets[$key]);
                    continue;
                }
                if (($message[0] ?? '') !== 'EVENT'
                    || !is_array($message[2] ?? null)) {
                    // EOSE is deliberately ignored: remain subscribed for
                    // approvals published after the historical snapshot.
                    continue;
                }
                $event = $message[2];
                $addressed = false;
                foreach (($event['tags'] ?? []) as $tag) {
                    if (($tag[0] ?? '') === 'p'
                        && in_array($tag[1] ?? null, $clientPks, true)) {
                        $addressed = true;
                        break;
                    }
                }
                if (($event['kind'] ?? null) === 24133
                    && $addressed
                    && fm_event_verify($event)) {
                    $eventId = $event['id'];
                    if (!isset($events[$eventId])) {
                        $events[$eventId] = [
                            'relays' => [],
                            'event' => $event,
                        ];
                    }
                    $events[$eventId]['relays'][$sockets[$key]['relay']] = true;
                }
            } catch (WsException $error) {
                ws_send_close($fp);
                unset($sockets[$key]);
            }
        }
    }
    foreach ($sockets as $entry) ws_send_close($entry['fp']);
    ksort($events, SORT_STRING);
    $result = [];
    foreach ($events as $entry) {
        $observedRelays = array_keys($entry['relays']);
        sort($observedRelays, SORT_STRING);
        $result[] = [
            'relays' => $observedRelays,
            'event' => $entry['event'],
        ];
    }
    return $result;
}
}

/**
 * Validate and decrypt a possible nostrconnect response.
 * Returns [remote-signer-pubkey, echoed-secret] or null when it is not ours.
 */
function nip46_decode_connect_event(
    array $ev, string $clientPriv, string $clientPk
): ?array {
    if (($ev['kind'] ?? 0) !== 24133 || !fm_event_verify($ev)) return null;
    $addressed = false;
    foreach ($ev['tags'] as $tag) {
        if (($tag[0] ?? '') === 'p' && ($tag[1] ?? '') === $clientPk) {
            $addressed = true;
            break;
        }
    }
    if (!$addressed) return null;

    $signerPk = strtolower($ev['pubkey']);
    try {
        $payload = nip44_decrypt($clientPriv, $signerPk, $ev['content']);
    } catch (RuntimeException $e) {
        return null;
    }
    $rpc = json_decode($payload, true);
    $secret = is_array($rpc)
        && is_string($rpc['id'] ?? null)
        && $rpc['id'] !== ''
        && is_string($rpc['result'] ?? null)
        && !array_key_exists('error', $rpc)
        ? $rpc['result'] : '';
    return $secret !== '' ? [$signerPk, $secret] : null;
}

/**
 * Publish a kind 24133 request and wait for the matching response.
 * $relayUrl: relay to use for both directions.
 * $remotePkHex: signer/bunker pubkey (p-tag target).
 * Returns decoded [id =>, result =>] array or null on timeout.
 */
function nip46_rpc(string $clientPriv, string $clientPk, string $remotePkHex,
                   string $relayUrl, string $method, array $params,
                   float $timeoutSecs = 8.0,
                   ?callable $onAuthUrl = null): ?array
{
    $reqId = bin2hex(random_bytes(8));
    $req = [
        'id'     => $reqId,
        'method' => $method,
        'params' => $params,
    ];

    $ev = [
        'pubkey'     => $clientPk,
        'created_at' => now(),
        'kind'       => 24133,
        'tags'       => [['p', $remotePkHex]],
        'content'    => nip44_encrypt($clientPriv, $remotePkHex, json_c($req)),
    ];
    // Wire events REQUIRE id+sig (NIP-01). fm_event_sign RETURNS the
    // signed copy; PHP arrays pass by value, so the result must be
    // captured -- calling it as a statement sends an unsigned event that
    // relays silently refuse to store.
    $ev = fm_event_sign($ev, $clientPriv);

    bridge_log('nip46', 'rpc: sending', [
        'method' => $method, 'to' => substr($remotePkHex, 0, 8), 'relay' => $relayUrl,
    ]);

    $fp = ws_connect($relayUrl, min($timeoutSecs, 10.0));

    // subscribe to responses addressed to us BEFORE sending the request
    $sub = json_c(['REQ', 'r' . $reqId, [
        'kinds'   => [24133],
        '#p'      => [$clientPk],
        'authors' => [$remotePkHex],
        'since'   => now() - 60,
    ]]);
    ws_send_text($fp, $sub);
    ws_send_text($fp, json_c(['EVENT', $ev]));

    $deadline = microtime(true) + $timeoutSecs;
    $sawAnything = false;
    while (microtime(true) < $deadline) {
        $left = $deadline - microtime(true);
        if ($left <= 0) break;
        stream_set_timeout($fp, (int)$left, (int)(fmod($left, 1) * 1e6));
        $raw = ws_read_message($fp);
        if ($raw === null) break;
        $dec = json_decode($raw, true);
        if (!is_array($dec)) continue;
        // EVENT, <sub>, <event>
        if (($dec[0] ?? '') === 'EVENT' && is_array($dec[2] ?? null)) {
            $sawAnything = true;
            $respEv = $dec[2];
            if (($respEv['kind'] ?? 0) !== 24133) continue;
            if (($respEv['pubkey'] ?? '') !== $remotePkHex) continue;
            $addressed = false;
            foreach (($respEv['tags'] ?? []) as $tag) {
                if (is_array($tag)
                    && ($tag[0] ?? '') === 'p'
                    && ($tag[1] ?? '') === $clientPk) {
                    $addressed = true;
                    break;
                }
            }
            if (!$addressed) {
                bridge_log('nip46', 'rpc: response missing client p tag', [
                    'method' => $method,
                ]);
                continue;
            }
            if (!fm_event_verify($respEv)) {
                bridge_log('nip46', 'rpc: response BAD SIGNATURE', ['method' => $method]);
                continue;
            }
            try {
                $payload = nip44_decrypt($clientPriv, $remotePkHex, $respEv['content']);
            } catch (RuntimeException $e) {
                bridge_log('nip46', 'rpc: response not decryptable', ['method' => $method]);
                continue;   // not addressed to us / wrong session
            }
            $rpc = json_decode($payload, true);
            if (!is_array($rpc) || ($rpc['id'] ?? '') !== $reqId) continue;
            if (($rpc['result'] ?? null) === 'auth_url') {
                $authUrl = nip46_auth_challenge_url($rpc['error'] ?? null);
                if ($authUrl === null) {
                    bridge_log('nip46', 'rpc: invalid authorization URL', [
                        'method' => $method,
                    ]);
                    continue;
                }
                // NIP-46 sends the eventual answer under this same request
                // id after interactive authorization. Show the challenge
                // through the caller, but keep this subscription alive.
                if ($onAuthUrl !== null) {
                    try {
                        $onAuthUrl($authUrl);
                    } catch (Throwable $error) {
                        ws_send_close($fp);
                        throw $error;
                    }
                }
                bridge_log('nip46', 'rpc: signer requested authorization', [
                    'method' => $method,
                    'host' => (string)parse_url($authUrl, PHP_URL_HOST),
                ]);
                continue;
            }
            ws_send_close($fp);
            bridge_log('nip46', 'rpc: got response', ['method' => $method,
                'result' => substr((string)($rpc['result'] ?? ''), 0, 20)]);
            return $rpc;
        }
        if (($dec[0] ?? '') === 'CLOSED' || ($dec[0] ?? '') === 'ERROR') {
            bridge_log('nip46', 'rpc: relay notice', ['method' => $method,
                'msg' => substr(json_c($dec), 0, 100)]);
            continue;   // keep reading until deadline
        }
    }
    ws_send_close($fp);
    bridge_log('nip46', 'rpc: TIMEOUT waiting for response', [
        'method' => $method, 'to' => substr($remotePkHex, 0, 8), 'relay' => $relayUrl,
        'saw_events' => $sawAnything,
    ]);
    return null;
}

/**
 * nostrconnect:// client flow: wait on our listen relay for the signer's
 * connect ANSWER. Returns the bunker pubkey or null (timeout).
 *
 * WHY it works this way (see file header): in this flow WE never send a
 * connect request -- the URI did that out-of-band (user's phone). The
 * first thing we receive is the signer's RESPONSE, so we subscribe to
 * events addressed to OUR key (#p filter) and accept whichever signer's
 * envelope decrypts and carries our secret.
 *
 * WHY every branch logs: a handshake over public relays has many failure
 * modes that are invisible from the outside (dead relay, signer answering
 * on a different relay, stale attempt, wrong recipient, bad signature);
 * each skip decision leaves a trace so the log can distinguish them.
 */
function nip46_wait_connect(string $clientPriv, string $clientPk,
                            string $listenRelay, string $secret,
                            float $timeoutSecs = 100.0): ?string
{
    bridge_log('nip46', 'wait: listening', [
        'relay' => $listenRelay, 'client' => substr($clientPk, 0, 8), 'secs' => $timeoutSecs,
    ]);
    $fp = ws_connect($listenRelay, min($timeoutSecs, 10.0));
    $subId = 'c' . bin2hex(random_bytes(4));

    // WHY #p=[our key]: responses are addressed to the client. Filtering
    // by the signer's key would match our own outgoing requests instead.
    // WHY no authors filter: the signer's key is unknown until its answer
    // arrives -- that's how we discover it.
    ws_send_text($fp, json_c(['REQ', $subId, [
        'kinds'   => [24133],
        '#p'      => [$clientPk],
        'since'   => now() - 120,
    ]]));

    $deadline = microtime(true) + $timeoutSecs;
    while (microtime(true) < $deadline) {
        $left = $deadline - microtime(true);
        if ($left <= 0) break;
        stream_set_timeout($fp, (int)$left, (int)(fmod($left, 1) * 1e6));
        $raw = ws_read_message($fp);
        if ($raw === null) break;
        $dec = json_decode($raw, true);
        if (!is_array($dec)) continue;
        if (($dec[0] ?? '') === 'EVENT' && is_array($dec[2] ?? null)) {
            $ev = $dec[2];
            $decoded = nip46_decode_connect_event($ev, $clientPriv, $clientPk);
            if ($decoded === null) continue;
            [$signerPk, $echoedSecret] = $decoded;
            // The secret from OUR nostrconnect URI, echoed back, is the
            // proof the signer saw the real URI (not a replay of another
            // client's handshake).
            if (hash_equals($secret, $echoedSecret)) {
                bridge_log('nip46', 'wait: CONNECT accepted', ['signer' => substr($signerPk, 0, 8)]);
                ws_send_close($fp);
                // Bank the human approval immediately. get_public_key is a
                // separate, retryable RPC owned by the durable finish job.
                return strtolower($signerPk);
            }
            bridge_log('nip46', 'wait: event for us but secret mismatch (stale attempt?)', [
                'from' => substr($signerPk, 0, 8),
            ]);
        }
    }
    bridge_log('nip46', 'wait: window ended with no connect', ['relay' => $listenRelay]);
    ws_send_close($fp);
    return null;
}

/**
 * Convenience: one-shot sign_event against a stored bunker URI.
 *
 * WHY this is the workhorse of Direction A: every GitHub->Nostr mirror of
 * a LINKED author goes through here. The bunker URI comes from the
 * handshake above (stored encrypted); the relays inside it are where the
 * signer demonstrably listens -- which is why the connect-time relay is
 * persisted rather than re-using global defaults (a signer that answered
 * on nos.lol once will be polled on nos.lol again).
 */
function nip46_sign_event(string $clientPriv, string $clientPk,
                          string $bunkerUri, array $unsignedEv,
                          float $timeoutSecs = 8.0,
                          ?callable $onAuthUrl = null,
                          ?callable $onSignerError = null): ?array
{
    // parse bunker://<pk>?relay=..&relay=..
    if (!preg_match('#^bunker://([0-9a-f]{64})(?:\?(.*))?$#', $bunkerUri, $m)) {
        throw new InvalidArgumentException('bad bunker uri');
    }
    $bunkerPk = $m[1];
    $relays = nip46_bunker_relays($m[2] ?? '');
    if (!$relays) throw new InvalidArgumentException('bunker uri has no secure relay');

    $expectedPk = strtolower((string)($unsignedEv['pubkey'] ?? ''));
    if (!is_hex64($expectedPk)) throw new InvalidArgumentException('sign_event expected pubkey missing');
    $requestEv = nip46_unsigned_event($unsignedEv);
    // This is one logical signer attempt across a set of alternative relay
    // endpoints, so timeoutSecs is one total deadline, not a multiplier per
    // relay. Otherwise four unavailable relays can outlive the durable queue
    // lease and let another worker claim the same event concurrently.
    $deadline = microtime(true) + max(0.1, $timeoutSecs);

    foreach ($relays as $relay) {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) break;
        try {
            $resp = nip46_rpc(
                $clientPriv,
                $clientPk,
                $bunkerPk,
                $relay,
                'sign_event',
                [json_c($requestEv)],
                $remaining,
                $onAuthUrl
            );
        } catch (WsException $error) {
            // Bunker relays are alternative members of a set. One transport
            // failure cannot give that endpoint precedence over the others.
            bridge_log('nip46', 'sign_event relay unavailable', [
                'relay' => $relay,
                'error' => $error->getMessage(),
            ]);
            continue;
        }
        if ($resp !== null
            && is_string($resp['error'] ?? null)
            && $resp['error'] !== ''
            && $onSignerError !== null) {
            $message = preg_replace(
                '/[\x00-\x1f\x7f]+/',
                ' ',
                $resp['error']
            );
            $message = substr(trim((string)$message), 0, 160);
            if ($message !== '') $onSignerError($message);
        }
        if ($resp !== null && isset($resp['result'])) {
            $signed = json_decode($resp['result'], true);
            if (is_array($signed)
                && nip46_signed_event_matches($signed, $requestEv, $expectedPk)) {
                return nip46_wire_event($signed);
            }
            bridge_log('nip46', 'sign_event returned mismatched/invalid event', [
                'expected' => substr($expectedPk, 0, 8),
            ]);
        }
    }
    return null;
}

/** The exact unsigned event shape allowed by NIP-46 sign_event. */
function nip46_unsigned_event(array $ev): array
{
    if (!isset($ev['kind'], $ev['content'], $ev['tags'], $ev['created_at'])
        || !is_int($ev['kind']) || !is_string($ev['content'])
        || !is_int($ev['created_at']) || !is_array($ev['tags'])) {
        throw new InvalidArgumentException('malformed unsigned event');
    }
    foreach ($ev['tags'] as $tag) {
        if (!is_array($tag) || !$tag) {
            throw new InvalidArgumentException('malformed unsigned event tag');
        }
        foreach ($tag as $value) {
            if (!is_string($value)) {
                throw new InvalidArgumentException('malformed unsigned event tag value');
            }
        }
    }
    return [
        'kind'       => $ev['kind'],
        'content'    => $ev['content'],
        'tags'       => array_values(array_map('array_values', $ev['tags'])),
        'created_at' => $ev['created_at'],
    ];
}

function nip46_signed_event_matches(array $signed, array $requestEv, string $expectedPk): bool
{
    if (!fm_event_verify($signed) || strtolower((string)$signed['pubkey']) !== $expectedPk) {
        return false;
    }
    $actual = nip46_unsigned_event($signed);
    return $actual === $requestEv;
}

/** Strip any signer-added, unsigned extension fields before relay publish. */
function nip46_wire_event(array $ev): array
{
    return [
        'id'         => $ev['id'],
        'pubkey'     => strtolower($ev['pubkey']),
        'created_at' => (int)$ev['created_at'],
        'kind'       => (int)$ev['kind'],
        'tags'       => array_values(array_map('array_values', $ev['tags'])),
        'content'    => (string)$ev['content'],
        'sig'        => strtolower($ev['sig']),
    ];
}

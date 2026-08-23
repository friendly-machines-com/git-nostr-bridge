<?php
/**
 * ws.php -- minimal WebSocket (RFC 6455) client over streams.
 * Client-masked text frames, read with timeout, ping->pong. No deps.
 * Used ONLY for short-lived connections inside a request / cron tick.
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';

class WsException extends RuntimeException {}

function ws_ip_is_public(string $ip): bool
{
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) !== false;
}

/**
 * Resolve a hostname once and return a deterministic set of public IPv4
 * addresses. ws_connect uses the chosen address directly while retaining the
 * original hostname for TLS SNI/certificate and HTTP Host validation. This
 * prevents a second DNS lookup from turning validation into DNS-rebinding
 * SSRF.
 *
 * @return list<string>
 */
function ws_public_ipv4_set(string $host): array
{
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return ws_ip_is_public($host) ? [$host] : [];
    }
    if (!preg_match(
        '/\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}'
        . '[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}'
        . '[A-Za-z0-9])?\z/',
        $host
    )) {
        return [];
    }

    $set = [];
    $records = @dns_get_record($host, DNS_A);
    if (is_array($records)) {
        foreach ($records as $record) {
            $ip = is_string($record['ip'] ?? null) ? $record['ip'] : '';
            if (ws_ip_is_public($ip)) $set[$ip] = true;
        }
    }
    // Some constrained PHP resolvers do not expose DNS_A through
    // dns_get_record; gethostbynamel still returns addresses that we connect to
    // directly, so it does not reintroduce a validation/use DNS race.
    if (!$set) {
        $addresses = @gethostbynamel($host);
        foreach (is_array($addresses) ? $addresses : [] as $ip) {
            if (is_string($ip) && ws_ip_is_public($ip)) $set[$ip] = true;
        }
    }
    $addresses = array_keys($set);
    sort($addresses, SORT_STRING);
    return $addresses;
}

function ws_write_all($fp, string $data): void
{
    $off = 0;
    $len = strlen($data);
    while ($off < $len) {
        $n = @fwrite($fp, substr($data, $off));
        if ($n === false || $n === 0) throw new WsException('socket write failed');
        $off += $n;
    }
}

/** Open a WebSocket connection; returns the stream. */
function ws_connect(string $url, float $timeout = 10.0)
{
    // Offline protocol tests may provide an already-connected socket pair.
    // The seam is CLI-only; web entry points can never replace egress checks.
    if (PHP_SAPI === 'cli'
        && is_callable($GLOBALS['__fm_test_ws_connect'] ?? null)) {
        $fp = ($GLOBALS['__fm_test_ws_connect'])($url, $timeout);
        if (!is_resource($fp)) {
            throw new WsException('test websocket connector returned no stream');
        }
        return $fp;
    }

    $m = [];
    if (!preg_match('#^(wss|ws)://([^/:]+)(?::(\d+))?(/.*)?$#', $url, $m)) {
        throw new WsException("bad ws url: $url");
    }
    $secure = $m[1] === 'wss';
    $host = $m[2];
    $port = (int)($m[3] ?? ($secure ? 443 : 80));
    $path = $m[4] ?? '/';
    $addresses = ws_public_ipv4_set($host);
    if (!$addresses) {
        throw new WsException('websocket host has no public IPv4 address');
    }

    $ctx = stream_context_create(['ssl' => [
        'verify_peer' => true, 'verify_peer_name' => true, 'SNI_enabled' => true,
        'peer_name' => $host,
    ]]);
    $fp = false;
    $lastError = 'no public address accepted a connection';
    foreach ($addresses as $ip) {
        $errNo = 0;
        $errStr = '';
        $candidate = @stream_socket_client(
            "tcp://$ip:$port",
            $errNo,
            $errStr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        if ($candidate === false) {
            $lastError = "tcp connect failed: $errStr ($errNo)";
            continue;
        }
        stream_set_timeout(
            $candidate,
            (int)$timeout,
            (int)(($timeout - (int)$timeout) * 1e6)
        );
        if ($secure && !@stream_socket_enable_crypto(
            $candidate,
            true,
            STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT
                | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT
        )) {
            fclose($candidate);
            $lastError = 'tls handshake failed';
            continue;
        }
        $fp = $candidate;
        break;
    }
    if ($fp === false) throw new WsException($lastError);

    $key = base64_encode(random_bytes(16));
    $req = "GET $path HTTP/1.1\r\n"
         . "Host: $host" . (isset($m[3]) ? ":$port" : '') . "\r\n"
         . "Upgrade: websocket\r\n"
         . "Connection: Upgrade\r\n"
         . "Sec-WebSocket-Key: $key\r\n"
         . "Sec-WebSocket-Version: 13\r\n\r\n";
    try {
        ws_write_all($fp, $req);
    } catch (WsException $e) {
        fclose($fp);
        throw new WsException('write upgrade failed', 0, $e);
    }

    $hdr = '';
    while (($c = fgets($fp, 1024)) !== false) {
        $hdr .= $c;
        if (strlen($hdr) > 16384) {
            fclose($fp);
            throw new WsException('ws upgrade headers too large');
        }
        if (substr($hdr, -4, 4) === "\r\n\r\n") break;
    }
    if (strpos($hdr, ' 101 ') === false) {
        fclose($fp);
        throw new WsException('ws upgrade rejected: ' . substr($hdr, 0, 64));
    }
    $expectedAccept = base64_encode(sha1(
        $key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
    if (!preg_match('/^Sec-WebSocket-Accept:\s*(.+)\r?$/mi', $hdr, $accept)
        || !hash_equals($expectedAccept, trim($accept[1]))) {
        fclose($fp);
        throw new WsException('ws upgrade has invalid accept key');
    }
    return $fp;
}

function ws_send_text($fp, string $payload): void
{
    $b1 = 0x81; // FIN + text
    $len = strlen($payload);
    $mask = random_bytes(4);
    $masked = '';
    for ($i = 0; $i < $len; $i++) $masked .= $payload[$i] ^ $mask[$i % 4];
    if ($len < 126) {
        $head = pack('CC', $b1, 0x80 | $len);
    } elseif ($len < 65536) {
        $head = pack('CCn', $b1, 0x80 | 126, $len);
    } else {
        $head = pack('CCJ', $b1, 0x80 | 127, $len);
    }
    ws_write_all($fp, $head . $mask . $masked);
}

/** Read exactly $n bytes; false on timeout/eof. */
function ws_read_exact($fp, int $n)
{
    $buf = '';
    while (strlen($buf) < $n) {
        $c = fread($fp, $n - strlen($buf));
        if ($c === false || $c === '') return false;
        $buf .= $c;
    }
    return $buf;
}

/** @return array{fin:bool,opcode:int,payload:string}|null null = timeout/eof */
function ws_read_frame($fp): ?array
{
    $h = ws_read_exact($fp, 2);
    if ($h === false) return null;
    $b1 = ord($h[0]); $b2 = ord($h[1]);
    $fin = ($b1 & 0x80) !== 0;
    $opcode = $b1 & 0x0f;
    if (($b1 & 0x70) !== 0) throw new WsException('unsupported websocket RSV bits');
    $masked = ($b2 & 0x80) !== 0;
    if ($masked) throw new WsException('server sent a masked frame');
    $len = $b2 & 0x7f;
    if ($len === 126) {
        $ext = ws_read_exact($fp, 2); if ($ext === false) return null;
        $len = unpack('n', $ext)[1];
    } elseif ($len === 127) {
        $ext = ws_read_exact($fp, 8); if ($ext === false) return null;
        // RFC 6455 uses an unsigned 63-bit length. Reject values that cannot
        // fit our cap before converting them to a PHP integer.
        if (substr($ext, 0, 4) !== "\x00\x00\x00\x00") {
            throw new WsException('websocket frame too large');
        }
        $len = unpack('N', substr($ext, 4, 4))[1];
    }
    if ($len > 2 * 1024 * 1024) throw new WsException('websocket frame too large');
    if ($opcode >= 0x8 && (!$fin || $len > 125)) {
        throw new WsException('invalid websocket control frame');
    }
    $mask = $masked ? ws_read_exact($fp, 4) : '';
    if ($masked && $mask === false) return null;
    $payload = $len > 0 ? ws_read_exact($fp, $len) : '';
    if ($len > 0 && $payload === false) return null;
    if ($masked) {
        for ($i = 0; $i < $len; $i++) $payload[$i] = $payload[$i] ^ $mask[$i % 4];
    }
    return ['fin' => $fin, 'opcode' => $opcode, 'payload' => $payload];
}

/**
 * Read one complete message (handles fragmentation, answers pings).
 * @return string|null null on close frame / timeout / eof
 */
function ws_read_message($fp): ?string
{
    $msg = '';
    $fragmented = false;
    while (true) {
        $f = ws_read_frame($fp);
        if ($f === null) return null;
        switch ($f['opcode']) {
            case 0x9: // ping -> pong
                ws_send_pong($fp, $f['payload']);
                break;
            case 0xA: // pong, ignore
                break;
            case 0x8: // close
                return null;
            case 0x0: // continuation
                if (!$fragmented) {
                    throw new WsException('unexpected websocket continuation');
                }
                $msg .= $f['payload'];
                if (strlen($msg) > 2 * 1024 * 1024) {
                    throw new WsException('websocket message too large');
                }
                if ($f['fin']) return $msg;
                break;
            case 0x1: // text (or binary)
            case 0x2:
                if ($fragmented) {
                    throw new WsException('new websocket message before final continuation');
                }
                if ($f['fin']) return $f['payload'];
                $fragmented = true;
                $msg .= $f['payload'];
                if (strlen($msg) > 2 * 1024 * 1024) {
                    throw new WsException('websocket message too large');
                }
                break;
            default:
                return null;
        }
    }
}

function ws_send_pong($fp, string $payload): void
{
    $payload = substr($payload, 0, 125);
    $mask = random_bytes(4);
    $len = strlen($payload);
    $masked = '';
    for ($i = 0; $i < $len; $i++) $masked .= $payload[$i] ^ $mask[$i % 4];
    ws_write_all($fp, pack('CC', 0x8A, 0x80 | $len) . $mask . $masked);
}

function ws_send_close($fp): void
{
    $payload = "\x03\xe8";
    $mask = random_bytes(4);
    $masked = $payload[0] ^ $mask[0];
    $masked .= $payload[1] ^ $mask[1];
    try {
        ws_write_all($fp, pack('CC', 0x88, 0x80 | 2) . $mask . $masked);
    } catch (WsException $e) {
        // Best-effort close; the stream is closed locally below.
    }
    @fclose($fp);
}

/**
 * Send a JSON message and collect responses until $deadline or $match returns true.
 * $match(string $jsonDecoded): bool  -- return true to stop and return that msg.
 * @return array|null matched decoded message, or null on timeout
 */
function ws_rpc($fp, $send, callable $match, float $timeoutSec): ?array
{
    ws_send_text($fp, is_string($send) ? $send : json_c($send));
    $deadline = microtime(true) + $timeoutSec;
    while (microtime(true) < $deadline) {
        $left = $deadline - microtime(true);
        stream_set_timeout($fp, (int)$left, (int)(fmod($left, 1) * 1e6));
        $msg = ws_read_message($fp);
        if ($msg === null) return null;
        $dec = json_decode($msg, true);
        if (!is_array($dec)) continue;
        if ($match($dec)) return $dec;
    }
    return null;
}

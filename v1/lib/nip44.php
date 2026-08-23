<?php
/**
 * nip44.php -- NIP-44 v2 encrypt/decrypt, pure PHP.
 * conversation_key = HKDF-extract(salt="nip44-v2", IKM=ECDH-x)
 * message_keys     = HKDF-expand(PRK=conv, info=nonce, L=76)
 *                    -> chacha_key(32) || chacha_nonce(12) || hmac_key(32)
 * payload = base64( 0x02 || nonce(32) || chacha20(pad(pt)) || hmac(nonce||ct) )
 * Padding: [len u16][pt][zeros] to next padded bucket; extended 6-byte
 * prefix for len >= 65536. ChaCha20 RFC 8439, counter starts at 0.
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';
require_once __DIR__ . '/crypto.php';

// --------------------------------------------------------------------------
// HKDF (extract / expand), sha256
// --------------------------------------------------------------------------

function fm_hkdf_extract(string $ikm, string $salt): string
{
    return hash_hmac('sha256', $ikm, $salt, true);
}

function fm_hkdf_expand(string $prk, string $info, int $length): string
{
    $t = ''; $okm = ''; $i = 1;
    while (strlen($okm) < $length) {
        $t = hash_hmac('sha256', $t . $info . chr($i), $prk, true);
        $okm .= $t; $i++;
    }
    return substr($okm, 0, $length);
}

// --------------------------------------------------------------------------
// ChaCha20 (RFC 8439), pure PHP. Counter starts at 0 per NIP-44.
// --------------------------------------------------------------------------

function fm_rotl(int $v, int $c): int
{
    return ((($v << $c) | ($v >> (32 - $c))) & 0xffffffff);
}

function fm_chacha_quarter(array &$x, int $a, int $b, int $c, int $d): void
{
    $x[$a] = ($x[$a] + $x[$b]) & 0xffffffff; $x[$d] ^= $x[$a]; $x[$d] = fm_rotl($x[$d], 16);
    $x[$c] = ($x[$c] + $x[$d]) & 0xffffffff; $x[$b] ^= $x[$c]; $x[$b] = fm_rotl($x[$b], 12);
    $x[$a] = ($x[$a] + $x[$b]) & 0xffffffff; $x[$d] ^= $x[$a]; $x[$d] = fm_rotl($x[$d], 8);
    $x[$c] = ($x[$c] + $x[$d]) & 0xffffffff; $x[$b] ^= $x[$c]; $x[$b] = fm_rotl($x[$b], 7);
}

/** One 64-byte ChaCha20 block. $key 32 bytes, $nonce 12 bytes, $counter int. */
function fm_chacha20_block(string $key, string $nonce, int $counter): string
{
    $kw = array_values(unpack('V8', $key));
    $nw = array_values(unpack('V3', $nonce));
    $x = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        $kw[0], $kw[1], $kw[2], $kw[3], $kw[4], $kw[5], $kw[6], $kw[7],
        $counter & 0xffffffff, $nw[0], $nw[1], $nw[2],
    ];
    $orig = $x;
    for ($i = 0; $i < 10; $i++) {
        fm_chacha_quarter($x, 0, 4, 8, 12);
        fm_chacha_quarter($x, 1, 5, 9, 13);
        fm_chacha_quarter($x, 2, 6, 10, 14);
        fm_chacha_quarter($x, 3, 7, 11, 15);
        fm_chacha_quarter($x, 0, 5, 10, 15);
        fm_chacha_quarter($x, 1, 6, 11, 12);
        fm_chacha_quarter($x, 2, 7, 8, 13);
        fm_chacha_quarter($x, 3, 4, 9, 14);
    }
    $out = '';
    for ($i = 0; $i < 16; $i++) {
        $out .= pack('V', ($x[$i] + $orig[$i]) & 0xffffffff);
    }
    return $out;
}

function fm_chacha20_xor(string $key, string $nonce, string $data, int $counter = 0): string
{
    $out = ''; $len = strlen($data);
    for ($off = 0; $off < $len; $off += 64) {
        $ks = fm_chacha20_block($key, $nonce, $counter++);
        $chunk = substr($data, $off, 64);
        $n = strlen($chunk);
        for ($i = 0; $i < $n; $i++) {
            $out .= $chunk[$i] ^ $ks[$i];
        }
    }
    return $out;
}

// --------------------------------------------------------------------------
// NIP-44 v2
// --------------------------------------------------------------------------

const NIP44_MAX_PLAINTEXT = 1048576; // application cap: 1 MiB

function nip44_conversation_key(string $privhex_a, string $pubhex_b): string
{
    return fm_hkdf_extract(fm_ecdh_x($privhex_a, $pubhex_b), 'nip44-v2');
}

function nip44_calc_padded_len(int $unpadded): int
{
    if ($unpadded <= 32) return 32;
    $next_power = 1 << ((int)floor(log($unpadded - 1, 2)) + 1);
    $chunk = ($next_power <= 256) ? 32 : (int)($next_power / 8);
    return $chunk * (int)(floor(($unpadded - 1) / $chunk) + 1);
}

function nip44_pad(string $pt): string
{
    $len = strlen($pt);
    if ($len < 1 || $len > NIP44_MAX_PLAINTEXT) {
        throw new InvalidArgumentException('plaintext length outside application limits');
    }
    $padded_len = nip44_calc_padded_len($len);
    if ($len < 65536) {
        $prefix = pack('n', $len);
        $total = $padded_len + 2;
    } else {
        $prefix = "\x00\x00" . pack('N', $len);
        $total = $padded_len + 6;
    }
    return $prefix . str_pad($pt, $total - strlen($prefix), "\x00");
}

function nip44_unpad(string $padded): string
{
    $n = strlen($padded);
    if ($n < 34) throw new RuntimeException('nip44: padded too short');
    $prefix = substr($padded, 0, 2);
    if ($prefix === "\x00\x00") {
        if ($n < 38) throw new RuntimeException('nip44: bad extended prefix');
        $len = unpack('N', substr($padded, 2, 4))[1];
        if ($len < 65536) throw new RuntimeException('nip44: noncanonical extended prefix');
        $body_off = 6;
    } else {
        $len = unpack('n', $prefix)[1];
        $body_off = 2;
    }
    if ($len < 1 || $len > NIP44_MAX_PLAINTEXT || $len > $n - $body_off) {
        throw new RuntimeException('nip44: bad length prefix');
    }
    if ($n !== $body_off + nip44_calc_padded_len($len)) {
        throw new RuntimeException('nip44: noncanonical padding length');
    }
    $body = substr($padded, $body_off, $len);
    $rest = substr($padded, $body_off + $len);
    if (trim($rest, "\x00") !== '') throw new RuntimeException('nip44: nonzero padding');
    return $body;
}

/**
 * Encrypt to pubkey_b using our private key. $nonce32 optional (tests).
 * Returns payload string ("2" + base64...), as in the spec.
 */
function nip44_encrypt(string $privhex_a, string $pubhex_b, string $pt, ?string $nonce32 = null): string
{
    $ck = nip44_conversation_key($privhex_a, $pubhex_b);
    $nonce = $nonce32 === null ? random_bytes(32) : h2b($nonce32);
    if (strlen($nonce) !== 32) throw new InvalidArgumentException('nonce len');
    $keys = fm_hkdf_expand($ck, $nonce, 76);
    $ckey = substr($keys, 0, 32); $cnonce = substr($keys, 32, 12); $hkey = substr($keys, 44, 32);
    $ct = fm_chacha20_xor($ckey, $cnonce, nip44_pad($pt));
    $mac = hash_hmac('sha256', $nonce . $ct, $hkey, true);
    return base64_encode(chr(2) . $nonce . $ct . $mac);   // RFC 4648, padded
}

function nip44_decrypt(string $privhex_a, string $pubhex_b, string $payload): string
{
    $maxRaw = 65 + 6 + nip44_calc_padded_len(NIP44_MAX_PLAINTEXT);
    if (strlen($payload) > (int)ceil($maxRaw / 3) * 4) {
        throw new RuntimeException('nip44: payload exceeds application limit');
    }
    $bin = base64_decode($payload, true);
    if ($bin === false || strlen($bin) < 99 || strlen($bin) > $maxRaw) {
        throw new RuntimeException('nip44: bad payload length');
    }
    if (ord($bin[0]) !== 2) throw new RuntimeException('nip44: unsupported version');
    $nonce = substr($bin, 1, 32);
    $ct = substr($bin, 33, -32);
    $mac = substr($bin, -32);
    $ck = nip44_conversation_key($privhex_a, $pubhex_b);
    $keys = fm_hkdf_expand($ck, $nonce, 76);
    $ckey = substr($keys, 0, 32); $cnonce = substr($keys, 32, 12); $hkey = substr($keys, 44, 32);
    $expect = hash_hmac('sha256', $nonce . $ct, $hkey, true);
    if (!hash_equals($expect, $mac)) throw new RuntimeException('nip44: mac mismatch');
    return nip44_unpad(fm_chacha20_xor($ckey, $cnonce, $ct));
}

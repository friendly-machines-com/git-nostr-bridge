<?php
/**
 * crypto.php -- BIP-340 schnorr (secp256k1 over BCMath), nostr event ids,
 * bech32 (npub/nsec). Pure PHP.
 *
 * NUMERIC LAYER: BCMath decimal strings. NOT GMP -- the production host
 * (DreamHost iad1-shared-e1-15) has bcmath but not gmp (checked
 * 2026-08-20). One implementation, identical results everywhere.
 *
 * All values are normalized non-negative decimal strings EXCEPT where a
 * subtraction feeds straight back through fm_mod (which re-normalizes).
 * Points are Jacobian arrays ['x'=>string,'y'=>string,'z'=>string];
 * z == '0' is the point at infinity.
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';

if (!extension_loaded('bcmath')) {
    throw new RuntimeException('ext-bcmath required (server has it; gmp not needed)');
}

// --------------------------------------------------------------------------
// decimal-string bignum primitives (thin, always-normalizing)
// --------------------------------------------------------------------------

function fm_n(string $s): string
{
    $s = ltrim($s, '+');
    if ($s === '' || $s === '-') return '0';
    if ($s[0] !== '-') return ltrim($s, '0') === '' ? '0' : $s;
    return '-' . ltrim(substr($s, 1), '0');   // '-0' impossible after below
}

function fm_add(string $a, string $b): string { return bcadd($a, $b); }
function fm_sub(string $a, string $b): string { return bcsub($a, $b); }
function fm_mul(string $a, string $b): string { return bcmul($a, $b); }
function fm_cmp(string $a, string $b): int    { return bccomp($a, $b); }
function fm_pow(string $a, int $e): string    { return bcpow($a, (string)$e); }

/** Always non-negative modulus (bcmod keeps dividend sign). */
function fm_mod(string $a, string $m): string
{
    $r = bcmod($a, $m);
    if ($r[0] === '-') $r = bcadd($r, $m);
    return $r === '' ? '0' : $r;
}

/** Modular exponentiation, non-negative result. */
function fm_powmod(string $a, string $e, string $m): string
{
    return fm_mod(bcpowmod(fm_mod($a, $m), $e, $m), $m);
}

function fm_hex_dec(string $hex): string
{
    $hex = strtolower($hex);
    if (!preg_match('/^[0-9a-f]+$/', $hex)) throw new InvalidArgumentException('bad hex');
    if ($hex === '0' || $hex === '') return '0';
    $d = '0';
    // 7 hex chars = 28 bits per chunk, exact in bcmath
    $chunks = str_split(str_pad($hex, (int)ceil(strlen($hex) / 7) * 7, '0', STR_PAD_LEFT), 7);
    foreach ($chunks as $c) {
        $d = bcadd(bcmul($d, '268435456'), (string)hexdec($c)); // 2^28
    }
    return fm_n($d);
}

function fm_dec_hex(string $d): string
{
    if ($d === '0' || $d === '' ) return '0';
    $d = fm_n($d);
    $hex = '';
    while (fm_cmp($d, '0') > 0) {
        $hex = dechex((int)bcmod($d, '16')) . $hex;
        $d = bcdiv($d, '16', 0);
    }
    return $hex === '' ? '0' : $hex;
}

/** decimal string -> 32-byte binary (big-endian), zero-padded */
function d_to32(string $d): string
{
    $h = str_pad(fm_dec_hex(fm_mod($d, '115792089237316195423570985008687907853269984665640564039457584007913129639936')), 64, '0', STR_PAD_LEFT);
    return hex2bin($h);
}

/** 32-byte binary -> decimal string */
function d_from32(string $b): string
{
    if (strlen($b) !== 32) throw new InvalidArgumentException('want 32 bytes');
    return fm_hex_dec(bin2hex($b));
}

/** decimal string -> binary string ('1'/'0' chars), no leading zeros */
function fm_dec_bin(string $d): string
{
    if (fm_cmp($d, '0') === 0) return '0';
    $bits = '';
    while (fm_cmp($d, '0') > 0) {
        $bits = (bcmod($d, '2') === '1' ? '1' : '0') . $bits;
        $d = bcdiv($d, '2', 0);
    }
    return $bits;
}

/** XOR two 32-byte binaries -> decimal string (BIP-340 aux). */
function fm_xor_dec(string $a, string $b): string
{
    if (strlen($a) !== 32 || strlen($b) !== 32) throw new InvalidArgumentException('xor len');
    $out = '';
    for ($i = 0; $i < 32; $i++) $out .= $a[$i] ^ $b[$i];
    return fm_hex_dec(bin2hex($out));
}

// --------------------------------------------------------------------------
// curve constants (decimal, lazy)
// --------------------------------------------------------------------------

function fm_c(string $name): string
{
    static $cache = [];
    if (!isset($cache[$name])) {
        $cache = [
            'P'  => fm_hex_dec('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
            'N'  => fm_hex_dec('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
            'Gx' => fm_hex_dec('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
            'Gy' => fm_hex_dec('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
        ] + $cache;
    }
    return $cache[$name];
}

function fm_pt_inf(): array { return ['x' => '0', 'y' => '1', 'z' => '0']; }

function fm_is_inf(array $p): bool { return fm_cmp($p['z'], '0') === 0; }

function fm_pt_dbl(array $p): array
{
    if (fm_is_inf($p) || fm_cmp($p['y'], '0') === 0) return fm_pt_inf();
    $P = fm_c('P');
    $X = $p['x']; $Y = $p['y']; $Z = $p['z'];
    $A = fm_mod(fm_pow($X, 2), $P);
    $B = fm_mod(fm_pow($Y, 2), $P);
    $C = fm_mod(fm_pow($B, 2), $P);
    $t = fm_mod(fm_pow(fm_add($X, $B), 2), $P);
    $D = fm_mod(fm_mul('2', fm_sub($t, fm_add($A, $C))), $P);
    $E = fm_mod(fm_mul('3', $A), $P);
    $F = fm_mod(fm_pow($E, 2), $P);
    $X3 = fm_mod(fm_sub($F, fm_mul('2', $D)), $P);
    $Y3 = fm_mod(fm_sub(fm_mul($E, fm_sub($D, $X3)), fm_mul('8', $C)), $P);
    $Z3 = fm_mod(fm_mul('2', fm_mul($Y, $Z)), $P);
    return ['x' => $X3, 'y' => $Y3, 'z' => $Z3];
}

function fm_pt_add(array $p, array $q): array
{
    if (fm_is_inf($p)) return $q;
    if (fm_is_inf($q)) return $p;
    $P = fm_c('P');
    $Z1Z1 = fm_mod(fm_pow($p['z'], 2), $P);
    $Z2Z2 = fm_mod(fm_pow($q['z'], 2), $P);
    $U1 = fm_mod(fm_mul($p['x'], $Z2Z2), $P);
    $U2 = fm_mod(fm_mul($q['x'], $Z1Z1), $P);
    $S1 = fm_mod(fm_mul(fm_mul($p['y'], $q['z']), $Z2Z2), $P);
    $S2 = fm_mod(fm_mul(fm_mul($q['y'], $p['z']), $Z1Z1), $P);
    if (fm_cmp($U1, $U2) === 0) {
        if (fm_cmp($S1, $S2) === 0) return fm_pt_dbl($p);
        return fm_pt_inf();
    }
    $H   = fm_mod(fm_sub($U2, $U1), $P);
    $r   = fm_mod(fm_sub($S2, $S1), $P);
    $HH  = fm_mod(fm_pow($H, 2), $P);
    $HHH = fm_mod(fm_mul($H, $HH), $P);
    $V   = fm_mod(fm_mul($U1, $HH), $P);
    $X3  = fm_mod(fm_sub(fm_sub(fm_pow($r, 2), $HHH), fm_mul('2', $V)), $P);
    $Y3  = fm_mod(fm_sub(fm_mul($r, fm_sub($V, $X3)), fm_mul($S1, $HHH)), $P);
    $Z3  = fm_mod(fm_mul(fm_mul($p['z'], $q['z']), $H), $P);
    return ['x' => $X3, 'y' => $Y3, 'z' => $Z3];
}

/** Scalar mult: double-and-add, MSB first. $k decimal string. */
function fm_pt_mul(string $k, array $p): array
{
    $k = fm_mod($k, fm_c('N'));
    if (fm_cmp($k, '0') === 0) return fm_pt_inf();
    $bits = fm_dec_bin($k);
    $r = fm_pt_inf(); $a = $p;
    for ($i = 0, $n = strlen($bits); $i < $n; $i++) {
        $r = fm_pt_dbl($r);
        if ($bits[$i] === '1') $r = fm_pt_add($r, $a);
    }
    return $r;
}

/** @return array{x:string,y:string}|null affine, null if infinity */
function fm_pt_affine(array $p): ?array
{
    if (fm_is_inf($p)) return null;
    $P = fm_c('P');
    $zi   = fm_powmod($p['z'], fm_sub($P, '2'), $P);   // z^-1 mod P
    $zi2  = fm_mod(fm_pow($zi, 2), $P);
    return [
        'x' => fm_mod(fm_mul($p['x'], $zi2), $P),
        'y' => fm_mod(fm_mul($p['y'], fm_mul($zi2, $zi)), $P),
    ];
}

function fm_generator(): array
{
    static $g = null;
    if ($g === null) $g = ['x' => fm_c('Gx'), 'y' => fm_c('Gy'), 'z' => '1'];
    return $g;
}

// --------------------------------------------------------------------------
// BIP-340
// --------------------------------------------------------------------------

function fm_tagged_hash(string $tag, string $msg): string
{
    $t = hash('sha256', $tag, true);
    return hash('sha256', $t . $t . $msg, true);
}

/** @return array{x:string,y:string}|null even-y point with given x, or null */
function fm_lift_x(string $x32): ?array
{
    if (strlen($x32) !== 32) return null;
    $P = fm_c('P');
    $x = d_from32($x32);
    if (fm_cmp($x, '0') < 0 || fm_cmp($x, $P) >= 0) return null;
    $c = fm_mod(fm_add(fm_pow($x, 3), '7'), $P);
    $exp = bcdiv(bcadd($P, '1'), '4', 0);
    $y = fm_powmod($c, $exp, $P);
    if (fm_cmp(fm_mod(fm_pow($y, 2), $P), $c) !== 0) return null; // not QR
    if (bcmod($y, '2') === '1') $y = fm_sub($P, $y);
    return ['x' => $x, 'y' => $y];
}

function fm_pubkey_hex(string $privhex): string
{
    $pt = fm_pt_affine(fm_pt_mul(fm_hex_dec($privhex), fm_generator()));
    if ($pt === null) throw new InvalidArgumentException('privkey 0');
    return bin2hex(d_to32($pt['x']));
}

/** Generate a uniformly random valid secp256k1 private key. */
function fm_private_key_generate(): string
{
    do {
        $hex = random_hex(32);
        $d = fm_hex_dec($hex);
    } while (fm_cmp($d, '0') <= 0 || fm_cmp($d, fm_c('N')) >= 0);
    return $hex;
}

/** ECDH x-coordinate (NIP-44). */
function fm_ecdh_x(string $privhex, string $pubhex): string
{
    if (!is_hex64($pubhex)) throw new InvalidArgumentException('pubkey hex64');
    $pt = fm_lift_x(hex2bin($pubhex));
    if ($pt === null) throw new InvalidArgumentException('pubkey not on curve');
    $shared = fm_pt_affine(fm_pt_mul(fm_hex_dec($privhex),
        ['x' => $pt['x'], 'y' => $pt['y'], 'z' => '1']));
    if ($shared === null) throw new RuntimeException('ecdh infinity');
    return d_to32($shared['x']);
}

function fm_schnorr_sign(string $privhex, string $msg32, ?string $aux32 = null): string
{
    if (!is_hex64($privhex)) throw new InvalidArgumentException('privhex');
    $d = fm_hex_dec($privhex);
    $N = fm_c('N');
    if (fm_cmp($d, '0') <= 0 || fm_cmp($d, $N) >= 0) throw new InvalidArgumentException('privkey range');
    $msg = hex2bin($msg32);
    if ($msg === false) throw new InvalidArgumentException('msg hex');

    $Pp = fm_pt_affine(fm_pt_mul($d, fm_generator()));
    $px = d_to32($Pp['x']);
    $dprime = (bcmod($Pp['y'], '2') === '0') ? $d : fm_sub($N, $d);

    $aux = $aux32 === null ? random_bytes(32) : hex2bin($aux32);
    if (strlen($aux) !== 32) throw new InvalidArgumentException('aux len');
    $t = fm_xor_dec(d_to32($dprime), fm_tagged_hash('BIP0340/aux', $aux));

    $rand = fm_tagged_hash('BIP0340/nonce', d_to32($t) . $px . $msg);
    $k0 = fm_mod(fm_hex_dec(bin2hex($rand)), $N);
    if (fm_cmp($k0, '0') === 0) throw new RuntimeException('zero nonce (astronomically unlikely)');
    $R = fm_pt_affine(fm_pt_mul($k0, fm_generator()));
    $rx = d_to32($R['x']);
    $k = (bcmod($R['y'], '2') === '0') ? $k0 : fm_sub($N, $k0);

    $e = fm_mod(fm_hex_dec(bin2hex(fm_tagged_hash('BIP0340/challenge', $rx . $px . $msg))), $N);
    $s = fm_mod(fm_add($k, fm_mul($e, $dprime)), $N);
    return bin2hex($rx . d_to32($s));
}

function fm_schnorr_verify(string $pubhex, string $msgHex, string $sighex): bool
{
    // msg may be any byte length (BIP-340); nostr always uses 32
    if (!is_hex64($pubhex)
        || !preg_match('/^([0-9a-f]{2})*$/', $msgHex)
        || !preg_match('/^[0-9a-f]{128}$/', $sighex)) return false;
    $N = fm_c('N');
    $Ppt = fm_lift_x(hex2bin($pubhex));
    if ($Ppt === null) return false;
    $sig = hex2bin($sighex);
    $rx = substr($sig, 0, 32); $s = d_from32(substr($sig, 32, 32));
    if (fm_cmp($s, '0') < 0 || fm_cmp($s, $N) >= 0) return false;
    $msg = hex2bin($msgHex);
    $e = fm_mod(fm_hex_dec(bin2hex(fm_tagged_hash('BIP0340/challenge',
        $rx . hex2bin($pubhex) . $msg))), $N);
    // R = s*G - e*P  ==  s*G + (n-e)*P
    $sg = fm_pt_mul($s, fm_generator());
    $ep = fm_pt_mul(fm_sub($N, $e), ['x' => $Ppt['x'], 'y' => $Ppt['y'], 'z' => '1']);
    $R = fm_pt_affine(fm_pt_add($sg, $ep));
    if ($R === null) return false;
    if (bcmod($R['y'], '2') === '1') return false;
    return d_to32($R['x']) === $rx;
}

// --------------------------------------------------------------------------
// nostr events (NIP-01)
// --------------------------------------------------------------------------

function fm_event_id(array $ev): string
{
    $serialized = json_c([
        0,
        $ev['pubkey'],
        (int)$ev['created_at'],
        (int)$ev['kind'],
        array_values(array_map('array_values', $ev['tags'])),
        (string)$ev['content'],
    ]);
    return hash('sha256', $serialized);
}

function fm_event_verify(array $ev): bool
{
    if (!isset($ev['id'], $ev['sig'], $ev['pubkey'], $ev['created_at'],
               $ev['kind'], $ev['tags'], $ev['content'])
        || !is_string($ev['id']) || !is_string($ev['sig']) || !is_string($ev['pubkey'])
        || !is_int($ev['created_at']) || !is_int($ev['kind'])
        || !is_array($ev['tags']) || !is_string($ev['content'])
        || !preg_match('/^[0-9a-f]{64}$/', $ev['id'])
        || !preg_match('/^[0-9a-f]{64}$/', $ev['pubkey'])
        || $ev['kind'] < 0 || $ev['kind'] > 65535
        || !preg_match('/^[0-9a-f]{128}$/', $ev['sig'])) {
        return false;
    }
    foreach ($ev['tags'] as $tag) {
        if (!is_array($tag) || !$tag) return false;
        foreach ($tag as $value) if (!is_string($value)) return false;
    }
    try {
        return hash_equals($ev['id'], fm_event_id($ev))
            && fm_schnorr_verify($ev['pubkey'], $ev['id'], $ev['sig']);
    } catch (Throwable $e) {
        return false;
    }
}

/** Return a signed copy of an event array (PHP arrays are passed by value). */
function fm_event_sign(array $ev, string $privhex): array
{
    $ev['id']  = fm_event_id($ev);
    $ev['sig'] = fm_schnorr_sign($privhex, $ev['id']);
    return $ev;
}

// --------------------------------------------------------------------------
// bech32 (NIP-19 npub/nsec)
// --------------------------------------------------------------------------

const FM_BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function fm_bech32_polymod(array $values): int
{
    $GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    $chk = 1;
    foreach ($values as $v) {
        $b = $chk >> 25;
        $chk = (($chk & 0x1ffffff) << 5) ^ $v;
        for ($i = 0; $i < 5; $i++) {
            if (($b >> $i) & 1) $chk ^= $GEN[$i];
        }
    }
    return $chk;
}

function fm_bech32_hrp_expand(string $hrp): array
{
    $r = [];
    for ($i = 0, $n = strlen($hrp); $i < $n; $i++) $r[] = ord($hrp[$i]) >> 5;
    $r[] = 0;
    for ($i = 0, $n = strlen($hrp); $i < $n; $i++) $r[] = ord($hrp[$i]) & 31;
    return $r;
}

/** @param int[] $data 5-bit values */
function fm_bech32_encode(string $hrp, array $data): string
{
    // BIP-173: checksum = polymod(hrp_expand ++ data ++ [0]*6) ^ 1
    $values = array_merge(fm_bech32_hrp_expand($hrp), $data, [0, 0, 0, 0, 0, 0]);
    $polymod = fm_bech32_polymod($values) ^ 1;
    $chk = [];
    for ($i = 0; $i < 6; $i++) $chk[] = ($polymod >> 5 * (5 - $i)) & 31;
    $all = array_merge($data, $chk);
    $out = $hrp . '1';
    foreach ($all as $v) $out .= FM_BECH32_CHARSET[$v];
    return $out;
}

/** @return int[]|null 5-bit data values, or null if invalid */
function fm_bech32_decode(string $str, string $expectHrp): ?array
{
    if (strlen($str) > 4096) return null;
    if (preg_match('/[^0-9a-z]+/', $str)) return null;
    $pos = strrpos($str, '1');
    if ($pos === false || $pos < 1 || $pos + 7 > strlen($str)) return null;
    $hrp = substr($str, 0, $pos);
    if ($hrp !== $expectHrp) return null;
    $data = [];
    for ($i = $pos + 1, $n = strlen($str); $i < $n; $i++) {
        $d = strpos(FM_BECH32_CHARSET, $str[$i]);
        if ($d === false) return null;
        $data[] = $d;
    }
    $values = array_merge(fm_bech32_hrp_expand($hrp), $data);
    if (fm_bech32_polymod($values) !== 1) return null;
    return array_slice($data, 0, -6);
}

/** convert bits (8<->5); strict when not padding */
function fm_convert_bits(array $data, int $from, int $to, bool $pad): array
{
    $acc = 0; $bits = 0; $ret = [];
    $maxv = (1 << $to) - 1;
    foreach ($data as $value) {
        if ($value < 0 || ($value >> $from) !== 0) return [];
        $acc = ($acc << $from) | $value;
        $bits += $from;
        while ($bits >= $to) {
            $bits -= $to;
            $ret[] = ($acc >> $bits) & $maxv;
        }
    }
    if ($pad) {
        if ($bits) $ret[] = ($acc << ($to - $bits)) & $maxv;
    } elseif ($bits >= $from || (($acc << ($to - $bits)) & $maxv)) {
        return [];
    }
    return $ret;
}

function fm_npub_encode(string $pubhex): string
{
    $data = fm_convert_bits(array_values(unpack('C*', hex2bin($pubhex)) ?: []), 8, 5, true);
    return fm_bech32_encode('npub', $data);
}

function fm_npub_decode(string $npub): ?string
{
    $data = fm_bech32_decode($npub, 'npub');
    if ($data === null) return null;
    $bytes = fm_convert_bits($data, 5, 8, false);
    if (count($bytes) !== 32) return null;
    return bin2hex(pack('C*', ...$bytes));
}

function fm_nsec_encode(string $privhex): string
{
    $data = fm_convert_bits(array_values(unpack('C*', hex2bin($privhex)) ?: []), 8, 5, true);
    return fm_bech32_encode('nsec', $data);
}

function fm_nsec_decode(string $nsec): ?string
{
    $data = fm_bech32_decode($nsec, 'nsec');
    if ($data === null) return null;
    $bytes = fm_convert_bits($data, 5, 8, false);
    if (count($bytes) !== 32) return null;
    return bin2hex(pack('C*', ...$bytes));
}

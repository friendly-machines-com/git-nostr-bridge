<?php
/**
 * tests/run.php -- offline test harness. CLI only. No network.
 * Usage: php tests/run.php
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') exit(1);
require_once __DIR__ . '/../lib/util.php';
require_once __DIR__ . '/../lib/crypto.php';
require_once __DIR__ . '/../lib/nip44.php';
require_once __DIR__ . '/../lib/nip46.php';

$pass = 0; $fail = 0; $failures = [];
function ok(bool $cond, string $name): void
{
    global $pass, $fail, $failures;
    if ($cond) { $pass++; echo "  ok  $name\n"; }
    else { $fail++; $failures[] = $name; echo "FAIL  $name\n"; }
}
function eq($a, $b, string $name): void
{
    ok($a === $b, $name . ($a === $b ? '' : ' (got ' . var_export($a, true) . ')'));
}

echo "== BIP-340 schnorr (official vectors) ==\n";
$vectors = [
    // [seckey|null, pubkey, aux, msg, sig, expectedVerify]
    ['0000000000000000000000000000000000000000000000000000000000000003', 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9', '0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000000', 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0', true],
    ['B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF', 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', '0000000000000000000000000000000000000000000000000000000000000001', '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A', true],
    ['C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9', 'DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8', 'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906', '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C', '5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7', true],
    [null, '25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517', 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', '7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3', true],
    [null, 'EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34', '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769', '69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B', false], // pk not on curve
    ['0340034003400340034003400340034003400340034003400340034003400340', '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117', '0000000000000000000000000000000000000000000000000000000000000000', '', '71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63', true], // empty msg
    ['0340034003400340034003400340034003400340034003400340034003400340', '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117', '0000000000000000000000000000000000000000000000000000000000000000', '11', '08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF', true],
    ['0340034003400340034003400340034003400340034003400340034003400340', '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117', '0000000000000000000000000000000000000000000000000000000000000000', '0102030405060708090A0B0C0D0E0F1011', '5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5', true],
];
foreach ($vectors as $i => $v) {
    [$sec, $pub, $aux, $msg, $sig, $exp] = $v;
    ok(fm_schnorr_verify(strtolower($pub), strtolower($msg), strtolower($sig)) === $exp,
       "verify vector $i (expect " . ($exp ? 'TRUE' : 'FALSE') . ')');
    if ($sec !== null) {
        eq(fm_pubkey_hex($sec), strtolower($pub), "vector $i pubkey derivation");
        eq(fm_schnorr_sign($sec, strtolower($msg), strtolower($aux)), strtolower($sig), "vector $i deterministic sign");
    }
}
// roundtrip
$sk = random_hex(32); $pk = fm_pubkey_hex($sk); $m = random_hex(32);
ok(fm_schnorr_verify($pk, $m, fm_schnorr_sign($sk, $m)), 'schnorr sign/verify roundtrip');
ok(!fm_schnorr_verify($pk, random_hex(32), fm_schnorr_sign($sk, $m)), 'schnorr wrong msg rejected');
$generatedKey = fm_private_key_generate();
ok(is_hex64($generatedKey) && fm_pubkey_hex($generatedKey) !== '',
   'valid random private key generated');

echo "== bech32 / NIP-19 ==\n";
$npub = fm_npub_encode('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
eq($npub, 'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6', 'npub NIP-19 vector');
eq(fm_npub_decode($npub), '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d', 'npub decode roundtrip');
$sk2 = random_hex(32);
eq(fm_nsec_decode(fm_nsec_encode($sk2)), $sk2, 'nsec roundtrip');
ok(fm_npub_decode($npub . 'q') === null, 'bech32 bad checksum rejected');

echo "== ChaCha20 (RFC 8439 §2.3.2) ==\n";
$ks = fm_chacha20_block(
    h2b('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
    h2b('000000090000004a00000000'), 1);
eq(b2h(substr($ks, 0, 16)), '10f1e7e4d13b5915500fdd1fa32071c4', 'chacha20 block prefix');
eq(strlen($ks), 64, 'chacha20 block length');

echo "== NIP-44 v2 ==\n";
$ck = nip44_conversation_key(
    '0000000000000000000000000000000000000000000000000000000000000001',
    fm_pubkey_hex('0000000000000000000000000000000000000000000000000000000000000002'));
eq(b2h($ck), 'c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d', 'conversation key vector');
$payload = nip44_encrypt(
    '0000000000000000000000000000000000000000000000000000000000000001',
    fm_pubkey_hex('0000000000000000000000000000000000000000000000000000000000000002'),
    'a',
    '0000000000000000000000000000000000000000000000000000000000000001');
eq($payload, 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb', 'encrypt vector "a"');
$sec1 = '0000000000000000000000000000000000000000000000000000000000000001';
$sec2 = '0000000000000000000000000000000000000000000000000000000000000002';
$p12 = fm_pubkey_hex($sec2); $p21 = fm_pubkey_hex($sec1);
$pt = "hello bridge — unicode ✓ 'quotes' <tags> & such";
$enc = nip44_encrypt($sec1, $p12, $pt);
eq(nip44_decrypt($sec2, $p21, $enc), $pt, 'decrypt from other side (ECDH symmetry)');
foreach ([1, 32, 33, 100, 1024, 2049] as $L) {
    $s = str_repeat('x', $L);
    $okr = nip44_decrypt($sec2, $p21, nip44_encrypt($sec1, $p12, $s)) === $s;
    ok($okr, "roundtrip len $L");
}
eq(nip44_calc_padded_len(1), 32, 'pad bucket 1');
eq(nip44_calc_padded_len(33), 64, 'pad bucket 33');
eq(nip44_calc_padded_len(1024), 1024, 'pad bucket 1024');
eq(nip44_calc_padded_len(65535), 65536, 'pad bucket 65535');
eq(nip44_calc_padded_len(65536), 65536, 'pad bucket 65536');
eq(nip44_calc_padded_len(65537), 81920, 'pad bucket 65537');
$mid = substr(nip44_encrypt($sec1, $p12, 'a'), 40, 1);
$bad = substr_replace(nip44_encrypt($sec1, $p12, 'a'), ($mid === 'A' ? 'B' : 'A'), 40, 1);
try { nip44_decrypt($sec2, $p21, $bad); ok(false, 'tampered mac rejected'); }
catch (RuntimeException $e) { ok(true, 'tampered mac rejected'); }
try { nip44_unpad(pack('n', 1) . 'a' . str_repeat("\x00", 32)); ok(false, 'noncanonical padding rejected'); }
catch (RuntimeException $e) { ok(true, 'noncanonical padding rejected'); }

echo "== nostr events ==\n";
$ev = [
    'pubkey' => $pk, 'created_at' => 1730000000, 'kind' => 1,
    'tags' => [['e', 'aa'.str_repeat('b', 62)], ['p', $pk]],
    'content' => "hello / world \\ \"quote\" ünïcödé",
];
$signed = fm_event_sign($ev, $sk);
ok(is_hex64($signed['id']) && preg_match('/^[0-9a-f]{128}$/', $signed['sig']), 'event id/sig produced');
ok(fm_event_verify($signed), 'event verify ok');
$t2 = $signed; $t2['content'] .= 'x';
ok(!fm_event_verify($t2), 'tampered event rejected');
$uppercaseEvent = $signed;
$uppercaseEvent['pubkey'] = strtoupper($uppercaseEvent['pubkey']);
$uppercaseEvent['id'] = fm_event_id($uppercaseEvent);
$uppercaseEvent['sig'] = fm_schnorr_sign($sk, $uppercaseEvent['id']);
ok(!fm_event_verify($uppercaseEvent), 'uppercase wire pubkey rejected');
$invalidKindTemplate = $ev;
$invalidKindTemplate['kind'] = 65536;
$invalidKindEvent = fm_event_sign($invalidKindTemplate, $sk);
ok(!fm_event_verify($invalidKindEvent), 'out-of-range event kind rejected');
ok(!fm_event_verify(['id' => str_repeat('a', 64), 'sig' => str_repeat('b', 128),
    'pubkey' => $pk]), 'malformed event safely rejected');
ok(
    relay_event_matches_filter($signed, [
        'kinds' => [1],
        'authors' => [$signed['pubkey']],
        '#p' => [$pk],
    ])
    && !relay_event_matches_filter($signed, ['kinds' => [1621]])
    && !relay_event_matches_filter($signed, ['#p' => [str_repeat('f', 64)]]),
    'relay results must satisfy the exact local filter'
);

echo "== WebSocket framing ==\n";
$frameStream = fopen('php://memory', 'r+');
fwrite($frameStream, pack('CC', 0x01, 3) . 'hel'
    . pack('CC', 0x80, 2) . 'lo');
rewind($frameStream);
eq(ws_read_message($frameStream), 'hello', 'fragmented server message reassembled');
$badContinuation = fopen('php://memory', 'r+');
fwrite($badContinuation, pack('CC', 0x80, 1) . 'x');
rewind($badContinuation);
try {
    ws_read_message($badContinuation);
    ok(false, 'orphan continuation rejected');
} catch (WsException $e) {
    ok(true, 'orphan continuation rejected');
}
$badControl = fopen('php://memory', 'r+');
fwrite($badControl, pack('CCn', 0x09, 126, 126) . str_repeat('x', 126));
rewind($badControl);
try {
    ws_read_frame($badControl);
    ok(false, 'oversized control frame rejected');
} catch (WsException $e) {
    ok(true, 'oversized control frame rejected');
}

echo "== NIP-46 signed-event validation ==\n";
ok(
    relay_url_valid('wss://relay.example/path?x=1')
    && !relay_url_valid("wss://relay.example/\r\nInjected: yes")
    && !relay_url_valid('wss://relay.example/path#fragment')
    && !relay_url_valid('ws://relay.example'),
    'server relay URLs require clean fragment-free wss endpoints'
);
eq(
    relay_url_set([
        'wss://z.example',
        'wss://a.example',
        'wss://z.example',
    ], 2),
    ['wss://a.example', 'wss://z.example'],
    'relay fan-out cap applies after canonical set reduction'
);
ok(
    ws_ip_is_public('8.8.8.8')
    && !ws_ip_is_public('127.0.0.1')
    && !ws_ip_is_public('10.1.2.3')
    && ws_public_ipv4_set('127.0.0.1') === [],
    'websocket egress accepts only public IPv4 destinations'
);
eq(nip46_bunker_relays(
    'relay=wss%3A%2F%2Fone.example&relay=wss%3A%2F%2Ftwo.example'),
   ['wss://one.example', 'wss://two.example'],
   'repeated bunker relay parameters preserved');
eq(nip46_bunker_relays(
    'relay=wss%3A%2F%2Ftwo.example&relay=wss%3A%2F%2Fone.example'
    . '&relay=wss%3A%2F%2Ftwo.example'),
   ['wss://one.example', 'wss://two.example'],
   'bunker relays are a set, not query-string order');
eq(
    nip46_auth_challenge_url('https://signer.example/authorize?request=abc'),
    'https://signer.example/authorize?request=abc',
    'NIP-46 HTTPS authorization challenge accepted'
);
ok(
    nip46_auth_challenge_url('http://signer.example/authorize') === null
    && nip46_auth_challenge_url('https://user@signer.example/authorize') === null
    && nip46_auth_challenge_url("https://signer.example/\nheader") === null,
    'unsafe NIP-46 authorization challenges rejected'
);
eq(
    nip46_state_auth_url(
        NIP46_AUTH_STATE_PREFIX
        . 'https://signer.example/authorize?request=abc'
    ),
    'https://signer.example/authorize?request=abc',
    'stored NIP-46 authorization challenge roundtrips'
);
$remoteSec = random_hex(32);
$remotePk = fm_pubkey_hex($remoteSec);
$request = ['kind' => 1111, 'content' => 'remote', 'tags' => [['p', $pk]],
            'created_at' => 1730000001];
$remoteSigned = fm_event_sign($request + ['pubkey' => $remotePk], $remoteSec);
ok(nip46_signed_event_matches($remoteSigned, $request, $remotePk),
   'matching signer response accepted');
$wrong = $request; $wrong['content'] = 'different';
ok(!nip46_signed_event_matches($remoteSigned, $wrong, $remotePk),
   'mismatched signer response rejected');
$remoteSigned['internal'] = 'unsigned';
ok(!array_key_exists('internal', nip46_wire_event($remoteSigned)),
   'unsigned extension fields stripped');

echo "== NIP-46 RPC socket exchange ==\n";
function test_read_client_ws_text($fp): ?string
{
    $header = ws_read_exact($fp, 2);
    if ($header === false) return null;
    $length = ord($header[1]) & 0x7f;
    if ($length === 126) {
        $extended = ws_read_exact($fp, 2);
        if ($extended === false) return null;
        $length = unpack('n', $extended)[1];
    } elseif ($length === 127) {
        $extended = ws_read_exact($fp, 8);
        if ($extended === false || substr($extended, 0, 4) !== "\0\0\0\0") {
            return null;
        }
        $length = unpack('N', substr($extended, 4))[1];
    }
    if ((ord($header[1]) & 0x80) === 0) return null;
    $mask = ws_read_exact($fp, 4);
    $payload = ws_read_exact($fp, $length);
    if ($mask === false || $payload === false) return null;
    for ($i = 0; $i < $length; $i++) {
        $payload[$i] = $payload[$i] ^ $mask[$i % 4];
    }
    return $payload;
}
function test_send_server_ws_text($fp, string $payload): void
{
    $length = strlen($payload);
    if ($length < 126) {
        $header = pack('CC', 0x81, $length);
    } elseif ($length < 65536) {
        $header = pack('CCn', 0x81, 126, $length);
    } else {
        $header = pack('CCNN', 0x81, 127, 0, $length);
    }
    ws_write_all($fp, $header . $payload);
}

$rpcClientSec = fm_private_key_generate();
$rpcClientPk = fm_pubkey_hex($rpcClientSec);
$rpcSignerSec = fm_private_key_generate();
$rpcSignerPk = fm_pubkey_hex($rpcSignerSec);
$rpcUserPk = fm_pubkey_hex(fm_private_key_generate());
$rpcChildPid = null;
$GLOBALS['__fm_test_log'] = sys_get_temp_dir()
    . '/fm-nip46-rpc-' . getmypid() . '.log';
$GLOBALS['__fm_test_ws_connect'] = static function () use (
    $rpcClientPk,
    $rpcSignerSec,
    $rpcSignerPk,
    $rpcUserPk,
    &$rpcChildPid
) {
    $pair = stream_socket_pair(
        STREAM_PF_UNIX,
        STREAM_SOCK_STREAM,
        STREAM_IPPROTO_IP
    );
    if ($pair === false) throw new RuntimeException('socket pair failed');
    $pid = pcntl_fork();
    if ($pid === -1) throw new RuntimeException('fork failed');
    if ($pid === 0) {
        fclose($pair[0]);
        $subscription = json_decode(
            (string)test_read_client_ws_text($pair[1]),
            true
        );
        $published = json_decode(
            (string)test_read_client_ws_text($pair[1]),
            true
        );
        $requestEvent = is_array($published[1] ?? null)
            ? $published[1] : [];
        $valid = ($subscription[0] ?? null) === 'REQ'
            && ($subscription[2]['#p'] ?? null) === [$rpcClientPk]
            && ($subscription[2]['authors'] ?? null) === [$rpcSignerPk]
            && ($published[0] ?? null) === 'EVENT'
            && fm_event_verify($requestEvent);
        try {
            $request = json_decode(
                nip44_decrypt(
                    $rpcSignerSec,
                    $rpcClientPk,
                    (string)($requestEvent['content'] ?? '')
                ),
                true
            );
        } catch (Throwable) {
            $request = null;
        }
        $valid = $valid
            && is_array($request)
            && ($request['method'] ?? null) === 'get_public_key'
            && ($request['params'] ?? null) === []
            && is_string($request['id'] ?? null);
        if (!$valid) {
            fclose($pair[1]);
            exit(2);
        }
        $response = fm_event_sign([
            'pubkey' => $rpcSignerPk,
            'created_at' => now(),
            'kind' => 24133,
            'tags' => [['p', $rpcClientPk]],
            'content' => nip44_encrypt(
                $rpcSignerSec,
                $rpcClientPk,
                json_c([
                    'id' => $request['id'],
                    'result' => $rpcUserPk,
                ])
            ),
        ], $rpcSignerSec);
        test_send_server_ws_text(
            $pair[1],
            json_c(['EOSE', $subscription[1]])
        );
        test_send_server_ws_text(
            $pair[1],
            json_c(['EVENT', $subscription[1], $response])
        );
        fclose($pair[1]);
        exit(0);
    }
    fclose($pair[1]);
    $rpcChildPid = $pid;
    return $pair[0];
};
$rpcResponse = nip46_rpc(
    $rpcClientSec,
    $rpcClientPk,
    $rpcSignerPk,
    'wss://offline.invalid',
    'get_public_key',
    [],
    2.0
);
unset($GLOBALS['__fm_test_ws_connect']);
$rpcChildStatus = 0;
pcntl_waitpid((int)$rpcChildPid, $rpcChildStatus);
@unlink($GLOBALS['__fm_test_log']);
unset($GLOBALS['__fm_test_log']);
ok(
    ($rpcResponse['result'] ?? null) === $rpcUserPk
    && pcntl_wifexited($rpcChildStatus)
    && pcntl_wexitstatus($rpcChildStatus) === 0,
    'subscribe-before-publish RPC roundtrips through a fake signer'
);

echo "\n$pass passed, $fail failed\n";
if ($failures) { echo "FAILURES:\n"; foreach ($failures as $f) echo " - $f\n"; exit(1); }
exit(0);

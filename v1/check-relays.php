<?php
/**
 * check-relays.php -- CLI acceptance-test helper (DESIGN §12 walkthrough).
 *
 * Asks the bridge's own DB for repos/issues, queries the relays, reports
 * what's really published. No state changes.
 *
 * Usage:
 *   php check-relays.php                     # all mapped repos
 *   php check-relays.php dummy               # one repo by repo_id
 *   php check-relays.php dummy 1             # also show issue #1 thread
 *   php check-relays.php --events 1621 5     # raw recent events of a kind
 *   php check-relays.php --bridge-pubkey      # maintainer key for 30617
 *
 * Also serves the browser half of the walkthrough via HTTP GET:
 *   /v1/check-relays.php?html=1
 * renders a small page that fetches YOUR pubkey from window.nostr (NIP-07
 * extension) and queries relays for YOUR recent bridged activity.
 */
declare(strict_types=1);

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib/util.php';
require_once __DIR__ . '/lib/secrets.php';
require_once __DIR__ . '/lib/crypto.php';
require_once __DIR__ . '/lib/relay.php';

if (PHP_SAPI === 'cli') {
    main_cli($argv);
} else {
    http_main();
}
exit;

// ---------------------------------------------------------------- HTTP half

function http_main(): void
{
    if (!in_array(
        $_SERVER['REQUEST_METHOD'] ?? 'GET',
        ['GET', 'HEAD'],
        true
    )) {
        http_response_code(405);
        header('Allow: GET, HEAD');
        exit;
    }
    $repos = db()->query('SELECT * FROM repos
                          WHERE verified = 1
                          ORDER BY github_full_name')->fetchAll();
    $rows = '';
    foreach ($repos as $r) {
        $relays = relay_url_set(
            json_decode($r['relays'] ?? '[]', true) ?: []
        );
        $rows .= '<tr><td><code>' . e($r['github_full_name']) . '</code></td>'
               . '<td><code>' . e($r['repo_id']) . '</code></td>'
               . '<td><code>' . e(fm_npub_encode($r['owner_pubkey'])) . '</code></td>'
               . '<td><small>' . e(implode(' ', $relays)) . '</small></td></tr>';
    }
    if ($rows === '') $rows = '<tr><td colspan="4"><em>no verified repos yet</em></td></tr>';

    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<title>Bridge relay check</title><style>'
       . 'body{font-family:system-ui,sans-serif;max-width:52em;margin:2rem auto;padding:0 1rem;line-height:1.5}'
       . 'table{border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #ccc;padding:.3em .6em;text-align:left}'
       . 'code{font-size:.85em;background:#f4f4f4;padding:.1em .3em;border-radius:3px;word-break:break-all}'
       . '#out{white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:.8em;'
       . 'border:1px solid #ccc;padding:1em;border-radius:6px;margin:1rem 0;min-height:3em}'
       . '.ok{color:#0a7d28}.bad{color:#b00020}</style></head><body>'
       . '<h1>Bridge ↔ relay check</h1>'
       . '<h2>Mapped repos (from bridge DB)</h2>'
       . '<table><tr><th>GitHub repo</th><th>nostr repo_id</th><th>owner</th><th>relays</th></tr>'
       . $rows . '</table>'
       . '<h2>My bridged activity (needs NIP-07 extension)</h2>'
       . '<p>Reads your pubkey via <code>window.nostr.getPublicKey()</code> and asks each '
       . 'relay for your recent 1621/1111 events.</p>'
       . '<button id="go">Check my pubkey on relays</button>'
       . '<div id="out">waiting…</div>'
       . '<script>
	const RELAYS = ' . json_encode(collect_relays($repos)) . ';
async function ask(relay, filter) {
  return new Promise((resolve) => {
    const got = new Map();
    let done = false;
    let ws;
    try { ws = new WebSocket(relay); } catch (e) { return resolve([relay, null, "ws error"]); }
    const finish = (events, state) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      try { ws.close(); } catch (e) {}
      resolve([relay, events, state]);
    };
    const t = setTimeout(() => finish(Array.from(got.values()), "timeout"), 6000);
    ws.onopen = () => ws.send(JSON.stringify(["REQ", "c" + Math.random().toString(16).slice(2, 8), filter]));
    ws.onmessage = (m) => {
      const d = JSON.parse(m.data);
      if (d[0] === "EVENT" && typeof d[2]?.id === "string") got.set(d[2].id, d[2]);
      if (d[0] === "EOSE") finish(Array.from(got.values()), "eose");
    };
    ws.onerror = () => finish(null, "error");
  });
}
document.getElementById("go").onclick = async () => {
  const out = document.getElementById("out");
  if (!window.nostr) { out.textContent = "No NIP-07 extension found (Alby, nos2x, …)."; return; }
  out.textContent = "asking window.nostr…";
  let pk;
  try { pk = await window.nostr.getPublicKey(); } catch (e) { out.textContent = "getPublicKey failed: " + e; return; }
  out.textContent = "pubkey: " + pk + "\\nquerying relays…\\n";
  for (const r of RELAYS) {
    const [relay, evs, how] = await ask(r, { kinds: [1621, 1111, 1630, 1631, 1632, 1633], authors: [pk], limit: 20 });
    if (evs === null) { out.textContent += relay + ": ✖ " + how + "\\n"; continue; }
    out.textContent += relay + ": " + evs.length + " event(s)";
    for (const ev of evs) {
      out.textContent += "\\n  kind " + ev.kind + "  " + new Date(ev.created_at * 1000).toISOString()
                       + "  " + (ev.content || "").slice(0, 60).replace(/\\n/g, " ");
    }
    out.textContent += "\\n";
  }
};
</script></body></html>';
}

// ---------------------------------------------------------------- CLI half

function main_cli(array $argv): void
{
    if (($argv[1] ?? '') === '--bridge-pubkey') {
        echo fm_pubkey_hex(fm_secret_bridge_key()), "\n";
        return;
    }

    // --events <kind> <limit>: raw recent events of a kind, no repo needed
    if (($argv[1] ?? '') === '--events') {
        $kind = (int)($argv[2] ?? 1621);
        $limit = (int)($argv[3] ?? 5);
        $repos = db()->query('SELECT * FROM repos
                              WHERE verified = 1')->fetchAll();
        $relays = collect_relays($repos);
        echo "recent kind $kind events (any author) on: " . implode(' ', $relays) . "\n\n";
        foreach ($relays as $relay) {
            [$evs] = relay_query(['kinds' => [$kind], 'limit' => $limit], [$relay], 6.0);
            echo "== $relay: " . count($evs) . " event(s)\n";
            foreach ($evs as $ev) {
                if (!fm_event_verify($ev)) {
                    echo "  (invalid event skipped)\n";
                    continue;
                }
                $subject = relay_unique_tag_value($ev, 'subject') ?? '';
                printf("  %s kind=%d %s %s\n", substr($ev['id'], 0, 12), $ev['kind'],
                       date('Y-m-d H:i', (int)$ev['created_at']), $subject !== '' ? "\"$subject\"" : '');
            }
        }
        return;
    }

    $repoId = $argv[1] ?? null;
    $number = isset($argv[2]) ? (int)$argv[2] : null;

    if ($repoId === null) {
        $repos = db()->query('SELECT * FROM repos ORDER BY github_full_name')->fetchAll();
        echo "mapped repos (verify with: php check-relays.php <repo_id> [issue#]):\n";
        foreach ($repos as $r) {
            printf("  %-28s %-16s verified=%d owner=%s…\n",
                $r['github_full_name'], $r['repo_id'], (int)$r['verified'], substr($r['owner_pubkey'], 0, 8));
        }
        if (!$repos) echo "  (none yet -- publish a 30617 and POST it to repos.php)\n";
        return;
    }

    $st = db()->prepare('SELECT * FROM repos WHERE repo_id = ?');
    $st->execute([$repoId]);
    $repos = $st->fetchAll();
    if (!$repos) { echo "no repo row for '$repoId'\n"; exit(1); }

    foreach ($repos as $repo) {
        echo "== {$repo['github_full_name']} (repo_id={$repo['repo_id']})\n";
        $relays = collect_relays([$repo]);
        $aTag = '30617:' . $repo['owner_pubkey'] . ':' . $repo['repo_id'];

        // 1. repo announcement
        foreach ($relays as $relay) {
            [$evs] = relay_query(['kinds' => [30617], '#d' => [$repo['repo_id']], 'limit' => 5], [$relay], 5.0);
            $mine = array_values(array_filter($evs, function ($event) use ($repo) {
                if (($event['pubkey'] ?? '') !== $repo['owner_pubkey']
                    || !fm_event_verify($event)) return false;
                return relay_unique_tag_value($event, 'd')
                    === $repo['repo_id'];
            }));
            printf("  %-26s 30617: %s\n", $relay, $mine ? 'FOUND (' . count($mine) . ')' : 'not found');
        }

        // 2. issues
        foreach ($relays as $relay) {
            [$evs] = relay_query(['kinds' => [1621], '#a' => [$aTag], 'limit' => 20], [$relay], 5.0);
            printf("  %-26s 1621 issues: %d\n", $relay, count($evs));
            foreach ($evs as $ev) {
                $gh = relay_unique_tag_value($ev, 'gh') ?? '';
                printf("      %s %s %s\n", substr($ev['id'], 0, 12), date('m-d H:i', (int)$ev['created_at']), $gh);
            }
        }

        // 3. one issue's thread
        if ($number !== null) {
            $ghTag = "{$repo['github_full_name']}#$number";
            $root = db()->prepare("SELECT nostr_id FROM event_map
                                   WHERE kind=1621
                                   AND json_extract(meta,'$.full')=?
                                   AND json_extract(meta,'$.number')=?");
            $root->execute([$repo['github_full_name'], $number]);
            $rootId = $root->fetchColumn();
            if (!$rootId) {
                // fall back to scanning relays by gh tag
                foreach ($relays as $relay) {
                    [$evs] = relay_query(['kinds' => [1621], '#a' => [$aTag], 'limit' => 50], [$relay], 5.0);
                    foreach ($evs as $ev) {
                        if (relay_unique_tag_value($ev, 'gh') === $ghTag) {
                            $rootId = $ev['id'];
                            break;
                        }
                    }
                    if ($rootId) break;
                }
            }
            echo "\n  thread for $ghTag:\n";
            if (!$rootId) { echo "    no mirrored 1621 found (relay or bridge ledger)\n"; return; }
            echo "    root 1621: $rootId\n";
            foreach ($relays as $relay) {
                [$comments] = relay_query(
                    ['kinds' => [1111], '#E' => [$rootId], 'limit' => 50],
                    [$relay], 5.0);
                [$statuses] = relay_query(
                    ['kinds' => [1630, 1631, 1632, 1633], '#e' => [$rootId], 'limit' => 50],
                    [$relay], 5.0);
                $evs = array_merge($comments, $statuses);
                printf("    %-22s %d reply/status event(s)\n", $relay, count($evs));
                foreach ($evs as $ev) {
                    printf("      %s kind=%d %s\n", substr($ev['id'], 0, 12), $ev['kind'],
                           substr((string)$ev['content'], 0, 50));
                }
            }
        }
    }
}

/** relays of the given repos + defaults, deduped. */
function collect_relays(array $repos): array
{
    $relays = [];
    foreach ($repos as $r) {
        foreach (json_decode($r['relays'] ?? '[]', true) ?: [] as $u) $relays[$u] = true;
    }
    foreach (relay_defaults() as $u) $relays[$u] = true;
    return relay_url_set(array_keys($relays));
}

<?php
/** One-to-one GitHub ↔ Nostr identity binding helpers. */
declare(strict_types=1);

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/util.php';

class IdentityLinkConflict extends RuntimeException {}

/**
 * Insert an identity link, or accept the exact existing pair.
 * The caller may already own a transaction.
 */
function fm_link_identities(string $login, string $pubkey): void
{
    $pubkey = strtolower($pubkey);
    if ($login === '' || !is_hex64($pubkey)) {
        throw new InvalidArgumentException('invalid identity pair');
    }

    $st = db()->prepare('SELECT login,pubkey FROM links WHERE login=? OR pubkey=?');
    $st->execute([$login, $pubkey]);
    foreach ($st->fetchAll() as $row) {
        if ($row['login'] === $login && $row['pubkey'] === $pubkey) return;
        throw new IdentityLinkConflict('GitHub or Nostr identity is already linked elsewhere');
    }
    try {
        db()->prepare('INSERT INTO links (login,pubkey,created_at) VALUES (?,?,?)')
           ->execute([$login, $pubkey, now()]);
    } catch (PDOException $e) {
        if (str_contains($e->getMessage(), 'UNIQUE')) {
            throw new IdentityLinkConflict('identity was linked concurrently', 0, $e);
        }
        throw $e;
    }
}

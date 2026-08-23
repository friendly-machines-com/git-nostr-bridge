<?php
/**
 * jobs.php -- durable work queue in SQLite (DESIGN §5).
 * Dependency and transient-transport waits remain pending with capped
 * backoff. Other failed executions become dead after eight failures.
 * Unique pending job per dedupe_key (kills webhook double-delivery).
 */
declare(strict_types=1);

require_once __DIR__ . '/util.php';
require_once __DIR__ . '/../db.php';

function jobs_enqueue(string $type, array $payload, ?string $dedupeKey = null): int
{
    $t = now();
    try {
        $st = db()->prepare("INSERT INTO jobs (type, payload, dedupe_key, run_at, created_at, updated_at)
                             VALUES (?,?,?,?,?,?)");
        $st->execute([$type, json_c($payload), $dedupeKey, $t, $t, $t]);
        return (int)db()->lastInsertId();
    } catch (PDOException $e) {
        // unique dedupe violation -> already queued, fine
        if (str_contains($e->getMessage(), 'UNIQUE')) return 0;
        throw $e;
    }
}

/**
 * Immutable input deliveries are terminal after success, permanent skip, or
 * dead-lettering. Repeated delivery must not silently create a fresh failure
 * budget for the same input.
 */
function jobs_dedupe_terminal(string $dedupeKey): bool
{
    $query = db()->prepare(
        "SELECT 1 FROM jobs
         WHERE dedupe_key=? AND status IN ('done','dead') LIMIT 1"
    );
    $query->execute([$dedupeKey]);
    return (bool)$query->fetchColumn();
}

/**
 * Claim up to $n due jobs. Atomic: a conditional UPDATE moves run_at
 * forward as a LEASE, so only the worker whose UPDATE affected the row
 * owns it. This matters if cron ticks overlap or another worker is added; a
 * plain SELECT-then-mark lets both claim the same row and double-execute.
 * A crashed worker's lease simply expires (JOBS_LEASE_SECS) and the job
 * becomes due again.
 */
// A crossing can include bounded signer lookup, relay reconciliation, publish,
// and GitHub/relay acknowledgements. Keep the lease longer than that complete
// network budget so a slow but live worker cannot be claimed concurrently.
// A crashed worker remains automatically recoverable on the next due tick.
const JOBS_LEASE_SECS = 300;

function jobs_claim_due(int $n = 25): array
{
    $db = db();
    $rows = $db->prepare("SELECT * FROM jobs WHERE status='pending' AND run_at <= ?
                          ORDER BY run_at ASC, id ASC LIMIT ?");
    $rows->execute([now(), $n]);
    $claimed = [];
    foreach ($rows->fetchAll() as $job) {
        $claim = $db->prepare("UPDATE jobs
                               SET attempts = attempts+1, run_at = ?, updated_at = ?
                               WHERE id = ? AND status = 'pending' AND run_at <= ?");
        $claim->execute([now() + JOBS_LEASE_SECS, now(), $job['id'], now()]);
        if ($claim->rowCount() !== 1) {
            continue;   // another worker leased it between SELECT and UPDATE
        }
        $job['attempts'] = (int)$job['attempts'] + 1;
        $job['payload_arr'] = json_decode($job['payload'], true) ?: [];
        $claimed[] = $job;
    }
    return $claimed;
}

/**
 * Claim one known due job by immutable ID.
 *
 * Browser-assisted workflows use this to reduce first-action latency while
 * the ordinary cron worker remains the backstop. The same conditional lease
 * as jobs_claim_due prevents the web request and cron from executing it
 * concurrently.
 */
function jobs_claim_id(int $id): ?array
{
    if ($id < 1) return null;
    $query = db()->prepare(
        "SELECT * FROM jobs
         WHERE id=? AND status='pending' AND run_at<=?"
    );
    $query->execute([$id, now()]);
    $job = $query->fetch();
    if (!is_array($job)) return null;
    $claim = db()->prepare(
        "UPDATE jobs
         SET attempts=attempts+1,run_at=?,updated_at=?
         WHERE id=? AND status='pending' AND run_at<=?"
    );
    $claim->execute([now() + JOBS_LEASE_SECS, now(), $id, now()]);
    if ($claim->rowCount() !== 1) return null;
    $job['attempts'] = (int)$job['attempts'] + 1;
    $job['payload_arr'] = json_decode($job['payload'], true) ?: [];
    return $job;
}

function jobs_update_payload(int $id, array $payload): void
{
    $update = db()->prepare(
        "UPDATE jobs SET payload=?,updated_at=?
         WHERE id=? AND status='pending'"
    );
    $update->execute([json_c($payload), now(), $id]);
    if ($update->rowCount() !== 1) {
        throw new RuntimeException('durable job is no longer pending');
    }
}

function jobs_finish(int $id, bool $ok, string $error = ''): void
{
    $db = db();
    if ($ok) {
        $db->prepare("UPDATE jobs SET status='done', updated_at=?, last_error=NULL WHERE id=?")
           ->execute([now(), $id]);
        return;
    }
    $db->prepare("UPDATE jobs SET fails = fails+1, updated_at=? WHERE id=?")
       ->execute([now(), $id]);
    $job = $db->prepare('SELECT fails FROM jobs WHERE id=?');
    $job->execute([$id]);
    $fails = (int)($job->fetchColumn() ?: 0);
    if ($fails >= 8) {
        $db->prepare("UPDATE jobs SET status='dead', updated_at=?, last_error=? WHERE id=?")
           ->execute([now(), substr($error, 0, 500), $id]);
        bridge_log('jobs', "job $id DEAD", ['error' => $error]);
    } else {
        $backoff = min(3600, 60 * (2 ** max(0, $fails - 1)));
        $db->prepare("UPDATE jobs SET run_at=?, last_error=? WHERE id=?")
           ->execute([now() + $backoff, substr($error, 0, 500), $id]);
    }
}

/**
 * Release a leased job whose causal dependency has not arrived yet.
 * Dependency waits are not failed executions and therefore must not consume
 * the eight-attempt transport/error budget.
 */
function jobs_defer(int $id, int $delaySecs, string $reason): void
{
    db()->prepare("UPDATE jobs
                   SET run_at=?, updated_at=?, last_error=?
                   WHERE id=? AND status='pending'")
       ->execute([
           now() + max(1, $delaySecs),
           now(),
           substr($reason, 0, 500),
           $id,
       ]);
}

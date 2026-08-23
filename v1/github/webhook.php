<?php
/**
 * github/webhook.php  ==  /v1/github/webhook
 * Direction A entry point (GitHub -> Nostr).
 *
 * Pipeline (DESIGN §3):
 *   HMAC verify -> log delivery -> classify (issue/PR/star) ->
 *   durable github_delivery enqueue -> 202.
 * Cron owns acceptance, registered mapping, crossing jobs and retries.
 *
 * Everything fallible is a JOB; the webhook request performs no relay I/O.
 */
declare(strict_types=1);

define('BRIDGE_ENTRY', true);
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../lib/util.php';
require_once __DIR__ . '/../lib/secrets.php';
require_once __DIR__ . '/../lib/jobs.php';

// --- Verify GitHub webhook signature ---------------------------------------
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('POST required');
}
$payload = file_get_contents('php://input');
if (!is_string($payload)) {
    http_response_code(500);
    exit('Could not read request body');
}
if (strlen($payload) > 2 * 1024 * 1024) {
    http_response_code(413);
    exit('Payload too large');
}
$sigHeader = is_string($_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? null)
    ? $_SERVER['HTTP_X_HUB_SIGNATURE_256'] : '';

if ($sigHeader === '' || strpos($sigHeader, 'sha256=') !== 0) {
    http_response_code(401);
    exit('Missing signature');
}
$secret = fm_secret_github_webhook();          // loud if missing

$expected = 'sha256=' . hash_hmac('sha256', $payload, $secret);
if (!hash_equals($expected, $sigHeader)) {
    http_response_code(403);
    exit('Invalid signature');
}

$event  = json_decode($payload, true);
if (!is_array($event)) {
    http_response_code(400);
    exit('Invalid JSON');
}
$action = $event['action'] ?? '';
$ghEvent  = $_SERVER['HTTP_X_GITHUB_EVENT'] ?? '';
$delivery = $_SERVER['HTTP_X_GITHUB_DELIVERY'] ?? '';

// --- Private delivery log --------------------------------------------------
$line = sprintf("%s\t%s\t%s\t%s\n", date('c'), $delivery, $ghEvent, $payload);
$logFile = fm_log_file();
@file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
@chmod($logFile, 0600);

// --- Classify (DESIGN §3.0): PRs are issues; payload decides ---------------
$isPR = isset($event['issue']['pull_request']);

$handled = false;
if ($ghEvent === 'issues'
    && in_array(
        $action,
        ['opened', 'closed', 'reopened', 'edited', 'deleted'],
        true
    )) {
    if (!$isPR) {
        $handled = true;
    }
} elseif ($ghEvent === 'issue_comment'
          && in_array($action, ['created', 'edited', 'deleted'], true)) {
    if (!$isPR) {
        $handled = true;
    }
} elseif ($ghEvent === 'star'
          && in_array($action, ['created', 'deleted'], true)) {
    $handled = true;
} elseif (in_array(
    $ghEvent,
    ['installation', 'installation_repositories', 'installation_target',
     'repository', 'github_app_authorization'],
    true
)) {
    // These deliveries maintain App/account/repository access. The cron job
    // reconciles authoritative current state through the GitHub API, so their
    // arrival order cannot become state order.
    $handled = true;
}

if (!$handled) {
    http_response_code(200);
    exit('Ignored');
}

// A separately configured organization/repository webhook has no
// installation object. Accepting it would bypass App installation access and
// duplicate the App webhook.
$installationId = $event['installation']['id'] ?? null;
if ($ghEvent !== 'github_app_authorization') {
    if ((!is_int($installationId) && !is_string($installationId))
        || !ctype_digit((string)$installationId)
        || (string)$installationId === '0') {
        http_response_code(200);
        exit('Ignored: not a GitHub App delivery');
    }
}

// Durably bank the raw, authenticated delivery before acknowledging it.
// Mapping lookup, classification details, signing and publishing all happen
// in cron-drained jobs. A relay outage or missing mapping can no longer
// erase the only copy of an issue-open delivery.
$dedupe = $delivery !== ''
    ? 'ghdelivery:' . $delivery
    : 'ghdelivery:' . hash('sha256', $ghEvent . $payload);
try {
    if (!jobs_dedupe_terminal($dedupe)) {
        jobs_enqueue('github_delivery', [
            'delivery' => $delivery,
            'event_name' => $ghEvent,
            'event' => $event,
        ], $dedupe);
    }
} catch (Throwable $e) {
    bridge_log('webhook', 'durable enqueue failed', [
        'delivery' => $delivery, 'err' => $e->getMessage(),
    ]);
    http_response_code(503);
    exit('Queue unavailable');
}

http_response_code(202);
echo 'Queued';
if (function_exists('fastcgi_finish_request')) fastcgi_finish_request();

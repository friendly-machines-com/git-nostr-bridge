<?php
/** Offline GitHub issue-status history ordering and provenance tests. */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') exit(1);

$rest = [
    [
        'id' => 13,
        'node_id' => 'STATUS_close_bridge',
        'event' => 'closed',
        'created_at' => '2023-11-14T22:13:25Z',
        'performed_via_github_app' => ['id' => 4242],
    ],
    [
        'id' => 12,
        'node_id' => 'STATUS_reopen',
        'event' => 'reopened',
        'created_at' => '2023-11-14T22:13:20Z',
        'performed_via_github_app' => null,
    ],
    [
        'id' => 11,
        'node_id' => 'STATUS_close',
        'event' => 'closed',
        'created_at' => '2023-11-14T22:13:20Z',
        'performed_via_github_app' => null,
    ],
];

$GLOBALS['__fm_test_gh_request'] = static function (
    string $method,
    string $path,
    string $token,
    ?array $body
) use ($rest): array {
    if ($method === 'GET'
        && $path === '/repos/example/project/issues/7/events?per_page=100&page=1') {
        // Deliberately newest-first: REST array order is not causality.
        return $rest;
    }
    if ($method === 'POST' && $path === '/graphql') {
        $after = $body['variables']['after'] ?? null;
        if ($after === null) {
            return ['data' => ['repository' => ['issue' => [
                'timelineItems' => [
                    'nodes' => [
                        [
                            '__typename' => 'ClosedEvent',
                            'id' => 'STATUS_close',
                            'createdAt' => '2023-11-14T22:13:20Z',
                            'stateReason' => 'COMPLETED',
                            'actor' => ['login' => 'alice'],
                        ],
                        [
                            '__typename' => 'ReopenedEvent',
                            'id' => 'STATUS_reopen',
                            'createdAt' => '2023-11-14T22:13:20Z',
                            'stateReason' => 'REOPENED',
                            'actor' => ['login' => 'bob'],
                        ],
                    ],
                    'pageInfo' => [
                        'hasNextPage' => true,
                        'endCursor' => 'cursor-2',
                    ],
                ],
            ]]]];
        }
        if ($after === 'cursor-2') {
            return ['data' => ['repository' => ['issue' => [
                'timelineItems' => [
                    'nodes' => [[
                        '__typename' => 'ClosedEvent',
                        'id' => 'STATUS_close_bridge',
                        'createdAt' => '2023-11-14T22:13:25Z',
                        'stateReason' => 'NOT_PLANNED',
                        'actor' => ['login' => 'bridge-bot'],
                    ]],
                    'pageInfo' => [
                        'hasNextPage' => false,
                        'endCursor' => 'cursor-3',
                    ],
                ],
            ]]]];
        }
    }
    throw new RuntimeException("unexpected offline request $method $path");
};

require_once __DIR__ . '/../lib/github.php';

$events = gh_issue_status_events(
    'test-installation-token',
    'example/project',
    7,
    '4242'
);

$expected = [
    ['STATUS_close', 1631, 1700000000, false],
    ['STATUS_reopen', 1630, 1700000001, false],
    ['STATUS_close_bridge', 1632, 1700000005, true],
];
$actual = array_map(
    static fn(array $event): array => [
        $event['github_id'],
        $event['kind'],
        $event['nostr_created_at'],
        $event['performed_by_bridge'],
    ],
    $events
);

if ($actual !== $expected) {
    fwrite(STDERR, 'FAIL GitHub status causal ordering: '
        . var_export($actual, true) . PHP_EOL);
    exit(1);
}

echo "  ok  reversed REST order cannot reorder the GraphQL status timeline\n";
echo "  ok  same-second transitions receive causal Nostr timestamps\n";
echo "  ok  bridge provenance uses the stable numeric GitHub App id\n";
echo "\n3 passed, 0 failed\n";

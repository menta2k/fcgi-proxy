<?php
// Simulates a heavier workload: array operations + JSON encoding.
header('Content-Type: application/json');

$data = [];
for ($i = 0; $i < 100; $i++) {
    $data[] = [
        'id'    => $i,
        'name'  => 'user_' . $i,
        'email' => 'user' . $i . '@example.com',
        'hash'  => md5((string)$i),
    ];
}

echo json_encode(['users' => $data, 'count' => count($data)]) . "\n";

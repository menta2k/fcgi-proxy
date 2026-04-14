<?php
// Echoes back the POST body for POST benchmarks.
header('Content-Type: application/json');

$input = file_get_contents('php://input');
echo json_encode([
    'method'         => $_SERVER['REQUEST_METHOD'],
    'content_length' => $_SERVER['CONTENT_LENGTH'] ?? 0,
    'body_size'      => strlen($input),
]) . "\n";

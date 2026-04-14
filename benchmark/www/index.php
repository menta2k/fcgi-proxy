<?php
header('Content-Type: application/json');
echo json_encode([
    'status' => 'ok',
    'time'   => microtime(true),
    'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
]) . "\n";

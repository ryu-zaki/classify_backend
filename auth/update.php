<?php
// /progress/update.php

header("Access-Control-Allow-Origin: http://localhost:5173");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");

// Handle preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once '../vendor/autoload.php';
require_once '../config/db.php';
require_once '../config/jwt_config.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

try {
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? '';

    if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Unauthorized: No Bearer token']);
        exit;
    }

    $token = $matches[1];
    $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
    $userId = $decoded->data->id;

    $input = json_decode(file_get_contents("php://input"), true);

    if (!isset($input['progress'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing progress data']);
        exit;
    }

    $progressData = $input['progress']; 

    $progressJson = json_encode($progressData);
    $stmt = $pdo->prepare("UPDATE users SET progress = ? WHERE id = ?");
    $stmt->execute([$progressJson, $userId]);

    echo json_encode(['success' => true, 'message' => 'Progress updated successfully']);

} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'An error occurred: ' . $e->getMessage()]);
}
?>

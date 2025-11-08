<?php
header("Access-Control-Allow-Origin: http://localhost:5173");
header("Access-Control-Allow-Methods: DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'DELETE') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method Not Allowed']);
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

    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
    $stmt->execute([$userId]);

    if ($stmt->rowCount() > 0) {
        echo json_encode(['success' => true, 'message' => 'Account deleted successfully']);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'User not found or already deleted']);
    }

} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'An error occurred: ' . $e->getMessage()]);
}
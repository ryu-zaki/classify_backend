<?php
header("Access-Control-Allow-Origin: http://localhost:5173");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once '../vendor/autoload.php'; 
require_once '../config/db.php'; 
require_once '../config/jwt_config.php';

use Firebase\JWT\JWT;

$input = json_decode(file_get_contents("php://input"), true);

if (!isset($input['email'], $input['password'])) {
    echo json_encode(["success" => false, "message" => "Missing fields"]);
    exit;
}

$email = trim($input['email']);
$password = trim($input['password']);

try {
    $stmt = $pdo->prepare("SELECT id, name, email, password, created_at FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, $user['password'])) {
        echo json_encode(["success" => false, "message" => "Invalid email or password"]);
        exit;
    }

    $issuedAt = time();
    $expirationTime = $issuedAt + (60 * 60 * 24); 
    $payload = [
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'data' => [
            'id' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email'],
            "created_at" => $user['created_at']
        ]
    ];

    $token = JWT::encode($payload, JWT_SECRET_KEY, 'HS256');

    echo json_encode([
        "success" => true,
        "token" => $token,
        "user" => [
            "id" => $user['id'],
            "name" => $user['name'],
            "email" => $user['email'],
            "created_at" => $user['created_at']
        ]
    ]);
} catch (PDOException $e) {
    echo json_encode(["success" => false, "message" => $e->getMessage()]);
}

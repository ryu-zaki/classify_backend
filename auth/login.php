<?php
// ✅ CORS Configuration
header("Access-Control-Allow-Origin: http://localhost:5173");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");

// ✅ Handle preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once '../vendor/autoload.php'; // Composer autoloader
require_once '../config/db.php'; // Your PDO connection file
require_once '../config/jwt_config.php';

use Firebase\JWT\JWT;

// ✅ Read JSON input
$input = json_decode(file_get_contents("php://input"), true);

if (!isset($input['email'], $input['password'])) {
    echo json_encode(["success" => false, "message" => "Missing fields"]);
    exit;
}

$email = trim($input['email']);
$password = trim($input['password']);

try {
    // ✅ Check if user exists
    $stmt = $pdo->prepare("SELECT id, name, email, password FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, $user['password'])) {
        echo json_encode(["success" => false, "message" => "Invalid email or password"]);
        exit;
    }

    // ✅ Create JWT
    $issuedAt = time();
    $expirationTime = $issuedAt + (60 * 60 * 24); // Expires in 24 hours
    $payload = [
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'data' => [
            'id' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email']
        ]
    ];

    $token = JWT::encode($payload, JWT_SECRET_KEY, 'HS256');

    // ✅ Return success
    echo json_encode([
        "success" => true,
        "token" => $token,
        "user" => [
            "id" => $user['id'],
            "name" => $user['name'],
            "email" => $user['email']
        ]
    ]);
} catch (PDOException $e) {
    echo json_encode(["success" => false, "message" => $e->getMessage()]);
}

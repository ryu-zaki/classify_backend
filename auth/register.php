<?php
// signup.php
header("Access-Control-Allow-Origin: http://localhost:5173");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");

// Handle preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once '../vendor/autoload.php'; // Composer autoloader
require_once '../config/db.php';
require_once '../config/jwt_config.php';

use Firebase\JWT\JWT;

$input = json_decode(file_get_contents("php://input"), true);

if (!isset($input['name'], $input['email'], $input['password'])) {
    echo json_encode(["success" => false, "message" => "Missing fields"]);
    exit;
}

$name = trim($input['name']);
$email = trim($input['email']);
$password = trim($input['password']);

try {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);

    if ($stmt->fetch()) {
        http_response_code(403); 
        echo json_encode(["success" => false, "message" => "Email already registered"]);
        exit;
    }

    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    $stmt = $pdo->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    $stmt->execute([$name, $email, $hashedPassword]);

    $userId = $pdo->lastInsertId();

    // Create JWT
    $issuedAt = time();
    $expirationTime = $issuedAt + (60 * 60 * 24); // Expires in 24 hours
    $payload = [
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'data' => [
            'id' => $userId,
            'name' => $name,
            'email' => $email
        ]
    ];
    $token = JWT::encode($payload, JWT_SECRET_KEY, 'HS256');

    echo json_encode([
        "success" => true,
        "user" => [
            "id" => $userId,
            "name" => $name,
            "email" => $email
        ],
        "token" => $token // Your client-side JS should save this in localStorage
    ]);
} catch (PDOException $e) {
    echo json_encode(["success" => false, "message" => $e->getMessage()]);
}

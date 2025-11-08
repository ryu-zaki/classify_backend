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

require_once '../config/db.php'; // Your PDO connection file

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

    // ✅ Generate a token (you can replace this with JWT)
    $token = base64_encode(random_bytes(30));

    // Optional: store token in session or database
    // $stmt = $pdo->prepare("UPDATE users SET token = ? WHERE id = ?");
    // $stmt->execute([$token, $user['id']]);

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

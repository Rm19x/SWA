<?php
/**
 * Security Web Application (SWA) - Rate Limiter & Anti-DoS Engine
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

class SWA_RateLimiter {

    private $config;
    private $storageFile;

    public function __construct() {
        $this->config = require SWA_CONFIG_DIR . '/config.php';
        $this->storageFile = SWA_LOG_DIR . '/rate_limit.json';
    }

    public function checkRateLimit() {
        $clientIp = $this->getClientIp();

        // Mengabaikan pemfilteran untuk IP Whitelist
        if (in_array($clientIp, $this->config['whitelist']['ips'] ?? [])) {
            return true;
        }

        $data = $this->loadStorage();
        $currentTime = time();
        $window = SWA_RATE_LIMIT_WINDOW;
        $maxRequests = SWA_RATE_LIMIT_MAX_REQUESTS;

        // Inisialisasi atau bersihkan record IP yang sudah kedaluwarsa
        if (!isset($data[$clientIp])) {
            $data[$clientIp] = [
                'requests' => [],
                'blocked_until' => 0
            ];
        }

        // Cek status blokir permanen / sementara
        if ($data[$clientIp]['blocked_until'] > $currentTime) {
            $this->triggerRateBlock($clientIp, $data[$clientIp]['blocked_until'] - $currentTime);
        }

        // Hapus timestamp permintaan di luar window waktu saat ini
        $data[$clientIp]['requests'] = array_filter(
            $data[$clientIp]['requests'],
            function ($timestamp) use ($currentTime, $window) {
                return $timestamp > ($currentTime - $window);
            }
        );

        // Tambahkan permintaan baru
        $data[$clientIp]['requests'][] = $currentTime;

        // Evaluasi jumlah permintaan
        if (count($data[$clientIp]['requests']) > $maxRequests) {
            $data[$clientIp]['blocked_until'] = $currentTime + SWA_BLOCK_DURATION;
            $this->saveStorage($data);
            $this->triggerRateBlock($clientIp, SWA_BLOCK_DURATION);
        }

        $this->saveStorage($data);
        return true;
    }

    private function triggerRateBlock($ip, $remainingSeconds) {
        http_response_code(429);
        header('Retry-After: ' . $remainingSeconds);
        header('Content-Type: text/html; charset=utf-8');
        header('X-Protected-By: SWA Security Suite - Mr.Rm19');

        $minutes = ceil($remainingSeconds / 60);

        echo <<<HTML
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>429 Too Many Requests</title>
    <style>
        body { background-color: #0d0f12; color: #e1e6ed; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background-color: #161b22; border: 2px solid #d29922; border-radius: 8px; box-shadow: 0 0 20px rgba(210, 153, 34, 0.3); width: 90%; max-width: 550px; padding: 30px; text-align: center; }
        h1 { color: #d29922; margin-top: 0; font-size: 24px; border-bottom: 1px solid #30363d; padding-bottom: 15px; }
        p { font-size: 14px; line-height: 1.6; color: #8b949e; }
        .timer { font-size: 18px; color: #f85149; font-weight: bold; margin: 15px 0; }
        .footer { margin-top: 25px; font-size: 12px; color: #6e7681; border-top: 1px solid #21262d; padding-top: 15px; }
        .footer a { color: #d29922; text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <div class="card">
        <h1>429 - TERLALU BANYAK PERMINTAAN</h1>
        <p>Sistem mendeteksi lonjakan lalu lintas yang terlampau tinggi dari IP Anda. Untuk menjaga kestabilan server, akses dibatasi sementara.</p>
        <div class="timer">Silakan coba lagi dalam {$minutes} menit.</div>
        <div class="footer">
            SWA Rate Limiter Engine | Developed by <a href="https://github.com/Rm19x" target="_blank">Mr.Rm19</a>
        </div>
    </div>
</body>
</html>
HTML;
        exit();
    }

    private function loadStorage() {
        if (!file_exists($this->storageFile)) {
            return [];
        }
        $content = file_get_contents($this->storageFile);
        return json_decode($content, true) ?? [];
    }

    private function saveStorage($data) {
        if (!is_dir(SWA_LOG_DIR)) {
            mkdir(SWA_LOG_DIR, 0755, true);
        }
        file_put_contents($this->storageFile, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
    }

    private function getClientIp() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($ips[0]);
        }
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }
}
<?php
/**
 * Security Web Application (SWA) - File & Malware Scanner Engine
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

class SWA_FileScanner {

    private $config;
    private $signatures = [];
    private $scannedFiles = 0;
    private $threatsFound = [];

    public function __construct() {
        $this->config = require SWA_CONFIG_DIR . '/config.php';
        $this->signatures = $this->config['signatures'] ?? [];
    }

    public function scanDirectory($directoryPath) {
        $this->scannedFiles = 0;
        $this->threatsFound = [];

        if (!is_dir($directoryPath)) {
            return [
                'success' => false,
                'message' => 'Direktori sasaran tidak ditemukan.'
            ];
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directoryPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isFile()) {
                // Abaikan berkas dalam sistem SWA sendiri untuk menghindari false positive
                if (strpos($item->getPathname(), SWA_ROOT_DIR) === 0) {
                    continue;
                }

                $this->scannedFiles++;
                $this->inspectFile($item->getPathname());
            }
        }

        return [
            'success' => true,
            'scanned_files' => $this->scannedFiles,
            'threats_count' => count($this->threatsFound),
            'threats' => $this->threatsFound
        ];
    }

    public function inspectFile($filePath) {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            return;
        }

        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        // 1. Pemindaian File Gambar (Deteksi Steganografi Webshell)
        if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'])) {
            $this->checkImageSteganography($filePath);
            return;
        }

        // 2. Pemindaian Ekstensi Berbahaya
        $suspiciousExtensions = $this->signatures['suspicious_extensions'] ?? [];
        if (in_array($extension, $suspiciousExtensions)) {
            $content = file_get_contents($filePath);
            if (!empty($content)) {
                $this->analyzeCodeContent($filePath, $content);
            }
        }
    }

    private function analyzeCodeContent($filePath, $content) {
        // A. Deteksi Webshell & Backdoor Signature
        $webshellPatterns = [
            '/(c99shell|r57shell|wso\s+shell|b374k|FX29Shell)/i',
            '/(\$_POST|\$_GET|\$_COOKIE|\$_REQUEST)\s*\[.*?\]\s*\(\s*(\$_POST|\$_GET|\$_COOKIE|\$_REQUEST)/i',
            '/(passthru|shell_exec|exec|system|popen|proc_open)\s*\(\s*(\$_POST|\$_GET|\$_COOKIE|\$_REQUEST)/i'
        ];

        foreach ($webshellPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $this->addThreat($filePath, 'CRITICAL', 'Webshell / Backdoor Detected', 'Tanda tangan skrip peretas tingkat tinggi ditemukan.');
                return;
            }
        }

        // B. Deteksi Obfuscation / Obfuscated Code (misal Base64 Bertingkat)
        if (preg_match('/(eval|assert)\s*\(\s*gzinflate\s*\(\s*base64_decode/i', $content) ||
            preg_match('/base64_decode\s*\(\s*["\'][A-Za-z0-9+\/=]{100,}["\']\s*\)/i', $content)) {
            $this->addThreat($filePath, 'HIGH', 'Obfuscated PHP Code', 'Ditemukan enkripsi kode mencurigakan yang sering digunakan malware.');
        }

        // C. Deteksi Penggunaan Fungsi PHP Berbahaya
        $dangerousFuncs = $this->signatures['dangerous_functions'] ?? [];
        $foundFuncs = [];

        foreach ($dangerousFuncs as $func) {
            if (preg_match('/\b' . preg_quote($func, '/') . '\s*\(/i', $content)) {
                $foundFuncs[] = $func;
            }
        }

        if (count($foundFuncs) > 3) {
            $this->addThreat(
                $filePath, 
                'MEDIUM', 
                'Multiple Dangerous Functions', 
                'Penggunaan fungsi sensitif secara berlebihan: ' . implode(', ', $foundFuncs)
            );
        }
    }

    private function checkImageSteganography($filePath) {
        $content = file_get_contents($filePath);

        // Memeriksa keberadaan tag PHP di dalam file gambar
        if (preg_match('/<\?php/i', $content) || preg_match('/<\?=/', $content) || preg_match('/<script\s+language\s*=\s*["\']?php["\']?/i', $content)) {
            $this->addThreat(
                $filePath, 
                'CRITICAL', 
                'Image Steganography Webshell', 
                'File gambar memuat kode eksekusi PHP tersembunyi.'
            );
        }
    }

    public function quarantineFile($filePath) {
        if (!file_exists($filePath)) {
            return ['success' => false, 'message' => 'File tidak ditemukan.'];
        }

        if (!is_dir(SWA_QUARANTINE_DIR)) {
            mkdir(SWA_QUARANTINE_DIR, 0755, true);
            // Proteksi folder karantina dari eksekusi skrip
            file_put_contents(SWA_QUARANTINE_DIR . '/.htaccess', "Options -Indexes\nDeny from all");
        }

        $fileName = basename($filePath);
        $quarantineTarget = SWA_QUARANTINE_DIR . '/' . md5($filePath . time()) . '_' . $fileName . '.swaq';

        // Simpan metadata lokasi asli untuk pemulihan (Auto-Restore)
        $metadata = [
            'original_path' => $filePath,
            'quarantined_at' => date('Y-m-d H:i:s'),
            'file_hash' => hash_file('sha256', $filePath)
        ];

        file_put_contents($quarantineTarget . '.json', json_encode($metadata, JSON_PRETTY_PRINT));

        if (rename($filePath, $quarantineTarget)) {
            return ['success' => true, 'message' => 'File berhasil dikarantina.'];
        }

        return ['success' => false, 'message' => 'Gagal memindahkan file ke karantina.'];
    }

    public function restoreFile($quarantineFile) {
        $metadataFile = $quarantineFile . '.json';

        if (!file_exists($quarantineFile) || !file_exists($metadataFile)) {
            return ['success' => false, 'message' => 'Data karantina tidak valid.'];
        }

        $metadata = json_decode(file_get_contents($metadataFile), true);
        $originalPath = $metadata['original_path'] ?? '';

        if (empty($originalPath)) {
            return ['success' => false, 'message' => 'Jalur pemulihan tidak ditemukan dalam metadata.'];
        }

        $targetDir = dirname($originalPath);
        if (!is_dir($targetDir)) {
            mkdir($targetDir, 0755, true);
        }

        if (rename($quarantineFile, $originalPath)) {
            unlink($metadataFile);
            return ['success' => true, 'message' => 'File berhasil dipulihkan ke lokasi semula.'];
        }

        return ['success' => false, 'message' => 'Gagal memulihkan file.'];
    }

    private function addThreat($filePath, $severity, $type, $description) {
        $this->threatsFound[] = [
            'file' => $filePath,
            'severity' => $severity,
            'type' => $type,
            'description' => $description,
            'hash' => hash_file('sha256', $filePath),
            'detected_at' => date('Y-m-d H:i:s')
        ];
    }
}
<?php
/**
 * Security Web Application (SWA) - File & Malware Scanner Interface
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
require_once SWA_CORE_DIR . '/FileScanner.php';

$auth = new SWA_Auth();

// Proteksi Sesi Operator
if (!$auth->check()) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Sesi berakhir. Silakan login kembali.']);
        exit();
    }
    header('Location: login.php');
    exit();
}

$scanner = new SWA_FileScanner();

// ------------------------------------------------------------------------
// HANDLER PENANGANAN AJAX (SCAN RUNNER & QUARANTINE ACTION)
// ------------------------------------------------------------------------
$action = $_GET['action'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($action)) {
    header('Content-Type: application/json');

    if ($action === 'run_scan') {
        $targetDir = $_POST['target_dir'] ?? '';
        
        // Jika target direktori kosong, default ke root proyek website
        if (empty($targetDir)) {
            $targetDir = dirname(SWA_ROOT_DIR);
        }

        $result = $scanner->scanDirectory($targetDir);
        echo json_encode($result);
        exit();
    }

    if ($action === 'quarantine') {
        $filePath = $_POST['file_path'] ?? '';
        $result = $scanner->quarantineFile($filePath);
        echo json_encode($result);
        exit();
    }

    if ($action === 'restore') {
        $quarantineFile = $_POST['quarantine_file'] ?? '';
        $result = $scanner->restoreFile($quarantineFile);
        echo json_encode($result);
        exit();
    }

    echo json_encode(['success' => false, 'message' => 'Aksi tidak valid.']);
    exit();
}

$pageTitle = 'Pemindai File & Malware';
require_once SWA_ROOT_DIR . '/includes/header.php';
?>

<!-- CONTROL PANEL SCANNER -->
<div class="swa-card gold-border" style="margin-bottom: 25px;">
    <h3>KONTROL PEMINDAIAN FILE REAL-TIME</h3>
    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 15px;">
        Sistem akan memindai secara fisik direktori file server dari keberadaan Webshell, Backdoor, Obfuscated PHP, serta Steganografi pada gambar.
    </p>

    <div style="display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
        <div style="flex-grow: 1; min-width: 300px;">
            <label for="scan-target-dir" style="display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 5px;">
                Direktori Target Pemindaian (Kosongkan untuk memindai seluruh direktori web)
            </label>
            <input 
                type="text" 
                id="scan-target-dir" 
                class="form-control" 
                placeholder="Contoh: /var/www/html/ atau leave blank" 
                value=""
            >
        </div>

        <div style="margin-top: 20px;">
            <button id="btn-start-scan" class="btn btn-gold">
                Mulai Pemindaian Lengkap
            </button>
        </div>
    </div>

    <div id="scan-status-text" style="margin-top: 15px; font-size: 13px; color: var(--accent-blue); font-weight: 500;">
        Siap melakukan pemindaian.
    </div>
</div>

<!-- CONTAINER HASIL SCANNING -->
<div id="scan-results">
    <!-- Hasil AJAX scan akan ditampilkan di sini -->
</div>

<!-- JS Main Script File -->
<script src="assets/js/main.js"></script>

</main>
</body>
</html>
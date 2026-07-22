<?php
/**
 * Security Web Application (SWA) - Emergency Lockdown Interface
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

// Proteksi Sesi Operator
if (!$auth->check()) {
    header('Location: login.php');
    exit();
}

$lockdownFile = SWA_ROOT_DIR . '/.swa_lockdown_active';
$htaccessPath = dirname(SWA_ROOT_DIR) . '/.htaccess';
$htaccessBackup = dirname(SWA_ROOT_DIR) . '/.htaccess.swa_backup';

$message = '';
$messageType = 'green';

// ------------------------------------------------------------------------
// HANDLER PENGATURAN STATUS LOCKDOWN
// ------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'enable') {
        // Aktifkan Emergency Lockdown
        file_put_contents($lockdownFile, date('Y-m-d H:i:s'));

        // Backup .htaccess asli jika ada
        if (file_exists($htaccessPath) && !file_exists($htaccessBackup)) {
            copy($htaccessPath, $htaccessBackup);
        }

        // Tulis aturan isolasi total ke .htaccess
        $lockdownRules = "# SWA EMERGENCY LOCKDOWN ACTIVE\n";
        $lockdownRules .= "<IfModule mod_authz_core.c>\n";
        $lockdownRules .= "    Require all denied\n";
        
        // Tetap izinkan IP Whitelist Operator jika terdefinisi
        $config = require SWA_CONFIG_DIR . '/config.php';
        $whitelistedIps = $config['whitelist']['ips'] ?? [];
        foreach ($whitelistedIps as $ip) {
            $lockdownRules .= "    Require ip {$ip}\n";
        }
        $lockdownRules .= "</IfModule>\n";

        file_put_contents($htaccessPath, $lockdownRules);

        $message = "EMERGENCY LOCKDOWN BERHASIL DIAKTIFKAN! Seluruh akses aplikasi web utama telah diisolasi.";
        $messageType = "red";

    } elseif ($action === 'disable') {
        // Nonaktifkan Lockdown
        if (file_exists($lockdownFile)) {
            unlink($lockdownFile);
        }

        // Pulihkan .htaccess asli
        if (file_exists($htaccessBackup)) {
            copy($htaccessBackup, $htaccessPath);
            unlink($htaccessBackup);
        } else if (file_exists($htaccessPath)) {
            // Jika tidak ada backup, hapus .htaccess buatan lockdown
            unlink($htaccessPath);
        }

        $message = "Mode Lockdown telah dinonaktifkan. Akses aplikasi web kembali normal.";
        $messageType = "green";
    }
}

$isLockdownActive = file_exists($lockdownFile);
$pageTitle = 'Emergency Lockdown';
require_once SWA_ROOT_DIR . '/includes/header.php';
?>

<!-- STATUS DISPLAY CARD -->
<div class="swa-card <?php echo $isLockdownActive ? 'red-border' : 'green-border'; ?>" style="margin-bottom: 25px;">
    <h3>STATUS DARURAT SISTEM</h3>
    <div style="margin: 15px 0;">
        <?php if ($isLockdownActive): ?>
            <span class="btn btn-red" style="font-size: 16px; padding: 8px 16px;">
                🚨 MODE LOCKDOWN SEDANG AKTIF
            </span>
            <p style="font-size: 13px; color: var(--accent-red); margin-top: 10px;">
                Aktif Sejak: <strong><?php echo htmlspecialchars(file_get_contents($lockdownFile), ENT_QUOTES, 'UTF-8'); ?></strong>
            </p>
        <?php else: ?>
            <span class="btn btn-green" style="font-size: 16px; padding: 8px 16px;">
                ✓ SISTEM BEROPERASI NORMAL
            </span>
            <p style="font-size: 13px; color: var(--text-secondary); margin-top: 10px;">
                Tidak ada pembatasan darurat yang diterapkan pada lalu lintas server.
            </p>
        <?php endif; ?>
    </div>
</div>

<?php if (!empty($message)): ?>
    <div class="swa-card <?php echo $messageType === 'red' ? 'red-border' : 'green-border'; ?>" style="margin-bottom: 25px; padding: 15px;">
        <span style="color: var(--accent-<?php echo $messageType; ?>); font-size: 13px; font-weight: bold;">
            <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
        </span>
    </div>
<?php endif; ?>

<!-- CONTROL PANEL -->
<div class="swa-card gold-border">
    <h3>PANEL KONTROL ISOLASI DARURAT</h3>
    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px; line-height: 1.6;">
        Fitur <strong>Emergency Lockdown</strong> dirancang untuk merespons serangan siber berskala besar (seperti Zero-Day Exploit atau Ransomware). Ketika diaktifkan, modul ini akan memblokir seluruh lalu lintas HTTP dari publik secara langsung pada level server web web server (`.htaccess`).
    </p>

    <?php if (!$isLockdownActive): ?>
        <form method="POST" action="lockdown.php" onsubmit="return confirm('PERINGATAN SANGAT PENTING!\n\nMengaktifkan Mode Lockdown akan memblokir seluruh pengunjung umum dari mengakses website Anda.\n\nApakah Anda yakin ingin melanjutkan?');">
            <input type="hidden" name="action" value="enable">
            <button type="submit" class="btn btn-red" style="padding: 12px 24px; font-size: 15px;">
                🚨 AKTIFKAN LOCKDOWN DARURAT SEKARANG
            </button>
        </form>
    <?php else: ?>
        <form method="POST" action="lockdown.php" onsubmit="return confirm('Apakah Anda yakin ingin menonaktifkan Mode Lockdown dan membuka kembali akses website untuk umum?');">
            <input type="hidden" name="action" value="disable">
            <button type="submit" class="btn btn-green" style="padding: 12px 24px; font-size: 15px;">
                🔓 NONAKTIFKAN LOCKDOWN & NORMALKAN AKSES
            </button>
        </form>
    <?php endif; ?>
</div>

</main>
</body>
</html>
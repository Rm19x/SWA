<?php
/**
 * Security Web Application (SWA) - Firewall & Rules Management Interface
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

$configFile = SWA_CONFIG_DIR . '/config.php';
$configData = require $configFile;

$message = '';
$messageType = 'green';

// ------------------------------------------------------------------------
// HANDLER PEMBARUAN KONFIGURASI FIREWALL
// ------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'update_whitelist') {
        $whitelistIpsRaw = $_POST['whitelist_ips'] ?? '';
        
        // Split berdasarkan baris baru atau koma
        $ipArray = array_map('trim', preg_split('/[\r\n,]+/', $whitelistIpsRaw));
        $ipArray = array_filter($ipArray, function($ip) {
            return !empty($ip) && (filter_var($ip, FILTER_VALIDATE_IP) || $ip === '127.0.0.1');
        });

        $configData['whitelist']['ips'] = array_values(array_unique($ipArray));

        // Simpan kembali konfigurasi ke file config.php
        $configContent = "<?php\n/**\n * SWA Security Configuration\n * Auto-generated via Firewall Interface\n */\n\nif (!defined('SWA_EXEC')) {\n    exit('Direct access forbidden.');\n}\n\nreturn " . var_export($configData, true) . ";\n";

        if (file_put_contents($configFile, $configContent, LOCK_EX)) {
            $message = "Daftar IP Whitelist berhasil diperbarui.";
            $messageType = "green";
        } else {
            $message = "Gagal memperbarui file konfigurasi. Periksa izin akses (permission) folder config.";
            $messageType = "red";
        }
    }
}

$currentWhitelist = implode("\n", $configData['whitelist']['ips'] ?? []);
$pageTitle = 'Konfigurasi Firewall';
require_once SWA_ROOT_DIR . '/includes/header.php';
?>

<!-- STATUS RINGKASAN MODUL FIREWALL -->
<div class="swa-grid" style="margin-bottom: 25px;">
    <div class="swa-card <?php echo SWA_WAF_ENABLED ? 'green-border' : 'red-border'; ?>">
        <h3>Status WAF Core Engine</h3>
        <div class="metric" style="color: <?php echo SWA_WAF_ENABLED ? 'var(--accent-green)' : 'var(--accent-red)'; ?>;">
            <?php echo SWA_WAF_ENABLED ? 'AKTIF' : 'NON-AKTIF'; ?>
        </div>
        <span style="font-size: 11px; color: var(--text-secondary);">Inspeksi Payload HTTP Real-time</span>
    </div>

    <div class="swa-card gold-border">
        <h3>Rate Limit Max Request</h3>
        <div class="metric" style="color: var(--accent-gold);">
            <?php echo SWA_RATE_LIMIT_MAX_REQUESTS; ?> req
        </div>
        <span style="font-size: 11px; color: var(--text-secondary);">Batas per <?php echo SWA_RATE_LIMIT_WINDOW; ?> Detik</span>
    </div>

    <div class="swa-card blue-border">
        <h3>Durasi Blokir Rate Limit</h3>
        <div class="metric" style="color: var(--accent-blue);">
            <?php echo ceil(SWA_BLOCK_DURATION / 60); ?> min
        </div>
        <span style="font-size: 11px; color: var(--text-secondary);">Waktu Isolasian IP Terdeteksi Spam</span>
    </div>
</div>

<?php if (!empty($message)): ?>
    <div class="swa-card <?php echo $messageType === 'red' ? 'red-border' : 'green-border'; ?>" style="margin-bottom: 25px; padding: 15px;">
        <span style="color: var(--accent-<?php echo $messageType; ?>); font-size: 13px; font-weight: bold;">
            <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
        </span>
    </div>
<?php endif; ?>

<!-- MANAJEMEN WHITELIST IP -->
<div class="swa-card gold-border">
    <h3>MANAJEMEN ALAMAT IP WHITELIST</h3>
    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px; line-height: 1.6;">
        Alamat IP yang didaftarkan di bawah ini akan diabaikan oleh <strong>WAF Engine</strong> dan <strong>Rate Limiter</strong>. Masukkan satu alamat IP per baris.
    </p>

    <form method="POST" action="firewall.php">
        <input type="hidden" name="action" value="update_whitelist">
        
        <div class="form-group">
            <label for="whitelist_ips">Alamat IP Diizinkan (IP Whitelist)</label>
            <textarea 
                id="whitelist_ips" 
                name="whitelist_ips" 
                class="form-control" 
                rows="6" 
                style="font-family: monospace; font-size: 13px; line-height: 1.5;"
                placeholder="127.0.0.1&#10;192.168.1.100"
            ><?php echo htmlspecialchars($currentWhitelist, ENT_QUOTES, 'UTF-8'); ?></textarea>
        </div>

        <button type="submit" class="btn btn-gold" style="margin-top: 10px;">
            Simpan Perubahan Whitelist
        </button>
    </form>
</div>

</main>
</body>
</html>
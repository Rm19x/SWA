<?php
/**
 * Security Web Application (SWA) - WAF Attack Logs & Audit Interface
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
require_once SWA_CORE_DIR . '/Logger.php';

$auth = new SWA_Auth();

// Proteksi Sesi Operator
if (!$auth->check()) {
    header('Location: login.php');
    exit();
}

$logger = new SWA_Logger();

// ------------------------------------------------------------------------
// HANDLER EKSPOR CSV DAN PEMBERSIHAN LOG
// ------------------------------------------------------------------------
$action = $_GET['action'] ?? '';

if ($action === 'export_csv') {
    $logger->exportCsv();
    exit();
}

if ($action === 'clear_logs' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $logger->clearLogs();
    header('Location: waf_logs.php?msg=cleared');
    exit();
}

$logs = $logger->getLogs();
$pageTitle = 'Log Firewall & WAF';
require_once SWA_ROOT_DIR . '/includes/header.php';
?>

<!-- KONTROL PANAL UTAMA -->
<div class="swa-card gold-border" style="margin-bottom: 25px;">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;">
        <div>
            <h3>REKAPITULASI AUDIT SERANGAN WAF</h3>
            <p style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">
                Menampilkan seluruh catatan insiden keamanan yang berhasil dihalangi oleh SWA Engine.
            </p>
        </div>

        <div style="display: flex; gap: 10px;">
            <a href="waf_logs.php?action=export_csv" class="btn btn-blue" style="font-size: 13px;">
                📥 Ekspor CSV
            </a>
            
            <form method="POST" action="waf_logs.php?action=clear_logs" onsubmit="return confirm('Apakah Anda yakin ingin menghapus seluruh log insiden?');" style="margin: 0;">
                <button type="submit" class="btn btn-red" style="font-size: 13px;">
                    🗑️ Bersihkan Log
                </button>
            </form>
        </div>
    </div>
</div>

<?php if (isset($_GET['msg']) && $_GET['msg'] === 'cleared'): ?>
    <div class="swa-card green-border" style="margin-bottom: 20px; padding: 12px 20px;">
        <span style="color: var(--accent-green); font-size: 13px;">✓ Seluruh catatan log berhasil dibersihkan.</span>
    </div>
<?php endif; ?>

<!-- TABEL UTAMA LOG WAF -->
<div class="swa-card">
    <div class="swa-table-container">
        <table class="swa-table">
            <thead>
                <tr>
                    <th>Waktu Insiden</th>
                    <th>Alamat IP</th>
                    <th>Tipe Serangan</th>
                    <th>Target Parameter</th>
                    <th>Sampel Payload</th>
                    <th>User Agent</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($logs)): ?>
                    <tr>
                        <td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 25px;">
                            Tidak ditemukan log insiden. Sistem beroperasi secara aman.
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($logs as $log): ?>
                        <tr>
                            <td style="font-family: monospace; font-size: 12px; color: var(--accent-gold); white-space: nowrap;">
                                <?php echo htmlspecialchars($log['timestamp'] ?? '-', ENT_QUOTES, 'UTF-8'); ?>
                            </td>
                            <td style="font-family: monospace; font-size: 12px; color: var(--accent-blue); white-space: nowrap;">
                                <?php echo htmlspecialchars($log['ip'] ?? '-', ENT_QUOTES, 'UTF-8'); ?>
                            </td>
                            <td>
                                <span class="btn btn-red" style="padding: 3px 8px; font-size: 11px; display: inline-block;">
                                    <?php echo htmlspecialchars($log['type'] ?? 'Threat', ENT_QUOTES, 'UTF-8'); ?>
                                </span>
                            </td>
                            <td style="font-family: monospace; font-size: 12px; color: var(--text-primary);">
                                <?php echo htmlspecialchars($log['target'] ?? '-', ENT_QUOTES, 'UTF-8'); ?>
                            </td>
                            <td style="font-family: monospace; font-size: 11px; color: #f85149; background-color: rgba(248, 81, 73, 0.05); max-width: 250px; word-break: break-all;">
                                <?php echo htmlspecialchars($log['payload'] ?? '-', ENT_QUOTES, 'UTF-8'); ?>
                            </td>
                            <td style="color: var(--text-secondary); font-size: 11px; max-width: 200px; word-break: break-all;">
                                <?php echo htmlspecialchars($log['user_agent'] ?? '-', ENT_QUOTES, 'UTF-8'); ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

</main>
</body>
</html>
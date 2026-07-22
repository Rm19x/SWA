<?php
/**
 * Security Web Application (SWA) - Master Dashboard Interface
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
$summary = $logger->getSecuritySummary();

// ------------------------------------------------------------------------
// AUDIT KEAMANAN LINGKUNGAN SERVER & PERHITUNGAN HEALTH SCORE
// ------------------------------------------------------------------------
$healthScore = 100;
$healthIssues = [];

// Audit 1: Versi PHP (Fitur #60)
$phpVersion = PHP_VERSION;
if (version_compare($phpVersion, '8.0.0', '<')) {
    $healthScore -= 20;
    $healthIssues[] = "Versi PHP ({$phpVersion}) sudah usang/kedaluwarsa. Disarankan update ke PHP 8.x+.";
}

// Audit 2: Izin Akses Folder Utama / Permission Check (Fitur #59)
$rootPermission = substr(sprintf('%o', fileperms(SWA_ROOT_DIR)), -3);
if ($rootPermission === '777') {
    $healthScore -= 30;
    $healthIssues[] = "Izin folder root bersifat 777 (Sangat Berbahaya). Ubah ke 0755 atau 0750.";
}

// Audit 3: Status WAF Modul
if (!SWA_WAF_ENABLED) {
    $healthScore -= 25;
    $healthIssues[] = "WAF Engine dalam kondisi non-aktif.";
}

// Batasi skor minimum 0%
$healthScore = max(0, $healthScore);

$pageTitle = 'Dashboard Utama';
require_once SWA_ROOT_DIR . '/includes/header.php';
?>

<!-- METRIC CARDS -->
<div class="swa-grid">
    <div class="swa-card gold-border">
        <h3>Skor Kesehatan Keamanan</h3>
        <div class="metric" style="color: <?php echo ($healthScore >= 80) ? 'var(--accent-green)' : (($healthScore >= 50) ? 'var(--accent-gold)' : 'var(--accent-red)'); ?>;">
            <?php echo $healthScore; ?>%
        </div>
        <span style="font-size: 11px; color: var(--text-secondary);">Indikator Integritas Sistem</span>
    </div>

    <div class="swa-card red-border">
        <h3>Total Serangan Dicegah</h3>
        <div class="metric" style="color: var(--accent-red);">
            <?php echo $summary['total_attacks']; ?>
        </div>
        <span style="font-size: 11px; color: var(--text-secondary);">Payload & Anomali Terdeteksi</span>
    </div>

    <div class="swa-card blue-border">
        <h3>IP Penyerang Unik</h3>
        <div class="metric" style="color: var(--accent-blue);">
            <?php echo $summary['unique_attackers']; ?>
        </div>
        <span style="font-size: 11px; color: var(--text-secondary);">Alamat IP Diblokir / Dicatat</span>
    </div>

    <div class="swa-card green-border">
        <h3>Versi PHP Server</h3>
        <div class="metric" style="font-size: 20px; color: var(--accent-green); margin-top: 6px;">
            v<?php echo PHP_VERSION; ?>
        </div>
        <span style="font-size: 11px; color: var(--text-secondary);">Lingkungan Eksekusi PHP</span>
    </div>
</div>

<!-- AUDIT SYSTEM WARNINGS -->
<?php if (!empty($healthIssues)): ?>
    <div class="swa-card red-border" style="margin-bottom: 25px;">
        <h3 style="color: var(--accent-red);">PERINGATAN AUDIT KEAMANAN SERVER</h3>
        <ul style="margin-left: 20px; font-size: 13px; color: var(--text-primary); margin-top: 10px;">
            <?php foreach ($healthIssues as $issue): ?>
                <li style="margin-bottom: 6px;"><?php echo htmlspecialchars($issue, ENT_QUOTES, 'UTF-8'); ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<!-- RECENT ATTACK LOGS -->
<div class="swa-card" style="margin-bottom: 25px;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
        <h3>Aktivitas Serangan Terakhir</h3>
        <a href="waf_logs.php" class="btn btn-blue" style="font-size: 12px; padding: 5px 12px;">Lihat Semua Log</a>
    </div>

    <div class="swa-table-container">
        <table class="swa-table">
            <thead>
                <tr>
                    <th>Waktu</th>
                    <th>Alamat IP</th>
                    <th>Tipe Serangan</th>
                    <th>Target Parameter</th>
                    <th>User Agent</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($summary['recent_logs'])): ?>
                    <tr>
                        <td colspan="5" style="text-align: center; color: var(--text-secondary); padding: 20px;">
                            Belum ada catatan percobaan serangan. Sistem dalam keadaan kondusif.
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($summary['recent_logs'] as $log): ?>
                        <tr>
                            <td style="font-family: monospace; font-size: 12px; color: var(--accent-gold);">
                                <?php echo htmlspecialchars($log['timestamp'], ENT_QUOTES, 'UTF-8'); ?>
                            </td>
                            <td style="font-family: monospace; font-size: 12px; color: var(--accent-blue);">
                                <?php echo htmlspecialchars($log['ip'], ENT_QUOTES, 'UTF-8'); ?>
                            </td>
                            <td>
                                <span class="btn btn-red" style="padding: 2px 8px; font-size: 10px;">
                                    <?php echo htmlspecialchars($log['type'], ENT_QUOTES, 'UTF-8'); ?>
                                </span>
                            </td>
                            <td style="font-family: monospace; font-size: 12px;">
                                <?php echo htmlspecialchars($log['target'], ENT_QUOTES, 'UTF-8'); ?>
                            </td>
                            <td style="color: var(--text-secondary); font-size: 11px;">
                                <?php echo htmlspecialchars(mb_strimwidth($log['user_agent'], 0, 40, '...'), ENT_QUOTES, 'UTF-8'); ?>
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
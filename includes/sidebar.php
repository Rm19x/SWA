<?php
/**
 * Security Web Application (SWA) - Sidebar Navigation Component
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

$currentPage = basename($_SERVER['PHP_SELF']);
?>

<aside class="swa-sidebar">
    <div class="swa-brand">
        <h2>SWA SECURITY</h2>
        <a href="https://github.com/Rm19x" target="_blank" class="dev-tag">By Mr.Rm19</a>
    </div>

    <ul class="swa-nav">
        <li class="swa-nav-item <?php echo ($currentPage === 'dashboard.php' || $currentPage === 'index.php') ? 'active' : ''; ?>">
            <a href="dashboard.php">
                <span class="icon"></span>
                <span class="label">Dashboard Utama</span>
            </a>
        </li>

        <li class="swa-nav-item <?php echo ($currentPage === 'scanner.php') ? 'active' : ''; ?>">
            <a href="scanner.php">
                <span class="icon"></span>
                <span class="label">Pemindai Malware & File</span>
            </a>
        </li>

        <li class="swa-nav-item <?php echo ($currentPage === 'waf_logs.php') ? 'active' : ''; ?>">
            <a href="waf_logs.php">
                <span class="icon"></span>
                <span class="label">Log Firewall & WAF</span>
            </a>
        </li>

        <li class="swa-nav-item <?php echo ($currentPage === 'lockdown.php') ? 'active' : ''; ?>">
            <a href="lockdown.php">
                <span class="icon"></span>
                <span class="label">Emergency Lockdown</span>
            </a>
        </li>
    </ul>

    <div style="padding: 20px; border-top: 1px solid var(--border-color);">
        <div style="background-color: var(--bg-card); padding: 12px; border-radius: 6px; border: 1px solid var(--border-color); font-size: 11px;">
            <div style="color: var(--accent-green); font-weight: bold; margin-bottom: 4px;">● STATUS SYSTEM ACTIVE</div>
            <div style="color: var(--text-secondary);">Core WAF: Enforcing</div>
            <div style="color: var(--text-secondary);">Rate Limiter: Active</div>
        </div>

        <a href="logout.php" class="btn btn-red" style="width: 100%; text-align: center; margin-top: 15px; box-sizing: border-box;">
            Keluar (Logout)
        </a>
    </div>
</aside>
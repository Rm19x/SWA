<?php
/**
 * Security Web Application (SWA) - Header Component
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

$pageTitle = $pageTitle ?? 'Dashboard Keamanan';
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8'); ?> - SWA Security</title>
    
    <!-- SWA Master CSS -->
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>

<?php require_once SWA_ROOT_DIR . '/includes/sidebar.php'; ?>

<main class="swa-main">
    <header class="swa-header">
        <div>
            <h1><?php echo htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8'); ?></h1>
            <span style="font-size: 12px; color: var(--text-secondary);">
                SWA (Security Web Application) Engine v1.0.0
            </span>
        </div>

        <div style="display: flex; align-items: center; gap: 15px;">
            <div class="swa-user-badge">
                <span style="color: var(--accent-green);">●</span> Operator: <strong><?php echo SWA_ADMIN_USER; ?></strong>
            </div>
        </div>
    </header>

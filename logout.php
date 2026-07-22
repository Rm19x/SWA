<?php
/**
 * Security Web Application (SWA) - Logout Script
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
$auth->logout();

// Redirect ke halaman login setelah logout
header('Location: login.php');
exit();
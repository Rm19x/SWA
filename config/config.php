<?php
/**
 * Security Web Application (SWA) - Core Configuration
 * 
 * @package     SWA Security Suite
 * @author      Mr.Rm19
 * @link        https://github.com/Rm19x
 * @license     MIT License
 * @version     1.0.0
 */

if (!defined('SWA_EXEC')) {
    define('SWA_EXEC', true);
}

// ------------------------------------------------------------------------
// 1. SYSTEM & DIRECTORY PATHS (Dengan Proteksi Redefine)
// ------------------------------------------------------------------------
if (!defined('SWA_ROOT_DIR')) {
    define('SWA_ROOT_DIR', dirname(__DIR__));
}
if (!defined('SWA_CONFIG_DIR')) {
    define('SWA_CONFIG_DIR', SWA_ROOT_DIR . '/config');
}
if (!defined('SWA_CORE_DIR')) {
    define('SWA_CORE_DIR', SWA_ROOT_DIR . '/core');
}
if (!defined('SWA_LOG_DIR')) {
    define('SWA_LOG_DIR', SWA_ROOT_DIR . '/logs');
}
if (!defined('SWA_QUARANTINE_DIR')) {
    define('SWA_QUARANTINE_DIR', SWA_ROOT_DIR . '/quarantine');
}

if (!defined('SWA_LOG_FILE')) {
    define('SWA_LOG_FILE', SWA_LOG_DIR . '/attack_logs.json');
}
if (!defined('SWA_LOCKOUT_FILE')) {
    define('SWA_LOCKOUT_FILE', SWA_LOG_DIR . '/lockouts.json');
}

// ------------------------------------------------------------------------
// 2. AUTHENTICATION & SESSION CONFIGURATION
// ------------------------------------------------------------------------
if (!defined('SWA_ADMIN_USER')) {
    define('SWA_ADMIN_USER', 'Mr.Rm19');
}
if (!defined('SWA_ADMIN_PASS_HASH')) {
    define('SWA_ADMIN_PASS_HASH', '$2y$10$sX8.E3K8kE2LgZ/.r3xNceB1kS5j0/3T4w/5H8K5j/3T4w/5H8K5j');
}
if (!defined('SWA_SESSION_NAME')) {
    define('SWA_SESSION_NAME', 'SWA_SECURE_SESSID');
}
if (!defined('SWA_SESSION_LIFETIME')) {
    define('SWA_SESSION_LIFETIME', 3600); // 1 jam
}

// ------------------------------------------------------------------------
// 3. FIREWALL & RATE LIMITING SETTINGS
// ------------------------------------------------------------------------
if (!defined('SWA_WAF_ENABLED')) {
    define('SWA_WAF_ENABLED', true);
}
if (!defined('SWA_RATE_LIMIT_MAX_REQUESTS')) {
    define('SWA_RATE_LIMIT_MAX_REQUESTS', 100); // Maksimal request per window
}
if (!defined('SWA_RATE_LIMIT_WINDOW')) {
    define('SWA_RATE_LIMIT_WINDOW', 60);       // Window dalam detik
}
if (!defined('SWA_MAX_LOGIN_ATTEMPTS')) {
    define('SWA_MAX_LOGIN_ATTEMPTS', 5);         // Batas gagal login sebelum diblokir
}
if (!defined('SWA_BLOCK_DURATION')) {
    define('SWA_BLOCK_DURATION', 1800);          // Durasi pemblokiran IP (30 menit)
}

// ------------------------------------------------------------------------
// 4. SCANNER & THREAT DETECTION SIGNATURES
// ------------------------------------------------------------------------
return [
    'app' => [
        'name' => 'SWA Security',
        'version' => '1.0.0',
        'developer' => 'Mr.Rm19',
        'github' => 'https://github.com/Rm19x'
    ],
    
    'signatures' => [
        'sqli' => [
            '/(\%27)|(\')|(\-\-)|(\%23)|(#)/i',
            '/(SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)/i',
            '/(UNION\s+ALL\s+SELECT|UNION\s+SELECT)/i',
            '/(OR\s+1=1|AND\s+1=1|OR\s+\'1\'=\'1\')/i',
            '/(BENCHMARK\(|SLEEP\()/i'
        ],
        'xss' => [
            '/(<script[^>]*>.*<\/script>)/is',
            '/(javascript:[^\s]*)/i',
            '/(onerror|onload|onclick|onmouseover|onfocus)\s*=/i',
            '/(<iframe[^>]*>|<object[^>]*>|<embed[^>]*>)/i'
        ],
        'rce' => [
            '/(system|exec|passthru|shell_exec|popen|proc_open|assert)\s*\(/i',
            '/(`[^`]*`)/i',
            '/(eval|create_function)\s*\(/i'
        ],
        'lfi_rfi' => [
            '/(\.\.\/|\.\.\\\\)/i',
            '/(php:\/\/filter|php:\/\/input|data:\/\/|file:\/\/)/i',
            '/(http|https|ftp):\/\//i'
        ],
        'dangerous_functions' => [
            'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open',
            'pcntl_exec', 'eval', 'assert', 'create_function', 'include_once',
            'require_once', 'base64_decode', 'gzuncompress', 'gzinflate'
        ],
        'suspicious_extensions' => [
            'php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'pl', 'py', 'sh', 'cgi', 'asp', 'aspx'
        ]
    ],

    'whitelist' => [
        'ips' => [
            '127.0.0.1',
            '::1'
        ],
        'paths' => [
            '/assets/',
            '/favicon.ico'
        ]
    ]
];

<?php
/**
 * Security Web Application (SWA) - Web Application Firewall Engine
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

class SWA_WafEngine {
    
    private $config;
    private $logger;
    private $signatures = [];

    public function __construct($loggerInstance = null) {
        $this->config = require SWA_CONFIG_DIR . '/config.php';
        $this->signatures = $this->config['signatures'] ?? [];
        $this->logger = $loggerInstance;
    }

    public function inspectRequest() {
        if (!SWA_WAF_ENABLED) {
            return true;
        }

        $clientIp = $this->getClientIp();
        
        // Whitelist IP Check
        if (in_array($clientIp, $this->config['whitelist']['ips'] ?? [])) {
            return true;
        }

        // 1. Audit HTTP Method & Headers
        $this->validateHttpMethod();
        $this->inspectHeaders();

        // 2. Inspection Payload GET, POST, COOKIE
        $this->inspectArray('GET', $_GET);
        $this->inspectArray('POST', $_POST);
        $this->inspectArray('COOKIE', $_COOKIE);

        // 3. Inspection Raw Input (JSON / REST API)
        $rawInput = file_get_contents('php://input');
        if (!empty($rawInput)) {
            $this->inspectPayload('RAW_BODY', $rawInput);
        }

        return true;
    }

    private function inspectArray($source, $data, $prefix = '') {
        foreach ($data as $key => $value) {
            $paramName = $prefix !== '' ? "{$prefix}[{$key}]" : $key;

            if (is_array($value)) {
                $this->inspectArray($source, $value, $paramName);
            } else {
                $this->inspectPayload("{$source}:{$paramName}", $value);
            }
        }
    }

    private function inspectPayload($target, $value) {
        if (empty($value) || !is_string($value)) {
            return;
        }

        // Null Byte Injection
        if (strpos($value, "\0") !== false) {
            $this->triggerBlock('Null Byte Injection', $target, $value);
        }

        // SQL Injection Detection
        foreach ($this->signatures['sqli'] ?? [] as $pattern) {
            if (preg_match($pattern, $value)) {
                $this->triggerBlock('SQL Injection (SQLi)', $target, $value);
            }
        }

        // XSS Detection
        foreach ($this->signatures['xss'] ?? [] as $pattern) {
            if (preg_match($pattern, $value)) {
                $this->triggerBlock('Cross-Site Scripting (XSS)', $target, $value);
            }
        }

        // RCE Detection
        foreach ($this->signatures['rce'] ?? [] as $pattern) {
            if (preg_match($pattern, $value)) {
                $this->triggerBlock('Remote Code Execution (RCE)', $target, $value);
            }
        }

        // LFI / RFI Detection
        foreach ($this->signatures['lfi_rfi'] ?? [] as $pattern) {
            if (preg_match($pattern, $value)) {
                $this->triggerBlock('Local/Remote File Inclusion (LFI/RFI)', $target, $value);
            }
        }

        // Server-Side Template Injection (SSTI) Detection
        if (preg_match('/(\{\{.*\}\}|\{%.*%\})/i', $value)) {
            $this->triggerBlock('Server-Side Template Injection (SSTI)', $target, $value);
        }

        // LDAP Injection Detection
        if (preg_match('/(\*|\(|\)|&|\|)/i', $value) && preg_match('/(objectClass|admin|userPassword)/i', $value)) {
            $this->triggerBlock('LDAP Injection', $target, $value);
        }
    }

    private function validateHttpMethod() {
        $allowedMethods = ['GET', 'POST', 'HEAD', 'OPTIONS'];
        $requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        if (!in_array(strtoupper($requestMethod), $allowedMethods, true)) {
            $this->triggerBlock('Unsupported / Malicious HTTP Method', 'HEADER:METHOD', $requestMethod);
        }
    }

    private function inspectHeaders() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';

        // Suspicious User-Agent Detection
        if (empty($userAgent) || preg_match('/(sqlmap|nikto|nmap|dirbuster|gobuster|w3af|acunetix|havij)/i', $userAgent)) {
            $this->triggerBlock('Malicious Scanner / Bot User-Agent', 'HEADER:USER_AGENT', $userAgent);
        }

        // Referer & Header Payload Inspection
        $this->inspectPayload('HEADER:USER_AGENT', $userAgent);
        $this->inspectPayload('HEADER:REFERER', $referer);
    }

    private function triggerBlock($attackType, $target, $payload) {
        $eventData = [
            'ip'          => $this->getClientIp(),
            'timestamp'   => date('Y-m-d H:i:s'),
            'type'        => $attackType,
            'target'      => $target,
            'payload'     => mb_strimwidth($payload, 0, 200, '...'),
            'user_agent'  => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? ''
        ];

        if ($this->logger && method_exists($this->logger, 'logAttack')) {
            $this->logger->logAttack($eventData);
        }

        http_response_code(403);
        header('Content-Type: text/html; charset=utf-8');
        header('X-Protected-By: SWA Security Suite - Mr.Rm19');
        
        echo $this->renderBlockPage($attackType);
        exit();
    }

    private function renderBlockPage($attackType) {
        $ip = htmlspecialchars($this->getClientIp(), ENT_QUOTES, 'UTF-8');
        $time = date('Y-m-d H:i:s');
        $dev = htmlspecialchars($this->config['app']['developer'], ENT_QUOTES, 'UTF-8');
        $github = htmlspecialchars($this->config['app']['github'], ENT_QUOTES, 'UTF-8');

        return <<<HTML
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>403 Forbidden - Access Denied</title>
    <style>
        body { background-color: #0d0f12; color: #e1e6ed; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background-color: #161b22; border: 2px solid #da3633; border-radius: 8px; box-shadow: 0 0 20px rgba(218, 54, 51, 0.4); width: 90%; max-width: 600px; padding: 30px; text-align: center; }
        h1 { color: #f85149; margin-top: 0; font-size: 26px; border-bottom: 1px solid #30363d; padding-bottom: 15px; }
        p { font-size: 14px; line-height: 1.6; color: #8b949e; }
        .details { background-color: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin: 20px 0; text-align: left; font-family: monospace; font-size: 13px; color: #d2a8ff; }
        .footer { margin-top: 25px; font-size: 12px; color: #6e7681; border-top: 1px solid #21262d; padding-top: 15px; }
        .footer a { color: #d29922; text-decoration: none; font-weight: bold; }
        .footer a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="card">
        <h1>403 - PERMINTAAN DITOLAK</h1>
        <p>Sistem keamanan mendeteksi aktivitas mencurigakan dan telah memblokir permintaan ini demi melindungi integritas server.</p>
        <div class="details">
            <div><strong>Sistem Proteksi:</strong> SWA (Security Web Application)</div>
            <div><strong>Tipe Serangan:</strong> {$attackType}</div>
            <div><strong>Alamat IP Anda:</strong> {$ip}</div>
            <div><strong>Waktu Kejadian:</strong> {$time}</div>
        </div>
        <div class="footer">
            Dilindungi oleh <strong>SWA Engine</strong> | Developed by <a href="{$github}" target="_blank">{$dev}</a>
        </div>
    </div>
</body>
</html>
HTML;
    }

    private function getClientIp() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($ips[0]);
        }
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }
}
<?php
/**
 * Security Web Application (SWA) - Audit & Event Logger Engine
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

class SWA_Logger {

    private $logFile;
    private $maxLogEntries = 1000;

    public function __construct() {
        $this->logFile = SWA_LOG_FILE;
        $this->ensureLogDirectoryExists();
    }

    public function logAttack(array $eventData) {
        $logs = $this->getLogs();

        $entry = [
            'id'          => uniqid('swa_', true),
            'timestamp'   => $eventData['timestamp'] ?? date('Y-m-d H:i:s'),
            'ip'          => $eventData['ip'] ?? 'Unknown',
            'type'        => $eventData['type'] ?? 'Unspecified Threat',
            'target'      => $eventData['target'] ?? 'General',
            'payload'     => $eventData['payload'] ?? '',
            'user_agent'  => $eventData['user_agent'] ?? 'Unknown',
            'request_uri' => $eventData['request_uri'] ?? ''
        ];

        array_unshift($logs, $entry);

        // Rotasi Log: Batasi jumlah entri log maksimal agar file tetap efisien
        if (count($logs) > $this->maxLogEntries) {
            $logs = array_slice($logs, 0, $this->maxLogEntries);
        }

        $this->saveLogs($logs);
    }

    public function getLogs() {
        if (!file_exists($this->logFile)) {
            return [];
        }

        $content = file_get_contents($this->logFile);
        if (empty($content)) {
            return [];
        }

        return json_decode($content, true) ?? [];
    }

    public function clearLogs() {
        return file_put_contents($this->logFile, json_encode([], JSON_PRETTY_PRINT), LOCK_EX) !== false;
    }

    public function exportCsv() {
        $logs = $this->getLogs();

        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=SWA_Security_Report_' . date('Ymd_His') . '.csv');

        $output = fopen('php://output', 'w');

        // Header CSV
        fputcsv($output, ['ID', 'Waktu', 'Alamat IP', 'Tipe Serangan', 'Target/Parameter', 'Payload Sample', 'User Agent', 'Request URI']);

        foreach ($logs as $log) {
            fputcsv($output, [
                $log['id'] ?? '',
                $log['timestamp'] ?? '',
                $log['ip'] ?? '',
                $log['type'] ?? '',
                $log['target'] ?? '',
                $log['payload'] ?? '',
                $log['user_agent'] ?? '',
                $log['request_uri'] ?? ''
            ]);
        }

        fclose($output);
        exit();
    }

    public function getSecuritySummary() {
        $logs = $this->getLogs();
        $totalAttacks = count($logs);
        $uniqueIps = [];
        $attackTypes = [];

        foreach ($logs as $log) {
            $ip = $log['ip'] ?? 'Unknown';
            $type = $log['type'] ?? 'Unknown';

            $uniqueIps[$ip] = ($uniqueIps[$ip] ?? 0) + 1;
            $attackTypes[$type] = ($attackTypes[$type] ?? 0) + 1;
        }

        return [
            'total_attacks' => $totalAttacks,
            'unique_attackers' => count($uniqueIps),
            'top_attack_types' => $attackTypes,
            'recent_logs' => array_slice($logs, 0, 5)
        ];
    }

    private function ensureLogDirectoryExists() {
        if (!is_dir(SWA_LOG_DIR)) {
            mkdir(SWA_LOG_DIR, 0755, true);
        }

        if (!file_exists($this->logFile)) {
            file_put_contents($this->logFile, json_encode([], JSON_PRETTY_PRINT), LOCK_EX);
        }
    }

    private function saveLogs(array $logs) {
        file_put_contents($this->logFile, json_encode($logs, JSON_PRETTY_PRINT), LOCK_EX);
    }
}
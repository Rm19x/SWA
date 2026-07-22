/**
 * Security Web Application (SWA) - Core UI & AJAX Interactivity
 * 
 * @package     SWA Security Suite
 * @author      Mr.Rm19
 * @link        https://github.com/Rm19x
 * @version     1.0.0
 */

document.addEventListener('DOMContentLoaded', function () {
    
    // ------------------------------------------------------------------------
    // 1. DYNAMIC SIDEBAR NAV HIGHLIGHTING
    // ------------------------------------------------------------------------
    const currentPath = window.location.pathname.split('/').pop();
    const navLinks = document.querySelectorAll('.swa-nav-item a');

    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPath || (currentPath === '' && href === 'dashboard.php')) {
            link.parentElement.classList.add('active');
        } else {
            link.parentElement.classList.remove('active');
        }
    });

    // ------------------------------------------------------------------------
    // 2. SCANNER ENGINE AJAX HANDLER
    // ------------------------------------------------------------------------
    const btnStartScan = document.getElementById('btn-start-scan');
    const scanResultContainer = document.getElementById('scan-results');
    const scanStatusText = document.getElementById('scan-status-text');

    if (btnStartScan) {
        btnStartScan.addEventListener('click', function (e) {
            e.preventDefault();

            const targetDir = document.getElementById('scan-target-dir')?.value || '';

            btnStartScan.disabled = true;
            btnStartScan.innerHTML = '<span class="spinner"></span> Memindai Website...';
            if (scanStatusText) scanStatusText.innerText = 'Pemindaian sedang berlangsung. Mohon tunggu...';

            fetch('scanner.php?action=run_scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'target_dir=' + encodeURIComponent(targetDir)
            })
            .then(response => response.json())
            .then(data => {
                btnStartScan.disabled = false;
                btnStartScan.innerHTML = 'Mulai Pemindaian Lengkap';

                if (data.success) {
                    if (scanStatusText) {
                        scanStatusText.innerText = `Pemindaian selesai: ${data.scanned_files} berkas diperiksa, ${data.threats_count} ancaman ditemukan.`;
                    }
                    renderScanResults(data.threats);
                } else {
                    alert('Gagal melakukan pemindaian: ' + (data.message || 'Terjadi kesalahan sistem.'));
                }
            })
            .catch(error => {
                btnStartScan.disabled = false;
                btnStartScan.innerHTML = 'Mulai Pemindaian Lengkap';
                console.error('SWA Scan Error:', error);
                alert('Terjadi kesalahan koneksi saat memproses pemindaian.');
            });
        });
    }

    // ------------------------------------------------------------------------
    // 3. RENDER THREAT RESULTS
    // ------------------------------------------------------------------------
    function renderScanResults(threats) {
        if (!scanResultContainer) return;

        if (threats.length === 0) {
            scanResultContainer.innerHTML = `
                <div class="swa-card green-border" style="text-align: center; padding: 25px;">
                    <h3 style="color: var(--accent-green);">Sistem Aman</h3>
                    <p style="color: var(--text-secondary); font-size: 13px; margin-top: 5px;">
                        Tidak ditemukan berkas mencurigakan atau webshell pada direktori ini.
                    </p>
                </div>
            `;
            return;
        }

        let html = `
            <div class="swa-table-container">
                <table class="swa-table">
                    <thead>
                        <tr>
                            <th>Tingkat Bahaya</th>
                            <th>Tipe Ancaman</th>
                            <th>Jalur Berkas</th>
                            <th>Deskripsi</th>
                            <th>Tindakan</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        threats.forEach(item => {
            let badgeClass = 'btn-blue';
            if (item.severity === 'CRITICAL' || item.severity === 'HIGH') {
                badgeClass = 'btn-red';
            } else if (item.severity === 'MEDIUM') {
                badgeClass = 'btn-gold';
            }

            html += `
                <tr>
                    <td><span class="btn ${badgeClass}" style="padding: 3px 8px; font-size: 11px;">${item.severity}</span></td>
                    <td><strong>${escapeHtml(item.type)}</strong></td>
                    <td style="font-family: monospace; font-size: 12px; color: var(--accent-blue);">${escapeHtml(item.file)}</td>
                    <td>${escapeHtml(item.description)}</td>
                    <td>
                        <button class="btn btn-red btn-quarantine" data-file="${encodeURIComponent(item.file)}" style="padding: 4px 10px; font-size: 12px;">
                            Karantina
                        </button>
                    </td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                </table>
            </div>
        `;

        scanResultContainer.innerHTML = html;
        bindQuarantineEvents();
    }

    // ------------------------------------------------------------------------
    // 4. FILE QUARANTINE EVENT HANDLER
    // ------------------------------------------------------------------------
    function bindQuarantineEvents() {
        const quarantineButtons = document.querySelectorAll('.btn-quarantine');

        quarantineButtons.forEach(button => {
            button.addEventListener('click', function () {
                const filePath = decodeURIComponent(this.getAttribute('data-file'));

                if (!confirm(`Apakah Anda yakin ingin memindahkan berkas ini ke karantina?\n\nFile: ${filePath}`)) {
                    return;
                }

                this.disabled = true;
                this.innerText = 'Proses...';

                fetch('scanner.php?action=quarantine', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'file_path=' + encodeURIComponent(filePath)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Berkas berhasil dikarantina!');
                        this.closest('tr').remove();
                    } else {
                        alert('Gagal mengkarantina berkas: ' + data.message);
                        this.disabled = false;
                        this.innerText = 'Karantina';
                    }
                })
                .catch(error => {
                    console.error('Quarantine Error:', error);
                    alert('Terjadi kesalahan koneksi.');
                    this.disabled = false;
                    this.innerText = 'Karantina';
                });
            });
        });
    }

    // ------------------------------------------------------------------------
    // 5. HELPER: ESCAPE HTML
    // ------------------------------------------------------------------------
    function escapeHtml(text) {
        if (!text) return '';
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});

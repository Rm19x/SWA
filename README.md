

#  SWA Security  - Security Web Application 

![Version](https://img.shields.io/badge/Version-1.0.0-gold.svg)
![PHP Version](https://img.shields.io/badge/PHP-%3E%3D%207.4%20%7C%208.x-blue.svg)
![Developer](https://img.shields.io/badge/Developer-Mr.Rm19-red.svg)

**SWA Security** adalah aplikasi manajemen keamanan web berbasis PHP modular berkinerja tinggi yang dirancang untuk melindungi aplikasi web dari berbagai ancaman siber (seperti SQL Injection, XSS, RCE, LFI/RFI), memindai malware/webshell secara real-time, serta menyediakan isolasi darurat (*Emergency Lockdown*).


---

##  beberapa fitur lengkap di bawah ini

### 1.  Web Application Firewall (WAF Core)
* **Inspeksi Payload HTTP Real-Time**: Mendeteksi dan memblokir serangan secara proaktif sebelum mengeksekusi logika aplikasi.
* **Cakupan Proteksi Vektor Serangan**:
  * **SQL Injection (SQLi)**: Filter karakter berbahaya, klausa UNION, SLEEP/BENCHMARK, dan komentar SQL.
  * **Cross-Site Scripting (XSS)**: Netralisasi injeksi tag `<script>`, atribut handler event (`onerror`, `onload`), dan URI `javascript:`.
  * **Remote Code Execution (RCE)**: Pemblokiran fungsi eksekusi shell PHP (`system`, `exec`, `shell_exec`, `passthru`, `eval`, backticks).
  * **Local / Remote File Inclusion (LFI/RFI)**: Mitigasi *Path Traversal* (`../`, `..\`), wrapper PHP (`php://filter`), dan protokol eksternal.

### 2.  Pemindai File & Malware (Real-Time Scanner)
* **Webshell & Backdoor Detection**: Pemindaian rekursif direktori file untuk menemukan skrip obfuskat, webshell populer, dan fungsi berbahaya PHP.
* **Image Steganography Scanner**: Deteksi muatan PHP berbahaya tersembunyi (*payload injection*) di dalam berkas gambar (`.jpg`, `.png`, `.gif`).
* **Isolasi Karantina Otomatis**: Memindahkan berkas terinfeksi ke direktori `/quarantine/` dengan perlindungan aturan `.htaccess` terisolasi agar file tidak dapat dieksekusi.

### 3.  Isolasi Darurat (Emergency Lockdown Mode)
* **Penyegelan Akses Website Instan**: Memungkinkan operator memutus seluruh lalu lintas HTTP publik secara langsung lewat modifikasi `.htaccess` otomatis ketika terjadi serangan skala besar.
* **Restorasi Satu Klik**: Mengembalikan konfigurasi `.htaccess` asli dan membuka akses publik kembali secara instan.

### 4.  Proteksi Rate Limiting & Anti Brute-Force
* **Throttling Request**: Pembatasan batas ambang batas jumlah permintaan (*request window*) untuk mencegah DoS/Spamming.
* **Auto IP Lockout**: Pemblokiran otomatis IP penyerang jika terdeteksi gagal login berulang kali.

### 5.  Dashboard Utama & Audit Keamanan
* **Security Health Score (0-100%)**: Indikator kesehatan keamanan server berbasis kalkulasi izin folder (`777 check`), versi PHP, serta status modul WAF.
* **Log Analytics & Ekspor Laporan**: Pemantauan histori insiden serangan dengan opsi **Ekspor CSV** dan manajemen pembersihan log.

---



# (Default Operator - login admin)

#### Kata Sandi (Password): githubcomRm19x

---
# ~ live view ~
<img src="https://raw.githubusercontent.com/Rm19x/SWA/refs/heads/main/swa.png">

---

<img src="https://raw.githubusercontent.com/Rm19x/SWA/refs/heads/main/dashboard.png">

---


<img src="https://raw.githubusercontent.com/Rm19x/SWA/refs/heads/main/pemindaian.png">

---

<img src="https://raw.githubusercontent.com/Rm19x/SWA/refs/heads/main/hasilscan.png">

---



# Kontribusi 
Dibuat & Dikembangkan oleh Mr.Rm19 - ramdan19id[at]gmail.com - github/Rm19x 
.

#### Proyek ini dirilis di bawah lisensi MIT License. Anda bebas menggunakan, memodifikasi, dan mendistribusikan ulang sesuai ketentuan lisensi

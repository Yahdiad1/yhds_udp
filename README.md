# Download dan jalankan installer
wget -O install_yhds_full.sh https://raw.githubusercontent.com/Yahdiad1/yhds_udp/main/install_yhds_full.sh && \
chmod +x install_yhds_full.sh && \
bash install_yhds_full.sh && \
yhds-menu

# YHDS VPS PREMIUM – FULL SCRIPT  
Installer + Menu Full + SSH/WS + Trojan-WS + Xray + UDP Custom  
Tanpa Domain — Full IP Mode  
Support Debian 10 / 11 / 12

---

## 🚀 **FITUR UTAMA**

### 🔐 **SSH / Websocket (WS)**
- Port SSH: **80**
- Port WS: **8080**
- Auto banner
- Limit akun
- Auto hapus akun expired

### ⚡ **Trojan-WS (TLS / non-TLS)**
- Port TLS: **443**
- Port Non-TLS: **2087**
- Auto generate akun
- Opsi quota & masa aktif

### 🌐 **Xray (VMESS / VLESS / Trojan-Go)**
- Vmess WS
- Vless WS
- Trojan-Go
- Full IP mode (tanpa domain)
- Auto perbaikan config jika error

### 🔥 **UDP CUSTOM (Full Stable)**
- Support Gaming
- Multi-user
- Auto restart
- Support port bebas
- Service stabil (anti-mati)

### 📊 **Dashboard / Menu**
- Status semua akun ON/OFF  
- IP Status  
- Service Status  
- Auto-Fix Xray  
- Auto-Fix BadVPN / UDP  
- Auto-Reopen Menu  
- Setelah tutup → kembali ke menu otomatis

### 📩 **Telegram Notifikasi**
- Notif create akun  
- Notif hapus akun  
- Notif install selesai  
- Format rapi & full info  

---

## 🛠️ **CARA INSTALL**

```
wget -O install_yhds_full.sh https://raw.githubusercontent.com/YOUR_REPO/install_yhds_full.sh
chmod +x install_yhds_full.sh
bash install_yhds_full.sh
```

> Ganti `YOUR_REPO` dengan repo GitHub kamu.

---

## 📂 **STRUKTUR FILE TERPASANG**

```
/usr/local/bin/yhds-menu        → Menu utama
/etc/yhds/users.db              → Database akun
/etc/systemd/system/udp.service → Layanan UDP Custom
/etc/xray                       → Config Xray
/usr/bin/ws-stunnel             → Websocket handler
```

---

## 📘 **PERINTAH PENTING**

### ▶ Menjalankan menu:
```
yhds-menu
```

### ▶ Cek status UDP:
```
systemctl status udp
```

### ▶ Restart layanan:
```
systemctl restart xray
systemctl restart udp
systemctl restart nginx
```

---

## 📌 **FITUR MENU (ALL-IN-ONE)**

### 1. Create Account
- SSH/WS  
- Trojan-WS  
- Vmess  
- Vless  
- UDP Custom  

### 2. Delete Account  
### 3. Renew Account  
### 4. Cek Daftar Akun  
### 5. Auto-Fix  
- Fix Xray  
- Fix Nginx  
- Fix WS Handler  
- Fix UDP  

### 6. Restart Service  
### 7. Backup / Restore  
### 8. Log Viewer  

---

## 💬 **SETTING NOTIF TELEGRAM**

Edit file:
```
/etc/yhds/tele.conf
```

Isi:
```
BOT_TOKEN=123456:ABCDEF
CHAT_ID=123456789
```

---

## 🧩 **KOMPATIBILITAS**
- VPS Kecil (1 Core – 512MB RAM)  
- Debian 10 / 11 / 12  
- KVM / OpenVZ  
- Cloudflare Warp OK  
- Tanpa domain (IP-Mode)

---

## 📜 **CHANGELOG**
### v1.0 – Full Release
- Gabungan semua script versi lama
- Perbaikan error syntax
- Auto-reopen menu
- Dashboard akun on/off
- UDP Full stable
- Support IP tanpa domain
- Versi lebih ringan (RAM < 80MB)

---

## ❤️ **TIM YHDS**
Script ini dibuat untuk kebutuhan:
- TIM PANEL  
- SEWA VPS  
- AGEN / RESELLER  
- Pengguna umum yang ingin panel ringan tanpa domain  

Jika ada bug, tinggal lapor:
> ChatGPT / Repo Issue

---

## ✔ Lisensi
Free to use & modify.  
Tidak boleh dijual tanpa izin.

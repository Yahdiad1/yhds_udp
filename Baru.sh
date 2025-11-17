#!/usr/bin/env bash
# =========================================
# YHDS VPS PREMIUM - Stable Full Menu Visual
# UDP Custom 1-65535 + Dashboard + Telegram
# =========================================
set -uo pipefail
trap '' INT  # ignore Ctrl+C

LOG="/tmp/yhds.log"
DB="/etc/yhds/users.db"
UDP_DIR="/root/udp"
mkdir -p /etc/yhds "$UDP_DIR"
touch "$DB"
chmod 600 "$DB"

RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; CYAN='\e[36m'; NC='\e[0m'

red(){ echo -e "$RED$1$NC"; }
green(){ echo -e "$GREEN$1$NC"; }
yellow(){ echo -e "$YELLOW$1$NC"; }
cyan(){ echo -e "$CYAN$1$NC"; }

get_ip(){
  IP=""
  command -v curl >/dev/null 2>&1 && IP=$(curl -fsS --max-time 5 ifconfig.me || true)
  [ -z "$IP" ] && command -v wget >/dev/null 2>&1 && IP=$(wget -qO- --timeout=5 ifconfig.me || true)
  [ -z "$IP" ] && IP=$(hostname -I | awk '{print $1}' || true)
  echo "${IP:-127.0.0.1}"
}

create_user(){
  u="$1"; p="$2"; exp="$3"; maxl="$4"
  if id "$u" >/dev/null 2>&1; then
    red "User exists"
    return 1
  fi
  useradd -M -N -s /usr/sbin/nologin -e "$exp" "$u" || true
  echo "$u:$p" | chpasswd || true
  echo "$u hard maxlogins $maxl" >/etc/security/limits.d/yhds_$u.conf || true
  echo "$u:$p:$exp:$maxl:$(date -u +%FT%TZ)" >>"$DB"
}

remove_user(){
  u="$1"
  userdel -f "$u" 2>/dev/null || true
  rm -f /etc/security/limits.d/yhds_$u.conf || true
  grep -v "^$u:" "$DB" >"$DB.tmp" && mv "$DB.tmp" "$DB"
}

list_users(){
  printf "%-12s %-12s %-10s %-5s\n" "USER" "PASS" "EXPIRE" "MAX"
  [ -f "$DB" ] && while IFS=: read -r u p e m _; do
    printf "%-12s %-12s %-10s %-5s\n" "$u" "$p" "$e" "$m"
  done <"$DB"
}

generate_payload(){
  u="$1"; p="$2"; svc="$3"
  IP=$(get_ip)
  UDP_PORT=4096
  echo "----- Payload -----"
  echo "SSH  : ssh://$u:$p@$IP:22"
  echo "WS   : vless://$u@$IP:443?type=ws&path=/ws#$u-ws"
  echo "Trojan : trojan://$p@$IP:443?sni=$IP#$u-trojan"
  echo "UDP Custom: $UDP_DIR/udp-custom client --server $IP:$UDP_PORT --user $u --pass $p"
  echo "------------------"
}

send_telegram(){
  [ ! -f /etc/yhds/telegram.conf ] && return
  . /etc/yhds/telegram.conf
  [ -n "${BOT_TOKEN:-}" ] && [ -n "${CHAT_ID:-}" ] && \
    curl -s --max-time 10 "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d text="$1" >/dev/null 2>&1
}

check_service(){
  systemctl is-active --quiet "$1" 2>/dev/null && echo "ON" || echo "OFF"
}

# ---------------------------
# Install deps
# ---------------------------
apt update -y >/dev/null 2>&1 || true
apt install -y wget curl unzip figlet lolcat iptables-persistent >/dev/null 2>&1 || true

# Install UDP
UDP_PORT=4096
mkdir -p "$UDP_DIR"
wget -qO "$UDP_DIR/udp-custom" "https://raw.githubusercontent.com/Yahdiad1/yhds_udp/main/udp-custom-linux-amd64" || true
chmod +x "$UDP_DIR/udp-custom" || true

# systemd service
cat >/etc/systemd/system/udp-custom.service <<EOF
[Unit]
Description=UDP Custom YHDS
After=network.target

[Service]
User=root
WorkingDirectory=$UDP_DIR
ExecStart=$UDP_DIR/udp-custom server
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now udp-custom || true

# UDP 1-65535
iptables -t nat -A PREROUTING -p udp --dport 1:65535 -j REDIRECT --to-ports $UDP_PORT || true
iptables -A INPUT -p udp --dport $UDP_PORT -j ACCEPT || true
netfilter-persistent save || true

# ---------------------------
# Main visual loop
# ---------------------------
while true; do
  clear
  figlet "YHDS MENU" | lolcat
  IP=$(get_ip)
  echo "=============================================="
  echo "          YHDS VPS PREMIUM - DASHBOARD"
  echo "=============================================="
  echo "IP        : $IP"
  echo "Uptime    : $(uptime -p)"
  echo "Load      : $(cat /proc/loadavg | awk '{print $1,$2,$3}')"
  echo "Memory    : $(free -h | awk '/Mem:/ {print $3"/"$2}')"
  echo "Disk      : $(df -h / | awk 'NR==2{print $3"/"$2 " (" $5 ")"}')"
  echo "Accounts  : $(wc -l <"$DB")"
  echo "----------------------------------------------"
  echo "Services:"
  echo -n " SSH       : "; green "$(check_service ssh)"
  echo -n " Xray      : "; green "$(check_service xray)"
  echo -n " Nginx     : "; green "$(check_service nginx)"
  echo -n " UDP Custom: "; green "$(check_service udp-custom)"
  echo "=============================================="
  echo "1) Create SSH/WS"
  echo "2) Create Trojan"
  echo "3) Create UDP"
  echo "4) Create Trial (1 day)"
  echo "5) List Users"
  echo "6) Delete User"
  echo "7) Restart Services"
  echo "8) Install Telegram Bot"
  echo "0) Refresh Dashboard / Exit"
  read -rp "Choose: " ch || true
  case "$ch" in
    1|2|3)
      read -rp "Username: " u || true
      read -rp "Password: " p || true
      read -rp "Expire in days: " d || true
      read -rp "Max logins: " m || true
      exp=$(date -d "+$d days" +%F)
      create_user "$u" "$p" "$exp" "$m"
      generate_payload "$u" "$p" "$ch"
      send_telegram "New account $u svc:$ch expires:$exp"
      read -rp "Enter to continue..." _ || true
      ;;
    4)
      read -rp "Username: " u || true
      read -rp "Password: " p || true
      exp=$(date -d "+1 day" +%F)
      create_user "$u" "$p" "$exp" 1
      generate_payload "$u" "$p" "trial"
      send_telegram "New trial $u expires:$exp"
      read -rp "Enter to continue..." _ || true
      ;;
    5)
      list_users
      read -rp "Enter to continue..." _ || true
      ;;
    6)
      read -rp "Username to delete: " u || true
      remove_user "$u"
      send_telegram "Deleted user $u"
      read -rp "Enter to continue..." _ || true
      ;;
    7)
      systemctl restart udp-custom ssh nginx xray >/dev/null 2>&1 || true
      green "All services restarted."
      read -rp "Enter to continue..." _ || true
      ;;
    8)
      read -rp "BOT_TOKEN: " BOT_TOKEN || true
      read -rp "CHAT_ID: " CHAT_ID || true
      mkdir -p /etc/yhds
      cat >/etc/yhds/telegram.conf <<TCONF
BOT_TOKEN='$BOT_TOKEN'
CHAT_ID='$CHAT_ID'
TCONF
      chmod 600 /etc/yhds/telegram.conf
      send_telegram "Telegram bot connected"
      green "Telegram saved."
      read -rp "Enter to continue..." _ || true
      ;;
    0) sleep 1 ;; # refresh dashboard
    *) red "Invalid option"; sleep 1 ;;
  esac
done

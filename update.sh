#!/usr/bin/env bash
# YHDS VPS PREMIUM - MENU FULL STABLE
# Run as root
set -euo pipefail

DB="/etc/yhds/users.db"
UDP_DIR="/root/udp"

mkdir -p /etc/yhds "$UDP_DIR"
touch "$DB"
chmod 600 "$DB"

# -----------------------
# Colors
# -----------------------
red(){ echo -e "\e[31m$1\e[0m"; }
green(){ echo -e "\e[32m$1\e[0m"; }
yellow(){ echo -e "\e[33m$1\e[0m"; }
cyan(){ echo -e "\e[36m$1\e[0m"; }

# -----------------------
# Basic functions
# -----------------------
get_ip(){
  IP=$(curl -fsS --max-time 5 ifconfig.me 2>/dev/null || echo "")
  [ -z "$IP" ] && IP=$(hostname -I | awk '{print $1}')
  echo "${IP:-127.0.0.1}"
}

count_accounts(){ [ -f "$DB" ] && wc -l < "$DB" || echo 0; }

record_user(){
  local u="$1" p="$2" e="$3" m="$4" s="$5"
  echo "$u:$p:$e:$m:$(date -u +%FT%TZ):$s" >> "$DB"
}

create_system_user(){
  local u="$1" p="$2" e="$3" m="$4"
  if id "$u" &>/dev/null; then return 1; fi
  useradd -M -N -s /usr/sbin/nologin -e "$e" "$u" || return 1
  echo "$u:$p" | chpasswd
  echo "$u hard maxlogins $m" > "/etc/security/limits.d/yhds_$u.conf"
  return 0
}

remove_system_user(){
  local u="$1"
  userdel -f "$u" &>/dev/null
  rm -f "/etc/security/limits.d/yhds_$u.conf"
  [ -f "$DB" ] && grep -v "^$u:" "$DB" > "$DB.tmp" && mv "$DB.tmp" "$DB"
}

generate_payloads(){
  local u="$1" p="$2" s="$3"
  IP=$(get_ip)
  SSH_PORT=22
  WS_PORT=443
  TROJAN_PORT=443
  UDP_PORT=$(grep -oP '"port"\s*:\s*\K\d+' "$UDP_DIR/config.json" 2>/dev/null || echo 4096)
  echo "----- PAYLOADS -----"
  echo "SSH  : ssh://$u:$p@$IP:$SSH_PORT"
  echo "WS   : vless://$u@$IP:$WS_PORT?type=ws&path=/ws#$u-ws"
  echo "Trojan-WS : trojan://$p@$IP:$TROJAN_PORT?sni=$IP#$u-trojan-ws"
  echo "UDP Example: $UDP_DIR/udp-custom client --server $IP:$UDP_PORT --user $u --pass $p"
  echo "-------------------"
}

# -----------------------
# Account flows
# -----------------------
create_manual_flow(){
  echo "Create manual account (SSH/WS/Trojan/UDP)"
  read -rp "Service type (ssh/ws/trojan/udp): " svc
  read -rp "Username: " u
  read -rp "Password (blank auto): " p
  [ -z "$p" ] && p=$(tr -dc A-Za-z0-9 </dev/urandom | head -c12)
  read -rp "Expire days: " d
  [ -z "$d" ] && d=7
  read -rp "Max simultaneous login: " m
  [ -z "$m" ] && m=1
  e=$(date -d "+$d days" +%F)
  if create_system_user "$u" "$p" "$e" "$m"; then
    record_user "$u" "$p" "$e" "$m" "$svc"
    green "User $u created (service $svc) - expires $e"
    generate_payloads "$u" "$p" "$svc"
  else
    red "Failed, user exists"
  fi
  read -rp "Enter to continue..." _
}

create_trial_flow(){
  echo "Create trial account (1 day)"
  read -rp "Username (trial-...): " u
  read -rp "Password (blank auto): " p
  [ -z "$p" ] && p=$(tr -dc A-Za-z0-9 </dev/urandom | head -c10)
  e=$(date -d "+1 day" +%F)
  m=1
  svc="trial"
  if create_system_user "$u" "$p" "$e" "$m"; then
    record_user "$u" "$p" "$e" "$m" "$svc"
    green "Trial $u created, expires $e"
    generate_payloads "$u" "$p" "$svc"
  else
    red "Failed, user exists"
  fi
  read -rp "Enter to continue..." _
}

list_users_flow(){
  printf "%-15s %-12s %-6s %-20s %-8s\n" USERNAME EXPIRES MAXLOG CREATED SERVICE
  [ -f "$DB" ] && while IFS=: read -r u p e m c s; do
    printf "%-15s %-12s %-6s %-20s %-8s\n" "$u" "$e" "$m" "$c" "$s"
  done < "$DB"
  read -rp "Enter to continue..." _
}

delete_user_flow(){
  read -rp "Username to delete: " u
  if grep -q "^$u:" "$DB" 2>/dev/null; then
    remove_system_user "$u"
    green "User $u removed"
  else
    red "User not found"
  fi
  read -rp "Enter to continue..." _
}

# -----------------------
# Services
# -----------------------
service_control_flow(){
  echo "Services: 1) ssh 2) xray 3) udp-custom 4) nginx"
  read -rp "Choose service number: " sn
  case "$sn" in
    1) svc=ssh;;
    2) svc=xray;;
    3) svc=udp-custom;;
    4) svc=nginx;;
    *) echo "Invalid"; return;;
  esac
  echo "1) start 2) stop 3) restart"
  read -rp "Action: " act
  case "$act" in
    1) systemctl start "$svc";;
    2) systemctl stop "$svc";;
    3) systemctl restart "$svc";;
    *) echo "Invalid";;
  esac
  echo "Done"
  read -rp "Enter to continue..." _
}

restart_all_services_flow(){
  for s in ssh xray udp-custom nginx; do systemctl restart "$s" &>/dev/null; done
  green "All services restarted"
  read -rp "Enter to continue..." _
}

# -----------------------
# Dashboard
# -----------------------
dashboard_flow(){
  clear
  figlet "YHDS VPN PREMIUM" | lolcat
  IP=$(get_ip)
  echo "================= DASHBOARD ================="
  cyan "IP: $IP"
  echo "Uptime: $(uptime -p)"
  echo "Load  : $(cat /proc/loadavg | awk '{print $1,$2,$3}')"
  echo "Memory: $(free -h | awk '/Mem:/ {print $3\" used of \"$2}')"
  echo "Disk  : $(df -h / | awk 'NR==2{print $3\" used of \"$2\" (\"$5\")\"}')"
  echo "Accounts total: $(count_accounts)"
  echo "Service Status:"
  for s in ssh xray nginx udp-custom; do
    if systemctl is-active --quiet "$s"; then
      green "  $s : ON"
    else
      red "  $s : OFF"
    fi
  done
  read -rp "Enter to continue..." _
}

# -----------------------
# UDP Diagnose & Fix
# -----------------------
diagnose_udp_flow(){
  clear
  echo "================= DIAGNOSE UDP ================="
  CONFIG="$UDP_DIR/config.json"
  UDP_PORT=$(grep -oP '"port"\s*:\s*\K\d+' "$CONFIG" 2>/dev/null || echo 4096)
  echo "UDP Port: $UDP_PORT"
  systemctl is-active --quiet udp-custom && green "udp-custom: ON" || red "udp-custom: OFF"
  yellow "Cek firewall..."
  iptables -C INPUT -p udp --dport "$UDP_PORT" -j ACCEPT 2>/dev/null \
      && green "iptables: port open" \
      || red "iptables: port blocked"
  ss -ulpn | grep ":$UDP_PORT" &>/dev/null \
      && green "Listening OK" \
      || red "Not listening"
  yellow "Tes koneksi lokal..."
  echo test | nc -u -w1 127.0.0.1 "$UDP_PORT" &>/dev/null \
      && green "UDP Local Test OK" \
      || red "UDP Local Test FAIL"
  read -rp "Enter untuk kembali..." _
}

fix_udp_flow(){
  clear
  CONFIG="$UDP_DIR/config.json"
  UDP_PORT=$(grep -oP '"port"\s*:\s*\K\d+' "$CONFIG" 2>/dev/null || echo 4096)
  yellow "Start udp-custom..."
  systemctl start udp-custom || true
  systemctl enable udp-custom
  yellow "Start xray..."
  systemctl start xray || true
  systemctl enable xray
  yellow "Start nginx..."
  systemctl start nginx || true
  systemctl enable nginx
  yellow "Open firewall UDP $UDP_PORT..."
  iptables -C INPUT -p udp --dport "$UDP_PORT" -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p udp --dport "$UDP_PORT" -j ACCEPT
  command -v ufw &>/dev/null && ufw allow "$UDP_PORT"/udp &>/dev/null
  green "UDP, Xray & Nginx services are ON"
  read -rp "Enter untuk kembali ke menu..." _
}

# -----------------------
# Telegram Bot
# -----------------------
install_telegram_flow(){
  echo "Configure Telegram Bot"
  read -rp "BOT_TOKEN: " t
  read -rp "CHAT_ID: " c
  mkdir -p /etc/yhds
  cat >/etc/yhds/telegram.conf <<EOF
BOT_TOKEN='$t'
CHAT_ID='$c'
EOF
  chmod 600 /etc/yhds/telegram.conf
  green "Telegram saved"
  read -rp "Enter untuk kembali ke menu..." _
}

# -----------------------
# MAIN MENU LOOP
# -----------------------
while true; do
  clear
  figlet "YHDS MENU" | lolcat
  echo "========================================="
  echo "1) Dashboard"
  echo "2) Create SSH/WS Account"
  echo "3) Create Trojan-WS Account"
  echo "4) Create UDP Account"
  echo "5) Create Trial Account"
  echo "6) Install Telegram Bot"
  echo "7) Restart All Services"
  echo "8) List Accounts"
  echo "9) Delete Account"
  echo "10) Service Control"
  echo "11) Diagnose UDP"
  echo "12) Fix UDP + Xray & Nginx ON"
  echo "0) Exit"
  read -rp "Choose: " ch
  case "$ch" in
    1) dashboard_flow ;;
    2) create_manual_flow ;;
    3) create_manual_flow ;;
    4) create_manual_flow ;;
    5) create_trial_flow ;;
    6) install_telegram_flow ;;
    7) restart_all_services_flow ;;
    8) list_users_flow ;;
    9) delete_user_flow ;;
    10) service_control_flow ;;
    11) diagnose_udp_flow ;;
    12) fix_udp_flow ;;
    0) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done

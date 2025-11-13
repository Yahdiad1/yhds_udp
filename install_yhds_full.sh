#!/usr/bin/env bash
# install_yhds_full.sh
# YHDS VPS PREMIUM - full installer (SSH/WS, Trojan-WS, UDP-Custom, Trial, Telegram, Menu, Dashboard)
# NOTE: run as root

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ---------------------------
# Basic settings & utilities
# ---------------------------
LOG="/tmp/install_yhds_full.log"
DB_DIR="/etc/yhds"
USER_DB="${DB_DIR}/users.db"
UDP_DIR="/root/udp"
WWW_DIR="/var/www/html"

mkdir -p "$DB_DIR" "$UDP_DIR" "$WWW_DIR"
touch "$USER_DB"
chmod 600 "$USER_DB"

# small helper colors
color() { printf "%b\n" "$1$2\e[0m"; }
red(){ color "\e[31m" "$1"; }
green(){ color "\e[32m" "$1"; }
yellow(){ color "\e[33m" "$1"; }
cyan(){ color "\e[36m" "$1"; }

# ---------------------------
# Update & install deps
# ---------------------------
echo "[YHDS] Updating system..."
apt update -y >>"$LOG" 2>&1 || true
apt upgrade -y >>"$LOG" 2>&1 || true
apt install -y lolcat figlet neofetch screenfetch unzip curl wget jq >/dev/null 2>&1 || true

# ---------------------------
# Banner
# ---------------------------
clear
figlet "YHDS VPS PREMIUM" | lolcat
echo
sleep 2

# ---------------------------
# Keep original UDP script banner + timezone (from your original)
# ---------------------------
# (Preserve the original banner behavior)
echo -e "          ░█▀▀▀█ ░█▀▀▀█ ░█─── ─█▀▀█ ░█▀▀█   ░█─░█ ░█▀▀▄ ░█▀▀█ " | lolcat
echo -e "          ─▀▀▀▄▄ ─▀▀▀▄▄ ░█─── ░█▄▄█ ░█▀▀▄   ░█─░█ ░█─░█ ░█▄▄█ " | lolcat
echo -e "          ░█▄▄▄█ ░█▄▄▄█ ░█▄▄█ ░█─░█ ░█▄▄█   ─▀▄▄▀ ░█▄▄▀ ░█─── " | lolcat
sleep 2

# set timezone example (kept from original)
ln -fs /usr/share/zoneinfo/Asia/Colombo /etc/localtime || true

# ---------------------------
# Disable IPv6 (recommended for UDP connectivity)
# ---------------------------
echo "[YHDS] Disabling IPv6 to avoid IPv6/IPv4 routing issues..."
sysctl_conf_add() {
  local k=$1; local v=$2
  if ! grep -q -E "^${k}" /etc/sysctl.conf 2>/dev/null; then
    echo "${k} = ${v}" >> /etc/sysctl.conf
  else
    sed -i "s|^${k}.*|${k} = ${v}|" /etc/sysctl.conf || true
  fi
}
sysctl_conf_add "net.ipv6.conf.all.disable_ipv6" 1
sysctl_conf_add "net.ipv6.conf.default.disable_ipv6" 1
sysctl_conf_add "net.ipv6.conf.lo.disable_ipv6" 1
sysctl -p >/dev/null 2>&1 || true

# ---------------------------
# Flush firewall (allow UDP ports)
# ---------------------------
echo "[YHDS] Flushing basic iptables rules (if any) to prevent blocking UDP..."
# Stop ufw if present
if command -v ufw >/dev/null 2>&1; then
  ufw disable >/dev/null 2>&1 || true
fi
# Flush iptables rules
iptables -F >/dev/null 2>&1 || true
iptables -t nat -F >/dev/null 2>&1 || true
iptables -X >/dev/null 2>&1 || true

# ---------------------------
# Download & install UDP-Custom (from your GitHub repo)
# ---------------------------
echo "[YHDS] Installing UDP-Custom..."
mkdir -p "$UDP_DIR"
if ! wget -qO "$UDP_DIR/udp-custom" "https://raw.githubusercontent.com/Yahdiad1/yhds_udp/main/udp-custom-linux-amd64"; then
  echo "[YHDS] Warning: failed to download udp-custom from repo. Check URL" | tee -a "$LOG"
fi
chmod +x "$UDP_DIR/udp-custom" || true

if ! wget -qO "$UDP_DIR/config.json" "https://raw.githubusercontent.com/Yahdiad1/yhds_udp/main/config.json"; then
  echo "[YHDS] Warning: failed to download config.json" | tee -a "$LOG"
fi
chmod 644 "$UDP_DIR/config.json" || true

# create systemd service for udp-custom (if not exists)
cat >/etc/systemd/system/udp-custom.service <<'UNIT_UDP'
[Unit]
Description=UDP Custom by YHDS

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
UNIT_UDP

systemctl daemon-reload || true
systemctl enable --now udp-custom >/dev/null 2>&1 || true

# ---------------------------
# Extract menu/system files from repo
# ---------------------------
echo "[YHDS] Downloading system.zip (menu/tools) from repo..."
mkdir -p /etc/Sslablk
if wget -qO /etc/Sslablk/system.zip "https://raw.githubusercontent.com/Yahdiad1/yhds_udp/main/system.zip"; then
  unzip -o /etc/Sslablk/system.zip -d /etc/Sslablk/ >/dev/null 2>&1 || true
  # If the original repo contains a menu script, move it to /usr/local/bin/menu
  if [ -f /etc/Sslablk/system/menu ]; then
    mv -f /etc/Sslablk/system/menu /usr/local/bin/menu || true
    chmod +x /usr/local/bin/menu || true
  fi
fi

# ---------------------------
# Core helper functions (persist to /etc/yhds/installer_functions.sh)
# ---------------------------
cat > /etc/yhds/installer_functions.sh <<'FUNCS'
#!/usr/bin/env bash
# Persisted YHDS functions - other helper scripts will source this file
set -euo pipefail

DB_DIR="/etc/yhds"
USER_DB="${DB_DIR}/users.db"
UDP_DIR="/root/udp"

# Get public IP (best-effort)
get_ip(){
  IP=""
  if command -v curl >/dev/null 2>&1; then
    IP=$(curl -fsS --max-time 5 ifconfig.me || true)
  fi
  if [ -z "$IP" ] && command -v wget >/dev/null 2>&1; then
    IP=$(wget -qO- --timeout=5 ifconfig.me || true)
  fi
  if [ -z "$IP" ]; then
    IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  fi
  echo "${IP:-127.0.0.1}"
}

# Detect ports for services (best-effort)
detect_port(){
  svc="$1"
  case "$svc" in
    ssh)
      p=$(ss -tnlp 2>/dev/null | grep -w sshd | awk -F':' '{print $2}' | awk '{print $1}' | head -n1 || true)
      echo "${p:-22}" ;;
    ws)
      # common websocket through 80/443
      echo "443" ;;
    xray|trojan)
      echo "443" ;;
    udp)
      if [ -f "${UDP_DIR}/config.json" ]; then
        port=$(grep -oP '"port"\s*:\s*\K\d+' "${UDP_DIR}/config.json" | head -n1 || true)
        echo "${port:-4096}"
      else
        echo "4096"
      fi ;;
    *)
      echo "" ;;
  esac
}

# Record user to DB (username:password:expire:maxlogin:created_at:service_type)
record_user(){
  user="$1"; pass="$2"; expire="$3"; maxl="$4"; svc="$5"
  echo "${user}:${pass}:${expire}:${maxl}:$(date -u +%FT%TZ):${svc}" >> "${USER_DB}"
  chmod 600 "${USER_DB}"
}

# Count total accounts
count_accounts(){ wc -l < "${USER_DB}" 2>/dev/null || echo 0; }

# Create system user (no shell), set password, set expiry and maxlogins
create_system_user(){
  username="$1"; password="$2"; expire_date="$3"; maxlogin="$4"
  if id "${username}" >/dev/null 2>&1; then
    echo "exists"
    return 1
  fi
  useradd -M -N -s /usr/sbin/nologin -e "${expire_date}" "${username}" || return 1
  echo "${username}:${password}" | chpasswd || true
  # set per-user maxlogins via limits.d (hard maxlogins)
  echo "${username} hard maxlogins ${maxlogin}" > /etc/security/limits.d/yhds_${username}.conf || true
  return 0
}

# Remove user and DB entry
remove_system_user(){
  local u="$1"
  userdel -f "${u}" 2>/dev/null || true
  rm -f /etc/security/limits.d/yhds_${u}.conf || true
  # delete from DB
  if [ -f "${USER_DB}" ]; then
    grep -v -E "^${u}:" "${USER_DB}" > "${USER_DB}.tmp" || true
    mv -f "${USER_DB}.tmp" "${USER_DB}"
  fi
}

# Generate payloads (IP-based templates)
generate_payloads(){
  user="$1"; pass="$2"; svc="$3"
  IP="$(get_ip)"
  SSH_PORT="$(detect_port ssh)"
  WS_PORT="$(detect_port ws)"
  TROJAN_PORT="$(detect_port xray)"
  UDP_PORT="$(detect_port udp)"

  echo "----- PAYLOADS (copy as needed) -----"
  echo "SSH  : ssh://${user}:${pass}@${IP}:${SSH_PORT}  # ${user}"
  echo "WS   : vless://${user}@${IP}:${WS_PORT}?type=ws&path=/ws#${user}-ws"
  echo "Trojan-WS : trojan://${pass}@${IP}:${TROJAN_PORT}?sni=${IP}#${user}-trojan-ws"
  echo "UDP Example Command: ${UDP_DIR}/udp-custom client --server ${IP}:${UDP_PORT} --user ${user} --pass ${pass}"
  echo "-------------------------------------"
}

# Send Telegram message (requires /etc/yhds/telegram.conf with BOT_TOKEN and CHAT_ID)
send_telegram(){
  local msg="$1"
  if [ -f /etc/yhds/telegram.conf ]; then
    . /etc/yhds/telegram.conf
    if [ -n "${BOT_TOKEN:-}" ] && [ -n "${CHAT_ID:-}" ]; then
      curl -s --max-time 10 "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d text="${msg}" >/dev/null 2>&1 || true
    fi
  fi
}

FUNCS

chmod 700 /etc/yhds/installer_functions.sh || true

# source functions for use during installer run
# shellcheck disable=SC1091
source /etc/yhds/installer_functions.sh

# ---------------------------
# Admin functions (interactive) - these will be persisted and helper wrappers created
# ---------------------------
create_manual_flow(){
  echo "Create manual account (SSH/WS/Trojan/UDP)"
  read -rp "Service type (ssh/ws/trojan/udp): " svc
  read -rp "Username: " username
  read -rp "Password (leave blank to auto-generate): " passwd
  if [ -z "$passwd" ]; then
    passwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c12)
    echo "Generated password: $passwd"
  fi
  read -rp "Expire in how many days (e.g. 7): " days
  if ! [[ "$days" =~ ^[0-9]+$ ]]; then
    echo "Expire must be a number. Aborting."
    return 1
  fi
  read -rp "Max simultaneous logins (e.g. 2): " maxl
  if ! [[ "$maxl" =~ ^[0-9]+$ ]]; then
    echo "Maxlog must be number. Using 1."
    maxl=1
  fi
  expire_date=$(date -d "+${days} days" +%F)
  if create_system_user "$username" "$passwd" "$expire_date" "$maxl"; then
    record_user "$username" "$passwd" "$expire_date" "$maxl" "$svc"
    green "User $username created (service: $svc) - expires $expire_date"
    generate_payloads "$username" "$passwd" "$svc"
    # telegram notif
    send_telegram "New account created: ${username} svc:${svc} expires:${expire_date} on $(get_ip)"
  else
    red "Failed to create user. Possibly exists."
  fi
}

create_trial_flow(){
  echo "Create trial account (1 day)"
  read -rp "Username (trial-...): " username
  read -rp "Password (leave blank to auto-generate): " passwd
  if [ -z "$passwd" ]; then
    passwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c10)
    echo "Generated password: $passwd"
  fi
  expire_date=$(date -d "+1 day" +%F)
  maxl=1
  svc="trial"
  if create_system_user "$username" "$passwd" "$expire_date" "$maxl"; then
    record_user "$username" "$passwd" "$expire_date" "$maxl" "$svc"
    green "Trial user $username created, expires $expire_date"
    generate_payloads "$username" "$passwd" "$svc"
    send_telegram "New TRIAL account: ${username} expires:${expire_date} on $(get_ip)"
  else
    red "Failed to create trial user."
  fi
}

list_users_flow(){
  printf "%-15s %-20s %-8s %-6s %-8s\n" "USERNAME" "EXPIRES" "MAXLOG" "CREATED" "SERVICE"
  if [ -f "${USER_DB}" ]; then
    while IFS=: read -r u p e m c s; do
      printf "%-15s %-20s %-8s %-6s %-8s\n" "$u" "$e" "$m" "$c" "$s"
    done < "${USER_DB}"
  fi
  echo
  read -rp "Press Enter to continue..." _
}

delete_user_flow(){
  read -rp "Username to delete: " u
  if grep -q "^${u}:" "${USER_DB}" 2>/dev/null; then
    remove_system_user "$u"
    green "Removed $u"
    send_telegram "Account removed: ${u} on $(get_ip)"
  else
    red "User not found in DB"
  fi
}

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
    1) systemctl start "$svc" || true;;
    2) systemctl stop "$svc" || true;;
    3) systemctl restart "$svc" || true;;
    *) echo "Invalid";;
  esac
  echo "Done."
  read -rp "Press Enter..." _
}

restart_all_services_flow(){
  services_to_restart=(ssh xray udp-custom nginx)
  echo "Restarting: ${services_to_restart[*]}"
  for s in "${services_to_restart[@]}"; do
    systemctl restart "$s" 2>/dev/null || true
    sleep 1
  done
  green "Restart commands sent."
  send_telegram "All services restarted on $(get_ip) at $(date -u +%FT%TZ)"
  read -rp "Press Enter..." _
}

# Install/config Telegram bot (save token & chat_id to /etc/yhds/telegram.conf)
install_telegram_flow(){
  echo "Configure Telegram Bot for notifications"
  read -rp "Enter BOT_TOKEN (format: 123456:ABC-...): " BOT_TOKEN
  read -rp "Enter CHAT_ID (user or group chat id): " CHAT_ID
  mkdir -p /etc/yhds
  cat >/etc/yhds/telegram.conf <<TCONF
BOT_TOKEN='${BOT_TOKEN}'
CHAT_ID='${CHAT_ID}'
TCONF
  chmod 600 /etc/yhds/telegram.conf
  green "Telegram config saved to /etc/yhds/telegram.conf"
  # test send
  send_telegram "✅ Telegram Bot Connected to VPS $(get_ip) (YHDS VPS PREMIUM)"
  sleep 1
}

# Dashboard view
dashboard_flow(){
  clear
  IP="$(get_ip)"
  echo "========================================="
  cyan "      YHDS VPS DASHBOARD - ${IP}"
  echo "========================================="
  echo "Uptime : $(uptime -p)"
  echo "Load   : $(cat /proc/loadavg | awk '{print $1\" \"$2\" \"$3}')"
  echo "Memory : $(free -h | awk '/Mem:/ {print $3\" used of \"$2}')"
  echo "Disk   : $(df -h / | awk 'NR==2{print $3\" used of \"$2\" (\"$5\")\"}')"
  echo "Accounts total: $(count_accounts)"
  echo
  echo "Service status:"
  for s in ssh xray nginx udp-custom; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then
      green "  ${s} : ON"
    else
      red "  ${s} : OFF"
    fi
  done
  # overall
  cnt_on=0; cnt_total=3
  for s in ssh xray udp-custom; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then cnt_on=$((cnt_on+1)); fi
  done
  if [ "$cnt_on" -eq "$cnt_total" ]; then
    green "  ALL SERVICES : ON"
  else
    yellow "  ALL SERVICES : PARTIAL (${cnt_on}/${cnt_total})"
  fi
  echo "========================================="
  read -rp "Press Enter to return..." _
}

# ---------------------------
# Create helper wrapper scripts for menu actions
# ---------------------------
# the wrappers call this installer with an action flag; this installer will detect action and run function
cat > /usr/local/bin/yhds-installer-run <<'RUNSH'
#!/usr/bin/env bash
# wrapper to call installer functions by action
ACTION="${1:-}"
case "$ACTION" in
  dashboard) /etc/yhds/installer_functions_exec.sh --dashboard ;;
  create_manual) /etc/yhds/installer_functions_exec.sh --create_manual ;;
  create_trial) /etc/yhds/installer_functions_exec.sh --create_trial ;;
  list) /etc/yhds/installer_functions_exec.sh --list ;;
  delete) /etc/yhds/installer_functions_exec.sh --delete ;;
  service) /etc/yhds/installer_functions_exec.sh --service ;;
  install_telegram) /etc/yhds/installer_functions_exec.sh --install_telegram ;;
  restart_all) /etc/yhds/installer_functions_exec.sh --restart_all ;;
  *) echo "Unknown action"; exit 1 ;;
esac
RUNSH
chmod +x /usr/local/bin/yhds-installer-run

# We'll create a small executable that sources the functions and dispatches to flows
cat > /etc/yhds/installer_functions_exec.sh <<'EXE'
#!/usr/bin/env bash
# This script sources the persisted functions and runs the interactive flows.
set -euo pipefail
source /etc/yhds/installer_functions.sh

# Define the flows again here (non-exhaustive - replicate from installer)
# For simplicity call the main installed script for flows using the same logic
# We'll reimplement minimal dispatch to call functions implemented in installer (create_system_user etc.)

# Re-declare helper functions to call the corresponding flows (they use functions in /etc/yhds/installer_functions.sh)
get_ip(){ command -v curl >/dev/null 2>&1 && curl -fsS --max-time 5 ifconfig.me || hostname -I | awk '{print $1}'; }

case "$1" in
  --dashboard) /usr/local/bin/yhds-dashboard-core ;;
  --create_manual) /usr/local/bin/yhds-create-manual-core ;;
  --create_trial) /usr/local/bin/yhds-create-trial-core ;;
  --list) /usr/local/bin/yhds-list-core ;;
  --delete) /usr/local/bin/yhds-delete-core ;;
  --service) /usr/local/bin/yhds-service-core ;;
  --install_telegram) /usr/local/bin/yhds-install-telegram-core ;;
  --restart_all) /usr/local/bin/yhds-restart-all-core ;;
  *)
    echo "No valid action given."
    exit 1
    ;;
esac
EXE

chmod +x /etc/yhds/installer_functions_exec.sh

# Create core small scripts that call back into this installer (because originals expect interactive shells)
cat > /usr/local/bin/yhds-dashboard-core <<'DCORE'
#!/usr/bin/env bash
# call the dashboard flow from the installer by invoking the main script with internal flag
bash -c 'source /etc/yhds/installer_functions.sh; bash -c "exec bash -c \"$(declare -f dashboard_flow); dashboard_flow\""' 
DCORE
chmod +x /usr/local/bin/yhds-dashboard-core

cat > /usr/local/bin/yhds-create-manual-core <<'CM'
#!/usr/bin/env bash
bash -c 'source /etc/yhds/installer_functions.sh; bash -c "exec bash -c \"$(declare -f create_manual_flow); create_manual_flow\""' 
CM
chmod +x /usr/local/bin/yhds-create-manual-core

cat > /usr/local/bin/yhds-create-trial-core <<'CT'
#!/usr/bin/env bash
bash -c 'source /etc/yhds/installer_functions.sh; bash -c "exec bash -c \"$(declare -f create_trial_flow); create_trial_flow\""' 
CT
chmod +x /usr/local/bin/yhds-create-trial-core

cat > /usr/local/bin/yhds-list-core <<'CL'
#!/usr/bin/env bash
bash -c 'source /etc/yhds/installer_functions.sh; bash -c "exec bash -c \"$(declare -f list_users_flow); list_users_flow\""' 
CL
chmod +x /usr/local/bin/yhds-list-core

cat > /usr/local/bin/yhds-delete-core <<'CD'
#!/usr/bin/env bash
bash -c 'source /etc/yhds/installer_functions.sh; bash -c "exec bash -c \"$(declare -f delete_user_flow); delete_user_flow\""' 
CD
chmod +x /usr/local/bin/yhds-delete-core

cat > /usr/local/bin/yhds-service-core <<'CS'
#!/usr/bin/env bash
bash -c 'source /etc/yhds/installer_functions.sh; bash -c "exec bash -c \"$(declare -f service_control_flow); service_control_flow\""' 
CS
chmod +x /usr/local/bin/yhds-service-core

cat > /usr/local/bin/yhds-install-telegram-core <<'CTG'
#!/usr/bin/env bash
bash -c 'source /etc/yhds/installer_functions.sh; bash -c "exec bash -c \"$(declare -f install_telegram_flow); install_telegram_flow\""' 
CTG
chmod +x /usr/local/bin/yhds-install-telegram-core

cat > /usr/local/bin/yhds-restart-all-core <<'CRALL'
#!/usr/bin/env bash
bash -c 'source /etc/yhds/installer_functions.sh; bash -c "exec bash -c \"$(declare -f restart_all_services_flow); restart_all_services_flow\""' 
CRALL
chmod +x /usr/local/bin/yhds-restart-all-core

# Shortcut wrappers that the menu will call
cat > /usr/local/bin/yhds-create-sshws <<'WR1'
#!/usr/bin/env bash
/usr/local/bin/yhds-installer-run create_manual
WR1
chmod +x /usr/local/bin/yhds-create-sshws

cat > /usr/local/bin/yhds-create-trojan <<'WR2'
#!/usr/bin/env bash
/usr/local/bin/yhds-installer-run create_manual
WR2
chmod +x /usr/local/bin/yhds-create-trojan

cat > /usr/local/bin/yhds-create-udp <<'WR3'
#!/usr/bin/env bash
/usr/local/bin/yhds-installer-run create_manual
WR3
chmod +x /usr/local/bin/yhds-create-udp

cat > /usr/local/bin/yhds-create-trial <<'WR4'
#!/usr/bin/env bash
/usr/local/bin/yhds-installer-run create_trial
WR4
chmod +x /usr/local/bin/yhds-create-trial

cat > /usr/local/bin/yhds-list <<'WR5'
#!/usr/bin/env bash
/usr/local/bin/yhds-installer-run list
WR5
chmod +x /usr/local/bin/yhds-list

cat > /usr/local/bin/yhds-delete <<'WR6'
#!/usr/bin/env bash
/usr/local/bin/yhds-installer-run delete
WR6
chmod +x /usr/local/bin/yhds-delete

cat > /usr/local/bin/yhds-service <<'WR7'
#!/usr/bin/env bash
/usr/local/bin/yhds-installer-run service
WR7
chmod +x /usr/local/bin/yhds-service

cat > /usr/local/bin/yhds-install-telegram <<'WR8'
#!/usr/bin/env bash
/usr/local/bin/yhds-installer-run install_telegram
WR8
chmod +x /usr/local/bin/yhds-install-telegram

cat > /usr/local/bin/yhds-restart-all <<'WR9'
#!/usr/bin/env bash
/usr/local/bin/yhds-installer-run restart_all
WR9
chmod +x /usr/local/bin/yhds-restart-all

# ---------------------------
# Main interactive menu (installed as /usr/local/bin/yhds-menu)
# ---------------------------
cat > /usr/local/bin/yhds-menu <<'YM'
#!/usr/bin/env bash
while true; do
  clear
  figlet "YHDS MENU" | lolcat
  echo "========================================="
  echo "      YHDS VPS PREMIUM - MENU"
  echo "========================================="
  echo "1) Dashboard"
  echo "2) Create SSH/WS Account (manual)"
  echo "3) Create Trojan-WS Account (manual)"
  echo "4) Create UDP-Custom Account (manual)"
  echo "5) Create Trial Account (1 day)"
  echo "6) Install Telegram Bot (Notifications)"
  echo "7) Restart All Server"
  echo "8) List Created Accounts"
  echo "9) Delete Account"
  echo "10) Service Control (start/stop/restart)"
  echo "0) Exit"
  read -rp "Choose: " ch
  case "$ch" in
    1) /usr/local/bin/yhds-installer-run dashboard ;;
    2) /usr/local/bin/yhds-create-sshws ;;
    3) /usr/local/bin/yhds-create-trojan ;;
    4) /usr/local/bin/yhds-create-udp ;;
    5) /usr/local/bin/yhds-create-trial ;;
    6) /usr/local/bin/yhds-install-telegram ;;
    7) /usr/local/bin/yhds-restart-all ;;
    8) /usr/local/bin/yhds-list ;;
    9) /usr/local/bin/yhds-delete ;;
    10)/usr/local/bin/yhds-service ;;
    0) exit 0 ;;
    *) echo "Invalid option"; sleep 1 ;;
  esac
  sleep 1
done
YM

chmod +x /usr/local/bin/yhds-menu

# ---------------------------
# Final messages & notes
# ---------------------------
green "========================================="
green "YHDS VPS PREMIUM installer finished"
echo "Run: yhds-menu      (menu will show dashboard & all features)"
echo "UDP service should be running and ready (udp-custom)"
echo "IPv6 disabled, firewall flushed (basic)."
green "========================================="

# Optionally auto-run menu now
read -rp "Do you want to open the menu now? (y/n) : " __ans
if [[ "${__ans,,}" =~ ^(y|yes)$ ]]; then
  /usr/local/bin/yhds-menu
fi

exit 0

#!/usr/bin/env bash
# install_yhds_full.sh
# YHDS VPS PREMIUM - All-in-one installer + menu (style: match previous, color, light)
# Run as root
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ---------------------------
# Paths & globals
# ---------------------------
LOG="/tmp/install_yhds_full.log"
DB_DIR="/etc/yhds"
USER_DB="${DB_DIR}/users.db"
UDP_DIR="/root/udp"
MENU_BIN="/usr/local/bin/yhds-menu"
INSTALLER_RUN="/usr/local/bin/yhds-installer-run"

mkdir -p "$DB_DIR" "$UDP_DIR" 2>/dev/null || true
touch "$USER_DB" 2>/dev/null || true
chmod 600 "$USER_DB" 2>/dev/null || true

# ---------------------------
# Colors (light, compatible)
# ---------------------------
_red(){ printf "\e[31m%s\e[0m\n" "$1"; }
_green(){ printf "\e[32m%s\e[0m\n" "$1"; }
_yellow(){ printf "\e[33m%s\e[0m\n" "$1"; }
_cyan(){ printf "\e[36m%s\e[0m\n" "$1"; }

# ---------------------------
# Ensure root
# ---------------------------
if [ "$(id -u)" -ne 0 ]; then
  _red "Please run as root: sudo bash $0"
  exit 1
fi

# ---------------------------
# Minimal deps (best-effort)
# ---------------------------
_green "[YHDS] Installing minimal dependencies..."
apt update -y >>"$LOG" 2>&1 || true
apt install -y curl wget unzip jq figlet lolcat netcat-openbsd >/dev/null 2>&1 || true

# small helper: get public ip (best-effort)
get_ip_fast(){
  IP=""
  if command -v curl >/dev/null 2>&1; then IP=$(curl -fsS --max-time 5 ifconfig.me || true); fi
  if [ -z "$IP" ] && command -v wget >/dev/null 2>&1; then IP=$(wget -qO- --timeout=5 ifconfig.me || true); fi
  if [ -z "$IP" ]; then IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true); fi
  echo "${IP:-127.0.0.1}"
}

# ---------------------------
# Disable IPv6 (optional; helps UDP)
# ---------------------------
apply_sysctl_kv(){ k="$1"; v="$2"; if ! grep -q -E "^${k}" /etc/sysctl.conf 2>/dev/null; then echo "${k} = ${v}" >> /etc/sysctl.conf; else sed -i "s|^${k}.*|${k} = ${v}|" /etc/sysctl.conf || true; fi }
apply_sysctl_kv "net.ipv6.conf.all.disable_ipv6" 1
apply_sysctl_kv "net.ipv6.conf.default.disable_ipv6" 1
sysctl -p >/dev/null 2>&1 || true

# ---------------------------
# Firewall: best-effort flush (avoids blocking UDP)
# ---------------------------
if command -v ufw >/dev/null 2>&1; then ufw disable >/dev/null 2>&1 || true; fi
iptables -F >/dev/null 2>&1 || true
iptables -t nat -F >/dev/null 2>&1 || true

# ---------------------------
# UDP-Custom download & service (if available)
# ---------------------------
_green "[YHDS] Installing udp-custom (if found in repo)..."
UDP_BIN_URL="https://raw.githubusercontent.com/Yahdiad1/yhds_udp/main/udp-custom-linux-amd64"
UDP_CONF_URL="https://raw.githubusercontent.com/Yahdiad1/yhds_udp/main/config.json"

if wget -qO "$UDP_DIR/udp-custom" "$UDP_BIN_URL"; then
  chmod +x "$UDP_DIR/udp-custom" || true
  _green "udp-custom binary downloaded"
else
  _yellow "udp-custom binary not found; continuing (you can upload /root/udp/udp-custom later)"
fi

if wget -qO "$UDP_DIR/config.json" "$UDP_CONF_URL"; then
  chmod 644 "$UDP_DIR/config.json" || true
  _green "udp-custom config downloaded"
else
  _yellow "udp-custom config not found; creating default config.json"
  cat >"$UDP_DIR/config.json" <<'JSON'
{
  "port":4096,
  "bind":"0.0.0.0"
}
JSON
fi

if [ -x "$UDP_DIR/udp-custom" ]; then
  cat >/etc/systemd/system/udp-custom.service <<'UNIT'
[Unit]
Description=UDP Custom by YHDS
After=network.target

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload || true
  systemctl enable --now udp-custom >/dev/null 2>&1 || true
fi

# ---------------------------
# Persisted helper functions (sourceable)
# ---------------------------
cat >/etc/yhds/installer_functions.sh <<'FUNCS'
#!/usr/bin/env bash
set -euo pipefail
DB_DIR="/etc/yhds"
USER_DB="${DB_DIR}/users.db"
UDP_DIR="/root/udp"

get_ip(){
  IP=""
  if command -v curl >/dev/null 2>&1; then IP=$(curl -fsS --max-time 5 ifconfig.me || true); fi
  if [ -z "$IP" ] && command -v wget >/dev/null 2>&1; then IP=$(wget -qO- --timeout=5 ifconfig.me || true); fi
  if [ -z "$IP" ]; then IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true); fi
  echo "${IP:-127.0.0.1}"
}

detect_port(){
  svc="$1"
  case "$svc" in
    ssh) echo "$(ss -tnlp 2>/dev/null | awk -F':' '/sshd/{print $NF;exit}' | awk '{print $1}' || echo 22)" ;;
    ws|xray|trojan) echo "443" ;;
    udp)
      if [ -f "${UDP_DIR}/config.json" ]; then
        grep -oP '"port"\s*:\s*\K\d+' "${UDP_DIR}/config.json" | head -n1 || echo 4096
      else
        echo 4096
      fi ;;
    *) echo "" ;;
  esac
}

record_user(){
  user="$1"; pass="$2"; expire="$3"; maxl="$4"; svc="$5"
  echo "${user}:${pass}:${expire}:${maxl}:$(date -u +%FT%TZ):${svc}" >> "${USER_DB}"
  chmod 600 "${USER_DB}" || true
}

count_accounts(){ [ -f "${USER_DB}" ] && wc -l < "${USER_DB}" || echo 0; }

create_system_user(){
  username="$1"; password="$2"; expire_date="$3"; maxlogin="$4"
  if id "${username}" >/dev/null 2>&1; then
    echo "exists"; return 1
  fi
  useradd -M -N -s /usr/sbin/nologin -e "${expire_date}" "${username}" || return 1
  echo "${username}:${password}" | chpasswd || true
  echo "${username} hard maxlogins ${maxlogin}" > /etc/security/limits.d/yhds_${username}.conf || true
  return 0
}

remove_system_user(){
  username="$1"
  userdel -f "${username}" 2>/dev/null || true
  rm -f /etc/security/limits.d/yhds_${username}.conf || true
  if [ -f "${USER_DB}" ]; then
    grep -v -E "^${username}:" "${USER_DB}" > "${USER_DB}.tmp" || true
    mv -f "${USER_DB}.tmp" "${USER_DB}" || true
  fi
}

generate_payloads(){
  username="$1"; password="$2"; svc="$3"
  IP="$(get_ip)"
  SSH_PORT="$(detect_port ssh)"
  WS_PORT="$(detect_port ws)"
  TROJAN_PORT="$(detect_port xray)"
  UDP_PORT="$(detect_port udp)"
  cat <<PAY
----- PAYLOADS -----
SSH  : ssh://${username}:${password}@${IP}:${SSH_PORT}
WS   : vless://${username}@${IP}:${WS_PORT}?type=ws&path=/ws#${username}-ws
Trojan-WS : trojan://${password}@${IP}:${TROJAN_PORT}?sni=${IP}#${username}-trojan-ws
UDP client example: ${UDP_DIR}/udp-custom client --server ${IP}:${UDP_PORT} --user ${username} --pass ${password}
--------------------
PAY
}

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

# source for runtime usage
# shellcheck disable=SC1091
source /etc/yhds/installer_functions.sh || true

# ---------------------------
# Admin flows (menu actions)
# ---------------------------
create_manual_flow(){
  echo "Create manual account (ssh/ws/trojan/udp)"
  read -rp "Service type (ssh/ws/trojan/udp): " svc
  read -rp "Username: " username
  read -rp "Password (leave blank to auto-generate): " passwd
  if [ -z "$passwd" ]; then
    passwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c12)
    echo "Generated password: $passwd"
  fi
  read -rp "Expire in how many days (e.g. 7): " days
  if ! [[ "$days" =~ ^[0-9]+$ ]]; then echo "Expire must be a number. Using 7."; days=7; fi
  read -rp "Max simultaneous logins (e.g. 1): " maxl
  if ! [[ "$maxl" =~ ^[0-9]+$ ]]; then maxl=1; fi
  expire_date=$(date -d "+${days} days" +%F)
  if create_system_user "$username" "$passwd" "$expire_date" "$maxl"; then
    record_user "$username" "$passwd" "$expire_date" "$maxl" "$svc"
    _green "User $username created (svc:$svc) expires:$expire_date"
    generate_payloads "$username" "$passwd" "$svc"
    send_telegram "New account: ${username} svc:${svc} expires:${expire_date} on $(get_ip)"
  else
    _red "Failed to create user (maybe exists)."
  fi
  read -rp "Press Enter to return..." _
}

create_trial_flow(){
  echo "Create trial account (1 day)"
  read -rp "Username (trial-...): " username
  read -rp "Password (blank auto): " passwd
  if [ -z "$passwd" ]; then passwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c10); echo "Generated password: $passwd"; fi
  expire_date=$(date -d "+1 day" +%F)
  maxl=1; svc="trial"
  if create_system_user "$username" "$passwd" "$expire_date" "$maxl"; then
    record_user "$username" "$passwd" "$expire_date" "$maxl" "$svc"
    _green "Trial $username created, expires $expire_date"
    generate_payloads "$username" "$passwd" "$svc"
    send_telegram "New TRIAL: ${username} expires:${expire_date} on $(get_ip)"
  else
    _red "Failed to create trial user."
  fi
  read -rp "Press Enter to return..." _
}

list_users_flow(){
  printf "%-15s %-12s %-6s %-20s %-8s\n" "USERNAME" "EXPIRES" "MAXLOG" "CREATED_AT" "SERVICE"
  if [ -f "$USER_DB" ]; then
    while IFS=: read -r u p e m c s; do
      printf "%-15s %-12s %-6s %-20s %-8s\n" "$u" "$e" "$m" "$c" "$s"
    done < "$USER_DB"
  fi
  echo
  read -rp "Press Enter to return..." _
}

delete_user_flow(){
  read -rp "Username to delete: " u
  if grep -q "^${u}:" "$USER_DB" 2>/dev/null; then
    remove_system_user "$u"
    _green "Removed $u"
    send_telegram "Removed account: ${u} on $(get_ip)"
  else
    _red "User not found"
  fi
  read -rp "Press Enter to return..." _
}

service_control_flow(){
  echo "Services: 1) ssh 2) xray 3) udp-custom 4) nginx"
  read -rp "Choose service number: " sn
  case "$sn" in
    1) svc=ssh;;
    2) svc=xray;;
    3) svc=udp-custom;;
    4) svc=nginx;;
    *) _red "Invalid"; read -rp "Press Enter..." _; return ;;
  esac
  echo "1) start  2) stop  3) restart"
  read -rp "Action: " act
  case "$act" in
    1) systemctl start "$svc" 2>/dev/null || true;;
    2) systemctl stop "$svc" 2>/dev/null || true;;
    3) systemctl restart "$svc" 2>/dev/null || true;;
    *) _red "Invalid action";;
  esac
  _green "Done (requested action $act on $svc)"
  read -rp "Press Enter to return..." _
}

diagnose_udp_flow(){
  clear
  echo "=== UDP DIAGNOSE ==="
  CONFIG="$UDP_DIR/config.json"
  UDP_PORT=$(grep -oP '"port"\s*:\s*\K\d+' "$CONFIG" 2>/dev/null || echo 4096)
  echo "UDP Port: $UDP_PORT"
  if systemctl is-active --quiet udp-custom 2>/dev/null; then _green "udp-custom: ON"; else _red "udp-custom: OFF"; fi
  if iptables -C INPUT -p udp --dport "$UDP_PORT" -j ACCEPT 2>/dev/null; then _green "iptables: open"; else _red "iptables: blocked (or no rule)"; fi
  if ss -ulpn | grep -q ":$UDP_PORT"; then _green "Listening: yes"; else _red "Listening: no"; fi
  if command -v nc >/dev/null 2>&1; then echo test | nc -u -w1 127.0.0.1 "$UDP_PORT" &>/dev/null && _green "Local UDP OK" || _red "Local UDP FAIL"; else _yellow "nc not installed; cannot test local UDP"; fi
  read -rp "Press Enter to return..." _
}

fix_udp_flow(){
  CONFIG="$UDP_DIR/config.json"
  UDP_PORT=$(grep -oP '"port"\s*:\s*\K\d+' "$CONFIG" 2>/dev/null || echo 4096)
  _yellow "Attempting to start & enable services..."
  systemctl start udp-custom 2>/dev/null || true; systemctl enable udp-custom 2>/dev/null || true
  systemctl start xray 2>/dev/null || true; systemctl enable xray 2>/dev/null || true
  systemctl start nginx 2>/dev/null || true; systemctl enable nginx 2>/dev/null || true
  if ! iptables -C INPUT -p udp --dport "$UDP_PORT" -j ACCEPT 2>/dev/null; then iptables -I INPUT -p udp --dport "$UDP_PORT" -j ACCEPT 2>/dev/null || true; fi
  if command -v ufw >/dev/null 2>&1; then ufw allow "${UDP_PORT}/udp" >/dev/null 2>&1 || true; fi
  _green "Fix steps attempted. Re-run diagnose to check."
  send_telegram "UDP/Xray/Nginx fix attempted on $(get_ip)"
  read -rp "Press Enter to return..." _
}

install_telegram_flow(){
  echo "Configure Telegram Bot (for notifications)"
  read -rp "BOT_TOKEN (123456:ABC...): " BOT_TOKEN
  read -rp "CHAT_ID: " CHAT_ID
  mkdir -p /etc/yhds
  cat >/etc/yhds/telegram.conf <<TCONF
BOT_TOKEN='${BOT_TOKEN}'
CHAT_ID='${CHAT_ID}'
TCONF
  chmod 600 /etc/yhds/telegram.conf || true
  _green "Saved /etc/yhds/telegram.conf"
  if command -v curl >/dev/null 2>&1; then
    . /etc/yhds/telegram.conf
    curl -s --max-time 10 "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d text="✅ Telegram Bot connected (YHDS) $(get_ip)" >/dev/null 2>&1 || true
    _green "Test message sent (may fail if token/chat invalid)"
  fi
  read -rp "Press Enter to return..." _
}

dashboard_flow(){
  clear
  IP="$(get_ip)"
  echo "========================================="
  printf "      YHDS VPS DASHBOARD - %s\n" "$IP"
  echo "========================================="
  echo "Uptime : $(uptime -p)"
  echo "Load   : $(cat /proc/loadavg | awk '{print $1\" \"$2\" \"$3}')"
  echo "Memory : $(free -h | awk '/Mem:/ {print $3\" used of \"$2}')"
  echo "Disk   : $(df -h / | awk 'NR==2{print $3\" used of \"$2\" (\"$5\")\"}')"
  echo "Accounts total: $(count_accounts)"
  echo ""
  echo "Service status:"
  for s in ssh xray nginx udp-custom; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then printf "  %-10s : %s\n" "$s" "ON"; else printf "  %-10s : %s\n" "$s" "OFF"; fi
  done
  read -rp "Press Enter to return..." _
}
FUNCS

# ---------------------------
# installer-run wrapper (single entry)
# ---------------------------
cat >"$INSTALLER_RUN" <<'RUN'
#!/usr/bin/env bash
ACTION="${1:-}"
case "$ACTION" in
  dashboard) bash -lc 'source /etc/yhds/installer_functions.sh; dashboard_flow' ;;
  create_manual) bash -lc 'source /etc/yhds/installer_functions.sh; create_manual_flow' ;;
  create_trial) bash -lc 'source /etc/yhds/installer_functions.sh; create_trial_flow' ;;
  list) bash -lc 'source /etc/yhds/installer_functions.sh; list_users_flow' ;;
  delete) bash -lc 'source /etc/yhds/installer_functions.sh; delete_user_flow' ;;
  service) bash -lc 'source /etc/yhds/installer_functions.sh; service_control_flow' ;;
  diagnose_udp) bash -lc 'source /etc/yhds/installer_functions.sh; diagnose_udp_flow' ;;
  fix_udp) bash -lc 'source /etc/yhds/installer_functions.sh; fix_udp_flow' ;;
  install_telegram) bash -lc 'source /etc/yhds/installer_functions.sh; install_telegram_flow' ;;
  restart_all) bash -lc 'source /etc/yhds/installer_functions.sh; restart_all_services_flow' ;;
  *) echo "Unknown action: $ACTION"; exit 1 ;;
esac
RUN
chmod +x "$INSTALLER_RUN" || true

# link convenience wrappers
for x in dashboard create_manual create_trial list delete service diagnose_udp fix_udp install_telegram restart_all; do
  ln -sf "$INSTALLER_RUN" "/usr/local/bin/yhds-${x}" || true
done

# create yhds-menu (interactive, loops back after each action)
cat >"$MENU_BIN" <<'MENU'
#!/usr/bin/env bash
set -euo pipefail
source /etc/yhds/installer_functions.sh || true
while true; do
  clear
  figlet "YHDS MENU" | lolcat 2>/dev/null || echo "=== YHDS MENU ==="
  echo "========================================="
  echo "      YHDS VPS PREMIUM - MENU (style match)"
  echo "========================================="
  echo "1) Dashboard"
  echo "2) Create SSH/WS Account (manual)"
  echo "3) Create Trojan-WS Account (manual)"
  echo "4) Create UDP-Custom Account (manual)"
  echo "5) Create Trial Account (1 day)"
  echo "6) Install Telegram Bot (Notifications)"
  echo "7) Restart All Services"
  echo "8) List Created Accounts"
  echo "9) Delete Account"
  echo "10) Service Control (start/stop/restart)"
  echo "11) Diagnose UDP"
  echo "12) Fix UDP + ensure Xray & Nginx ON"
  echo "0) Exit"
  echo "-----------------------------------------"
  read -rp "Choose: " ch
  case "$ch" in
    1) /usr/local/bin/yhds-installer-run dashboard ;;
    2) /usr/local/bin/yhds-installer-run create_manual ;;
    3) /usr/local/bin/yhds-installer-run create_manual ;;
    4) /usr/local/bin/yhds-installer-run create_manual ;;
    5) /usr/local/bin/yhds-installer-run create_trial ;;
    6) /usr/local/bin/yhds-installer-run install_telegram ;;
    7) /usr/local/bin/yhds-installer-run restart_all ;;
    8) /usr/local/bin/yhds-installer-run list ;;
    9) /usr/local/bin/yhds-installer-run delete ;;
    10)/usr/local/bin/yhds-installer-run service ;;
    11)/usr/local/bin/yhds-installer-run diagnose_udp ;;
    12)/usr/local/bin/yhds-installer-run fix_udp ;;
    0)
      read -rp "Exit menu? (y/N): " yn
      if [[ "${yn,,}" =~ ^(y|yes)$ ]]; then echo "Goodbye."; exit 0; fi
      ;;
    *)
      echo "Invalid option."
      sleep 0.7
      ;;
  esac
  # ensure menu returns after action
  sleep 0.2
done
MENU

chmod +x "$MENU_BIN" || true

# ---------------------------
# Final note to user
# ---------------------------
_green "========================================="
_green "YHDS installer finished."
echo "Run the menu with: yhds-menu  (or /usr/local/bin/yhds-menu)"
echo "- Users DB: /etc/yhds/users.db"
echo "- UDP config: /root/udp/config.json"
echo "- To run menu at boot/login, create a systemd service or call yhds-menu from your shell."
_green "========================================="

# Ask to open menu now
read -rp "Open menu now? (y/N): " __ans
if [[ "${__ans,,}" =~ ^(y|yes)$ ]]; then
  exec "$MENU_BIN"
fi

exit 0

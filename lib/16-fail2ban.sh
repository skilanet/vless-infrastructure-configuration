#!/usr/bin/env bash
#
# lib/17-fail2ban.sh — устанавливает fail2ban для SSH

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

if ! $INSTALL_FAIL2BAN; then
    log_info "fail2ban пропущен по выбору юзера"
    exit 0
fi

# Установка
if ! command -v fail2ban-server >/dev/null 2>&1; then
    log_info "устанавливаю fail2ban..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban
fi

# Конфиг для SSH.
# backend=systemd читает journald напрямую; logpath с ним конфликтует и
# на современных Debian/Ubuntu /var/log/auth.log может вообще отсутствовать
# (journald-only). Поэтому только backend=systemd.
cat > /etc/fail2ban/jail.d/sshd.conf <<EOF
[sshd]
enabled = true
port = $SSH_PORT
backend = systemd
maxretry = 3
findtime = 600
bantime = 3600
EOF

chmod 644 /etc/fail2ban/jail.d/sshd.conf

systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban

sleep 2

if systemctl is-active fail2ban >/dev/null 2>&1; then
    log_ok "fail2ban запущен и охраняет SSH ($SSH_PORT)"
else
    log_warn "fail2ban не стартует, проверь journalctl -u fail2ban"
fi

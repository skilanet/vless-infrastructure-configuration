#!/usr/bin/env bash
#
# lib/14-xray-install.sh — устанавливает xray-core и готовит инфраструктуру.
#
# НЕ создаёт конфиги — это делает админ-панель.
# НЕ запускает xray — нечем (нет конфига).

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

# === Установка xray-core ===
if command -v xray >/dev/null 2>&1; then
    log_info "xray уже установлен: $(xray version 2>/dev/null | head -1)"
else
    log_info "устанавливаю xray-core от XTLS..."

    INSTALLER_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
    if ! curl -fsSL "$INSTALLER_URL" -o /tmp/xray-install.sh; then
        log_error "не удалось скачать xray installer"
        exit 1
    fi

    chmod +x /tmp/xray-install.sh
    bash /tmp/xray-install.sh @ install -u "$XRAY_USER" >/dev/null

    if ! command -v xray >/dev/null 2>&1; then
        log_error "xray не установился"
        exit 1
    fi

    log_ok "xray установлен: $(xray version 2>/dev/null | head -1)"
    rm -f /tmp/xray-install.sh
fi

# === Создание директорий ===
log_info "подготавливаю файловую структуру..."

# conf.d/ — здесь админ-панель будет писать конфиги
mkdir -p /usr/local/etc/xray/conf.d
mkdir -p /usr/local/etc/xray/backups
chown root:"$XRAY_USER" /usr/local/etc/xray
chown root:"$XRAY_USER" /usr/local/etc/xray/conf.d
chmod 750 /usr/local/etc/xray
chmod 750 /usr/local/etc/xray/conf.d

# Логи xray
mkdir -p /var/log/xray
chown "$XRAY_USER:$XRAY_USER" /var/log/xray
chmod 750 /var/log/xray

# Старый config.json убираем чтобы systemd точно стартовал в режиме -confdir
if [[ -f /usr/local/etc/xray/config.json ]]; then
    backup_file /usr/local/etc/xray/config.json
    rm -f /usr/local/etc/xray/config.json
fi

log_ok "директории готовы"

# === systemd drop-in для conf.d ===
mkdir -p /etc/systemd/system/xray.service.d/

cat > /etc/systemd/system/xray.service.d/30-confdir.conf <<EOF
# Использовать conf.d/ вместо одиночного config.json
[Service]
ExecStart=
ExecStart=/usr/local/bin/xray run -confdir /usr/local/etc/xray/conf.d
EOF

# === systemd drop-in для лимитов ===
cat > /etc/systemd/system/xray.service.d/20-limits.conf <<EOF
# Лимиты ресурсов и Go runtime tuning
[Service]
MemoryHigh=400M
MemoryMax=600M
Restart=always
RestartSec=2s
Environment="GOGC=20"
Environment="GOMEMLIMIT=400MiB"
EOF

systemctl daemon-reload

log_ok "systemd drop-ins созданы"

# === Останавливаем xray и снимаем enable ===
# Без конфига он будет стартовать и падать. Панель сама запустит когда напишет конфиг.
systemctl stop xray 2>/dev/null || true
systemctl disable xray 2>/dev/null || true

log_info "xray установлен но не запущен — панель его стартует после первой настройки"

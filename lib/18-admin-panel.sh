#!/usr/bin/env bash
#
# lib/18-admin-panel.sh — устанавливает админ-панель
#
# Делает:
# - копирует код панели в /opt/xray-admin
# - создаёт venv, ставит зависимости
# - генерит config.json с захэшированным паролем
# - создаёт systemd-сервис xray-admin
# - запускает

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

PANEL_DIR="/opt/xray-admin"
PANEL_CONFIG="/etc/xray-admin/config.json"

# === Python deps ===
log_info "ставлю Python зависимости..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3-venv \
    python3-pip

# === Копируем код панели ===
log_info "копирую код панели в $PANEL_DIR..."
mkdir -p "$PANEL_DIR"
cp -r "$SCRIPT_DIR/admin-panel/"* "$PANEL_DIR/"

# Права: владелец panel-юзер, читать может группа xray
chown -R "$PANEL_USER:$XRAY_USER" "$PANEL_DIR"
chmod -R 750 "$PANEL_DIR"

# === Создаём venv и ставим зависимости ===
log_info "создаю virtualenv..."
sudo -u "$PANEL_USER" python3 -m venv "$PANEL_DIR/venv"
sudo -u "$PANEL_USER" "$PANEL_DIR/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$PANEL_USER" "$PANEL_DIR/venv/bin/pip" install --quiet -r "$PANEL_DIR/requirements.txt"

log_ok "зависимости установлены"

# === Генерируем хэш пароля ===
PASSWORD_HASH=$("$PANEL_DIR/venv/bin/python3" -c "
from werkzeug.security import generate_password_hash
import sys
print(generate_password_hash(sys.argv[1]))
" "$PANEL_PASSWORD")

# === Генерируем secret_key для Flask sessions ===
SECRET_KEY=$(openssl rand -hex 32)

# === Конфиг панели ===
mkdir -p /etc/xray-admin
cat > "$PANEL_CONFIG" <<EOF
{
  "host": "0.0.0.0",
  "port": $PANEL_PORT,
  "admin_login": "$PANEL_LOGIN",
  "admin_password_hash": "$PASSWORD_HASH",
  "secret_key": "$SECRET_KEY"
}
EOF

chown "$PANEL_USER:$PANEL_USER" "$PANEL_CONFIG"
chmod 600 "$PANEL_CONFIG"
chmod 750 /etc/xray-admin

log_ok "конфиг панели сохранён в $PANEL_CONFIG"

# === systemd unit ===
cat > /etc/systemd/system/xray-admin.service <<EOF
[Unit]
Description=xray-admin web panel
After=network.target
Wants=network.target

[Service]
Type=simple
User=$PANEL_USER
Group=$PANEL_USER
WorkingDirectory=$PANEL_DIR
ExecStart=$PANEL_DIR/venv/bin/gunicorn \\
    --bind 0.0.0.0:$PANEL_PORT \\
    --workers 2 \\
    --threads 2 \\
    --access-logfile - \\
    --error-logfile - \\
    app:app
Restart=on-failure
RestartSec=5s

# Безопасность
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/usr/local/etc/xray /var/log/xray-admin /etc/xray-admin
ProtectHome=true

# Лимиты
MemoryMax=200M

# Логи
StandardOutput=journal
StandardError=journal
SyslogIdentifier=xray-admin

[Install]
WantedBy=multi-user.target
EOF

# Директория для логов панели если потребуется
mkdir -p /var/log/xray-admin
chown "$PANEL_USER:$PANEL_USER" /var/log/xray-admin

systemctl daemon-reload
systemctl enable xray-admin >/dev/null 2>&1 || true
systemctl start xray-admin

sleep 3

if systemctl is-active xray-admin >/dev/null 2>&1; then
    log_ok "xray-admin запущен на порту $PANEL_PORT"
else
    log_error "xray-admin не стартует"
    journalctl -u xray-admin -n 30 --no-pager
    exit 1
fi

# === Финальная проверка ===
if curl -fsSL --max-time 5 "http://127.0.0.1:$PANEL_PORT/health" >/dev/null 2>&1; then
    log_ok "админ-панель отвечает на /health"
else
    log_warn "панель не отвечает на /health, но процесс запущен"
fi

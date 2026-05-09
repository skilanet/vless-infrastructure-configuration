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
PANEL_BIND="${PANEL_BIND:-127.0.0.1}"

# === Python deps ===
log_info "ставлю Python зависимости..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3-venv \
    python3-pip

# === Копируем код панели ===
# rsync с --delete, чтобы удалённые из репо файлы исчезли и из /opt/xray-admin
# (cp -r поверх старой версии оставлял бы устаревшие файлы).
# venv/ исключаем — он создаётся следующим шагом и не должен затираться.
log_info "копирую код панели в $PANEL_DIR..."
mkdir -p "$PANEL_DIR"

if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
          --exclude 'venv/' \
          --exclude '__pycache__/' \
          "$SCRIPT_DIR/admin-panel/" "$PANEL_DIR/"
else
    # Fallback без rsync — менее аккуратно, но всё ещё работает.
    cp -r "$SCRIPT_DIR/admin-panel/"* "$PANEL_DIR/"
fi

# Права: владелец panel-юзер, читать может группа xray
chown -R "$PANEL_USER:$XRAY_USER" "$PANEL_DIR"
chmod -R 750 "$PANEL_DIR"

# === Создаём venv и ставим зависимости ===
log_info "создаю virtualenv..."
sudo -u "$PANEL_USER" python3 -m venv "$PANEL_DIR/venv"
sudo -u "$PANEL_USER" "$PANEL_DIR/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$PANEL_USER" "$PANEL_DIR/venv/bin/pip" install --quiet -r "$PANEL_DIR/requirements.txt"

log_ok "зависимости установлены"

# === Считываем существующий конфиг (для rerun) ===
# При rerun после finalize PANEL_PASSWORD уже стёрт из state.env,
# а secret_key регенерировать нельзя — иначе разлогинятся все сессии.
EXISTING_HASH=""
EXISTING_SECRET=""
if [[ -f "$PANEL_CONFIG" ]]; then
    EXISTING_HASH=$(jq -r '.admin_password_hash // empty' "$PANEL_CONFIG" 2>/dev/null || true)
    EXISTING_SECRET=$(jq -r '.secret_key // empty' "$PANEL_CONFIG" 2>/dev/null || true)
fi

# === Хэш пароля ===
# Если PANEL_PASSWORD задан — генерим новый хэш.
# Если пуст и есть существующий — переиспользуем (rerun сценарий).
# Если ни того ни другого — фейл с понятным сообщением.
if [[ -n "${PANEL_PASSWORD:-}" ]]; then
    # Передаём пароль через stdin, чтобы он не попал в argv (видим через ps).
    PASSWORD_HASH=$(printf '%s' "$PANEL_PASSWORD" | "$PANEL_DIR/venv/bin/python3" -c "
import sys
from werkzeug.security import generate_password_hash
pwd = sys.stdin.read()
print(generate_password_hash(pwd))
")
    if [[ -z "$PASSWORD_HASH" ]]; then
        log_error "не удалось сгенерировать хэш пароля"
        exit 1
    fi
elif [[ -n "$EXISTING_HASH" ]]; then
    PASSWORD_HASH="$EXISTING_HASH"
    log_info "PANEL_PASSWORD пуст — переиспользую существующий хэш из $PANEL_CONFIG"
else
    log_error "PANEL_PASSWORD не задан и нет существующего конфига для переиспользования"
    log_error "запусти: sudo bash install.sh --rerun 01-prompts (введёшь новый пароль)"
    log_error "или удали $PANEL_CONFIG и сделай полный --reset"
    exit 1
fi

# === secret_key ===
# Переиспользуем существующий, чтобы не инвалидировать сессии при rerun.
SECRET_KEY="${EXISTING_SECRET:-$(openssl rand -hex 32)}"

# === Конфиг панели ===
mkdir -p /etc/xray-admin
# Создаём пустой файл сразу с правами 600 root — без окна, в которое
# можно подсмотреть содержимое через мир-читаемый файл.
install -m 600 -o root -g root /dev/null "$PANEL_CONFIG"

PANEL_BIND="$PANEL_BIND" \
PANEL_PORT="$PANEL_PORT" \
PANEL_LOGIN="$PANEL_LOGIN" \
PANEL_PASSWORD_HASH="$PASSWORD_HASH" \
PANEL_SECRET_KEY="$SECRET_KEY" \
PANEL_CONFIG_PATH="$PANEL_CONFIG" \
"$PANEL_DIR/venv/bin/python3" - <<'PYEOF'
import json, os
cfg = {
    "host": os.environ["PANEL_BIND"],
    "port": int(os.environ["PANEL_PORT"]),
    "admin_login": os.environ["PANEL_LOGIN"],
    "admin_password_hash": os.environ["PANEL_PASSWORD_HASH"],
    "secret_key": os.environ["PANEL_SECRET_KEY"],
}
with open(os.environ["PANEL_CONFIG_PATH"], "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF

chown "$PANEL_USER:$PANEL_USER" "$PANEL_CONFIG"
chmod 600 "$PANEL_CONFIG"

# Директория должна быть проходимой для panel-юзера, иначе он не дотянется
# до config.json (даже если он его owner). root:panel + 750 даёт юзеру
# rx через группу, но не write — добавлять/удалять файлы по-прежнему может
# только root.
chown "root:$PANEL_USER" /etc/xray-admin
chmod 750 /etc/xray-admin

# Пароль больше не нужен — затираем переменную.
unset PANEL_PASSWORD PASSWORD_HASH

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
    --bind $PANEL_BIND:$PANEL_PORT \\
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
PrivateDevices=true
ProtectSystem=strict
ReadWritePaths=/usr/local/etc/xray /var/log/xray-admin /etc/xray-admin
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=

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

# Restart, не start: на rerun нужно поднять сервис с обновлённым конфигом.
# Если он не активен — restart всё равно его запустит.
systemctl restart xray-admin

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

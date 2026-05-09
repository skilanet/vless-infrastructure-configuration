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

    # Скачиваем установщик в защищённую временную директорию (TOCTOU-free).
    # /tmp небезопасен — другие юзеры могут подменить файл между chmod и bash.
    TMPDIR=$(mktemp -d -t xray-install.XXXXXX)
    trap 'rm -rf "$TMPDIR"' EXIT
    chmod 700 "$TMPDIR"

    # Можно переопределить URL через env (для пиннига к конкретному коммиту в проде).
    INSTALLER_URL="${XRAY_INSTALLER_URL:-https://github.com/XTLS/Xray-install/raw/main/install-release.sh}"
    INSTALLER_PATH="$TMPDIR/install-release.sh"

    if ! curl -fsSL --proto '=https' --tlsv1.2 "$INSTALLER_URL" -o "$INSTALLER_PATH"; then
        log_error "не удалось скачать xray installer"
        exit 1
    fi

    # Sanity-check: размер должен быть в разумных пределах и shebang на месте.
    size=$(wc -c < "$INSTALLER_PATH")
    if (( size < 1024 || size > 200000 )); then
        log_error "подозрительный размер xray installer: $size байт"
        log_error "возможно, скачался HTML-ошибка или подменили скрипт"
        exit 1
    fi
    if ! head -1 "$INSTALLER_PATH" | grep -q '^#!/.*\(bash\|sh\)'; then
        log_error "xray installer не начинается с shebang — отказываюсь запускать"
        exit 1
    fi

    # Если есть ожидаемый sha256 — сверяем. Иначе показываем фактический хэш в лог,
    # чтобы можно было пиннуть его в проде через XRAY_INSTALLER_SHA256.
    actual_hash=$(sha256sum "$INSTALLER_PATH" | awk '{print $1}')
    if [[ -n "${XRAY_INSTALLER_SHA256:-}" ]]; then
        if [[ "$actual_hash" != "$XRAY_INSTALLER_SHA256" ]]; then
            log_error "xray installer hash mismatch"
            log_error "ожидался: $XRAY_INSTALLER_SHA256"
            log_error "получен:  $actual_hash"
            exit 1
        fi
        log_ok "xray installer прошёл проверку sha256"
    else
        log_info "xray installer sha256: $actual_hash"
        log_info "(можно зафиксировать через XRAY_INSTALLER_SHA256=...)"
    fi

    bash "$INSTALLER_PATH" @ install -u "$XRAY_USER" >/dev/null

    if ! command -v xray >/dev/null 2>&1; then
        log_error "xray не установился"
        exit 1
    fi

    log_ok "xray установлен: $(xray version 2>/dev/null | head -1)"
    rm -rf "$TMPDIR"
    trap - EXIT
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

# === systemd drop-in для security hardening ===
cat > /etc/systemd/system/xray.service.d/40-hardening.conf <<EOF
# Изоляция xray-процесса.
# CAP_NET_BIND_SERVICE нужен для портов <1024 (например, 443).
[Service]
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ReadWritePaths=/var/log/xray
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
EOF

systemctl daemon-reload

log_ok "systemd drop-ins созданы"

# === Останавливаем xray только при первой установке ===
# Если в conf.d уже есть конфиги (значит панель уже что-то настроила и xray
# может работать), то трогать сервис НЕ надо — иначе rerun этого модуля
# уронит живой VPN.
shopt -s nullglob
existing_configs=( /usr/local/etc/xray/conf.d/*.json )
shopt -u nullglob

if [[ ${#existing_configs[@]} -eq 0 ]]; then
    # Первый запуск — без конфига xray всё равно крутится в crash-loop, тушим.
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    log_info "xray установлен но не запущен — панель его стартует после первой настройки"
else
    log_info "в conf.d уже ${#existing_configs[@]} конфигов — сервис xray не трогаю"
    # Конфиг systemd мог измениться (drop-ins), даём xray применить новые лимиты/hardening
    if systemctl is-active xray >/dev/null 2>&1; then
        systemctl restart xray
        log_ok "xray перезапущен с обновлёнными drop-in'ами"
    fi
fi

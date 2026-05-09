#!/usr/bin/env bash
#
# lib/11-users.sh — создание системных пользователей.
#
# Три юзера:
# 1. ADMIN_USER — для SSH-логина, sudo, ручных вмешательств
# 2. XRAY_USER — runtime-юзер для xray-процесса (без shell)
# 3. PANEL_USER — runtime-юзер для админ-панели (без shell), в группе xray

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

# === 1. Админский юзер ===
if id "$ADMIN_USER" >/dev/null 2>&1; then
    log_info "пользователь $ADMIN_USER уже существует"
else
    log_info "создаю пользователя $ADMIN_USER..."
    useradd -m -s /bin/bash -c "VPN administrator" "$ADMIN_USER"
    log_ok "пользователь $ADMIN_USER создан"
fi

if ! id -nG "$ADMIN_USER" | grep -qw sudo; then
    usermod -aG sudo "$ADMIN_USER"
    log_ok "$ADMIN_USER добавлен в группу sudo"
fi

# === SSH ключ для админа ===
if [[ -n "${SSH_PUBLIC_KEY:-}" ]]; then
    home="/home/$ADMIN_USER"
    ssh_dir="$home/.ssh"
    auth_keys="$ssh_dir/authorized_keys"

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"

    if [[ -f "$auth_keys" ]] && grep -qxF "$SSH_PUBLIC_KEY" "$auth_keys"; then
        log_info "ssh-ключ уже в authorized_keys"
    else
        # гарантируем перевод строки перед добавлением
        if [[ -s "$auth_keys" ]] && [[ -n "$(tail -c1 "$auth_keys")" ]]; then
            printf '\n' >> "$auth_keys"
        fi
        printf '%s\n' "$SSH_PUBLIC_KEY" >> "$auth_keys"
        log_ok "ssh-ключ добавлен в authorized_keys"
    fi

    chmod 600 "$auth_keys"
    chown -R "$ADMIN_USER:$ADMIN_USER" "$ssh_dir"
else
    log_warn "ssh-ключ не задан — login будет только по паролю"
fi

# === 2. Xray runtime user ===
if id "$XRAY_USER" >/dev/null 2>&1; then
    log_info "пользователь $XRAY_USER уже существует"
else
    log_info "создаю системного пользователя $XRAY_USER..."
    useradd -r -s /usr/sbin/nologin -d /var/lib/xray -M "$XRAY_USER"
    log_ok "пользователь $XRAY_USER создан"
fi

# === 3. Panel runtime user ===
if id "$PANEL_USER" >/dev/null 2>&1; then
    log_info "пользователь $PANEL_USER уже существует"
else
    log_info "создаю системного пользователя $PANEL_USER..."
    # Панель пишет в conf.d/ — поэтому в группу xray (чтобы был доступ к директории)
    useradd -r -s /usr/sbin/nologin -d /opt/xray-admin -M "$PANEL_USER"
    log_ok "пользователь $PANEL_USER создан"
fi

# Добавляем panel-юзера в группу xray (для доступа к conf.d/)
if ! id -nG "$PANEL_USER" | grep -qw "$XRAY_USER"; then
    usermod -aG "$XRAY_USER" "$PANEL_USER"
    log_ok "$PANEL_USER добавлен в группу $XRAY_USER (для доступа к conf.d)"
fi

# === Sudoers для админа ===
#
# ADMIN_USER уже в группе sudo и может стать root по паролю — здесь
# только NOPASSWD-исключения для удобства (алиасы xstat/xwatch и т.п.).
#
# ВАЖНО: никаких glob-аргументов с '*' — sudo-wildcard это не fnmatch и
# легко обходится через '../'. Никаких 'find', потому что у find есть
# -exec и это приводит к мгновенной эскалации до root.
sudoers_admin="/etc/sudoers.d/$ADMIN_USER-xray-tools"
cat > "$sudoers_admin" <<EOF
# Управление сервисами xray и админ-панели
$ADMIN_USER ALL=(root) NOPASSWD: /bin/systemctl restart xray
$ADMIN_USER ALL=(root) NOPASSWD: /bin/systemctl reload xray
$ADMIN_USER ALL=(root) NOPASSWD: /bin/systemctl status xray
$ADMIN_USER ALL=(root) NOPASSWD: /bin/systemctl is-active xray
$ADMIN_USER ALL=(root) NOPASSWD: /bin/systemctl restart xray-admin
$ADMIN_USER ALL=(root) NOPASSWD: /bin/systemctl status xray-admin
$ADMIN_USER ALL=(root) NOPASSWD: /bin/systemctl is-active xray-admin

# Только конкретные read-only api команды для метрик
$ADMIN_USER ALL=(root) NOPASSWD: /usr/local/bin/xray api statsquery --server=127.0.0.1\:10085 -pattern user>>>
$ADMIN_USER ALL=(root) NOPASSWD: /usr/local/bin/xray api stats --server=127.0.0.1\:10085 -reset=false

# Health-чек скрипты (нужны для алиасов xstat/xwatch)
$ADMIN_USER ALL=(root) NOPASSWD: /usr/local/sbin/xray-health.sh
$ADMIN_USER ALL=(root) NOPASSWD: /usr/local/sbin/xray-metrics.sh
EOF

chmod 440 "$sudoers_admin"

if ! visudo -cf "$sudoers_admin" >/dev/null 2>&1; then
    log_error "sudoers-файл для $ADMIN_USER невалиден"
    rm -f "$sudoers_admin"
    exit 1
fi
log_ok "sudoers для $ADMIN_USER настроен"

# === Sudoers для PANEL_USER — разрешаем restart xray ===
# (UFW-разрешения добавит модуль 13-firewall.sh)
sudoers_panel="/etc/sudoers.d/$PANEL_USER-xray"
cat > "$sudoers_panel" <<EOF
# Разрешения для админ-панели на управление xray
# Только конкретные команды без glob-аргументов.
$PANEL_USER ALL=(root) NOPASSWD: /bin/systemctl restart xray
$PANEL_USER ALL=(root) NOPASSWD: /bin/systemctl reload xray
$PANEL_USER ALL=(root) NOPASSWD: /bin/systemctl start xray
$PANEL_USER ALL=(root) NOPASSWD: /bin/systemctl stop xray
$PANEL_USER ALL=(root) NOPASSWD: /bin/systemctl is-active xray
$PANEL_USER ALL=(root) NOPASSWD: /bin/systemctl status xray
$PANEL_USER ALL=(root) NOPASSWD: /bin/systemctl enable xray
$PANEL_USER ALL=(root) NOPASSWD: /bin/systemctl disable xray

# Валидация конфига (фиксированный набор аргументов)
$PANEL_USER ALL=(root) NOPASSWD: /usr/local/bin/xray -test -confdir /usr/local/etc/xray/conf.d

# Генерация ключей — только без аргументов, иначе xray принимает file/pipe и
# можно протащить произвольные данные.
$PANEL_USER ALL=(root) NOPASSWD: /usr/local/bin/xray x25519
$PANEL_USER ALL=(root) NOPASSWD: /usr/local/bin/xray uuid

# Read-only метрики
$PANEL_USER ALL=(root) NOPASSWD: /usr/local/bin/xray api statsquery --server=127.0.0.1\:10085 -pattern user>>>
$PANEL_USER ALL=(root) NOPASSWD: /usr/local/bin/xray api stats --server=127.0.0.1\:10085 -reset=false
EOF

chmod 440 "$sudoers_panel"

if ! visudo -cf "$sudoers_panel" >/dev/null 2>&1; then
    log_error "sudoers-файл для $PANEL_USER невалиден"
    rm -f "$sudoers_panel"
    exit 1
fi
log_ok "sudoers для $PANEL_USER настроен"

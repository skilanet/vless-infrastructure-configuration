#!/usr/bin/env bash
#
# lib/13-firewall.sh — настройка UFW.
#
# Открываем только SSH-порт и порт админ-панели.
# VLESS-порты будет открывать сама панель через sudoers-whitelist.

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

log_info "настраиваю UFW..."

# Дефолты
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw default deny routed >/dev/null

# SSH с rate-limit (защита от перебора)
ufw limit "$SSH_PORT/tcp" comment 'SSH (rate-limited)' >/dev/null

# Порт админ-панели
ufw allow "$PANEL_PORT/tcp" comment 'admin panel' >/dev/null

# Включаем
if ufw status | grep -q "Status: inactive"; then
    log_info "включаю ufw..."
    echo "y" | ufw enable >/dev/null
fi

ufw reload >/dev/null 2>&1 || true

log_ok "ufw настроен:"
ufw status numbered | grep -v "^$" | sed 's/^/  /'

# === Sudoers для админ-панели — разрешаем UFW operations ===
# Чтобы панель могла открывать порты для своих VLESS-инбаундов.
sudoers_panel="/etc/sudoers.d/$PANEL_USER-ufw"
cat > "$sudoers_panel" <<EOF
# Админ-панель может управлять UFW для добавления/удаления портов
$PANEL_USER ALL=(root) NOPASSWD: /usr/sbin/ufw allow [0-9]*[0-9]/tcp
$PANEL_USER ALL=(root) NOPASSWD: /usr/sbin/ufw allow [0-9]*[0-9]/tcp comment *
$PANEL_USER ALL=(root) NOPASSWD: /usr/sbin/ufw delete allow [0-9]*[0-9]/tcp
$PANEL_USER ALL=(root) NOPASSWD: /usr/sbin/ufw status
$PANEL_USER ALL=(root) NOPASSWD: /usr/sbin/ufw reload
EOF
chmod 440 "$sudoers_panel"

if ! visudo -cf "$sudoers_panel" >/dev/null 2>&1; then
    log_error "sudoers для $PANEL_USER невалидный"
    rm -f "$sudoers_panel"
    exit 1
fi

log_ok "sudoers для управления UFW из панели настроен"

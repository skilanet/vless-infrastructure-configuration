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

# Удаляем старые правила с нашими comment'ами, чтобы при смене порта
# (rerun со сменой SSH_PORT/PANEL_PORT) старые порты не остались открытыми.
# Удаляем по индексам с конца — индексы при удалении сдвигаются.
remove_rules_with_comment() {
    local comment_pattern="$1"
    while true; do
        # Находим самый большой номер правила, у которого в комментарии — наш паттерн
        local idx
        idx=$(ufw status numbered 2>/dev/null \
              | awk -v p="$comment_pattern" '$0 ~ p { match($0, /\[ *([0-9]+) *\]/, a); if (a[1] != "") print a[1] }' \
              | sort -rn | head -1)
        [[ -z "$idx" ]] && break
        yes | ufw delete "$idx" >/dev/null 2>&1 || break
    done
}
remove_rules_with_comment "SSH \(rate-limited\)"
remove_rules_with_comment "admin panel"

# SSH с rate-limit (защита от перебора)
ufw limit "$SSH_PORT/tcp" comment 'SSH (rate-limited)' >/dev/null

# Порт админ-панели — открываем только если она биндится на 0.0.0.0.
# При loopback-режиме порт не нужно открывать (доступ через SSH-туннель).
if [[ "${PANEL_BIND:-127.0.0.1}" == "0.0.0.0" ]]; then
    ufw allow "$PANEL_PORT/tcp" comment 'admin panel (public)' >/dev/null
    log_info "панель открыта на $PANEL_PORT (PANEL_BIND=0.0.0.0)"
else
    log_info "панель привязана к 127.0.0.1 — порт $PANEL_PORT в ufw не открыт"
    log_info "доступ через SSH-туннель: ssh -L 8088:localhost:$PANEL_PORT user@host"
fi

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

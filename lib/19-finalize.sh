#!/usr/bin/env bash
#
# lib/19-finalize.sh — финальные проверки

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

log_info "финальные проверки..."

# === xray установлен (но не запущен — это ОК) ===
if command -v xray >/dev/null 2>&1; then
    log_ok "xray установлен: $(xray version 2>/dev/null | head -1)"
else
    log_error "xray не установлен"
    exit 1
fi

# === sshd работает на новом порту ===
if ss -tlnp 2>/dev/null | grep -q ":$SSH_PORT.*sshd"; then
    log_ok "sshd слушает на $SSH_PORT"
else
    log_warn "sshd не виден на $SSH_PORT"
fi

# === ufw активен ===
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    log_ok "ufw активен"
fi

# === админ-панель работает ===
if systemctl is-active xray-admin >/dev/null 2>&1; then
    log_ok "xray-admin (панель) запущена"
    if ss -tlnp 2>/dev/null | grep -q ":$PANEL_PORT"; then
        log_ok "панель слушает на порту $PANEL_PORT"
    fi
else
    log_warn "xray-admin не активна, проверь journalctl -u xray-admin"
fi

# === conf.d пустая (это ОК) ===
if [[ -d /usr/local/etc/xray/conf.d ]]; then
    file_count=$(find /usr/local/etc/xray/conf.d -name "*.json" 2>/dev/null | wc -l)
    if [[ "$file_count" -eq 0 ]]; then
        log_info "conf.d пуста — настроишь через панель"
    else
        log_info "в conf.d уже $file_count конфигов"
    fi
fi

log_ok "финализация завершена"

# === Сохраняем итоговый отчёт ===
report_file="/root/xray-vpn-stack-installed.txt"
{
    echo "xray-vpn-stack установка завершена $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    echo "=== Системные параметры ==="
    echo "Админ user:        $ADMIN_USER"
    echo "Xray user:         $XRAY_USER"
    echo "Panel user:        $PANEL_USER"
    echo "SSH port:          $SSH_PORT"
    echo "Panel port:        $PANEL_PORT"
    echo "Panel login:       $PANEL_LOGIN"
    echo ""
    echo "=== Что дальше ==="
    echo "1. ssh -p $SSH_PORT $ADMIN_USER@<server-ip>"
    echo "2. Открой http://<server-ip>:$PANEL_PORT в браузере"
    echo "3. Залогинься как $PANEL_LOGIN"
    echo "4. Создай первый VLESS-инбаунд через UI"
    echo ""
    echo "Все скрипты установки: /opt/xray-vpn-stack/"
    echo "Лог установки:         /var/log/xray-vpn-stack-install.log"
    echo ""
} > "$report_file"

chmod 600 "$report_file"
log_info "итоговый отчёт сохранён в $report_file"

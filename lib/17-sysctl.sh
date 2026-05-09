#!/usr/bin/env bash
#
# lib/18-sysctl.sh — применяет sysctl-настройки для VPN-сервера

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

if ! $APPLY_SYSCTL; then
    log_info "sysctl tuning пропущен по выбору"
    exit 0
fi

# Проверяем доступность BBR
if ! grep -q bbr /lib/modules/$(uname -r)/kernel/net/ipv4/tcp_bbr* 2>/dev/null \
   && ! lsmod | grep -q bbr; then
    log_info "загружаю модуль tcp_bbr..."
    modprobe tcp_bbr 2>/dev/null || log_warn "не удалось загрузить tcp_bbr (возможно встроен)"
fi

# Копируем sysctl-конфиг
log_info "применяю sysctl настройки..."
cp "$CONFIGS_DIR/sysctl/99-vpn-tuning.conf" /etc/sysctl.d/

if sysctl --system 2>&1 | grep -qE "error|invalid"; then
    log_warn "некоторые sysctl-параметры не применились (возможно недоступны на этом ядре)"
else
    log_ok "sysctl применены"
fi

# Проверяем что BBR работает
current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
if [[ "$current_cc" == "bbr" ]]; then
    log_ok "TCP congestion control: $current_cc"
else
    log_warn "TCP congestion control = $current_cc (ожидался bbr)"
fi

# tc qdisc fq на основном интерфейсе
main_iface=$(ip route | awk '/default/ {print $5; exit}')
if [[ -n "$main_iface" ]]; then
    tc qdisc replace dev "$main_iface" root fq 2>/dev/null || true
    current_qdisc=$(tc qdisc show dev "$main_iface" | head -1 | awk '{print $2}')
    log_ok "qdisc на $main_iface: $current_qdisc"
fi

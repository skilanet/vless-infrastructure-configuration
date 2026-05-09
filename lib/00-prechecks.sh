#!/usr/bin/env bash
#
# lib/00-prechecks.sh — проверки системы перед началом установки

set -euo pipefail
source "$LIB_DIR/common.sh"

# === root ===
if [[ $EUID -ne 0 ]]; then
    log_error "запусти через sudo"
    exit 1
fi
log_ok "запущено от root"

# === ОС ===
if [[ ! -f /etc/os-release ]]; then
    log_error "не найден /etc/os-release"
    exit 1
fi

source /etc/os-release

case "${ID,,}" in
    ubuntu)
        version_major="${VERSION_ID%%.*}"
        if (( version_major < 22 )); then
            log_error "Ubuntu $VERSION_ID слишком старая, нужно 22.04+"
            exit 1
        fi
        log_ok "ОС: Ubuntu $VERSION_ID"
        ;;
    debian)
        version_major="${VERSION_ID%%.*}"
        if (( version_major < 11 )); then
            log_error "Debian $VERSION_ID слишком старая, нужно 11+"
            exit 1
        fi
        log_ok "ОС: Debian $VERSION_ID"
        ;;
    *)
        log_warn "ОС $PRETTY_NAME не тестировалась, продолжаю с предположением что это Debian-like"
        ;;
esac

# === архитектура ===
arch=$(uname -m)
case "$arch" in
    x86_64|amd64) log_ok "архитектура: x86_64" ;;
    aarch64|arm64) log_ok "архитектура: arm64" ;;
    *)
        log_error "архитектура $arch не поддерживается"
        exit 1
        ;;
esac

# === systemd ===
if ! command -v systemctl >/dev/null 2>&1; then
    log_error "systemctl не найден — systemd обязателен"
    exit 1
fi
log_ok "systemd доступен"

# === интернет ===
if ! curl -fsSL --max-time 5 https://1.1.1.1 >/dev/null 2>&1; then
    log_error "нет интернета, проверь сеть"
    exit 1
fi
log_ok "интернет работает"

# === свободное место ===
free_mb=$(df -Pm /usr/local | awk 'NR==2 {print $4}')
if (( free_mb < 500 )); then
    log_warn "только ${free_mb}MB свободного места в /usr/local"
    log_warn "для установки рекомендуется минимум 500MB"
fi
log_ok "свободно ${free_mb}MB на /usr/local"

# === RAM ===
total_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
if (( total_mb < 768 )); then
    log_warn "только ${total_mb}MB RAM, для xray рекомендуется минимум 1GB"
fi
log_ok "RAM: ${total_mb}MB"

# === xray уже установлен? ===
if command -v xray >/dev/null 2>&1; then
    existing_version=$(xray version 2>/dev/null | head -1 || echo "unknown")
    log_warn "xray уже установлен: $existing_version"
    if ! confirm_dangerous "Переустановить? Текущий конфиг будет в backup'е."; then
        exit 0
    fi
    save_state "REINSTALL_XRAY" "true"
fi

# === ufw уже настроен? ===
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    log_warn "ufw уже активен — добавлю свои правила, существующие не трогаю"
fi

log_ok "все проверки пройдены"

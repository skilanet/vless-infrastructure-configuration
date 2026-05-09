#!/usr/bin/env bash
#
# install-real.sh — основной инсталлер xray-vpn-stack
#
# Запускается из /opt/xray-vpn-stack после клонирования через install.sh.
# Все модули в lib/ выполняются по порядку.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"
CONFIGS_DIR="$SCRIPT_DIR/configs"

# Файл со state — переменные окружения накапливаются между модулями
STATE_FILE="/tmp/xray-vpn-stack-state.env"

# Если есть прерванная установка — спросим
if [[ -f "$STATE_FILE" ]] && [[ -z "${RESUME:-}" ]]; then
    echo ""
    echo "Найден файл прошлой установки: $STATE_FILE"
    read -p "Продолжить с того места где остановились? [Y/n]: " resume
    case "${resume,,}" in
        n|no) rm -f "$STATE_FILE" ;;
        *)    source "$STATE_FILE" ;;
    esac
fi

# Подключаем библиотеку общих функций
source "$LIB_DIR/common.sh"

# Экспортируем пути для модулей
export SCRIPT_DIR LIB_DIR SCRIPTS_DIR CONFIGS_DIR STATE_FILE

# Лог установки
LOG_FILE="/var/log/xray-vpn-stack-install.log"
mkdir -p "$(dirname "$LOG_FILE")"

# Запись всего вывода в лог + терминал
exec > >(tee -a "$LOG_FILE") 2>&1

# === Заголовок ===
clear 2>/dev/null || true
banner

# === Pre-checks ===
log_section "Проверка системы"
"$LIB_DIR/00-prechecks.sh"

# === Сбор параметров ===
log_section "Конфигурация установки"
"$LIB_DIR/01-prompts.sh"

# Загружаем состояние с введёнными параметрами
source "$STATE_FILE"

# === Подтверждение ===
log_section "Резюме конфигурации"
print_summary
echo ""
read -p "Начать установку? [Y/n]: " confirm
case "${confirm,,}" in
    n|no) log_warn "Отменено пользователем"; exit 0 ;;
esac

# === Запуск модулей по порядку ===
modules=(
    "10-system-update.sh"
    "11-users.sh"
    "12-ssh-harden.sh"
    "13-firewall.sh"
    "14-xray-install.sh"
    "15-monitoring.sh"
    "16-fail2ban.sh"
    "17-sysctl.sh"
    "18-admin-panel.sh"
    "19-finalize.sh"
)

for module in "${modules[@]}"; do
    log_section "Запуск $module"
    if [[ ! -x "$LIB_DIR/$module" ]]; then
        log_error "Модуль $module не найден или не исполняемый"
        exit 1
    fi
    "$LIB_DIR/$module"
done

# === Завершение ===
echo ""
log_ok "Установка успешно завершена"
echo ""
print_post_install_info

# Удаляем state-файл если установка прошла полностью
rm -f "$STATE_FILE"

#!/usr/bin/env bash
#
# install-real.sh — главный оркестратор vless-infrastructure-configuration.
#
# Поддерживает:
# - checkpoints (отметки о выполненных модулях)
# - hash файлов модулей (auto-rerun при изменении кода)
# - команды: install, --status, --reset, --rerun MODULE
#
# State хранится в /var/lib/vless-infrastructure-configuration/:
#   state.env              — переменные от prompts
#   checkpoints/01-prompts — пустой файл-маркер выполнения, имя = модуль без .sh
#   checkpoints.hash       — sha256 модулей на момент чекпоинта
#   logs/14-xray-install.log — отдельный лог каждого модуля

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"
CONFIGS_DIR="$SCRIPT_DIR/configs"

# === Persistent state ===
STATE_DIR="/var/lib/vless-infrastructure-configuration"
STATE_FILE="$STATE_DIR/state.env"
CHECKPOINT_DIR="$STATE_DIR/checkpoints"
HASH_FILE="$STATE_DIR/checkpoints.hash"
LOG_DIR="$STATE_DIR/logs"
INSTALL_LOG="$LOG_DIR/install.log"

mkdir -p "$STATE_DIR" "$CHECKPOINT_DIR" "$LOG_DIR"
chmod 700 "$STATE_DIR" "$CHECKPOINT_DIR" "$LOG_DIR"

# state.env содержит секреты (PANEL_PASSWORD до его очистки финализатором) —
# создаём заранее с правильными правами
if [[ ! -f "$STATE_FILE" ]]; then
    install -m 600 /dev/null "$STATE_FILE"
else
    chmod 600 "$STATE_FILE"
fi

# Подключаем общие функции
source "$LIB_DIR/common.sh"

export SCRIPT_DIR LIB_DIR SCRIPTS_DIR CONFIGS_DIR STATE_FILE STATE_DIR

# === Список модулей в порядке выполнения ===
MODULES=(
    "00-prechecks.sh"
    "01-prompts.sh"
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

# === Helpers для checkpoints ===
checkpoint_name() {
    # 14-xray-install.sh → 14-xray-install
    echo "${1%.sh}"
}

module_hash() {
    # SHA256 модуля + common.sh (изменения общих хелперов тоже инвалидируют чекпоинт).
    # Берём первые 16 символов агрегированного хеша.
    {
        sha256sum "$LIB_DIR/$1"
        sha256sum "$LIB_DIR/common.sh"
    } | sha256sum | awk '{print substr($1, 1, 16)}'
}

is_completed() {
    local name; name=$(checkpoint_name "$1")
    local cp_file="$CHECKPOINT_DIR/$name"

    [[ -f "$cp_file" ]] || return 1

    # Проверяем что хэш модуля не изменился
    local current_hash; current_hash=$(module_hash "$1")
    local saved_hash=""
    if [[ -f "$HASH_FILE" ]]; then
        saved_hash=$(grep "^$name " "$HASH_FILE" 2>/dev/null | awk '{print $2}')
    fi

    if [[ -n "$saved_hash" && "$saved_hash" != "$current_hash" ]]; then
        # код модуля изменился — невалидируем чекпоинт
        return 1
    fi

    return 0
}

mark_completed() {
    local name; name=$(checkpoint_name "$1")
    local cp_file="$CHECKPOINT_DIR/$name"
    local hash; hash=$(module_hash "$1")

    # маркер
    date -u +"%Y-%m-%dT%H:%M:%SZ" > "$cp_file"

    # обновляем hash в HASH_FILE
    if [[ -f "$HASH_FILE" ]]; then
        sed -i "/^$name /d" "$HASH_FILE"
    fi
    echo "$name $hash" >> "$HASH_FILE"
}

clear_checkpoint() {
    local name; name=$(checkpoint_name "$1")
    rm -f "$CHECKPOINT_DIR/$name"
    if [[ -f "$HASH_FILE" ]]; then
        sed -i "/^$name /d" "$HASH_FILE"
    fi
}

# === Команды ===
cmd_status() {
    banner
    echo "${BOLD}Статус установки${RESET}"
    echo ""

    if [[ -f "$STATE_FILE" ]]; then
        echo "${GREEN}✓${RESET} state.env существует ($STATE_FILE)"
    else
        echo "${YELLOW}—${RESET} state.env пуст (установка ещё не начиналась)"
    fi
    echo ""

    local total=${#MODULES[@]}
    local done_count=0

    for module in "${MODULES[@]}"; do
        local name; name=$(checkpoint_name "$module")
        local cp_file="$CHECKPOINT_DIR/$name"

        if is_completed "$module"; then
            local ts="?"
            [[ -f "$cp_file" ]] && ts=$(cat "$cp_file" 2>/dev/null || echo "?")
            echo "  ${GREEN}✓${RESET} $name  ${GRAY}($ts)${RESET}"
            done_count=$((done_count + 1))
        elif [[ -f "$cp_file" ]]; then
            echo "  ${YELLOW}⟳${RESET} $name  ${YELLOW}(код изменился, требует перезапуска)${RESET}"
        else
            echo "  ${RED}✗${RESET} $name"
        fi
    done

    echo ""
    echo "${BOLD}Прогресс:${RESET} $done_count / $total"

    if [[ "$done_count" -eq "$total" ]]; then
        echo "${GREEN}Установка полностью завершена ✓${RESET}"
    elif [[ "$done_count" -gt 0 ]]; then
        echo "${BLUE}Частично выполнена. Запусти 'sudo bash install.sh' чтобы продолжить.${RESET}"
    else
        echo "${YELLOW}Не запускалась. Выполни 'sudo bash install.sh' для старта.${RESET}"
    fi
}

cmd_reset() {
    banner
    log_warn "Сброс всех checkpoint'ов"
    log_warn "При следующем запуске установка пойдёт с самого начала"
    echo ""

    if ! confirm_dangerous "Удалить все checkpoint'ы? (state.env с параметрами останется)"; then
        log_info "отменено"
        exit 0
    fi

    rm -rf "$CHECKPOINT_DIR"
    rm -f "$HASH_FILE"
    mkdir -p "$CHECKPOINT_DIR"

    log_ok "checkpoint'ы сброшены"
    log_info "запусти 'sudo bash install.sh' чтобы начать установку"
}

cmd_rerun() {
    local target_module="$1"
    [[ -z "$target_module" ]] && { log_error "укажи имя модуля"; exit 1; }

    # нормализуем — добавляем .sh если нет
    [[ "$target_module" == *.sh ]] || target_module="${target_module}.sh"

    local found=false
    for m in "${MODULES[@]}"; do
        if [[ "$m" == "$target_module" ]]; then
            found=true
            break
        fi
    done

    if ! $found; then
        log_error "модуль $target_module не найден"
        log_info "доступные модули:"
        for m in "${MODULES[@]}"; do
            echo "  - $(checkpoint_name "$m")"
        done
        exit 1
    fi

    log_info "сбрасываю checkpoint для $target_module"
    clear_checkpoint "$target_module"
    log_ok "готово, запускаю установщик заново"
    echo ""

    # рекурсивно вызываем себя без аргументов — обычный install
    exec "$0"
}

# === Основной флоу установки ===
cmd_install() {
    # Логирование всего вывода
    exec > >(tee -a "$INSTALL_LOG") 2>&1

    clear 2>/dev/null || true
    banner

    # Загружаем state-файл если есть
    if [[ -f "$STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$STATE_FILE"
    fi

    # Информируем юзера какие модули будут пропущены
    local skipped_count=0
    for module in "${MODULES[@]}"; do
        if is_completed "$module"; then
            skipped_count=$((skipped_count + 1))
        fi
    done

    if [[ "$skipped_count" -gt 0 ]]; then
        log_info "Найдено $skipped_count выполненных модулей — пропускаю их."
        log_info "Используй 'sudo bash install.sh --status' чтобы посмотреть прогресс"
        log_info "или 'sudo bash install.sh --reset' для полного сброса."
        echo ""
    fi

    # Запуск модулей
    for module in "${MODULES[@]}"; do
        local name; name=$(checkpoint_name "$module")

        if is_completed "$module"; then
            log_info "${GRAY}⊙ $name — пропускаю (выполнен)${RESET}"
            continue
        fi

        log_section "Запуск $module"

        # Перезагружаем state-файл перед каждым модулем
        # (предыдущие модули могли в него что-то записать)
        if [[ -f "$STATE_FILE" ]]; then
            # shellcheck disable=SC1090
            source "$STATE_FILE"
        fi

        # запускаем модуль с собственным логом
        local module_log="$LOG_DIR/${name}.log"

        local start_time; start_time=$(date +%s)

        if "$LIB_DIR/$module" 2>&1 | tee "$module_log"; then
            local end_time; end_time=$(date +%s)
            local duration=$((end_time - start_time))
            mark_completed "$module"
            log_ok "$name — завершён за ${duration}s"
        else
            log_error "$name — упал"
            log_info "лог модуля: $module_log"
            log_info "после исправления запусти 'sudo bash install.sh' — продолжит с этого места"
            exit 1
        fi
    done

    # Финал
    echo ""
    log_ok "Все модули завершены"
    echo ""
    if [[ -f "$STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$STATE_FILE"
    fi
    print_post_install_info
}

# === Роутинг команд ===
case "${1:-install}" in
    --status|status)
        cmd_status
        ;;
    --reset|reset)
        cmd_reset
        ;;
    --rerun|rerun)
        cmd_rerun "${2:-}"
        ;;
    install|"")
        cmd_install
        ;;
    *)
        log_error "неизвестная команда: $1"
        exit 1
        ;;
esac

#!/usr/bin/env bash
#
# lib/common.sh — общие функции для всех модулей инсталлера
#
# Source-инг этого файла даёт доступ к функциям логирования,
# prompt'ам и сохранению/восстановлению state.

# === Цвета ===
if [[ -t 1 ]]; then
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    CYAN=$'\033[36m'
    GRAY=$'\033[90m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RESET=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""
    GRAY=""; BOLD=""; DIM=""; RESET=""
fi

# === Логирование ===
log_info()  { echo "${BLUE}[i]${RESET} $*"; }
log_ok()    { echo "${GREEN}[✓]${RESET} $*"; }
log_warn()  { echo "${YELLOW}[!]${RESET} $*"; }
log_error() { echo "${RED}[✗]${RESET} $*" >&2; }

log_section() {
    echo ""
    echo "${BOLD}${CYAN}═══ $* ═══${RESET}"
    echo ""
}

# === Banner ===
banner() {
    cat <<'EOF'

  ┌──────────────────────────────────────────────────────┐
  │                                                      │
  │            xray-vpn-stack installer                  │
  │                                                      │
  │   VLESS + Reality + XHTTP + TCP/Vision               │
  │   monitoring · subscriptions · hardening             │
  │                                                      │
  └──────────────────────────────────────────────────────┘

EOF
}

# === Prompts ===
# prompt_string "Текст вопроса" "default_value" var_name
prompt_string() {
    local question=$1
    local default=$2
    local var_name=$3
    local current_value=""

    # Если в state уже есть — берём оттуда
    if [[ -n "${!var_name:-}" ]]; then
        current_value="${!var_name}"
        default="$current_value"
    fi

    if [[ -n "$default" ]]; then
        read -p "${BOLD}$question${RESET} [${GRAY}$default${RESET}]: " input
        eval "$var_name=\"${input:-$default}\""
    else
        while true; do
            read -p "${BOLD}$question${RESET}: " input
            if [[ -n "$input" ]]; then
                eval "$var_name=\"$input\""
                break
            fi
            log_warn "поле обязательное"
        done
    fi
}

# prompt_yesno "Текст вопроса" "y|n" var_name
prompt_yesno() {
    local question=$1
    local default=${2:-y}
    local var_name=$3
    local hint
    if [[ "${default,,}" == "y" ]]; then
        hint="[${GREEN}Y${RESET}/n]"
    else
        hint="[y/${RED}N${RESET}]"
    fi

    while true; do
        read -p "${BOLD}$question${RESET} $hint: " answer
        answer=${answer:-$default}
        case "${answer,,}" in
            y|yes) eval "$var_name=true"; return 0 ;;
            n|no)  eval "$var_name=false"; return 0 ;;
            *)     log_warn "введи y или n" ;;
        esac
    done
}

# prompt_int "Текст" min max default var_name
prompt_int() {
    local question=$1
    local min=$2
    local max=$3
    local default=$4
    local var_name=$5

    while true; do
        read -p "${BOLD}$question${RESET} (${min}-${max}) [${GRAY}$default${RESET}]: " input
        input=${input:-$default}
        if [[ "$input" =~ ^[0-9]+$ ]] && (( input >= min && input <= max )); then
            eval "$var_name=$input"
            return 0
        fi
        log_warn "введи число от $min до $max"
    done
}

# prompt_list "Текст" "опция 1|опция 2|опция 3" default_index var_name
prompt_list() {
    local question=$1
    local options_str=$2
    local default_idx=$3
    local var_name=$4

    IFS='|' read -ra options <<< "$options_str"
    echo "${BOLD}$question${RESET}"
    for i in "${!options[@]}"; do
        local marker="  "
        [[ $((i + 1)) == "$default_idx" ]] && marker="${GREEN}* ${RESET}"
        echo "  ${marker}$((i + 1))) ${options[$i]}"
    done

    while true; do
        read -p "Выбор [${GRAY}$default_idx${RESET}]: " choice
        choice=${choice:-$default_idx}
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            eval "$var_name=\"${options[$((choice - 1))]}\""
            return 0
        fi
        log_warn "введи номер от 1 до ${#options[@]}"
    done
}

# === State persistence ===
save_state() {
    local key=$1
    local value=$2
    # удаляем старое значение если есть
    if [[ -f "$STATE_FILE" ]]; then
        sed -i "/^export $key=/d" "$STATE_FILE"
    fi
    # добавляем новое
    echo "export $key=$(printf '%q' "$value")" >> "$STATE_FILE"
}

# === Утилиты ===
# Запуск с retry
retry() {
    local max_attempts=$1
    shift
    local attempt=1
    until "$@"; do
        if (( attempt >= max_attempts )); then
            return 1
        fi
        log_warn "попытка $attempt из $max_attempts не удалась, повторяю..."
        attempt=$((attempt + 1))
        sleep 2
    done
}

# Подтверждение перед опасным действием
confirm_dangerous() {
    local message=$1
    echo ""
    echo "${YELLOW}${BOLD}⚠  $message${RESET}"
    read -p "Точно продолжить? [yes/NO]: " answer
    if [[ "${answer,,}" != "yes" ]]; then
        log_warn "Отменено"
        return 1
    fi
    return 0
}

# Бэкап файла
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local backup="${file}.bak.$(date +%Y%m%d-%H%M%S)"
        cp -a "$file" "$backup"
        log_info "бэкап: $backup"
    fi
}

# Печать резюме введённых параметров
print_summary() {
    cat <<EOF
${BOLD}Системные пользователи:${RESET}
  Админ:           ${GREEN}$ADMIN_USER${RESET}
  Xray runtime:    ${GREEN}$XRAY_USER${RESET}
  Panel runtime:   ${GREEN}$PANEL_USER${RESET}

${BOLD}SSH:${RESET}
  Изменить порт:   $($CHANGE_SSH_PORT && echo "${GREEN}да${RESET} → $SSH_PORT" || echo "${YELLOW}нет (остаётся 22)${RESET}")
  Password auth:   ${RED}отключается${RESET}
  Root login:      ${RED}отключается${RESET}

${BOLD}Админ-панель:${RESET}
  Порт:            ${GREEN}$PANEL_PORT${RESET}
  Логин:           ${GREEN}$PANEL_LOGIN${RESET}
  Пароль:          ${GREEN}*****${RESET} (сохранён)

${BOLD}xray:${RESET}
  Установка:       ${GREEN}xray-core от XTLS${RESET}
  Конфигурация:    ${YELLOW}через панель${RESET} (после установки)

${BOLD}Дополнительно:${RESET}
  fail2ban:        $($INSTALL_FAIL2BAN && echo "${GREEN}да${RESET}" || echo "нет")
  sysctl tuning:   $($APPLY_SYSCTL && echo "${GREEN}да${RESET}" || echo "нет")
  Мониторинг:      $($INSTALL_MONITORING && echo "${GREEN}да${RESET} (cron каждые 5 минут)" || echo "нет")
EOF
}

# Финальный отчёт после установки
print_post_install_info() {
    local server_ip
    server_ip=$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "<your-server-ip>")

    cat <<EOF

${BOLD}${GREEN}╔════════════════════════════════════════════════════════════╗${RESET}
${BOLD}${GREEN}║           Установка успешно завершена ✓                    ║${RESET}
${BOLD}${GREEN}╚════════════════════════════════════════════════════════════╝${RESET}

${BOLD}Сервер:${RESET}
  IP:               ${CYAN}$server_ip${RESET}
  SSH:              ${CYAN}ssh -p $SSH_PORT $ADMIN_USER@$server_ip${RESET}

${BOLD}Админ-панель:${RESET}
  URL:              ${CYAN}http://$server_ip:$PANEL_PORT${RESET}
  Логин:            ${CYAN}$PANEL_LOGIN${RESET}
  Пароль:           тот что ввёл при установке

  ${YELLOW}⚠  Панель работает по HTTP. Для безопасности либо:${RESET}
  ${YELLOW}    - не открывай порт публично, ходи через SSH-туннель:${RESET}
  ${YELLOW}      ssh -p $SSH_PORT -L 8088:localhost:$PANEL_PORT $ADMIN_USER@$server_ip${RESET}
  ${YELLOW}      потом открой http://localhost:8088 в браузере${RESET}
  ${YELLOW}    - или используй Tailscale для приватной сети${RESET}

${BOLD}Что дальше:${RESET}

${CYAN}1.${RESET} Открой админ-панель в браузере и залогинься.

${CYAN}2.${RESET} В панели:
   - создай служебные настройки (log/api/metrics — одним кликом)
   - создай VLESS-инбаунды
   - добавь юзеров
   - получи подписочные ссылки

${CYAN}3.${RESET} Проверь здоровье через SSH:
   ${GRAY}xstat${RESET}      — быстрая проверка
   ${GRAY}xwatch${RESET}     — live-мониторинг

${BOLD}Состояние сервиса xray:${RESET}
  xray установлен но ${YELLOW}не запущен${RESET} — ждёт конфиг от панели.
  После того как создашь первый inbound через панель — она сама стартует xray.

EOF
}

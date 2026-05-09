#!/usr/bin/env bash
#
# xray-health.sh
#
# Быстрая проверка здоровья xray.
# Показывает каждую метрику с пороговыми значениями и цветным статусом.
#
# Использование:
#   sudo ./xray-health.sh
#   watch -n 5 sudo ./xray-health.sh   # автообновление каждые 5 секунд

set -u

# === Цвета ANSI ===
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    CYAN=$'\033[36m'
    GRAY=$'\033[90m'
    RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; GRAY=""; RESET=""
fi

# === Хелперы для статусов ===
# arg1: значение, arg2: warn-порог, arg3: crit-порог, arg4: метка нормы
# возвращает строку "STATUS_LABEL" с цветом
status_str() {
    local val=$1
    local warn=$2
    local crit=$3
    local norm_label=$4
    # сравнение чисел через awk (чтобы поддержать дробные)
    if awk "BEGIN{exit !($val >= $crit)}"; then
        printf "${RED}${BOLD}CRITICAL${RESET}"
    elif awk "BEGIN{exit !($val >= $warn)}"; then
        printf "${YELLOW}${BOLD}WARNING${RESET}"
    else
        printf "${GREEN}${BOLD}OK${RESET}"
    fi
}

# Печать одной метрики с порогами и статусом
# args: name, value, unit, warn, crit
metric() {
    local name=$1
    local value=$2
    local unit=$3
    local warn=$4
    local crit=$5

    local status=$(status_str "$value" "$warn" "$crit" "OK")

    # форматируем значение
    local val_fmt
    if [[ "$value" == *.* ]]; then
        val_fmt=$(printf "%.1f%s" "$value" "$unit")
    else
        val_fmt="${value}${unit}"
    fi

    # цвет значения
    local val_color
    if awk "BEGIN{exit !($value >= $crit)}"; then
        val_color="${RED}"
    elif awk "BEGIN{exit !($value >= $warn)}"; then
        val_color="${YELLOW}"
    else
        val_color="${GREEN}"
    fi

    printf "  ${BOLD}%-15s${RESET} ${val_color}%10s${RESET}  %s ${GRAY}(warn>=%s%s, crit>=%s%s)${RESET}\n" \
        "$name" "$val_fmt" "$status" "$warn" "$unit" "$crit" "$unit"
}

# ============================================================
# Сбор данных
# ============================================================

PID=$(pgrep -x xray | head -1)

if [[ -z "$PID" ]]; then
    printf "\n${RED}${BOLD}✗ xray НЕ ЗАПУЩЕН${RESET}\n\n"
    systemctl status xray --no-pager 2>/dev/null | head -5
    exit 1
fi

# ресурсы xray
FD=$(ls /proc/$PID/fd 2>/dev/null | wc -l)
MEM_KB=$(awk '/VmRSS:/ {print $2}' /proc/$PID/status 2>/dev/null)
MEM_MB=$(( ${MEM_KB:-0} / 1024 ))
CPU=$(ps -o %cpu= -p $PID 2>/dev/null | tr -d ' ')
CPU=${CPU:-0}

# uptime сервиса
UPTIME_TS=$(systemctl show xray --property=ActiveEnterTimestamp --value 2>/dev/null)
if [[ -n "$UPTIME_TS" && "$UPTIME_TS" != "n/a" ]]; then
    UPTIME_EPOCH=$(date -d "$UPTIME_TS" +%s 2>/dev/null || echo 0)
    NOW_EPOCH=$(date +%s)
    UPTIME_SEC=$(( NOW_EPOCH - UPTIME_EPOCH ))
    UPTIME_H=$(( UPTIME_SEC / 3600 ))
    UPTIME_M=$(( (UPTIME_SEC % 3600) / 60 ))
    UPTIME_FMT="${UPTIME_H}h ${UPTIME_M}m"
else
    UPTIME_FMT="—"
fi

# соединения
EST=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
SYN_RECV=$(ss -tn state syn-recv 2>/dev/null | tail -n +2 | wc -l)
TIME_WAIT=$(ss -tn state time-wait 2>/dev/null | tail -n +2 | wc -l)
CLOSE_WAIT=$(ss -tn state close-wait 2>/dev/null | tail -n +2 | wc -l)

# хост
LOAD1=$(awk '{print $1}' /proc/loadavg)
STEAL=$(top -bn1 | awk '/%Cpu/{print $16}' | tr -d ',' | head -1)
STEAL=${STEAL:-0}
RAM_FREE=$(free -h | awk 'NR==2 {print $7}')
RAM_USED_PCT=$(free | awk 'NR==2 {printf "%.0f", ($3/$2)*100}')

# слушающие порты xray
LISTEN_PORTS=$(ss -tlnp 2>/dev/null | grep xray | awk '{print $4}' | awk -F: '{print $NF}' | sort -un | tr '\n' ' ')

# ============================================================
# Вывод
# ============================================================

clear 2>/dev/null || printf "\n"

printf "${BOLD}${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}${CYAN}║${RESET}  ${BOLD}xray health check${RESET}  ${GRAY}— $(date '+%Y-%m-%d %H:%M:%S')${RESET}                ${BOLD}${CYAN}║${RESET}\n"
printf "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}\n"
printf "\n"

printf "  ${BOLD}service:${RESET}  ${GREEN}● running${RESET}  ${GRAY}(pid=$PID, uptime=$UPTIME_FMT)${RESET}\n"
printf "  ${BOLD}listen:${RESET}   ${CYAN}$LISTEN_PORTS${RESET}\n"
printf "\n"

printf "${BOLD}РЕСУРСЫ XRAY${RESET}\n"
metric "fd"        "$FD"     ""  500   2000
metric "memory"    "$MEM_MB" "M" 250   400
metric "cpu"       "$CPU"    "%" 30    70
printf "\n"

printf "${BOLD}TCP СОЕДИНЕНИЯ${RESET}\n"
metric "established" "$EST"        "" 1000  5000
metric "syn-recv"    "$SYN_RECV"   "" 20    100
metric "time-wait"   "$TIME_WAIT"  "" 500   2000
metric "close-wait"  "$CLOSE_WAIT" "" 50    200
printf "\n"

printf "${BOLD}НАГРУЗКА ХОСТА${RESET}\n"
metric "load (1m)"   "$LOAD1"        ""  1     2
metric "steal"       "$STEAL"        "%" 15    30
metric "ram used"    "$RAM_USED_PCT" "%" 70    85
printf "  ${BOLD}%-15s${RESET} ${CYAN}%10s${RESET}\n" "ram free" "$RAM_FREE"
printf "\n"

# ============================================================
# Финальный вердикт
# ============================================================

# Считаем сколько метрик в каком статусе
crit_count=0
warn_count=0

# fd
if (( FD >= 2000 )); then ((crit_count++))
elif (( FD >= 500 )); then ((warn_count++)); fi

# memory
if (( MEM_MB >= 400 )); then ((crit_count++))
elif (( MEM_MB >= 250 )); then ((warn_count++)); fi

# cpu (через awk т.к. дробное)
if awk "BEGIN{exit !($CPU >= 70)}"; then ((crit_count++))
elif awk "BEGIN{exit !($CPU >= 30)}"; then ((warn_count++)); fi

# established
if (( EST >= 5000 )); then ((crit_count++))
elif (( EST >= 1000 )); then ((warn_count++)); fi

# close-wait
if (( CLOSE_WAIT >= 200 )); then ((crit_count++))
elif (( CLOSE_WAIT >= 50 )); then ((warn_count++)); fi

# steal
if awk "BEGIN{exit !($STEAL >= 30)}"; then ((crit_count++))
elif awk "BEGIN{exit !($STEAL >= 15)}"; then ((warn_count++)); fi

printf "${BOLD}ВЕРДИКТ${RESET}\n"
if (( crit_count > 0 )); then
    printf "  ${RED}${BOLD}✗ КРИТИЧНО${RESET} — $crit_count метрик в крит. зоне, $warn_count в warning\n"
elif (( warn_count > 0 )); then
    printf "  ${YELLOW}${BOLD}⚠ ПРЕДУПРЕЖДЕНИЕ${RESET} — $warn_count метрик в warning, всё ещё в норме\n"
else
    printf "  ${GREEN}${BOLD}✓ ВСЁ ХОРОШО${RESET} — все метрики в норме\n"
fi
printf "\n"

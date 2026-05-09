#!/usr/bin/env bash
#
# update-subs.sh
#
# Полный цикл обновления подписок для клиентов xray.
#
# 1. Запускает gen-vless-links.sh --subs для генерации файлов
# 2. Для каждого юзера: загружает/обновляет его персональный GitHub Gist
# 3. Показывает raw-ссылки для раздачи юзерам
#
# Маппинг "имя_клиента → gist_id" хранится в mapping-файле.
# При первом запуске создаёт новые приватные гисты, записывает ID в маппинг.
# При последующих — обновляет существующие.
#
# Использование:
#   ./update-subs.sh <public_key>                    # обновить всё
#   ./update-subs.sh --list <public_key>             # показать текущий маппинг и raw-ссылки, не обновляя
#   ./update-subs.sh --dry-run <public_key>          # только сгенерить файлы, не пушить
#   ./update-subs.sh --init <public_key>             # создать гисты для всех клиентов у кого их нет
#
# Требует: gh (GitHub CLI), jq, authorized gh (gh auth login выполнен)

set -euo pipefail

# === Пути и дефолты ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_SCRIPT="${GEN_SCRIPT:-${SCRIPT_DIR}/gen-vless-links.sh}"
CONFIG_DIR="${HOME}/.config/xray-subs"
MAPPING_FILE="${CONFIG_DIR}/mapping.conf"
SUBS_DIR="${CONFIG_DIR}/subs"
XRAY_CONFIG="${XRAY_CONFIG:-/usr/local/etc/xray/conf.d}"
SERVER_IP="${SERVER_IP:-}"

DRY_RUN=false
LIST_ONLY=false
INIT_MODE=false
PUBLIC_KEY=""

# === Цвета ===
if [[ -t 1 ]]; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4); BOLD=$(tput bold); RESET=$(tput sgr0)
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; RESET=""
fi

log()  { echo "${BLUE}[*]${RESET} $*"; }
ok()   { echo "${GREEN}[✓]${RESET} $*"; }
warn() { echo "${YELLOW}[!]${RESET} $*"; }
err()  { echo "${RED}[✗]${RESET} $*" >&2; }

# === Парсинг опций ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)    LIST_ONLY=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --init)    INIT_MODE=true; shift ;;
        -h|--help)
            sed -n '2,22p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        -*) err "неизвестная опция: $1"; exit 1 ;;
        *)  PUBLIC_KEY="$1"; shift ;;
    esac
done

if [[ -z "$PUBLIC_KEY" ]]; then
    err "не указан public_key"
    exit 1
fi

# === Проверка зависимостей ===
for cmd in gh jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "не найден: $cmd"
        [[ "$cmd" == "gh" ]] && warn "установи GitHub CLI: https://cli.github.com/"
        exit 1
    fi
done

if ! gh auth status >/dev/null 2>&1; then
    err "gh не авторизован, выполни: gh auth login"
    exit 1
fi

if [[ ! -x "$GEN_SCRIPT" ]]; then
    err "не найден или не исполняемый: $GEN_SCRIPT"
    exit 1
fi

# === Подготовка директорий и маппинга ===
mkdir -p "$CONFIG_DIR" "$SUBS_DIR"
chmod 700 "$CONFIG_DIR"

if [[ ! -f "$MAPPING_FILE" ]]; then
    touch "$MAPPING_FILE"
    chmod 600 "$MAPPING_FILE"
    log "создан пустой маппинг: $MAPPING_FILE"
fi

# === Хелперы для работы с маппингом ===
# Формат: одна пара "имя gist_id" на строку
get_gist_id() {
    local name="$1"
    awk -v n="$name" '$1 == n { print $2; exit }' "$MAPPING_FILE"
}

set_gist_id() {
    local name="$1"
    local gist_id="$2"
    # убрать старую строку если есть
    grep -v "^${name}[[:space:]]" "$MAPPING_FILE" > "${MAPPING_FILE}.tmp" || true
    mv "${MAPPING_FILE}.tmp" "$MAPPING_FILE"
    # добавить новую
    echo "$name $gist_id" >> "$MAPPING_FILE"
    chmod 600 "$MAPPING_FILE"
}

# === Определяем IP сервера ===
if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="$(curl -4 -s --max-time 5 https://api.ipify.org || true)"
    if [[ -z "$SERVER_IP" ]]; then
        err "не удалось определить IP сервера, передай через переменную SERVER_IP"
        exit 1
    fi
fi

log "server:      $SERVER_IP"
log "config:      $XRAY_CONFIG"
log "subs dir:    $SUBS_DIR"
log "mapping:     $MAPPING_FILE"
log ""


# ============================================================
# LIST MODE — показать текущий маппинг без обновления
# ============================================================
if $LIST_ONLY; then
    log "${BOLD}Текущий маппинг:${RESET}"

    if [[ ! -s "$MAPPING_FILE" ]]; then
        warn "маппинг пустой — сначала запусти без --list для первичной инициализации"
        exit 0
    fi

    printf "\n%-15s %-25s %s\n" "КЛИЕНТ" "GIST_ID" "RAW URL"
    echo "---------------------------------------------------------------------------------------"

    while read -r name gist_id; do
        [[ -z "$name" ]] && continue

        gh_user=$(gh api "gists/$gist_id" --jq '.owner.login' 2>/dev/null || echo "—")
        raw_url="https://gist.githubusercontent.com/${gh_user}/${gist_id}/raw/${name}.txt"
        printf "%-15s %-25s %s\n" "$name" "$gist_id" "$raw_url"
    done < "$MAPPING_FILE"

    exit 0
fi


# ============================================================
# GENERATE — генерация подписочных файлов
# ============================================================
log "${BOLD}Генерация подписок${RESET}"

# Очищаем старые файлы подписок
rm -f "$SUBS_DIR"/*.txt "$SUBS_DIR"/*.b64 2>/dev/null || true

bash "$GEN_SCRIPT" \
    -c "$XRAY_CONFIG" \
    -s "$SERVER_IP" \
    --subs "$SUBS_DIR" \
    "$PUBLIC_KEY" > /dev/null

if [[ -z "$(ls -A "$SUBS_DIR"/*.txt 2>/dev/null)" ]]; then
    err "gen-vless-links.sh не создал подписочных файлов"
    exit 1
fi

CLIENTS=($(ls "$SUBS_DIR"/*.txt | xargs -n1 basename | sed 's/\.txt$//'))
ok "сгенерено подписок: ${#CLIENTS[@]}"

if $DRY_RUN; then
    log ""
    log "${BOLD}--dry-run — файлы сгенерированы, гисты не обновляются${RESET}"
    ls -la "$SUBS_DIR/"
    exit 0
fi


# ============================================================
# UPDATE / CREATE GISTS
# ============================================================
log ""
log "${BOLD}Обновление гистов${RESET}"

printf "\n%-15s %-10s %-25s\n" "КЛИЕНТ" "ДЕЙСТВИЕ" "GIST_ID"
echo "---------------------------------------------------------------"

for name in "${CLIENTS[@]}"; do
    sub_file="$SUBS_DIR/${name}.txt"
    gist_id="$(get_gist_id "$name")"

    if [[ -z "$gist_id" ]]; then
        # Создаём новый приватный гист
        gist_url=$(gh gist create "$sub_file" --desc "xray subscription: ${name}" 2>/dev/null)
        gist_id=$(basename "$gist_url")
        set_gist_id "$name" "$gist_id"
        printf "%-15s %-10s %-25s\n" "$name" "created" "$gist_id"
    else
        # Обновляем существующий
        if gh gist edit "$gist_id" -f "${name}.txt" "$sub_file" 2>/dev/null; then
            printf "%-15s %-10s %-25s\n" "$name" "updated" "$gist_id"
        else
            printf "%-15s ${RED}%-10s${RESET} %-25s\n" "$name" "FAILED" "$gist_id"
            err "не удалось обновить $gist_id — возможно, он был удалён"
            warn "удали его из $MAPPING_FILE чтобы пересоздать"
        fi
    fi
done


# ============================================================
# RAW URLS — показать итоговые ссылки для юзеров
# ============================================================
log ""
log "${BOLD}Итоговые raw-ссылки для раздачи:${RESET}"
echo ""

printf "%-15s  %s\n" "КЛИЕНТ" "SUBSCRIPTION URL"
echo "---------------------------------------------------------------------------------------"

while read -r name gist_id; do
    [[ -z "$name" ]] && continue

    # получаем GitHub username для построения стабильного URL
    gh_user=$(gh api "gists/$gist_id" --jq '.owner.login' 2>/dev/null || echo "—")
    # стабильный URL без sha — всегда ведёт на последнюю версию
    raw_url="https://gist.githubusercontent.com/${gh_user}/${gist_id}/raw/${name}.txt"
    printf "%-15s  %s\n" "$name" "$raw_url"
done < "$MAPPING_FILE"

echo ""
ok "Готово. Перешли эти URL юзерам один раз — они добавят в v2rayTun/Hiddify"
ok "как subscription. При изменении конфига просто запусти ./update-subs.sh снова."

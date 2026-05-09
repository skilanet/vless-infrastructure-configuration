#!/usr/bin/env bash
#
# install.sh — bootstrap для vless-infrastructure-configuration
#
# Использование:
#   sudo bash install.sh [команда] [опции]
#
# Команды:
#   (без аргументов)        — установить, продолжая с последнего checkpoint'а
#   --reset                 — сбросить все checkpoint'ы и начать заново
#   --rerun MODULE          — пересобрать конкретный модуль (например --rerun 14-xray-install)
#   --status                — показать статус выполненных модулей
#   --update                — git pull в /opt/vless-infrastructure-configuration
#   --help                  — эта справка

set -euo pipefail

REPO_URL="${XRAY_VPN_REPO:-https://github.com/skilanet/vless-infrastructure-configuration.git}"
REPO_BRANCH="${XRAY_VPN_BRANCH:-main}"
INSTALL_DIR="/opt/vless-infrastructure-configuration"

# === Цвета ===
if [[ -t 1 ]]; then
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    BLUE=$'\033[34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; RESET=""
fi

log() { echo "${BLUE}[bootstrap]${RESET} $*"; }
err() { echo "${RED}[bootstrap]${RESET} $*" >&2; }
ok()  { echo "${GREEN}[bootstrap]${RESET} $*"; }

show_help() {
    sed -n '3,15p' "$0" | sed 's/^# \?//'
}

# === Парсинг команд ===
COMMAND="${1:-install}"
case "$COMMAND" in
    --help|-h|help)
        show_help
        exit 0
        ;;
    --status|status)
        ;;
    --reset|reset|--rerun|rerun|--update|update|install|"")
        ;;
    *)
        err "неизвестная команда: $COMMAND"
        echo ""
        show_help
        exit 1
        ;;
esac

# === Проверки ===
if [[ $EUID -ne 0 ]]; then
    err "запусти через sudo: sudo bash $0"
    exit 1
fi

# Команды, которым не нужен интерактивный stdin
needs_tty=true
case "$COMMAND" in
    --status|status|--update|update|--help|-h|help|--reset|reset)
        needs_tty=false ;;
esac

if $needs_tty && [[ ! -t 0 ]]; then
    err "stdin не подключен к терминалу — установка интерактивная"
    err "запусти так:  sudo bash <(curl -fsSL <URL>)"
    err "  или сначала скачай: curl -fsSL <URL> -o install.sh && sudo bash install.sh"
    exit 1
fi

# === Установка git если нет ===
if ! command -v git >/dev/null 2>&1; then
    log "git не установлен, ставлю..."
    apt-get update -qq
    apt-get install -y -qq git
fi

# === Клонируем / обновляем репо ===
if [[ -d "$INSTALL_DIR/.git" ]]; then
    if [[ "$COMMAND" == "--update" || "$COMMAND" == "update" ]]; then
        log "обновляю репо..."
        cd "$INSTALL_DIR"
        git fetch origin "$REPO_BRANCH"
        git reset --hard "origin/$REPO_BRANCH"
        ok "репо обновлён"
        # после --update — выходим, юзер сам решит когда запускать установку
        exit 0
    fi
elif [[ -d "$INSTALL_DIR" ]]; then
    err "$INSTALL_DIR существует, но это не git-репо"
    err "удали его или перенеси: mv $INSTALL_DIR ${INSTALL_DIR}.bak"
    exit 1
else
    log "клонирую $REPO_URL в $INSTALL_DIR..."
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi

# === Делаем скрипты исполняемыми ===
chmod +x "$INSTALL_DIR/install-real.sh"
find "$INSTALL_DIR/lib" -name "*.sh" -exec chmod +x {} \;
find "$INSTALL_DIR/scripts" -name "*.sh" -exec chmod +x {} \;
find "$INSTALL_DIR/scripts" -name "*.py" -exec chmod +x {} \;

# === Запускаем основной инсталлер ===
exec "$INSTALL_DIR/install-real.sh" "$@"

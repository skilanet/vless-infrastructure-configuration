#!/usr/bin/env bash
#
# gen-vless-links.sh
#
# Генерирует vless:// ссылки по всем VLESS+Reality inbound'ам из xray-конфига.
# Поддерживает как одиночный config.json, так и conf.d/ директорию.
# Поддерживает XHTTP и TCP+Vision транспорты.
#
# Для каждого клиента создаёт по одной ссылке на каждый inbound.
# Метка: <имя>:<порт>-<транспорт>, например: skilanet:443-xhttp, skilanet:8443-tcp
#
# Режимы вывода:
#   stdout      — все ссылки с заголовками клиентов (по умолчанию)
#   --qr        — QR-коды в терминал
#   --qr-png    — PNG с QR-кодами (один на inbound-link)
#   --subs DIR  — один текстовый файл на клиента с его ссылками (для подписок)
#   --base64    — в режиме --subs дополнительно создаёт .b64 версии
#
# Использование:
#   ./gen-vless-links.sh [опции] <public_key>
#
# Опции:
#   -c, --config PATH        путь к config.json или conf.d/ директории
#                            (по умолчанию пробует /usr/local/etc/xray/conf.d,
#                             затем /usr/local/etc/xray/config.json)
#   -s, --server IP          внешний IP сервера (по умолчанию через api.ipify.org)
#   -q, --qr                 QR-коды в терминал (ANSI)
#   -p, --qr-png DIR         PNG-файлы с QR в директорию
#       --subs DIR           создать по одному .txt на клиента в директорию
#       --base64             вместе с --subs создать base64-версии
#   -h, --help               эта справка
#
# Примеры:
#   ./gen-vless-links.sh <PK>                                    # вывод в терминал
#   ./gen-vless-links.sh --subs ~/subs <PK>                      # файлы для гистов
#   ./gen-vless-links.sh --subs ~/subs --base64 <PK>             # + base64 версии
#   ./gen-vless-links.sh -c /путь/к/conf.d --qr-png ./qr <PK>    # PNG в QR

set -euo pipefail

# === Дефолты ===
CONFIG_PATH=""
SERVER_IP=""
QR_ANSI=false
QR_PNG_DIR=""
SUBS_DIR=""
MAKE_BASE64=false
PUBLIC_KEY=""

usage() {
    sed -n '2,37p' "$0" | sed 's/^# \?//'
    exit "${1:-0}"
}

# === Парсинг опций ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--config)   CONFIG_PATH="$2"; shift 2 ;;
        -s|--server)   SERVER_IP="$2"; shift 2 ;;
        -q|--qr)       QR_ANSI=true; shift ;;
        -p|--qr-png)   QR_PNG_DIR="$2"; shift 2 ;;
        --subs)        SUBS_DIR="$2"; shift 2 ;;
        --base64)      MAKE_BASE64=true; shift ;;
        -h|--help)     usage 0 ;;
        -*)            echo "error: неизвестная опция: $1" >&2; usage 1 ;;
        *)
            if [[ -z "$PUBLIC_KEY" ]]; then
                PUBLIC_KEY="$1"; shift
            else
                echo "error: лишний позиционный аргумент: $1" >&2
                usage 1
            fi
            ;;
    esac
done

# === Проверка обязательных аргументов ===
if [[ -z "$PUBLIC_KEY" ]]; then
    echo "error: не указан public_key" >&2
    usage 1
fi

# === Автодетект конфига ===
# Используем sudo test, потому что /usr/local/etc/xray/ обычно 750 root:xray
# и обычный юзер не может его прочитать
if [[ -z "$CONFIG_PATH" ]]; then
    if sudo test -d /usr/local/etc/xray/conf.d 2>/dev/null; then
        CONFIG_PATH="/usr/local/etc/xray/conf.d"
    elif sudo test -f /usr/local/etc/xray/config.json 2>/dev/null; then
        CONFIG_PATH="/usr/local/etc/xray/config.json"
    else
        echo "error: конфиг не найден, укажи явно через -c PATH" >&2
        exit 1
    fi
fi

# === Проверка зависимостей ===
if ! command -v jq >/dev/null 2>&1; then
    echo "error: 'jq' не найден в PATH (apt install jq)" >&2
    exit 1
fi

if { $QR_ANSI || [[ -n "$QR_PNG_DIR" ]]; } && ! command -v qrencode >/dev/null 2>&1; then
    echo "error: 'qrencode' не найден в PATH (apt install qrencode)" >&2
    exit 1
fi

# === Проверка конфига ===
# Пытаемся обычным test, если не проходит - пробуем через sudo
# (конфиг может быть в директории, недоступной текущему юзеру)
if [[ ! -e "$CONFIG_PATH" ]]; then
    if ! sudo test -e "$CONFIG_PATH" 2>/dev/null; then
        echo "error: не существует: $CONFIG_PATH" >&2
        exit 1
    fi
fi

# === Подготовка директорий ===
[[ -n "$QR_PNG_DIR" ]] && mkdir -p "$QR_PNG_DIR"
[[ -n "$SUBS_DIR" ]] && mkdir -p "$SUBS_DIR"

# === Если IP не задан — пытаемся определить ===
if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="$(curl -4 -s --max-time 5 https://api.ipify.org || true)"
    if [[ -z "$SERVER_IP" ]]; then
        echo "error: не удалось определить IP, используй --server" >&2
        exit 1
    fi
fi

# === URL-encode ===
urlencode() {
    local s="$1"
    local out=""
    local i c
    for (( i=0; i<${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) printf -v out '%s%%%02X' "$out" "'$c" ;;
        esac
    done
    printf '%s' "$out"
}

# === Собираем все VLESS+Reality inbound'ы из конфига ===
# Работаем и с одиночным файлом, и с директорией.

gather_inbounds() {
    local path="$1"
    if sudo test -d "$path" 2>/dev/null; then
        # директория: получаем список файлов через sudo, читаем их через sudo cat
        # и пайпим в jq -s чтобы собрать все в массив, потом плющим inbounds
        local files
        files=$(sudo find "$path" -maxdepth 1 -name '*.json' -type f 2>/dev/null | sort)
        if [[ -z "$files" ]]; then
            echo "[]"
            return
        fi
        # передаём каждый файл через sudo cat, jq их читает через -s
        # используем bash process substitution и sudo cat
        local tmp_json
        tmp_json=$(mktemp)
        # собираем контент всех файлов в валидный JSON-массив через jq
        {
            echo "["
            local first=true
            while IFS= read -r f; do
                if $first; then first=false; else echo ","; fi
                sudo cat "$f"
            done <<<"$files"
            echo "]"
        } > "$tmp_json"

        jq '
            [
              .[].inbounds // []
            ] | add
            | map(
                select(.protocol == "vless")
                | select(.streamSettings.security == "reality")
              )
        ' "$tmp_json"
        rm -f "$tmp_json"
    else
        # одиночный файл — читаем через sudo cat
        sudo cat "$path" | jq '[
            .inbounds[]
            | select(.protocol == "vless")
            | select(.streamSettings.security == "reality")
        ]'
    fi
}

INBOUNDS_JSON="$(gather_inbounds "$CONFIG_PATH")"
INBOUND_COUNT="$(jq 'length' <<<"$INBOUNDS_JSON")"

if [[ "$INBOUND_COUNT" -eq 0 ]]; then
    echo "error: не найдено VLESS+Reality inbound'ов в $CONFIG_PATH" >&2
    exit 1
fi

# === Построение одной vless:// ссылки для конкретного клиента и inbound'а ===
build_link() {
    local ib_json="$1"
    local uuid="$2"
    local name="$3"

    local tag port network
    tag="$(jq -r '.tag' <<<"$ib_json")"
    port="$(jq -r '.port' <<<"$ib_json")"
    network="$(jq -r '.streamSettings.network' <<<"$ib_json")"

    local sni fp sid
    sni="$(jq -r '.streamSettings.realitySettings.serverNames[0]' <<<"$ib_json")"
    fp="$(jq -r '.streamSettings.realitySettings.fingerprint // "chrome"' <<<"$ib_json")"
    sid="$(jq -r '.streamSettings.realitySettings.shortIds[] | select(length > 0)' <<<"$ib_json" | head -n1)"

    local label="${name}:${port}-${network}"

    local link="vless://${uuid}@${SERVER_IP}:${port}"
    link+="?encryption=none"
    link+="&security=reality"
    link+="&sni=${sni}"
    link+="&fp=${fp}"
    link+="&pbk=${PUBLIC_KEY}"
    link+="&sid=${sid}"
    link+="&type=${network}"

    if [[ "$network" == "xhttp" ]]; then
        local path mode host path_enc
        path="$(jq -r '.streamSettings.xhttpSettings.path' <<<"$ib_json")"
        mode="$(jq -r '.streamSettings.xhttpSettings.mode // "auto"' <<<"$ib_json")"
        host="$(jq -r '.streamSettings.xhttpSettings.host' <<<"$ib_json")"
        path_enc="$(urlencode "$path")"
        link+="&path=${path_enc}"
        link+="&mode=${mode}"
        link+="&host=${host}"
    elif [[ "$network" == "tcp" ]]; then
        # Для TCP с Vision — добавляем flow
        local flow
        flow="$(jq -r --arg uuid "$uuid" '.settings.clients[] | select(.id == $uuid) | .flow // empty' <<<"$ib_json")"
        if [[ -n "$flow" ]]; then
            link+="&flow=${flow}"
        fi
    fi

    link+="#${label}"
    printf '%s' "$link"
}

# === Список клиентов: берём из первого inbound'а (все inbound'ы должны иметь одинаковый список) ===
CLIENT_COUNT="$(jq '.[0].settings.clients | length' <<<"$INBOUNDS_JSON")"
if [[ "$CLIENT_COUNT" -eq 0 ]]; then
    echo "error: нет клиентов в первом inbound'е" >&2
    exit 1
fi

# === Режим --subs: создаём по файлу на клиента ===
if [[ -n "$SUBS_DIR" ]]; then
    echo "# Генерация подписок в $SUBS_DIR"
    echo "# inbound'ов: $INBOUND_COUNT, клиентов: $CLIENT_COUNT"
    echo ""

    jq -r '.[0].settings.clients[] | "\(.id)\t\(.email)"' <<<"$INBOUNDS_JSON" \
    | while IFS=$'\t' read -r uuid email; do
        name="${email%%@*}"
        sub_file="${SUBS_DIR}/${name}.txt"

        {
            for (( i=0; i<INBOUND_COUNT; i++ )); do
                ib="$(jq -c ".[$i]" <<<"$INBOUNDS_JSON")"
                build_link "$ib" "$uuid" "$name"
                echo
            done
        } > "$sub_file"

        # base64-версия (некоторые клиенты требуют base64-encoded подписку)
        if $MAKE_BASE64; then
            base64 -w0 < "$sub_file" > "${SUBS_DIR}/${name}.b64"
        fi

        echo "  ${name}.txt ($(wc -l < "$sub_file") ссылок)"
    done

    echo ""
    echo "Готово. Загрузи файлы в гисты и раздай юзерам raw-ссылки."
    exit 0
fi

# === Обычный режим: вывод в stdout (+ опционально QR) ===
echo "# VLESS Reality links"
echo "# generated:  $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
echo "# server:     $SERVER_IP"
echo "# config:     $CONFIG_PATH"
echo "# inbounds:   $INBOUND_COUNT"
echo "# publicKey:  $PUBLIC_KEY"
[[ -n "$QR_PNG_DIR" ]] && echo "# qr-png dir: $QR_PNG_DIR"
echo

# Обзор инбаундов
for (( i=0; i<INBOUND_COUNT; i++ )); do
    ib="$(jq -c ".[$i]" <<<"$INBOUNDS_JSON")"
    tag="$(jq -r '.tag' <<<"$ib")"
    port="$(jq -r '.port' <<<"$ib")"
    network="$(jq -r '.streamSettings.network' <<<"$ib")"
    echo "# inbound #$((i+1)): $tag ($network) port=$port"
done
echo

jq -r '.[0].settings.clients[] | "\(.id)\t\(.email)"' <<<"$INBOUNDS_JSON" \
| while IFS=$'\t' read -r uuid email; do
    name="${email%%@*}"
    printf '## %s\n' "$name"

    for (( i=0; i<INBOUND_COUNT; i++ )); do
        ib="$(jq -c ".[$i]" <<<"$INBOUNDS_JSON")"
        port="$(jq -r '.port' <<<"$ib")"
        network="$(jq -r '.streamSettings.network' <<<"$ib")"
        label="${name}:${port}-${network}"

        link="$(build_link "$ib" "$uuid" "$name")"
        printf '### %s\n%s\n' "$label" "$link"

        if $QR_ANSI; then
            echo
            qrencode -t ANSIUTF8 -m 1 <<<"$link"
        fi

        if [[ -n "$QR_PNG_DIR" ]]; then
            png_path="${QR_PNG_DIR}/${name}-${port}-${network}.png"
            qrencode -t PNG -s 8 -m 2 -o "$png_path" <<<"$link"
            echo "png: $png_path"
        fi

        echo
    done
    echo
done

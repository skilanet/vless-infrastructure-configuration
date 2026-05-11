#!/usr/bin/env bash
#
# find-sni.sh
#
# Поиск оптимального SNI-домена для VLESS+Reality с этого сервера.
#
# Проверяет каждого кандидата на:
#   - TLS 1.3 (Reality его требует)
#   - X25519 ECDH (Reality его требует)
#   - HTTP/2 на 443
#   - issuer != Cloudflare (CF-fronted не подходит)
#   - RTT с этого сервера (чем меньше, тем лучше — Reality
#     при срыве handshake форвардит коннект на этот хост,
#     медленный SNI = медленный fallback)
#
# Использование:
#   find-sni.sh                  топ-10 из встроенного списка
#   find-sni.sh -n 20            топ-20
#   find-sni.sh --scan           добавить соседей по своей /24 (нужен nmap)
#   find-sni.sh --all            показать все, не только PASS
#   find-sni.sh --candidates F   добавить домены из F (по одному в строке)
#   find-sni.sh --timeout 6      tаймаут на пробу (default 4)
#   find-sni.sh --jobs 16        параллельных тестов (default 8)
#
# Совет: бери топ-3 с лучшим RTT, и которые НЕ через Cloudflare/Akamai.

set -uo pipefail

TOP_N=10
SCAN_NEIGHBORS=false
EXTRA_FILE=""
TIMEOUT=4
JOBS=8
SHOW_ALL=false

usage() { sed -n '2,28p' "$0" | sed 's/^# \?//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n)            TOP_N="$2"; shift 2 ;;
        --scan)        SCAN_NEIGHBORS=true; shift ;;
        --candidates)  EXTRA_FILE="$2"; shift 2 ;;
        --timeout)     TIMEOUT="$2"; shift 2 ;;
        --jobs)        JOBS="$2"; shift 2 ;;
        --all)         SHOW_ALL=true; shift ;;
        -h|--help)     usage 0 ;;
        *)             echo "неизвестный аргумент: $1" >&2; usage 1 ;;
    esac
done

# === Цвета ===
if [[ -t 1 ]]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
    BLUE=$'\033[34m'; BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; BLUE=""; BOLD=""; GRAY=""; RESET=""
fi

# === Проверка зависимостей ===
for cmd in openssl curl awk timeout xargs; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "не найден: $cmd" >&2; exit 1; }
done

# === Curated список кандидатов ===
read -r -d '' BUILTIN_CANDIDATES <<'EOF' || true
# JP — обычно лучшее качество, без HSTS-сюрпризов
www.lovelive-anime.jp
gateway.icloud.com
www.cybozu.com
www.kingsoft.jp
www.yahoo.co.jp
www.rakuten.co.jp
www.line.me
www.softbank.jp
www.nintendo.co.jp
www.sony.jp
# KR
www.naver.com
www.daum.net
www.kakaocorp.com
shopping.naver.com
# «Скучный» enterprise
www.tesla.com
www.swift.com
www.cisco.com
www.canon.com
www.nvidia.com
www.intel.com
www.qualcomm.com
shop.lego.com
www.docker.com
www.unity3d.com
www.epicgames.com
www.spotify.com
# Apple/Google statics (без HSTS-pin)
init.itunes.apple.com
dl.google.com
www.apple.com
# EU
www.ovh.com
www.scaleway.com
www.hetzner.com
www.gandi.net
www.bahn.de
# US
www.linode.com
www.digitalocean.com
www.vultr.com
EOF

CANDIDATES=$(printf '%s\n' "$BUILTIN_CANDIDATES" | grep -Ev '^\s*(#|$)' | sort -u)

# доп. кандидаты от юзера
if [[ -n "$EXTRA_FILE" ]]; then
    if [[ ! -f "$EXTRA_FILE" ]]; then
        echo "${RED}не найден:${RESET} $EXTRA_FILE" >&2
        exit 1
    fi
    extra=$(grep -Ev '^\s*(#|$)' "$EXTRA_FILE")
    CANDIDATES=$(printf '%s\n%s\n' "$CANDIDATES" "$extra" | sort -u)
fi

# === Опционально — соседи по /24 ===
if $SCAN_NEIGHBORS; then
    if ! command -v nmap >/dev/null 2>&1; then
        echo "${YELLOW}[!]${RESET} --scan указан, но nmap не установлен — пропускаю" >&2
        echo "${YELLOW}[!]${RESET} установи: sudo apt install -y nmap" >&2
    else
        echo "${BLUE}[*]${RESET} определяю свой публичный IP..." >&2
        SERVER_IP=$(curl -4 -s --max-time 5 https://api.ipify.org || true)
        if [[ -z "$SERVER_IP" ]]; then
            echo "${RED}[!]${RESET} не удалось определить IP, пропускаю --scan" >&2
        else
            SUBNET="${SERVER_IP%.*}.0/24"
            echo "${BLUE}[*]${RESET} сканирую $SUBNET (это занимает минуту)..." >&2

            tmp_open=$(mktemp)
            # -sT — TCP connect, не нужен root; быстро для одной /24
            nmap -p 443 --open -sT --max-retries 1 --host-timeout 5s \
                "$SUBNET" -oG "$tmp_open" >/dev/null 2>&1 || true

            ips=$(awk '/Ports:.*443\/open/ {print $2}' "$tmp_open")
            rm -f "$tmp_open"

            ip_count=$(echo "$ips" | grep -c . || true)
            echo "${BLUE}[*]${RESET} нашёл $ip_count живых хостов на 443, тяну SAN..." >&2

            neighbors=$(echo "$ips" | while read -r ip; do
                [[ -z "$ip" ]] && continue
                echo | timeout "$TIMEOUT" openssl s_client -connect "$ip:443" \
                    -servername "$ip" -showcerts 2>/dev/null \
                    | openssl x509 -noout -text 2>/dev/null \
                    | grep -oP 'DNS:\K[^,\s]+' | head -3
            done | grep -v '^\*\.' | sort -u)

            if [[ -n "$neighbors" ]]; then
                added=$(echo "$neighbors" | wc -l)
                CANDIDATES=$(printf '%s\n%s\n' "$CANDIDATES" "$neighbors" | sort -u)
                echo "${BLUE}[*]${RESET} добавлено соседей: $added" >&2
            else
                echo "${YELLOW}[!]${RESET} соседей с валидным сертом не найдено" >&2
            fi
        fi
    fi
fi

TOTAL=$(echo "$CANDIDATES" | grep -c .)
echo "${BOLD}Кандидатов на проверку: $TOTAL${RESET}" >&2
echo "" >&2

# === Тест одного домена ===
# Формат вывода: STATUS|domain|rtt|tls|kex|http|issuer
test_one() {
    local domain="$1"
    [[ -z "$domain" ]] && return

    # TLS 1.3 + X25519 + issuer
    local tls_out
    tls_out=$(echo | timeout "$TIMEOUT" openssl s_client \
        -connect "$domain:443" -tls1_3 -groups X25519 \
        -servername "$domain" 2>/dev/null || true)

    if [[ -z "$tls_out" ]]; then
        printf 'FAIL|%s|99|--|--|--|tls-handshake-fail\n' "$domain"
        return
    fi

    local tls_ver kex issuer
    tls_ver=$(awk -F': ' '/^\s*Protocol\s*:/ {print $2; exit}' <<<"$tls_out")
    kex=$(awk -F': ' '/Server Temp Key/ {print $2; exit}' <<<"$tls_out")
    # Issuer — последняя CN= в строке issuer=
    issuer=$(awk -F'issuer=' '/^issuer=/ {print $2; exit}' <<<"$tls_out" \
             | grep -oP 'CN ?= ?\K[^,]+' | head -1)
    [[ -z "$issuer" ]] && issuer="--"

    # HTTP/2
    local h2
    h2=$(curl -sI --http2 --max-time "$TIMEOUT" "https://$domain/" 2>/dev/null \
         | awk 'NR==1{print $1}' || true)
    h2=${h2:---}

    # RTT
    local rtt
    rtt=$(curl -o /dev/null -s --max-time "$TIMEOUT" \
          -w "%{time_total}" "https://$domain/" 2>/dev/null || echo 99)
    [[ -z "$rtt" || "$rtt" == "0.000000" ]] && rtt=99

    # Решаем pass/fail
    local status="PASS"
    [[ "$tls_ver" != "TLSv1.3" ]] && status="FAIL"
    [[ "$kex" != *X25519* ]] && status="FAIL"
    [[ "$h2" != "HTTP/2" ]] && status="FAIL"
    # Cloudflare/Akamai-fronted — не годятся для Reality
    if [[ "$issuer" == *Cloudflare* || "$issuer" == *Akamai* ]]; then
        status="FAIL"
    fi

    printf '%s|%s|%s|%s|%s|%s|%s\n' \
        "$status" "$domain" "$rtt" \
        "${tls_ver:---}" "${kex:---}" "$h2" "$issuer"
}
export -f test_one
export TIMEOUT

# === Параллельный прогон ===
echo "${BLUE}[*]${RESET} запускаю $TOTAL тестов в $JOBS потоков (timeout=${TIMEOUT}s)..." >&2

results=$(echo "$CANDIDATES" \
    | xargs -P "$JOBS" -I {} bash -c 'test_one "$@"' _ {})

# === Вывод ===
echo ""
echo "${BOLD}Результаты (отсортировано: PASS сверху, по возрастанию RTT):${RESET}"
printf '%s\n' "${GRAY}status  domain                                rtt     tls       kex        http     issuer${RESET}"
printf '%s\n' "${GRAY}──────────────────────────────────────────────────────────────────────────────────────────${RESET}"

# PASS перед FAIL, внутри — по RTT
sorted=$(echo "$results" | sort -t'|' -k1,1 -k3,3g)

if ! $SHOW_ALL; then
    sorted=$(echo "$sorted" | grep '^PASS' || true)
fi

if [[ -z "$sorted" ]]; then
    echo "${YELLOW}нет PASS-кандидатов. попробуй --all чтобы видеть FAIL и понять что случилось.${RESET}"
    exit 1
fi

shown=0
while IFS='|' read -r status domain rtt tls kex h2 issuer; do
    [[ -z "$domain" ]] && continue
    shown=$((shown + 1))
    [[ $shown -gt $TOP_N ]] && break

    color="$GREEN"
    [[ "$status" == "FAIL" ]] && color="$RED"

    # обрезаем длинный issuer
    short_issuer="${issuer:0:30}"

    printf '%s%-7s%s %-37s %5.2fs   %-9s %-10s %-8s %s\n' \
        "$color" "$status" "$RESET" \
        "$domain" "$rtt" \
        "$tls" "$kex" "$h2" "$short_issuer"
done <<<"$sorted"

echo ""
total_pass=$(echo "$results" | grep -c '^PASS' || true)
total_fail=$(echo "$results" | grep -c '^FAIL' || true)
echo "${GRAY}итого: PASS=$total_pass  FAIL=$total_fail  показано=$shown${RESET}"
echo ""
echo "${BOLD}Совет:${RESET}"
echo "  • бери топ-3 с минимальным RTT"
echo "  • избегай тех у кого issuer = Cloudflare/Akamai (отфильтрованы автоматически)"
echo "  • для Reality в xray:  ${GRAY}\"serverNames\": [\"<выбранный_домен>\"]${RESET}"

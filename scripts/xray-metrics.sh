#!/usr/bin/env bash
#
# xray-metrics.sh
#
# Собирает метрики xray и пишет их в структурированный лог.
# Запускается из cron каждые N минут.
#
# Лог: /var/log/xray-monitor/metrics.log
#      /var/log/xray-monitor/connections.log (детали по соединениям)
#
# Формат metrics.log: одна строка = один snapshot, поля через |
#   timestamp | fd | mem_mb | cpu% | conn_total | conn_syn_recv | conn_time_wait |
#   conn_close_wait | load1 | steal% | uplink_total_mb | downlink_total_mb
#
# Использование:
#   # однократный запуск
#   sudo ./xray-metrics.sh
#
#   # cron (каждые 5 минут)
#   */5 * * * * /usr/local/sbin/xray-metrics.sh
#
#   # посмотреть metrics
#   tail -f /var/log/xray-monitor/metrics.log

set -u

LOG_DIR="/var/log/xray-monitor"
METRICS_LOG="$LOG_DIR/metrics.log"
CONNECTIONS_LOG="$LOG_DIR/connections.log"
DAILY_SUMMARY="$LOG_DIR/daily-summary.log"

mkdir -p "$LOG_DIR"

# === Проверяем что xray работает ===
XRAY_PID=$(pgrep -x xray | head -1)
if [[ -z "$XRAY_PID" ]]; then
    echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ')|XRAY_NOT_RUNNING" >> "$METRICS_LOG"
    exit 0
fi

TS=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

# === Ресурсы xray ===
if [[ -r /proc/$XRAY_PID/status ]]; then
    MEM_KB=$(awk '/VmRSS:/ {print $2}' /proc/$XRAY_PID/status)
    MEM_MB=$(( MEM_KB / 1024 ))
else
    MEM_MB=0
fi

# ls на /proc/PID/fd может потребовать root, на 750-доступе сработает только владелец.
FD=$(ls "/proc/$XRAY_PID/fd" 2>/dev/null | wc -l)
CPU=$(ps -o %cpu= -p "$XRAY_PID" 2>/dev/null | tr -d ' ')
CPU=${CPU:-0}

# === TCP соединения (по состояниям) ===
# -H убирает заголовок, поэтому wc -l даёт чистый счётчик.
CONN_TOTAL=$(ss -Htn state established 2>/dev/null | wc -l)
CONN_SYN_RECV=$(ss -Htn state syn-recv 2>/dev/null | wc -l)
CONN_TIME_WAIT=$(ss -Htn state time-wait 2>/dev/null | wc -l)
CONN_CLOSE_WAIT=$(ss -Htn state close-wait 2>/dev/null | wc -l)
CONN_FIN_WAIT=$(ss -Htn state fin-wait-1 2>/dev/null | wc -l)

# === Load и CPU ===
LOAD1=$(awk '{print $1}' /proc/loadavg)

# steal % через /proc/stat (две выборки с интервалом 1с — мгновенный показатель).
# Выкинули top: позиция колонки "st" зависит от версии и локали.
read -r _ user1 nice1 sys1 idle1 iowait1 irq1 softirq1 steal1 _ < /proc/stat
sleep 1
read -r _ user2 nice2 sys2 idle2 iowait2 irq2 softirq2 steal2 _ < /proc/stat
total_delta=$(( (user2+nice2+sys2+idle2+iowait2+irq2+softirq2+steal2) -
                (user1+nice1+sys1+idle1+iowait1+irq1+softirq1+steal1) ))
steal_delta=$(( steal2 - steal1 ))
if (( total_delta > 0 )); then
    STEAL=$(awk -v s="$steal_delta" -v t="$total_delta" 'BEGIN{printf "%.1f", (s/t)*100}')
else
    STEAL=0
fi

# === Трафик по юзерам (cumulative с момента старта xray) ===
# xray api statsquery возвращает JSON — парсим через jq, не grep+awk.
STATS_RAW=$(xray api statsquery --server=127.0.0.1:10085 -pattern "user>>>" 2>/dev/null || echo '{}')

if command -v jq >/dev/null 2>&1; then
    UPLINK_TOTAL_B=$(jq -r '
        [.stat[]? | select((.name // "") | test("uplink$")) | (.value // "0" | tonumber)] | add // 0
    ' <<<"$STATS_RAW" 2>/dev/null || echo 0)
    DOWNLINK_TOTAL_B=$(jq -r '
        [.stat[]? | select((.name // "") | test("downlink$")) | (.value // "0" | tonumber)] | add // 0
    ' <<<"$STATS_RAW" 2>/dev/null || echo 0)
else
    UPLINK_TOTAL_B=0
    DOWNLINK_TOTAL_B=0
fi
UPLINK_MB=$(( ${UPLINK_TOTAL_B%.*} / 1048576 ))
DOWNLINK_MB=$(( ${DOWNLINK_TOTAL_B%.*} / 1048576 ))

# === Пишем метрику ===
echo "$TS|fd=$FD|mem_mb=$MEM_MB|cpu=$CPU|conn_est=$CONN_TOTAL|syn_recv=$CONN_SYN_RECV|time_wait=$CONN_TIME_WAIT|close_wait=$CONN_CLOSE_WAIT|fin_wait=$CONN_FIN_WAIT|load=$LOAD1|steal=$STEAL|up_mb=$UPLINK_MB|down_mb=$DOWNLINK_MB" >> "$METRICS_LOG"

# === Топ клиентов и их соединения — пишем только если fd > 1000 (подозрительно) ===
if [[ $FD -gt 1000 ]]; then
    {
        echo ""
        echo "=== $TS — fd=$FD (подозрительно) ==="
        echo ""
        echo "[Топ внешних хостов куда xray исходит]"
        ss -tnp state established 2>/dev/null | grep xray | \
            awk '{print $5}' | sed -E 's/^\[::ffff:([0-9.]+)\]:.*/\1/; s/^\[(.*)\]:.*/\1/; s/:[0-9]+$//' | \
            sort | uniq -c | sort -rn | head -10
        echo ""
        echo "[Топ удалённых портов куда xray идёт]"
        ss -tnp state established 2>/dev/null | grep xray | \
            awk '{print $5}' | awk -F: '{print $NF}' | \
            sort | uniq -c | sort -rn | head -10
        echo ""
        echo "[Клиенты на 443]"
        ss -tnp state established "( sport = :443 )" 2>/dev/null | grep xray | \
            awk '{print $5}' | sed -E 's/^\[::ffff:([0-9.]+)\]:.*/\1/' | \
            sort | uniq -c | sort -rn | head -5
        echo ""
        echo "[Клиенты на 49152]"
        ss -tnp state established "( sport = :49152 )" 2>/dev/null | grep xray | \
            awk '{print $5}' | sed -E 's/^\[::ffff:([0-9.]+)\]:.*/\1/' | \
            sort | uniq -c | sort -rn | head -5
        echo ""
        echo "[Клиенты на 8443]"
        ss -tnp state established "( sport = :8443 )" 2>/dev/null | grep xray | \
            awk '{print $5}' | sed -E 's/^\[::ffff:([0-9.]+)\]:.*/\1/' | \
            sort | uniq -c | sort -rn | head -5
        echo ""
        echo "[Трафик по юзерам]"
        echo "$STATS_RAW"
        echo ""
    } >> "$CONNECTIONS_LOG"
fi

# === Ежедневный дайджест (раз в сутки в 04:00) ===
CURRENT_HOUR=$(date +%H)
CURRENT_MIN=$(date +%M)
if [[ "$CURRENT_HOUR" == "04" ]] && [[ "$CURRENT_MIN" -lt "10" ]]; then
    {
        echo ""
        echo "=================================================="
        echo "ДАЙДЖЕСТ за сутки до $TS"
        echo "=================================================="
        echo ""
        echo "Последние 24 часа (по metrics.log):"

        # берём записи за последние 1440 минут = 288 строк при cron каждые 5 мин
        tail -288 "$METRICS_LOG" | awk -F'|' '
        /fd=/ {
            # парсим поля вида key=value
            for(i=1;i<=NF;i++) {
                split($i, kv, "=");
                if(kv[1]=="fd") { fd_sum+=kv[2]; fd_n++; if(kv[2]>fd_max)fd_max=kv[2] }
                if(kv[1]=="mem_mb") { mem_sum+=kv[2]; mem_n++; if(kv[2]>mem_max)mem_max=kv[2] }
                if(kv[1]=="cpu") { cpu_sum+=kv[2]; cpu_n++; if(kv[2]>cpu_max)cpu_max=kv[2] }
                if(kv[1]=="conn_est") { conn_sum+=kv[2]; conn_n++; if(kv[2]>conn_max)conn_max=kv[2] }
                if(kv[1]=="steal") { steal_sum+=kv[2]; steal_n++; if(kv[2]>steal_max)steal_max=kv[2] }
            }
        }
        END {
            if(fd_n>0) printf "  fd:    avg=%d max=%d\n", fd_sum/fd_n, fd_max
            if(mem_n>0) printf "  mem:   avg=%d MB max=%d MB\n", mem_sum/mem_n, mem_max
            if(cpu_n>0) printf "  cpu:   avg=%.1f%% max=%.1f%%\n", cpu_sum/cpu_n, cpu_max
            if(conn_n>0) printf "  conn:  avg=%d max=%d\n", conn_sum/conn_n, conn_max
            if(steal_n>0) printf "  steal: avg=%.1f%% max=%.1f%%\n", steal_sum/steal_n, steal_max
        }'

        echo ""
    } >> "$DAILY_SUMMARY"
fi

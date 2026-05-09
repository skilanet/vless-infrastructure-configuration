#!/usr/bin/env bash
#
# lib/16-monitoring.sh — устанавливает скрипты мониторинга, cron, logrotate

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

if ! $INSTALL_MONITORING; then
    log_info "мониторинг пропущен по выбору юзера"
    exit 0
fi

# === Копируем скрипты в /usr/local/sbin ===
log_info "копирую скрипты в /usr/local/sbin/..."

declare -A SCRIPTS=(
    ["xray-metrics.sh"]="755"
    ["xray-health.sh"]="755"
    ["gen-vless-links.sh"]="755"
    ["update-subs.sh"]="755"
    ["analyze-metrics.py"]="755"
)

for script in "${!SCRIPTS[@]}"; do
    src="$SCRIPTS_DIR/$script"
    dst="/usr/local/sbin/$script"

    if [[ ! -f "$src" ]]; then
        log_warn "скрипт $src не найден, пропускаю"
        continue
    fi

    cp "$src" "$dst"
    chmod "${SCRIPTS[$script]}" "$dst"
    chown root:root "$dst"
    log_ok "  $script"
done

# === Директория для метрик ===
mkdir -p /var/log/xray-monitor
chmod 755 /var/log/xray-monitor

# === Cron для метрик каждые 5 минут ===
# Всегда перезаписываем — иначе после изменения скрипта/расписания на rerun
# пользователь будет ловить устаревший cron.
cat > /etc/cron.d/xray-metrics <<EOF
# Сбор метрик xray каждые 5 минут
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

*/5 * * * * root /usr/local/sbin/xray-metrics.sh
EOF
chmod 644 /etc/cron.d/xray-metrics
log_ok "cron для метрик установлен (каждые 5 минут)"

# === Logrotate ===
log_info "настраиваю logrotate..."
envsubst < "$CONFIGS_DIR/logrotate/xray" > /etc/logrotate.d/xray
cp "$CONFIGS_DIR/logrotate/xray-monitor" /etc/logrotate.d/xray-monitor
chmod 644 /etc/logrotate.d/xray /etc/logrotate.d/xray-monitor
log_ok "logrotate настроен"

# === Алиасы для удобства ===
# Управляемый блок: при rerun вырезаем старый блок целиком и вставляем
# свежий. Так список алиасов всегда соответствует тому, что в этом модуле.
log_info "обновляю алиасы для $ADMIN_USER..."

bashrc="/home/$ADMIN_USER/.bashrc"
BEGIN_MARKER="# >>> vless-infrastructure-configuration aliases >>>"
END_MARKER="# <<< vless-infrastructure-configuration aliases <<<"

if [[ -f "$bashrc" ]]; then
    # Удаляем старый блок (если есть) — между маркерами включительно.
    # Плюс старый формат "=== vless-...aliases ===" из ранних версий,
    # чтобы не оставались дубликаты.
    sed -i \
        -e "/^$BEGIN_MARKER\$/,/^$END_MARKER\$/d" \
        -e '/^# === vless-infrastructure-configuration aliases ===$/,/^$/d' \
        "$bashrc"

    {
        printf '\n%s\n' "$BEGIN_MARKER"
        cat <<'ALIASES'
alias xstat='sudo /usr/local/sbin/xray-health.sh'
alias xwatch='watch -c -n 5 sudo /usr/local/sbin/xray-health.sh'
alias xlogs='sudo tail -f /var/log/xray/access.log'
alias xerr='sudo tail -f /var/log/xray/error.log'
alias xmetrics='sudo tail -f /var/log/xray-monitor/metrics.log'
ALIASES
        printf '%s\n' "$END_MARKER"
    } >> "$bashrc"

    chown "$ADMIN_USER:$ADMIN_USER" "$bashrc"
    log_ok "алиасы обновлены"
fi

# === Первый запуск xray-metrics для теста ===
log_info "запускаю первый раз xray-metrics.sh..."
if /usr/local/sbin/xray-metrics.sh; then
    log_ok "метрики работают"
    if [[ -f /var/log/xray-monitor/metrics.log ]]; then
        log_info "первая запись:"
        tail -1 /var/log/xray-monitor/metrics.log | head -c 150
        echo ""
    fi
else
    log_warn "xray-metrics.sh завершился с ошибкой, проверь руками"
fi

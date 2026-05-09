#!/usr/bin/env bash
#
# lib/01-prompts.sh — собирает параметры установки.
#
# Все настройки касаются только инфраструктуры: юзеры, SSH, панель.
# Конкретика xray (Reality keys, инбаунды, юзеры VPN) настраивается
# через админ-панель уже после установки.

set -euo pipefail
source "$LIB_DIR/common.sh"

# === Юзеры системы ===
log_info "Системные пользователи"
prompt_string "Имя админского пользователя (sudo + ssh-доступ)" "vpn-admin" ADMIN_USER
save_state "ADMIN_USER" "$ADMIN_USER"

prompt_string "Имя системного пользователя для xray (без shell)" "xray" XRAY_USER
save_state "XRAY_USER" "$XRAY_USER"

prompt_string "Имя системного пользователя для админ-панели" "xray-admin" PANEL_USER
save_state "PANEL_USER" "$PANEL_USER"

# === SSH ключ ===
echo ""
log_info "SSH-ключ для админа"
echo "Сгенерируй ключ на твоём компьютере (если ещё нет):"
echo "  ${GRAY}ssh-keygen -t ed25519 -C \"vpn-server\"${RESET}"
echo ""
echo "Покажи публичный ключ:"
echo "  ${GRAY}cat ~/.ssh/id_ed25519.pub${RESET}"
echo ""
echo "Вставь содержимое ниже (одна строка). Enter без ввода — пропустить."
echo ""

while true; do
    read -p "ssh-ключ: " ssh_key
    ssh_key=$(echo "$ssh_key" | xargs)

    if [[ -z "$ssh_key" ]]; then
        log_warn "ключ не задан — login по паролю опасен на публичном VPS"
        if prompt_yesno "Точно пропустить?" "n" SKIP_KEY && $SKIP_KEY; then
            save_state "SSH_PUBLIC_KEY" ""
            break
        fi
        continue
    fi

    if [[ "$ssh_key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) ]]; then
        save_state "SSH_PUBLIC_KEY" "$ssh_key"
        log_ok "ключ принят"
        break
    fi

    log_warn "не похоже на публичный SSH-ключ, попробуй снова"
done

# === SSH порт ===
echo ""
log_info "SSH порт"
prompt_yesno "Изменить SSH порт с 22 на нестандартный? (рекомендуется)" "y" CHANGE_SSH_PORT
save_state "CHANGE_SSH_PORT" "$CHANGE_SSH_PORT"

if $CHANGE_SSH_PORT; then
    prompt_int "Новый SSH порт" 1024 65535 51510 SSH_PORT
else
    SSH_PORT=22
fi
save_state "SSH_PORT" "$SSH_PORT"

# === Админ-панель ===
echo ""
log_info "Админ-панель"
echo "После установки панель будет доступна по HTTP на этом порту."
echo "Через панель ты создаёшь VLESS-инбаунды, юзеров, настраиваешь routing."
echo ""

prompt_int "Порт админ-панели" 1024 65535 8088 PANEL_PORT
save_state "PANEL_PORT" "$PANEL_PORT"

echo ""
echo "Логин и пароль для входа в панель."
prompt_string "Логин админа панели" "admin" PANEL_LOGIN
save_state "PANEL_LOGIN" "$PANEL_LOGIN"

# Пароль читаем без эха
while true; do
    read -s -p "${BOLD}Пароль (минимум 8 символов)${RESET}: " panel_pwd
    echo
    if [[ ${#panel_pwd} -lt 8 ]]; then
        log_warn "минимум 8 символов"
        continue
    fi
    read -s -p "${BOLD}Повтори пароль${RESET}: " panel_pwd2
    echo
    if [[ "$panel_pwd" != "$panel_pwd2" ]]; then
        log_warn "пароли не совпадают"
        continue
    fi
    PANEL_PASSWORD="$panel_pwd"
    save_state "PANEL_PASSWORD" "$PANEL_PASSWORD"
    log_ok "пароль принят"
    break
done

# === Доп. опции ===
echo ""
log_info "Дополнительные опции"

prompt_yesno "Установить fail2ban для защиты SSH?" "y" INSTALL_FAIL2BAN
save_state "INSTALL_FAIL2BAN" "$INSTALL_FAIL2BAN"

prompt_yesno "Применить sysctl-настройки для сети (BBR, keepalive, fastopen)?" "y" APPLY_SYSCTL
save_state "APPLY_SYSCTL" "$APPLY_SYSCTL"

prompt_yesno "Установить cron для метрик каждые 5 минут?" "y" INSTALL_MONITORING
save_state "INSTALL_MONITORING" "$INSTALL_MONITORING"

log_ok "все параметры собраны"

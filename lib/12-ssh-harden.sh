#!/usr/bin/env bash
#
# lib/12-ssh-harden.sh — изменение порта SSH, отключение password auth,
# с проверкой что новая SSH-сессия может подключиться.

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

# Бэкап оригинала
backup_file /etc/ssh/sshd_config

# Создаём drop-in директорию для наших настроек
mkdir -p /etc/ssh/sshd_config.d

# Наш drop-in
cat > /etc/ssh/sshd_config.d/99-xray-vpn-stack.conf <<EOF
# Настройки от xray-vpn-stack installer
# Изменения:
# - порт сменён на $SSH_PORT (если CHANGE_SSH_PORT=true)
# - root login отключён
# - password auth отключён (вход только по ключу)
# - keepalive против троттлинга РКН

Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 15
ClientAliveCountMax 4

# AEAD-шифры — менее распознаются DPI
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
EOF

# Если в основном sshd_config есть конфликтующие старые директивы — комментируем
# (drop-in применяется поверх, но visual cleanup полезен)
sed -i.bak \
    -e '/^Port /s/^/# /' \
    -e '/^PermitRootLogin /s/^/# /' \
    -e '/^PasswordAuthentication /s/^/# /' \
    /etc/ssh/sshd_config

# Валидация конфига
if ! sshd -t 2>/dev/null; then
    log_error "sshd конфиг невалиден после изменений"
    log_error "восстанавливаю из бэкапа"
    rm -f /etc/ssh/sshd_config.d/99-xray-vpn-stack.conf
    cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config 2>/dev/null || true
    exit 1
fi
log_ok "sshd конфиг валиден"

# === Перед перезапуском — оставляем текущую сессию работать ===
log_warn "Сейчас будет перезагружен sshd"
log_warn "Текущая сессия НЕ должна разорваться (но если что — переподключайся на $SSH_PORT)"
echo ""

# Если изменили порт — открываем его в ufw до рестарта
if $CHANGE_SSH_PORT && [[ "$SSH_PORT" != "22" ]]; then
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "$SSH_PORT/tcp" comment 'SSH custom port' >/dev/null 2>&1 || true
    fi
fi

# Если есть socket activation — отключаем (чтобы порт точно сменился)
if systemctl is-active ssh.socket >/dev/null 2>&1; then
    log_info "отключаю ssh.socket (socket activation)"
    systemctl stop ssh.socket
    systemctl disable ssh.socket >/dev/null 2>&1 || true
fi

# Рестарт ssh
systemctl restart ssh

sleep 2

# Проверяем что sshd слушает на новом порту
if ss -tlnp | grep -q ":$SSH_PORT"; then
    log_ok "sshd слушает на порту $SSH_PORT"
else
    log_error "sshd не слушает на $SSH_PORT — возможно проблема"
    log_error "проверь systemctl status ssh"
    log_warn "не закрывай текущую SSH сессию пока не убедишься что новая работает"
fi

# Финальное предупреждение
echo ""
log_warn "${BOLD}ВАЖНО${RESET}"
log_warn "Открой ${BOLD}новое${RESET} окно/вкладку терминала и проверь подключение:"
log_warn "  ${CYAN}ssh -p $SSH_PORT $ADMIN_USER@<server-ip>${RESET}"
log_warn ""
log_warn "Если новая сессия НЕ подключается — НЕ закрывай эту, чини конфиг."
log_warn "Иначе можешь потерять доступ к серверу."
echo ""

read -p "Нажми Enter когда проверишь что новая SSH-сессия работает (или Ctrl+C для отмены) " -r
log_ok "SSH harden завершён"

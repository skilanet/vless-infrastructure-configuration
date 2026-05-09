#!/usr/bin/env bash
#
# lib/12-ssh-harden.sh — изменение порта SSH, отключение password auth,
# с проверкой что новая SSH-сессия может подключиться.

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

# Бэкап оригинала. Делаем только если бэкапа от нас ещё нет —
# иначе rerun-ы плодили бы по бэкапу за каждый запуск, и после
# нескольких rerun-ов "оригинал" в самом старом из них уже был бы
# нашим же изменённым конфигом.
SSHD_BACKUP="/etc/ssh/sshd_config.vless-bak"
if [[ -f /etc/ssh/sshd_config ]] && [[ ! -f "$SSHD_BACKUP" ]]; then
    cp -a /etc/ssh/sshd_config "$SSHD_BACKUP"
    log_info "бэкап sshd_config: $SSHD_BACKUP"
fi

# Создаём drop-in директорию для наших настроек
mkdir -p /etc/ssh/sshd_config.d

# Наш drop-in
cat > /etc/ssh/sshd_config.d/99-vless-infrastructure-configuration.conf <<EOF
# Настройки от vless-infrastructure-configuration installer
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
    log_error "восстанавливаю из бэкапа $SSHD_BACKUP"
    rm -f /etc/ssh/sshd_config.d/99-vless-infrastructure-configuration.conf
    if [[ -f "$SSHD_BACKUP" ]]; then
        cp -a "$SSHD_BACKUP" /etc/ssh/sshd_config
    fi
    exit 1
fi
log_ok "sshd конфиг валиден"

# === Проверяем — нужно ли вообще перезапускать ===
# При rerun на том же порту sshd уже слушает на $SSH_PORT, конфиг
# валиден, smoke-тест уже прошёл — нет смысла трогать сервис и
# заставлять юзера снова жать Enter.
already_listening=false
if ss -tlnH 2>/dev/null | awk '{print $4}' | grep -q ":${SSH_PORT}\$"; then
    already_listening=true
fi

if $already_listening; then
    log_info "sshd уже слушает на $SSH_PORT — рестарт не нужен"
else
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
fi

# Проверяем что sshd слушает на новом порту
if ss -tlnp | grep -q ":$SSH_PORT"; then
    log_ok "sshd слушает на порту $SSH_PORT"
else
    log_error "sshd не слушает на $SSH_PORT — возможно проблема"
    log_error "проверь systemctl status ssh"
    log_warn "не закрывай текущую SSH сессию пока не убедишься что новая работает"
fi

# Финальное предупреждение — только если мы реально только что переключили порт.
# На rerun без рестарта (sshd уже на нужном порту) не дёргаем юзера.
if ! $already_listening; then
    echo ""
    log_warn "${BOLD}ВАЖНО${RESET}"
    log_warn "Открой ${BOLD}новое${RESET} окно/вкладку терминала и проверь подключение:"
    log_warn "  ${CYAN}ssh -p $SSH_PORT $ADMIN_USER@<server-ip>${RESET}"
    log_warn ""
    log_warn "Если новая сессия НЕ подключается — НЕ закрывай эту, чини конфиг."
    log_warn "Иначе можешь потерять доступ к серверу."
    echo ""

    read -rp "Нажми Enter когда проверишь что новая SSH-сессия работает (или Ctrl+C для отмены) "
fi
log_ok "SSH harden завершён"

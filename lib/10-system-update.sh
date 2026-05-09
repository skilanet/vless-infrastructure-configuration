#!/usr/bin/env bash
#
# lib/10-system-update.sh — обновление apt-индекса и базовые пакеты

set -euo pipefail
source "$LIB_DIR/common.sh"
source "$STATE_FILE"

log_info "Обновляю apt-индекс..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq

log_info "Устанавливаю базовые пакеты..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    ca-certificates \
    curl \
    wget \
    jq \
    dnsutils \
    cron \
    logrotate \
    ufw \
    sudo \
    iputils-ping \
    iproute2 \
    procps \
    sysstat \
    gnupg \
    git \
    python3 \
    uuid-runtime \
    openssl \
    gettext-base \
    apt-transport-https

log_ok "базовые пакеты установлены"

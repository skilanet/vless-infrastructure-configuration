# vless-infrastructure-configuration

Идемпотентный установщик для xray-сервера с веб-админкой.

Один запуск на чистом VPS — получаешь готовый сервер с панелью управления.
Дальше всё (VLESS-инбаунды, юзеры, routing) настраивается через UI.

## Что делает

**Инсталлер (bash):**
- 🔐 Создаёт системных юзеров: админ для SSH, отдельные runtime-юзеры для xray и панели
- 🛡️ SSH harden: смена порта, отключение root/password auth, AEAD-шифры
- 🛡️ UFW + fail2ban
- ⚙️ sysctl-тюнинг (BBR, TCP keepalive, fastopen, SYN protection)
- 📦 Ставит xray-core (без конфигурации — это работа панели)
- 📊 Ставит мониторинг: метрики каждые 5 минут, health-check, анализатор
- 🌐 Ставит и запускает админ-панель (Flask + HTML/CSS)

**Админ-панель (Python/Flask):**
- Создание VLESS-инбаундов (XHTTP / TCP+Vision)
- Автоматическая генерация Reality keys, paths, shortIds
- Управление юзерами (UUID-генерация, привязка ко всем инбаундам)
- Live-статистика трафика по юзерам через xray API
- Restart/Stop/Start xray
- Авто-открытие портов в UFW при создании inbound

## Установка

```bash
# Скачать установщик
curl -fsSL https://raw.githubusercontent.com/skilanet/vless-infrastructure-configuration/main/install.sh -o /tmp/install.sh

# Запустить (интерактивно)
sudo bash /tmp/install.sh
```

Или одной командой:

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/skilanet/vless-infrastructure-configuration/main/install.sh)
```

Установщик спросит:

- Имена системных юзеров (`vpn-admin`, `xray`, `xray-admin`)
- Публичный SSH-ключ
- Менять ли SSH-порт (по умолчанию `51510`)
- Порт админ-панели (по умолчанию `8088`)
- Логин и пароль для входа в панель
- Доп. опции: fail2ban, sysctl tuning, monitoring

## После установки

```bash
# логин по SSH
ssh -p 51510 vpn-admin@<server-ip>

# открыть админ-панель в браузере
http://<server-ip>:8088
```

Дальше всё через UI:

1. **Dashboard** — обзор состояния (xray running/stopped, кол-во инбаундов и юзеров)
2. **Inbounds → New inbound** — создать первый VLESS-инбаунд
3. **Users → Add user** — добавить юзера (UUID-ы привязываются ко всем инбаундам)
4. xray стартует автоматически после создания первого inbound

## Безопасность панели

⚠️ **Панель работает по HTTP**, не публикуй её в интернете без защиты.

Варианты:
1. **SSH-туннель** (рекомендуется): на маке открыть туннель и работать через `localhost`:
   ```bash
   ssh -p 51510 -L 8088:localhost:8088 vpn-admin@<server-ip>
   # потом открой http://localhost:8088
   ```
2. **Tailscale**: поставить на сервер и мак, изменить `host` в `/etc/xray-admin/config.json`
   на Tailscale IP `100.x.x.x` — порт перестанет быть публичным

## Структура проекта

```
vless-infrastructure-configuration/
├── install.sh                 # bootstrap entry point
├── install-real.sh            # основной оркестратор
├── README.md
├── lib/                       # модули установки (выполняются по порядку)
│   ├── common.sh              # логирование, prompts, state-management
│   ├── 00-prechecks.sh        # проверка ОС/RAM/интернета
│   ├── 01-prompts.sh          # сбор параметров от юзера
│   ├── 10-system-update.sh    # apt + базовые пакеты
│   ├── 11-users.sh            # 3 юзера: admin/xray/panel + sudoers
│   ├── 12-ssh-harden.sh       # SSH-порт, отключение root/password auth
│   ├── 13-firewall.sh         # UFW + sudoers для UFW из панели
│   ├── 14-xray-install.sh     # xray-core (без конфига)
│   ├── 15-monitoring.sh       # скрипты + cron + logrotate
│   ├── 16-fail2ban.sh         # SSH-защита
│   ├── 17-sysctl.sh           # BBR + сетевой тюнинг
│   ├── 18-admin-panel.sh      # установка Flask-панели
│   └── 19-finalize.sh         # финальный отчёт
├── admin-panel/               # код админ-панели
│   ├── app.py                 # Flask-приложение
│   ├── requirements.txt
│   ├── templates/             # Jinja2 HTML-шаблоны
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── inbounds.html
│   │   ├── inbound_form.html
│   │   └── users.html
│   └── static/
│       └── style.css
├── scripts/                   # → копируются в /usr/local/sbin/
│   ├── xray-health.sh         # быстрая проверка
│   ├── xray-metrics.sh        # cron-метрики
│   ├── gen-vless-links.sh     # генерация vless:// ссылок из conf.d
│   ├── update-subs.sh         # пуш подписок в GitHub Gist
│   └── analyze-metrics.py     # анализ накопленных metrics.log
└── configs/
    ├── sysctl/
    │   └── 99-vpn-tuning.conf
    └── logrotate/
        ├── xray
        └── xray-admin
        └── xray-monitor
```

## Архитектура

**Разделение ответственности:**

```
┌─────────────────────────────────────────────────────┐
│  install.sh (один раз на новом VPS)                │
│  ├─ ставит ОС-зависимости                          │
│  ├─ создаёт юзеров (vpn-admin, xray, xray-admin)   │
│  ├─ harden SSH                                      │
│  ├─ ставит UFW                                      │
│  ├─ ставит xray-core (без конфига)                 │
│  ├─ ставит админ-панель                            │
│  └─ запускает только панель                         │
└─────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│  Админ-панель (используется постоянно)             │
│  ├─ создаёт inbound'ы → пишет в conf.d/            │
│  ├─ создаёт юзеров → добавляет в clients           │
│  ├─ открывает порты в UFW                          │
│  ├─ restart xray                                    │
│  └─ показывает stats и логи                        │
└─────────────────────────────────────────────────────┘
```

xray работает под user `xray`, панель под user `xray-admin`. Панель в группе `xray`,
поэтому может писать в `/usr/local/etc/xray/conf.d/`. Доступ к `systemctl restart xray`
и `ufw allow N/tcp` — через sudoers-whitelist (без пароля, с конкретными командами).

## Безопасность по умолчанию

- SSH **только по ключу**, root login и password auth отключены
- Всем процессам выделены отдельные системные юзеры
- conf.d/ доступна только `root:xray` (`750`)
- ufw default deny, открыты только SSH-порт + порт панели
- fail2ban охраняет SSH (3 попытки за 10 минут → бан на час)
- sudoers строгие: панель может только конкретные команды, не shell

## Что НЕ делает (намеренно)

- Не выпускает Let's Encrypt сертификаты (Reality их не требует, для панели нужен домен)
- Не настраивает Tailscale (опционально вручную после установки)
- Не предполагает работу за nginx (всё прямо)
- Не делает backup/restore (через `git` у админа)

## Тестирование

Минимальные требования:
- Ubuntu 22.04+ или Debian 11+
- 1 GB RAM (рекомендуется 2 GB)
- 1 vCPU
- 10 GB диска
- Прямой публичный IPv4

## Лицензия

MIT.

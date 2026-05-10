"""
xray-admin-panel — админ-панель для xray-сервера.
Версия 2: добавлено редактирование inbound'ов и юзеров, валидации.
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
import secrets
import socket
import subprocess
import uuid as uuid_module
from functools import wraps
from pathlib import Path
from urllib.parse import quote

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session, url_for)
from qrcode.image.svg import SvgPathImage
from werkzeug.security import check_password_hash

# ==== Конфиг ====
CONFIG_DIR = Path("/usr/local/etc/xray/conf.d")
CONFIG_FILE = Path("/etc/xray-admin/config.json")

# Дефолтные SNI для Reality (отдаются в форму)
DEFAULT_SNI_OPTIONS = [
    "yahoo.com",
    "www.lovelive-anime.jp",
    "gateway.icloud.com",
    "www.amazon.com",
    "aws.amazon.com",
    "www.cloudflare.com",
    "www.microsoft.com",
]

# Допустимые транспорты для VLESS
TRANSPORT_CHOICES = ["xhttp", "tcp"]
XHTTP_MODES = ["stream-one", "packet-up", "auto"]

# Служебная инфраструктура (пишется одной кнопкой в /settings)
BASE_INFRA_FILES = [
    "00-base.json",
    "01-routing.json",
    "02-outbounds.json",
    "10-service-inbounds.json",
]
DEFAULT_API_PORT = 10085
DEFAULT_METRICS_PORT = 10086
DEFAULT_SOCKS_PORT = 10808

# ==== Загрузка конфига ====
if not CONFIG_FILE.exists():
    raise RuntimeError(f"Файл конфига не найден: {CONFIG_FILE}")

with CONFIG_FILE.open() as f:
    PANEL_CONFIG = json.load(f)

app = Flask(__name__)
app.secret_key = PANEL_CONFIG["secret_key"]


# ==== Утилиты ====
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def run_xray(*args: str) -> str:
    result = subprocess.run(
        ["sudo", "/usr/local/bin/xray", *args],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"xray failed: {result.stderr}")
    return result.stdout


def systemctl(action: str, service: str = "xray") -> tuple[bool, str]:
    result = subprocess.run(
        ["sudo", "/bin/systemctl", action, service],
        capture_output=True, text=True, timeout=15,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def is_xray_active() -> bool:
    ok, _ = systemctl("is-active", "xray")
    return ok


# ==== File helpers ====
def list_config_files() -> list[Path]:
    if not CONFIG_DIR.exists():
        return []
    return sorted(CONFIG_DIR.glob("*.json"))


def read_config_file(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def write_config_file(path: Path, data: dict) -> None:
    """Атомарная запись JSON-файла."""
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp.replace(path)
    os.chmod(path, 0o660)


def find_inbound_by_tag(tag: str) -> tuple[Path, dict, int] | None:
    """Возвращает (path_к_файлу, json_данные_файла, индекс_inbound'а_в_массиве)."""
    for f in list_config_files():
        data = read_config_file(f)
        for i, ib in enumerate(data.get("inbounds", [])):
            if ib.get("tag") == tag:
                return f, data, i
    return None


def collect_inbounds() -> list[dict]:
    inbounds = []
    for f in list_config_files():
        data = read_config_file(f)
        for ib in data.get("inbounds", []):
            ib["_file"] = f.name
            inbounds.append(ib)
    return inbounds


def collect_vless_inbounds() -> list[dict]:
    """Только VLESS-инбаунды (без service-инбаундов)."""
    return [ib for ib in collect_inbounds() if ib.get("protocol") == "vless"]


def collect_users() -> list[dict]:
    """Уникальные юзеры (по UUID), с информацией в каких inbound'ах состоят."""
    users_by_id: dict[str, dict] = {}
    for ib in collect_inbounds():
        if ib.get("protocol") != "vless":
            continue
        for client in ib.get("settings", {}).get("clients", []):
            uid = client.get("id")
            if uid not in users_by_id:
                users_by_id[uid] = {
                    "id": uid,
                    "email": client.get("email", "—"),
                    "level": client.get("level", 0),
                    "inbounds": [],
                }
            users_by_id[uid]["inbounds"].append(ib.get("tag", "?"))
    return list(users_by_id.values())


def get_user_by_uuid(uid: str) -> dict | None:
    for u in collect_users():
        if u["id"] == uid:
            return u
    return None


def get_xray_stats() -> dict[str, dict]:
    """{email: {uplink: bytes, downlink: bytes}}"""
    if not is_xray_active():
        return {}
    try:
        out = run_xray("api", "statsquery",
                       "--server=127.0.0.1:10085",
                       "-pattern", "user>>>")
        data = json.loads(out)
        result: dict[str, dict] = {}
        for s in data.get("stat", []):
            parts = s["name"].split(">>>")
            if len(parts) >= 4:
                email = parts[1]
                direction = parts[3]  # uplink или downlink
                result.setdefault(email, {})[direction] = s["value"]
        return result
    except (RuntimeError, json.JSONDecodeError):
        return {}


# ==== Валидаторы ====
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,30}$")
EMAIL_LOCAL_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


def validate_port(port_str: str, exclude_tag: str | None = None) -> int:
    """Проверка порта: число, диапазон, не занят другим inbound'ом."""
    try:
        port = int(port_str)
    except (TypeError, ValueError):
        raise ValueError("порт должен быть числом")

    if port < 1 or port > 65535:
        raise ValueError("порт должен быть в диапазоне 1-65535")

    # проверка что порт не занят другим inbound'ом в conf.d/
    for ib in collect_inbounds():
        if ib.get("port") == port and ib.get("tag") != exclude_tag:
            # игнорируем service-инбаунды на 127.0.0.1 — они слушают локально
            if ib.get("listen") in ("127.0.0.1", "localhost"):
                continue
            raise ValueError(f"порт {port} уже занят inbound'ом «{ib.get('tag')}»")

    return port


def validate_tag(tag: str) -> str:
    tag = tag.strip().lower()
    if not TAG_RE.match(tag):
        raise ValueError("tag должен содержать только латиницу, цифры и дефис, начинаться с буквы/цифры")
    return tag


def validate_sni(sni: str) -> str:
    sni = sni.strip().lower()
    if not DOMAIN_RE.match(sni):
        raise ValueError("SNI должен быть валидным доменом (например yahoo.com)")
    return sni


def validate_email(email: str) -> str:
    email = email.strip()
    if not email:
        raise ValueError("email не может быть пустым")
    if "@" not in email:
        # автодополняем @server
        if not EMAIL_LOCAL_RE.match(email):
            raise ValueError("email содержит недопустимые символы")
        email = f"{email}@server"
    else:
        local, _, domain = email.partition("@")
        if not EMAIL_LOCAL_RE.match(local) or not domain:
            raise ValueError("email невалиден")
    return email


def validate_uuid(uid: str) -> str:
    uid = uid.strip().lower()
    try:
        return str(uuid_module.UUID(uid))
    except (ValueError, AttributeError):
        raise ValueError("UUID невалиден")


def resolve_dest(sni: str, custom_dest: str = "") -> str:
    """Возвращает dest в формате IP:443. Резолвит SNI если custom_dest пустой."""
    custom_dest = custom_dest.strip()
    if custom_dest:
        # принимаем как есть, ожидаем формат host:port
        if ":" not in custom_dest:
            raise ValueError("dest должен быть в формате host:port")
        return custom_dest
    # резолвим SNI
    try:
        ip = socket.gethostbyname(sni)
        return f"{ip}:443"
    except socket.gaierror:
        raise ValueError(f"не удалось разрешить {sni} в IP-адрес")


# ==== Builders ====
def build_inbound(tag: str, port: int, transport: str, sni: str, dest: str,
                  xhttp_mode: str = "stream-one",
                  private_key: str | None = None,
                  short_ids: list[str] | None = None,
                  xhttp_path: str | None = None,
                  clients: list[dict] | None = None) -> dict:
    """Собирает структуру inbound'а. Reality keys не пересоздаются если переданы."""
    if private_key is None:
        out = run_xray("x25519")
        for line in out.splitlines():
            if "Private" in line:
                private_key = line.split(":", 1)[1].strip()
                break
        if not private_key:
            raise RuntimeError("не удалось получить Reality private key")

    if short_ids is None:
        short_ids = ["", secrets.token_hex(1), secrets.token_hex(2),
                     secrets.token_hex(4), secrets.token_hex(8)]

    inbound = {
        "tag": tag,
        "listen": "0.0.0.0",
        "port": port,
        "protocol": "vless",
        "settings": {"clients": clients or [], "decryption": "none"},
        "streamSettings": {
            "network": transport,
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": dest,
                "xver": 0,
                "serverNames": [sni],
                "privateKey": private_key,
                "shortIds": short_ids,
                "fingerprint": "chrome",
            },
            "sockopt": {
                "tcpKeepAliveIdle": 60,
                "tcpKeepAliveInterval": 30,
            },
        },
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "metadataOnly": False,
            "routeOnly": True,
        },
    }

    if transport == "xhttp":
        if xhttp_path is None:
            xhttp_path = f"/{secrets.token_hex(8)}"
        inbound["streamSettings"]["xhttpSettings"] = {
            "path": xhttp_path,
            "mode": xhttp_mode,
            "host": sni,
        }

    return inbound


# ==== VLESS link / QR helpers ====
def derive_public_key(private_b64: str) -> str:
    """Reality privateKey хранится в base64url. Деривим X25519 public key из него."""
    pad = "=" * (-len(private_b64) % 4)
    raw = base64.urlsafe_b64decode(private_b64 + pad)
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode()


def get_server_ip() -> str:
    """Внешний IP сервера. Берётся только из config.json — без внешних запросов."""
    sip = PANEL_CONFIG.get("server_ip")
    if sip:
        return str(sip)
    return "<server_ip-не-задан-в-config.json>"


def build_vless_link(inbound: dict, client: dict, server_ip: str,
                     public_key: str) -> str:
    """Формирует vless:// URL для одного клиента в одном инбаунде."""
    ss = inbound.get("streamSettings", {})
    rs = ss.get("realitySettings", {})
    network = ss.get("network", "tcp")
    port = inbound.get("port")
    sni = (rs.get("serverNames") or [""])[0]
    fp = rs.get("fingerprint", "chrome")

    # Берём первый непустой short id
    sids = [s for s in rs.get("shortIds", []) if s]
    sid = sids[0] if sids else ""

    uid = client["id"]
    name = client.get("email", "user").split("@")[0] or "user"
    label = f"{name}:{port}-{network}"

    qs = [
        ("encryption", "none"),
        ("security", "reality"),
        ("sni", sni),
        ("fp", fp),
        ("pbk", public_key),
        ("sid", sid),
        ("type", network),
    ]

    if network == "xhttp":
        xs = ss.get("xhttpSettings", {})
        qs.extend([
            ("path", xs.get("path", "/")),
            ("mode", xs.get("mode", "auto")),
            ("host", xs.get("host", sni)),
        ])
    elif network == "tcp":
        flow = client.get("flow", "")
        if flow:
            qs.append(("flow", flow))

    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in qs)
    return f"vless://{uid}@{server_ip}:{port}?{query}#{quote(label)}"


def make_qr_svg(data: str) -> str:
    """Генерит QR-код в SVG (без Pillow). Возвращает строку с готовым <svg>."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(image_factory=SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


# ==== Base infrastructure templates ====
# Шаблоны 4 служебных файлов: log/api/metrics/stats/policy/dns + routing +
# outbounds + service-inbounds. Один в один соответствуют рабочему серверу.
# При необходимости можно править прямо JSON-ом через `sudoedit`, но дефолты
# подобраны так, чтобы панель видела статсы и применялись блокировки.

def base_config_template() -> dict:
    return {
        "log": {
            "loglevel": "info",
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log",
        },
        "api": {
            "tag": "api",
            "services": ["StatsService", "LoggerService", "HandlerService"],
        },
        "metrics": {"tag": "metrics"},
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "handshake": 4,
                    "connIdle": 120,
                    "uplinkOnly": 2,
                    "downlinkOnly": 5,
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                    "bufferSize": 512,
                },
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "dns": {
            "servers": [
                {
                    "address": "https+local://1.1.1.1/dns-query",
                    "domains": ["geosite:geolocation-!cn"],
                    "skipFallback": True,
                },
                {
                    "address": "https+local://9.9.9.9/dns-query",
                    "skipFallback": True,
                },
                "localhost",
            ],
            "queryStrategy": "UseIP",
            "disableCache": False,
            "disableFallback": False,
            "tag": "dns_inbound",
        },
    }


def routing_config_template() -> dict:
    return {
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "inboundTag": ["metrics"], "outboundTag": "metrics"},
                {"type": "field", "inboundTag": ["dns_inbound"], "outboundTag": "direct"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:ru", "geoip:by"], "outboundTag": "block"},
                {
                    "type": "field",
                    "domain": [
                        "geosite:category-gov-ru",
                        "regexp:.*\\.(ru|рф|by|su)$",
                        "domain:yandex.com",
                        "domain:yandex.net",
                        "domain:yandex.kz",
                        "domain:2gis.com",
                        "domain:vk.com",
                        "domain:vk.me",
                        "domain:vk.link",
                        "domain:mail.ru",
                        "domain:ozon.com",
                        "domain:wildberries.com",
                        "domain:avito.ma",
                        "domain:sberbank.com",
                        "domain:tinkoff.com",
                        "domain:kinopoisk.org",
                        "domain:kaspersky.com",
                    ],
                    "outboundTag": "block",
                },
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
            ],
        },
    }


def outbounds_config_template() -> dict:
    return {
        "outbounds": [
            {
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIPv4"},
                "tag": "direct",
                "streamSettings": {
                    "sockopt": {
                        "tcpFastOpen": True,
                        "tcpCongestion": "bbr",
                        "tcpNoDelay": True,
                        "tcpKeepAliveInterval": 30,
                        "mark": 255,
                    },
                },
            },
            {
                "protocol": "blackhole",
                "settings": {"response": {"type": "http"}},
                "tag": "block",
            },
            {"protocol": "freedom", "tag": "api"},
            {"protocol": "freedom", "tag": "metrics"},
        ],
    }


def service_inbounds_template(socks_port: int = DEFAULT_SOCKS_PORT,
                              api_port: int = DEFAULT_API_PORT,
                              metrics_port: int = DEFAULT_METRICS_PORT) -> dict:
    return {
        "inbounds": [
            {
                "tag": "socks-in",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth"},
            },
            {
                "listen": "127.0.0.1",
                "port": api_port,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
                "tag": "api",
            },
            {
                "listen": "127.0.0.1",
                "port": metrics_port,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
                "tag": "metrics",
            },
        ],
    }


def base_infra_status() -> list[dict]:
    """Статус каждого служебного файла: есть/нет + размер."""
    out = []
    for name in BASE_INFRA_FILES:
        path = CONFIG_DIR / name
        out.append({
            "name": name,
            "path": str(path),
            "exists": path.exists(),
            "size": path.stat().st_size if path.exists() else 0,
        })
    return out


def collect_user_links(uid: str) -> list[dict]:
    """Для всех инбаундов где есть юзер uid, строит vless-link и QR.
    Если приватный ключ Reality невалидный — пропускает инбаунд."""
    server_ip = get_server_ip()
    items: list[dict] = []
    for ib in collect_vless_inbounds():
        clients = ib.get("settings", {}).get("clients", [])
        client = next((c for c in clients if c.get("id") == uid), None)
        if not client:
            continue

        rs = ib.get("streamSettings", {}).get("realitySettings", {})
        priv = rs.get("privateKey", "")
        if not priv:
            continue
        try:
            pub = derive_public_key(priv)
        except Exception:
            continue

        link = build_vless_link(ib, client, server_ip, pub)
        items.append({
            "tag": ib.get("tag"),
            "port": ib.get("port"),
            "network": ib.get("streamSettings", {}).get("network", "tcp"),
            "sni": (rs.get("serverNames") or [""])[0],
            "link": link,
            "qr_svg": make_qr_svg(link),
        })
    return items


# ============================================================
# Routes
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_input = request.form.get("login", "")
        password = request.form.get("password", "")
        if (login_input == PANEL_CONFIG["admin_login"] and
                check_password_hash(PANEL_CONFIG["admin_password_hash"], password)):
            session["logged_in"] = True
            session["login"] = login_input
            session.permanent = True
            return redirect(request.args.get("next", "/"))
        flash("неверный логин или пароль", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    inbounds = collect_inbounds()
    users = collect_users()
    return render_template("dashboard.html",
                           xray_active=is_xray_active(),
                           inbounds=inbounds,
                           users=users,
                           config_count=len(list_config_files()))


# ===== Inbounds =====

@app.route("/inbounds")
@login_required
def inbounds_list():
    return render_template("inbounds.html", inbounds=collect_inbounds())


@app.route("/inbounds/new", methods=["GET", "POST"])
@login_required
def inbounds_new():
    if request.method == "POST":
        try:
            tag = validate_tag(request.form.get("tag", ""))
            port = validate_port(request.form.get("port", ""))
            transport = request.form.get("transport", "")
            if transport not in TRANSPORT_CHOICES:
                raise ValueError(f"transport должен быть один из: {TRANSPORT_CHOICES}")

            sni = validate_sni(request.form.get("sni", ""))
            dest = resolve_dest(sni, request.form.get("dest", ""))

            xhttp_mode = request.form.get("xhttp_mode", "stream-one")
            if transport == "xhttp" and xhttp_mode not in XHTTP_MODES:
                raise ValueError("неверный xhttp_mode")

            # Проверяем что нет inbound'а с таким tag
            if find_inbound_by_tag(tag):
                raise ValueError(f"inbound с tag «{tag}» уже существует")

            inbound = build_inbound(tag, port, transport, sni, dest, xhttp_mode)

            filename = f"20-vless-{tag}.json"
            file_path = CONFIG_DIR / filename
            write_config_file(file_path, {"inbounds": [inbound]})

            # UFW
            subprocess.run(
                ["sudo", "/usr/sbin/ufw", "allow", f"{port}/tcp",
                 "comment", f"vless-{tag}"],
                check=False, timeout=10,
            )

            ok, msg = systemctl("restart")
            if ok:
                flash(f"inbound «{tag}» создан, xray перезапущен", "success")
            else:
                flash(f"inbound создан, но xray не стартует: {msg}", "error")

            return redirect(url_for("inbounds_list"))

        except Exception as e:
            flash(f"ошибка: {e}", "error")

    return render_template("inbound_form.html",
                           mode="create",
                           inbound=None,
                           sni_options=DEFAULT_SNI_OPTIONS,
                           xhttp_modes=XHTTP_MODES)


@app.route("/inbounds/<tag>/edit", methods=["GET", "POST"])
@login_required
def inbounds_edit(tag: str):
    found = find_inbound_by_tag(tag)
    if not found:
        flash(f"inbound «{tag}» не найден", "error")
        return redirect(url_for("inbounds_list"))

    file_path, file_data, idx = found
    inbound = file_data["inbounds"][idx]

    # service-инбаунды не редактируем через эту форму
    if inbound.get("protocol") != "vless":
        flash("служебные inbound'ы не редактируются через форму", "error")
        return redirect(url_for("inbounds_list"))

    if request.method == "POST":
        try:
            new_port = validate_port(request.form.get("port", ""), exclude_tag=tag)
            transport = request.form.get("transport", "")
            if transport not in TRANSPORT_CHOICES:
                raise ValueError(f"transport должен быть один из: {TRANSPORT_CHOICES}")

            sni = validate_sni(request.form.get("sni", ""))
            dest = resolve_dest(sni, request.form.get("dest", ""))
            xhttp_mode = request.form.get("xhttp_mode", "stream-one")
            if transport == "xhttp" and xhttp_mode not in XHTTP_MODES:
                raise ValueError("неверный xhttp_mode")

            old_port = inbound.get("port")

            # Сохраняем существующих клиентов и Reality keys (не перегенерим без необходимости)
            current_clients = inbound.get("settings", {}).get("clients", [])
            current_rs = inbound.get("streamSettings", {}).get("realitySettings", {})
            current_xhttp = inbound.get("streamSettings", {}).get("xhttpSettings", {})

            new_inbound = build_inbound(
                tag=tag,
                port=new_port,
                transport=transport,
                sni=sni,
                dest=dest,
                xhttp_mode=xhttp_mode,
                private_key=current_rs.get("privateKey"),
                short_ids=current_rs.get("shortIds"),
                xhttp_path=current_xhttp.get("path"),
                clients=current_clients,
            )

            # Если transport был tcp, у клиентов был flow — приведём к новому формату
            if transport == "tcp":
                for c in new_inbound["settings"]["clients"]:
                    c["flow"] = "xtls-rprx-vision"
            else:
                for c in new_inbound["settings"]["clients"]:
                    c.pop("flow", None)

            file_data["inbounds"][idx] = new_inbound
            write_config_file(file_path, file_data)

            # UFW: если порт изменился — закрыть старый, открыть новый
            if new_port != old_port:
                subprocess.run(
                    ["sudo", "/usr/sbin/ufw", "delete", "allow", f"{old_port}/tcp"],
                    check=False, timeout=10,
                )
                subprocess.run(
                    ["sudo", "/usr/sbin/ufw", "allow", f"{new_port}/tcp",
                     "comment", f"vless-{tag}"],
                    check=False, timeout=10,
                )

            ok, msg = systemctl("restart")
            if ok:
                flash(f"inbound «{tag}» обновлён", "success")
            else:
                flash(f"inbound сохранён, но xray не стартует: {msg}", "error")

            return redirect(url_for("inbounds_list"))

        except Exception as e:
            flash(f"ошибка: {e}", "error")

    # Извлекаем текущие значения для пред-заполнения формы
    ss = inbound.get("streamSettings", {})
    rs = ss.get("realitySettings", {})
    xs = ss.get("xhttpSettings", {})
    inbound_view = {
        "tag": inbound.get("tag"),
        "port": inbound.get("port"),
        "transport": ss.get("network", "xhttp"),
        "sni": (rs.get("serverNames") or [""])[0],
        "dest": rs.get("dest", ""),
        "xhttp_mode": xs.get("mode", "stream-one"),
    }

    return render_template("inbound_form.html",
                           mode="edit",
                           inbound=inbound_view,
                           sni_options=DEFAULT_SNI_OPTIONS,
                           xhttp_modes=XHTTP_MODES)


@app.route("/inbounds/<tag>/delete", methods=["POST"])
@login_required
def inbounds_delete(tag: str):
    found = find_inbound_by_tag(tag)
    if not found:
        flash(f"inbound «{tag}» не найден", "error")
        return redirect(url_for("inbounds_list"))

    file_path, file_data, idx = found
    inbound = file_data["inbounds"][idx]

    if inbound.get("protocol") != "vless":
        flash("служебные inbound'ы нельзя удалять через UI", "error")
        return redirect(url_for("inbounds_list"))

    port = inbound.get("port")
    file_data["inbounds"].pop(idx)

    if file_data["inbounds"]:
        write_config_file(file_path, file_data)
    else:
        file_path.unlink()

    if port:
        subprocess.run(
            ["sudo", "/usr/sbin/ufw", "delete", "allow", f"{port}/tcp"],
            check=False, timeout=10,
        )

    systemctl("restart")
    flash(f"inbound «{tag}» удалён", "success")
    return redirect(url_for("inbounds_list"))


# ===== Users =====

@app.route("/users")
@login_required
def users_list():
    users = collect_users()
    stats = get_xray_stats()
    for u in users:
        s = stats.get(u["email"], {})
        u["uplink"] = s.get("uplink", 0)
        u["downlink"] = s.get("downlink", 0)
    return render_template("users.html", users=users)


@app.route("/users/new", methods=["GET", "POST"])
@login_required
def users_new():
    available_inbounds = [ib.get("tag") for ib in collect_vless_inbounds()]

    if request.method == "POST":
        try:
            email = validate_email(request.form.get("email", ""))
            uid = request.form.get("uuid", "").strip()
            uid = validate_uuid(uid) if uid else str(uuid_module.uuid4())

            # выбранные inbound'ы (chip selector)
            selected = request.form.getlist("inbounds")
            if not selected:
                raise ValueError("выбери хотя бы один inbound")

            # проверяем что email ещё не используется
            for u in collect_users():
                if u["email"] == email:
                    raise ValueError(f"юзер с email «{email}» уже существует")

            # добавляем во все выбранные inbound'ы
            for f in list_config_files():
                data = read_config_file(f)
                modified = False
                for ib in data.get("inbounds", []):
                    if ib.get("protocol") != "vless":
                        continue
                    if ib.get("tag") not in selected:
                        continue
                    clients = ib.setdefault("settings", {}).setdefault("clients", [])
                    client = {"id": uid, "email": email, "level": 0}
                    if ib.get("streamSettings", {}).get("network") == "tcp":
                        client["flow"] = "xtls-rprx-vision"
                    clients.append(client)
                    modified = True
                if modified:
                    write_config_file(f, data)

            systemctl("restart")
            flash(f"юзер «{email}» создан", "success")
            return redirect(url_for("users_list"))

        except Exception as e:
            flash(f"ошибка: {e}", "error")

    # для формы создания — все inbound'ы выбраны по умолчанию
    return render_template("user_form.html",
                           mode="create",
                           user=None,
                           available_inbounds=available_inbounds,
                           selected_inbounds=available_inbounds)


@app.route("/users/<uid>/edit", methods=["GET", "POST"])
@login_required
def users_edit(uid: str):
    user = get_user_by_uuid(uid)
    if not user:
        flash("юзер не найден", "error")
        return redirect(url_for("users_list"))

    available_inbounds = [ib.get("tag") for ib in collect_vless_inbounds()]

    if request.method == "POST":
        try:
            new_email = validate_email(request.form.get("email", ""))
            new_uid = request.form.get("uuid", "").strip()
            new_uid = validate_uuid(new_uid)
            selected = request.form.getlist("inbounds")
            if not selected:
                raise ValueError("выбери хотя бы один inbound")

            # проверяем коллизии email с другими юзерами
            for other in collect_users():
                if other["id"] != uid and other["email"] == new_email:
                    raise ValueError(f"юзер с email «{new_email}» уже существует")

            old_email = user["email"]
            old_uid = user["id"]

            # пробегаемся по всем inbound'ам:
            # - если inbound выбран и юзер там был → обновляем поля
            # - если inbound выбран но юзера не было → добавляем
            # - если inbound НЕ выбран и юзер был → удаляем
            for f in list_config_files():
                data = read_config_file(f)
                modified = False
                for ib in data.get("inbounds", []):
                    if ib.get("protocol") != "vless":
                        continue
                    tag = ib.get("tag")
                    clients = ib.setdefault("settings", {}).setdefault("clients", [])

                    existing_idx = next(
                        (i for i, c in enumerate(clients) if c.get("id") == old_uid),
                        None,
                    )

                    if tag in selected:
                        if existing_idx is not None:
                            clients[existing_idx]["id"] = new_uid
                            clients[existing_idx]["email"] = new_email
                        else:
                            new_client = {"id": new_uid, "email": new_email, "level": 0}
                            if ib.get("streamSettings", {}).get("network") == "tcp":
                                new_client["flow"] = "xtls-rprx-vision"
                            clients.append(new_client)
                        modified = True
                    else:
                        if existing_idx is not None:
                            clients.pop(existing_idx)
                            modified = True

                if modified:
                    write_config_file(f, data)

            systemctl("restart")
            flash(f"юзер «{new_email}» обновлён", "success")
            return redirect(url_for("users_list"))

        except Exception as e:
            flash(f"ошибка: {e}", "error")

    return render_template("user_form.html",
                           mode="edit",
                           user=user,
                           available_inbounds=available_inbounds,
                           selected_inbounds=user["inbounds"])


@app.route("/users/<uid>/links")
@login_required
def users_links(uid: str):
    user = get_user_by_uuid(uid)
    if not user:
        flash("юзер не найден", "error")
        return redirect(url_for("users_list"))

    items = collect_user_links(uid)
    return render_template("user_links.html", user=user, items=items,
                           server_ip=get_server_ip())


@app.route("/users/<uid>/delete", methods=["POST"])
@login_required
def users_delete(uid: str):
    user = get_user_by_uuid(uid)
    if not user:
        flash("юзер не найден", "error")
        return redirect(url_for("users_list"))

    removed = 0
    for f in list_config_files():
        data = read_config_file(f)
        modified = False
        for ib in data.get("inbounds", []):
            clients = ib.get("settings", {}).get("clients", [])
            new_clients = [c for c in clients if c.get("id") != uid]
            if len(new_clients) != len(clients):
                ib["settings"]["clients"] = new_clients
                removed += len(clients) - len(new_clients)
                modified = True
        if modified:
            write_config_file(f, data)

    if removed > 0:
        systemctl("restart")
        flash(f"юзер «{user['email']}» удалён из {removed} inbound'ов", "success")
    return redirect(url_for("users_list"))


# ===== AJAX helpers =====

@app.route("/api/generate-uuid")
@login_required
def api_generate_uuid():
    return jsonify({"uuid": str(uuid_module.uuid4())})


@app.route("/api/check-port")
@login_required
def api_check_port():
    port_str = request.args.get("port", "")
    exclude_tag = request.args.get("exclude_tag", "") or None
    try:
        port = validate_port(port_str, exclude_tag=exclude_tag)
        return jsonify({"valid": True, "port": port})
    except ValueError as e:
        return jsonify({"valid": False, "error": str(e)})


# ===== Settings (служебная инфраструктура) =====

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html",
                           files=base_infra_status(),
                           xray_active=is_xray_active(),
                           api_port=DEFAULT_API_PORT,
                           metrics_port=DEFAULT_METRICS_PORT,
                           socks_port=DEFAULT_SOCKS_PORT)


@app.route("/settings/bootstrap", methods=["POST"])
@login_required
def settings_bootstrap():
    overwrite = request.form.get("overwrite") == "1"

    targets = {
        "00-base.json": base_config_template(),
        "01-routing.json": routing_config_template(),
        "02-outbounds.json": outbounds_config_template(),
        "10-service-inbounds.json": service_inbounds_template(),
    }

    written, skipped = [], []
    for name, data in targets.items():
        path = CONFIG_DIR / name
        if path.exists() and not overwrite:
            skipped.append(name)
            continue
        write_config_file(path, data)
        written.append(name)

    if written:
        ok, msg = systemctl("restart")
        if ok:
            flash(f"созданы: {', '.join(written)}; xray перезапущен", "success")
        else:
            flash(f"созданы: {', '.join(written)}, но xray не стартует: {msg}", "error")
    if skipped:
        flash(f"пропущены (уже есть, overwrite не выбран): {', '.join(skipped)}", "info")
    if not written and not skipped:
        flash("ничего не записано", "info")

    return redirect(url_for("settings"))


# ===== System =====

@app.route("/system/restart", methods=["POST"])
@login_required
def system_restart():
    ok, msg = systemctl("restart")
    flash("xray перезапущен" if ok else f"ошибка: {msg}", "success" if ok else "error")
    return redirect(url_for("dashboard"))


@app.route("/system/start", methods=["POST"])
@login_required
def system_start():
    ok, msg = systemctl("start")
    flash("xray запущен" if ok else f"ошибка: {msg}", "success" if ok else "error")
    return redirect(url_for("dashboard"))


@app.route("/system/stop", methods=["POST"])
@login_required
def system_stop():
    ok, msg = systemctl("stop")
    flash("xray остановлен" if ok else f"ошибка: {msg}", "success" if ok else "error")
    return redirect(url_for("dashboard"))


@app.route("/health")
def health():
    return {"status": "ok", "xray": is_xray_active()}


if __name__ == "__main__":
    app.run(host=PANEL_CONFIG.get("host", "0.0.0.0"),
            port=PANEL_CONFIG.get("port", 8088),
            debug=False)

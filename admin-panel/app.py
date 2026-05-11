"""
xray-admin-panel — админ-панель для xray-сервера.
Версия 3: дизайн полностью переработан, добавлены экраны Connections / Logs /
Alerts / Outbounds / Routing и расширенные настройки.
"""
from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import secrets
import socket
import subprocess
import tarfile
import time
import uuid as uuid_module
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import quote

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore

try:
    import requests  # type: ignore
except ImportError:
    requests = None  # type: ignore

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, send_file, session, url_for)
from qrcode.image.svg import SvgPathImage
from werkzeug.security import check_password_hash, generate_password_hash

# ==== Конфиг ====
CONFIG_DIR = Path("/usr/local/etc/xray/conf.d")
CONFIG_FILE = Path("/etc/xray-admin/config.json")
# /etc/xray-admin is root:xray-admin 750 — read-only for the panel user;
# panel-writable state lives in /var/lib/xray-admin/ (xray-admin:xray-admin 750).
STATE_DIR = Path("/var/lib/xray-admin")
ALERTS_FILE = STATE_DIR / "alerts.json"
ACTIVITY_FILE = STATE_DIR / "activity.json"
BACKUPS_DIR = STATE_DIR / "backups"
GEOIP_FILE = Path("/usr/local/share/xray/geoip.dat")
GEOSITE_FILE = Path("/usr/local/share/xray/geosite.dat")
XRAY_LOG_DIR = Path("/var/log/xray")
ACCESS_LOG = XRAY_LOG_DIR / "access.log"
ERROR_LOG = XRAY_LOG_DIR / "error.log"

DEFAULT_SNI_OPTIONS = [
    "yahoo.com",
    "www.lovelive-anime.jp",
    "gateway.icloud.com",
    "www.amazon.com",
    "aws.amazon.com",
    "www.cloudflare.com",
    "www.microsoft.com",
    "www.spotify.com",
]

TRANSPORT_CHOICES = ["xhttp", "tcp"]
XHTTP_MODES = ["stream-one", "packet-up", "auto"]
FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android", "random"]

BASE_INFRA_FILES = [
    "00-base.json",
    "01-routing.json",
    "02-outbounds.json",
    "10-service-inbounds.json",
]
DEFAULT_API_PORT = 10085
DEFAULT_METRICS_PORT = 10086
DEFAULT_SOCKS_PORT = 10808

OUTBOUND_PROTOCOLS = [
    ("freedom", "freedom — прямой выход"),
    ("blackhole", "blackhole — заблокировать"),
    ("socks", "socks — SOCKS5-прокси"),
    ("http", "http — HTTP-прокси"),
    ("vless", "vless — proxy-chain"),
    ("vmess", "vmess"),
    ("trojan", "trojan"),
    ("wireguard", "wireguard"),
]

DEFAULT_THRESHOLDS = {
    "cpu":         {"warn": 60,   "crit": 85,   "unit": "%",  "label": "CPU"},
    "memory":      {"warn": 70,   "crit": 90,   "unit": "%",  "label": "Memory"},
    "disk":        {"warn": 70,   "crit": 90,   "unit": "%",  "label": "Disk"},
    "fd":          {"warn": 3000, "crit": 5000, "unit": "",   "label": "FD count"},
    "steal":       {"warn": 15,   "crit": 30,   "unit": "%",  "label": "Steal time"},
    "connections": {"warn": 2000, "crit": 5000, "unit": "",   "label": "Connections"},
}

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
            if request.path.startswith("/api/"):
                return jsonify({"error": "auth required"}), 401
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


def systemctl_show(service: str, field: str) -> str:
    """Получить одно поле через systemctl show. systemctl show не требует root."""
    try:
        result = subprocess.run(
            ["/bin/systemctl", "show", service, f"--property={field}", "--value"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def ufw_allow(port: int, comment: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["sudo", "/usr/sbin/ufw", "allow", f"{port}/tcp", "comment", comment],
        capture_output=True, text=True, timeout=10,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def ufw_delete(port: int) -> tuple[bool, str]:
    result = subprocess.run(
        ["sudo", "/usr/sbin/ufw", "delete", "allow", f"{port}/tcp"],
        capture_output=True, text=True, timeout=10,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


_XRAY_ACTIVE_CACHE: dict = {"value": False, "ts": 0.0}
_XRAY_ACTIVE_TTL = 5.0


def is_xray_active(force: bool = False) -> bool:
    """Кэшируем 5с — за один HTTP-запрос проверяется минимум 3-4 раза."""
    now = time.time()
    if not force and (now - _XRAY_ACTIVE_CACHE["ts"]) < _XRAY_ACTIVE_TTL:
        return _XRAY_ACTIVE_CACHE["value"]
    ok, _ = systemctl("is-active", "xray")
    _XRAY_ACTIVE_CACHE["value"] = ok
    _XRAY_ACTIVE_CACHE["ts"] = now
    return ok


def xray_version() -> str:
    """xray -version → первая строка, всё после слова Xray."""
    try:
        out = subprocess.run(
            ["/usr/local/bin/xray", "-version"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout:
            first = out.stdout.splitlines()[0]
            m = re.search(r"Xray\s+(\S+)", first)
            if m:
                return f"v{m.group(1)}"
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return "—"


def xray_uptime() -> str:
    """Возвращает 'XдYч' или '—'."""
    raw = systemctl_show("xray", "ActiveEnterTimestamp")
    if not raw:
        return "—"
    # формат: 'Sat 2026-05-10 10:30:00 UTC' или с TZ-сдвигом
    parts = raw.split()
    if len(parts) < 3:
        return "—"
    try:
        dt = datetime.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
        delta = datetime.now() - dt
        days = delta.days
        hours = delta.seconds // 3600
        if days > 0:
            return f"{days}д {hours}ч"
        mins = (delta.seconds % 3600) // 60
        return f"{hours}ч {mins}м"
    except ValueError:
        return "—"


def xray_pid() -> str:
    raw = systemctl_show("xray", "MainPID")
    return raw if raw and raw != "0" else "—"


# ==== File helpers ====
def list_config_files() -> list[Path]:
    if not CONFIG_DIR.exists():
        return []
    return sorted(CONFIG_DIR.glob("*.json"))


def read_config_file(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def write_config_file(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp.replace(path)
    os.chmod(path, 0o660)


def find_inbound_by_tag(tag: str) -> tuple[Path, dict, int] | None:
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
    return [ib for ib in collect_inbounds() if ib.get("protocol") == "vless"]


def collect_users() -> list[dict]:
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


# ==== xray stats ====
# Кэшируем счётчики xray — они и так монотонные (растут только), быстрая
# свежесть нам не нужна. -reset обходит кэш через force=True.
_USER_STATS_CACHE: dict = {"data": None, "ts": 0.0}
_INBOUND_STATS_CACHE: dict = {"data": None, "ts": 0.0}
_XRAY_STATS_TTL = 8.0


def get_xray_stats(reset: bool = False) -> dict[str, dict]:
    """{email: {uplink, downlink}} или {} если xray не работает."""
    now = time.time()
    if not reset and _USER_STATS_CACHE["data"] is not None \
            and (now - _USER_STATS_CACHE["ts"]) < _XRAY_STATS_TTL:
        return _USER_STATS_CACHE["data"]
    if not is_xray_active():
        return {}
    try:
        args = ["api", "statsquery",
                "--server=127.0.0.1:10085",
                "-pattern", "user>>>"]
        if reset:
            args.append("-reset")
        out = run_xray(*args)
        data = json.loads(out)
        result: dict[str, dict] = {}
        for s in data.get("stat", []):
            parts = s["name"].split(">>>")
            if len(parts) >= 4:
                email = parts[1]
                direction = parts[3]
                try:
                    val = int(s.get("value", 0) or 0)
                except (TypeError, ValueError):
                    val = 0
                result.setdefault(email, {})[direction] = val
        _USER_STATS_CACHE["data"] = result
        _USER_STATS_CACHE["ts"] = now
        return result
    except (RuntimeError, json.JSONDecodeError):
        return _USER_STATS_CACHE["data"] or {}


def get_inbound_stats() -> dict[str, dict]:
    now = time.time()
    if _INBOUND_STATS_CACHE["data"] is not None \
            and (now - _INBOUND_STATS_CACHE["ts"]) < _XRAY_STATS_TTL:
        return _INBOUND_STATS_CACHE["data"]
    if not is_xray_active():
        return {}
    try:
        out = run_xray("api", "statsquery",
                       "--server=127.0.0.1:10085",
                       "-pattern", "inbound>>>")
        data = json.loads(out)
        result: dict[str, dict] = {}
        for s in data.get("stat", []):
            parts = s["name"].split(">>>")
            if len(parts) >= 4:
                tag = parts[1]
                direction = parts[3]
                try:
                    val = int(s.get("value", 0) or 0)
                except (TypeError, ValueError):
                    val = 0
                result.setdefault(tag, {})[direction] = val
        _INBOUND_STATS_CACHE["data"] = result
        _INBOUND_STATS_CACHE["ts"] = now
        return result
    except (RuntimeError, json.JSONDecodeError):
        return _INBOUND_STATS_CACHE["data"] or {}


# ==== System stats (psutil) ====
# In-process cache. Per-worker — у gunicorn 2 worker-а каждый держит свой кэш,
# значения слегка разъезжаются, но это для админ-панели приемлемо.
_SYS_CACHE: dict = {"data": None, "ts": 0.0}
_SYS_TTL = 10.0   # секунды
_FD_CACHE: dict = {"value": 0, "ts": 0.0}
_FD_TTL = 30.0    # FD count считается итерацией всех процессов — кэшируем дольше


def _count_fds_cached() -> int:
    now = time.time()
    if now - _FD_CACHE["ts"] < _FD_TTL:
        return _FD_CACHE["value"]
    try:
        total = 0
        for p in psutil.process_iter():
            try:
                total += p.num_fds()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        _FD_CACHE["value"] = total
        _FD_CACHE["ts"] = now
        return total
    except Exception:
        return _FD_CACHE["value"]  # старое значение лучше нуля


def get_system_stats(force: bool = False) -> dict:
    """CPU/RAM/disk/network/uptime. Кэшируется на _SYS_TTL секунд."""
    now = time.time()
    if not force and _SYS_CACHE["data"] is not None and (now - _SYS_CACHE["ts"]) < _SYS_TTL:
        return _SYS_CACHE["data"]

    out = {
        "cpu": 0.0,
        "memory": {"used": 0, "total": 0, "percent": 0.0},
        "disk": {"used": 0, "total": 0, "percent": 0.0},
        "net": {"in": 0, "out": 0},
        "fd": 0,
        "steal": 0.0,
        "connections": 0,
        "uptime_sec": 0,
        "load_avg": (0.0, 0.0, 0.0),
        "available": False,
    }
    if psutil is None:
        _SYS_CACHE["data"] = out
        _SYS_CACHE["ts"] = now
        return out
    try:
        # interval=None — мгновенный снимок относительно предыдущего вызова.
        # На первом вызове даст 0.0, но в долгоживущем worker это случается один раз.
        out["cpu"] = psutil.cpu_percent(interval=None)
        vm = psutil.virtual_memory()
        out["memory"] = {"used": vm.used, "total": vm.total, "percent": vm.percent}
        du = psutil.disk_usage("/")
        out["disk"] = {"used": du.used, "total": du.total, "percent": du.percent}
        try:
            cpu_times = psutil.cpu_times_percent(interval=None)
            out["steal"] = float(getattr(cpu_times, "steal", 0.0))
        except Exception:
            pass
        try:
            out["connections"] = len(psutil.net_connections(kind="inet"))
        except Exception:
            out["connections"] = 0
        out["fd"] = _count_fds_cached()
        out["uptime_sec"] = int(time.time() - psutil.boot_time())
        if hasattr(os, "getloadavg"):
            out["load_avg"] = os.getloadavg()
        nio = psutil.net_io_counters()
        out["net"] = {"in": nio.bytes_recv, "out": nio.bytes_sent}
        out["available"] = True
    except Exception:
        pass

    _SYS_CACHE["data"] = out
    _SYS_CACHE["ts"] = now
    return out


# ==== Валидаторы ====
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,30}$")
EMAIL_LOCAL_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


def validate_port(port_str: str, exclude_tag: str | None = None) -> int:
    try:
        port = int(port_str)
    except (TypeError, ValueError):
        raise ValueError("порт должен быть числом")
    if port < 1 or port > 65535:
        raise ValueError("порт должен быть в диапазоне 1-65535")
    for ib in collect_inbounds():
        if ib.get("port") == port and ib.get("tag") != exclude_tag:
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
    custom_dest = custom_dest.strip()
    if custom_dest:
        if ":" not in custom_dest:
            raise ValueError("dest должен быть в формате host:port")
        return custom_dest
    try:
        ip = socket.gethostbyname(sni)
        return f"{ip}:443"
    except socket.gaierror:
        raise ValueError(f"не удалось разрешить {sni} в IP-адрес")


# ==== Builders ====
def build_inbound(tag: str, port: int, transport: str, sni: str, dest: str,
                  xhttp_mode: str = "stream-one",
                  fingerprint: str = "chrome",
                  private_key: str | None = None,
                  short_ids: list[str] | None = None,
                  xhttp_path: str | None = None,
                  clients: list[dict] | None = None) -> dict:
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
                "fingerprint": fingerprint,
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
    pad = "=" * (-len(private_b64) % 4)
    raw = base64.urlsafe_b64decode(private_b64 + pad)
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode()


def get_server_ip() -> str:
    sip = PANEL_CONFIG.get("server_ip")
    if sip:
        return str(sip)
    return "<server_ip-не-задан-в-config.json>"


def build_vless_link(inbound: dict, client: dict, server_ip: str,
                     public_key: str) -> str:
    ss = inbound.get("streamSettings", {})
    rs = ss.get("realitySettings", {})
    network = ss.get("network", "tcp")
    port = inbound.get("port")
    sni = (rs.get("serverNames") or [""])[0]
    fp = rs.get("fingerprint", "chrome")
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


def collect_user_links(uid: str) -> list[dict]:
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


# ==== Base infrastructure templates ====
def base_config_template() -> dict:
    return {
        "log": {
            "loglevel": "info",
            "access": str(ACCESS_LOG),
            "error": str(ERROR_LOG),
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
    out = []
    for name in BASE_INFRA_FILES:
        path = CONFIG_DIR / name
        stat = {
            "name": name,
            "path": str(path),
            "exists": path.exists(),
            "size": path.stat().st_size if path.exists() else 0,
            "mtime": None,
        }
        if path.exists():
            try:
                stat["mtime"] = datetime.fromtimestamp(path.stat().st_mtime)
            except OSError:
                pass
        out.append(stat)
    return out


# ==== Routing / Outbounds CRUD ====
def routing_file_path() -> Path:
    return CONFIG_DIR / "01-routing.json"


def outbounds_file_path() -> Path:
    return CONFIG_DIR / "02-outbounds.json"


def read_routing_rules() -> list[dict]:
    path = routing_file_path()
    if not path.exists():
        return []
    data = read_config_file(path)
    return data.get("routing", {}).get("rules", [])


def write_routing_rules(rules: list[dict],
                        domain_strategy: str = "IPIfNonMatch") -> None:
    path = routing_file_path()
    data = read_config_file(path) if path.exists() else {"routing": {}}
    data.setdefault("routing", {})["domainStrategy"] = domain_strategy
    data["routing"]["rules"] = rules
    write_config_file(path, data)


def rule_summary(rule: dict) -> dict:
    """Подготовка summary для отображения правила в таблице."""
    match_keys = ["inboundTag", "outboundTag", "domain", "ip",
                  "port", "network", "protocol", "user", "source"]
    matches = []
    for k in match_keys:
        v = rule.get(k)
        if v is None:
            continue
        # outboundTag в правиле — это action, не match
        if k == "outboundTag":
            continue
        if isinstance(v, list):
            matches.append({"k": k, "v": [str(x) for x in v]})
        else:
            matches.append({"k": k, "v": [str(v)]})
    action = rule.get("outboundTag", rule.get("balancerTag", "—"))
    return {
        "type": rule.get("type", "field"),
        "matches": matches,
        "action": action,
        "enabled": rule.get("_enabled", True),
    }


def read_outbounds() -> list[dict]:
    path = outbounds_file_path()
    if not path.exists():
        return []
    data = read_config_file(path)
    return data.get("outbounds", [])


def write_outbounds(outbounds: list[dict]) -> None:
    path = outbounds_file_path()
    data = read_config_file(path) if path.exists() else {"outbounds": []}
    data["outbounds"] = outbounds
    write_config_file(path, data)


def outbound_summary(ob: dict) -> dict:
    """Текстовая сводка для отображения."""
    proto = ob.get("protocol", "—")
    s = ob.get("settings", {}) or {}
    dest = "—"
    summary = "—"
    if proto in ("socks", "http"):
        servers = s.get("servers", [])
        if servers:
            srv = servers[0]
            dest = f"{srv.get('address','—')}:{srv.get('port','')}"
            users = srv.get("users", [])
            if users:
                summary = f"user: {users[0].get('user','')}"
    elif proto in ("vless", "vmess", "trojan"):
        servers = s.get("vnext", []) or s.get("servers", [])
        if servers:
            srv = servers[0]
            dest = f"{srv.get('address','—')}:{srv.get('port','')}"
            users = srv.get("users", [])
            if users:
                u = users[0]
                uid = u.get("id") or u.get("password") or u.get("user", "")
                summary = f"id: {uid[:8]}…" if uid else "—"
    elif proto == "freedom":
        ds = s.get("domainStrategy")
        if ds:
            summary = f"domainStrategy: {ds}"
    elif proto == "blackhole":
        summary = "—"
    elif proto == "wireguard":
        peers = s.get("peers", [])
        if peers:
            dest = peers[0].get("endpoint", "—")
    return {
        "tag": ob.get("tag", "—"),
        "proto": proto,
        "dest": dest,
        "summary": summary,
        "enabled": ob.get("_enabled", True),
    }


# ==== Alerts ====
def load_alerts_state() -> dict:
    if not ALERTS_FILE.exists():
        return {
            "thresholds": DEFAULT_THRESHOLDS,
            "active": [],
            "history": [],
            "snoozed": {},
        }
    try:
        with ALERTS_FILE.open() as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        state = {}
    # merge defaults
    state.setdefault("thresholds", {})
    for k, v in DEFAULT_THRESHOLDS.items():
        state["thresholds"].setdefault(k, v)
    state.setdefault("active", [])
    state.setdefault("history", [])
    state.setdefault("snoozed", {})
    return state


def save_alerts_state(state: dict) -> None:
    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = ALERTS_FILE.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(state, f, indent=2, default=str)
    tmp.replace(ALERTS_FILE)


def evaluate_alerts() -> dict:
    """Прогоняет правила, обновляет active/history. Не блокирует надолго."""
    state = load_alerts_state()
    now = datetime.now().isoformat(timespec="seconds")
    sys = get_system_stats()

    checks = [
        ("cpu", sys.get("cpu", 0.0), "CPU > {v}%", "CPU usage"),
        ("memory", sys.get("memory", {}).get("percent", 0.0), "Memory > {v}%", "Memory usage"),
        ("disk", sys.get("disk", {}).get("percent", 0.0), "Disk > {v}%", "Disk usage"),
        ("steal", sys.get("steal", 0.0), "Steal time > {v}%", "Hypervisor steal time"),
        ("fd", sys.get("fd", 0), "FD count > {v}", "Open file descriptors"),
        ("connections", sys.get("connections", 0), "Connections > {v}", "Established connections"),
    ]
    xray_running = is_xray_active()

    new_actives = []
    if not xray_running:
        new_actives.append({
            "id": "xray-down",
            "severity": "critical",
            "title": "xray service is not running",
            "sub": "systemctl is-active xray вернул не active",
            "metric": "xray",
            "value": "stopped",
            "first_seen": now,
            "last_seen": now,
        })

    for key, value, fmt, label in checks:
        thr = state["thresholds"].get(key, DEFAULT_THRESHOLDS.get(key))
        if not thr:
            continue
        try:
            v = float(value)
        except (TypeError, ValueError):
            continue
        severity = None
        if thr.get("crit") and v >= float(thr["crit"]):
            severity = "critical"
            threshold_val = thr["crit"]
        elif thr.get("warn") and v >= float(thr["warn"]):
            severity = "warning"
            threshold_val = thr["warn"]
        if severity:
            new_actives.append({
                "id": f"{key}-{severity}",
                "severity": severity,
                "title": fmt.format(v=threshold_val) + f"{thr.get('unit','')}",
                "sub": f"Текущее значение: {v:.1f}{thr.get('unit','')} · threshold: "
                       f"{threshold_val}{thr.get('unit','')}",
                "metric": key,
                "value": v,
                "first_seen": now,
                "last_seen": now,
                "label": label,
            })

    # Apply snooze: filter out alerts that are snoozed
    snoozed = state.get("snoozed", {})
    filtered = []
    for a in new_actives:
        until = snoozed.get(a["id"])
        if until:
            try:
                if datetime.fromisoformat(until) > datetime.now():
                    continue  # ещё в snooze
            except ValueError:
                pass
        filtered.append(a)

    # Preserve first_seen from previous active (skip corrupt entries)
    prev_by_id = {
        a["id"]: a
        for a in state.get("active", [])
        if isinstance(a, dict) and a.get("id")
    }
    for a in filtered:
        prev = prev_by_id.get(a["id"])
        if prev:
            a["first_seen"] = prev.get("first_seen", a["first_seen"])

    # Anything that disappeared from active → push to history as resolved
    history = state.get("history", [])
    for prev_id, prev in prev_by_id.items():
        if not any(a["id"] == prev_id for a in filtered):
            history.append({
                "t": now,
                "sev": prev.get("severity", "warning"),
                "title": prev.get("title", prev_id),
                "status": "Resolved",
                "by": "Auto",
            })

    history = history[-200:]  # cap
    state["active"] = filtered
    state["history"] = history
    save_alerts_state(state)
    return state


def push_activity(kind: str, title: str, sub: str = "") -> None:
    """Журнал последних действий администратора."""
    items = []
    if ACTIVITY_FILE.exists():
        try:
            with ACTIVITY_FILE.open() as f:
                items = json.load(f)
        except (OSError, json.JSONDecodeError):
            items = []
    items.append({
        "t": datetime.now().isoformat(timespec="seconds"),
        "kind": kind,
        "title": title,
        "sub": sub,
    })
    items = items[-60:]
    ACTIVITY_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with ACTIVITY_FILE.open("w") as f:
            json.dump(items, f, indent=2, ensure_ascii=False)
    except OSError:
        pass


def read_activity(limit: int = 12) -> list[dict]:
    if not ACTIVITY_FILE.exists():
        return []
    try:
        with ACTIVITY_FILE.open() as f:
            items = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    return list(reversed(items[-limit:]))


# ==== Log parsing ====
LOG_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
    r"(?:\[(?P<level>[^\]]+)\]\s+)?"
    r"(?:(?P<src>[\d\.:a-fA-F]+)\s+"
    r"(?P<kind>accepted|rejected|blocked|failed|closed)\s+"
    r"(?P<rest>.*))?",
    re.IGNORECASE,
)


def tail_file(path: Path, n: int = 200) -> list[str]:
    """Эффективное чтение последних n строк."""
    if not path.exists():
        return []
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 4096
            data = b""
            while size > 0 and data.count(b"\n") <= n:
                step = min(block, size)
                size -= step
                f.seek(size)
                data = f.read(step) + data
            lines = data.decode("utf-8", errors="replace").splitlines()
            return lines[-n:]
    except OSError:
        return []


def parse_access_line(line: str) -> dict | None:
    """Парсинг строки access.log xray. Поддерживаем два формата:
      a) 2026/05/10 12:34:56.521777 1.2.3.4:443 accepted tcp:host:443 ...
      b) 2026/05/10 12:34:56.521777 from 1.2.3.4:443 accepted tcp:host:443 ...
    """
    if not line.strip():
        return None
    head = line.split(maxsplit=2)
    if len(head) < 3:
        return {"raw": line}
    ts = f"{head[0]} {head[1]}"
    tail = head[2]
    # Optional `from ` prefix перед IP.
    if tail.startswith("from "):
        tail = tail[5:]
    sub = tail.split(maxsplit=2)
    if len(sub) < 2:
        return {"ts": ts, "raw": line}
    src = sub[0]
    action = sub[1].lower()
    rest = sub[2] if len(sub) > 2 else ""
    # Найти inbound/outbound в [tag -> tag]
    inbound = None
    outbound = None
    m = re.search(r"\[([^\]]+)\s*->\s*([^\]]+)\]", rest)
    if m:
        inbound = m.group(1).strip()
        outbound = m.group(2).strip()
    email = None
    me = re.search(r"email:\s*(\S+)", rest)
    if me:
        email = me.group(1).strip()
    # Найти dst
    dst = None
    md = re.search(r"(tcp|udp):([^\s\[]+)", rest)
    if md:
        dst = md.group(2).strip()
    kind = "ACCEPT"
    if "blocked" in action or "reject" in action or outbound == "block":
        kind = "BLOCK"
    elif "fail" in action:
        kind = "ERROR"
    elif "close" in action:
        kind = "CLOSE"
    return {
        "ts": ts,
        "src": src,
        "dst": dst,
        "kind": kind,
        "inbound": inbound,
        "outbound": outbound,
        "user": email,
        "raw": line,
    }


def parse_error_line(line: str) -> dict:
    """Минимальный парсер error.log — выделяет level и тело без timestamp."""
    if not line.strip():
        return {"raw": line}
    parts = line.split(maxsplit=2)
    if len(parts) < 2:
        return {"ts": "", "level": "INFO", "body": line, "raw": line}
    ts = f"{parts[0]} {parts[1]}"
    rest = parts[2] if len(parts) > 2 else ""
    level = "INFO"
    m = re.match(r"^\[(Info|Warning|Error|Debug)\]\s*", rest, re.IGNORECASE)
    if m:
        level = m.group(1).upper()
        if level == "WARNING":
            level = "WARN"
        rest = rest[m.end():]
    return {
        "ts": ts,
        "level": level,
        "body": rest,
        "raw": line,
    }


def collect_recent_connections(limit: int = 200) -> list[dict]:
    """Парсит последние N accepted-строк в access.log → список dict."""
    lines = tail_file(ACCESS_LOG, n=limit * 4)
    out = []
    for line in lines:
        parsed = parse_access_line(line)
        if not parsed or parsed.get("kind") != "ACCEPT":
            continue
        out.append(parsed)
    return list(reversed(out))[:limit]


# ==== Helpers for templates ====
@app.context_processor
def inject_globals():
    try:
        if session.get("logged_in"):
            active = [a for a in load_alerts_state().get("active", []) if isinstance(a, dict)]
        else:
            active = []
    except Exception:
        active = []
    try:
        users_count = len(collect_users()) if session.get("logged_in") else 0
    except Exception:
        users_count = 0
    hostname = PANEL_CONFIG.get("hostname") or socket.gethostname() or "xray"
    return {
        "nav_active_alerts": len(active),
        "nav_users_count": users_count,
        "server_ip": get_server_ip(),
        "server_hostname": hostname,
        "asset_version": _asset_version(),
        "fmt_bytes": fmt_bytes,
        "fmt_short_uuid": fmt_short_uuid,
        "fmt_humans_ago": fmt_humans_ago,
    }


_ASSET_DIR = Path(__file__).parent / "static"

def _asset_version() -> str:
    """Использует mtime style.css как cache-buster — меняется только при деплое."""
    try:
        return str(int((_ASSET_DIR / "style.css").stat().st_mtime))
    except OSError:
        return "0"


def fmt_bytes(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "—"
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n/1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n/1024**2:.1f} MB"
    if n < 1024 ** 4:
        return f"{n/1024**3:.2f} GB"
    return f"{n/1024**4:.2f} TB"


def fmt_short_uuid(uid: str) -> str:
    if not uid or len(uid) < 12:
        return uid or "—"
    return f"{uid[:8]}…{uid[-4:]}"


def fmt_humans_ago(ts) -> str:
    if ts is None:
        return "—"
    if isinstance(ts, str):
        # Try ISO first, then xray access.log timestamp, with optional ms tail.
        parsed = None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(ts[: len(fmt) + 4].split(".")[0], fmt)
                break
            except (ValueError, IndexError):
                continue
        if parsed is None:
            try:
                parsed = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                return ts
        ts = parsed
    if not isinstance(ts, datetime):
        return "—"
    delta = datetime.now() - ts
    sec = int(delta.total_seconds())
    if sec < 60:
        return f"{sec}с"
    if sec < 3600:
        return f"{sec//60}м"
    if sec < 86400:
        return f"{sec//3600}ч"
    return f"{sec//86400}д"


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
    stats = get_xray_stats()
    # обогащаем users трафиком
    total_up = 0
    total_down = 0
    for u in users:
        s = stats.get(u["email"], {})
        u["uplink"] = s.get("uplink", 0)
        u["downlink"] = s.get("downlink", 0)
        total_up += u["uplink"]
        total_down += u["downlink"]
    top_users = sorted(users, key=lambda u: u["uplink"] + u["downlink"], reverse=True)[:5]
    sys_stats = get_system_stats()
    alerts = evaluate_alerts().get("active", [])
    activity = read_activity()
    vless_inbounds = [ib for ib in inbounds if ib.get("protocol") == "vless"]
    inbound_stats = get_inbound_stats()
    inbound_rows = []
    for ib in inbounds:
        ss = ib.get("streamSettings", {}) or {}
        rs = ss.get("realitySettings", {}) or {}
        xs = ss.get("xhttpSettings", {}) or {}
        sns = rs.get("serverNames") or []
        is_service = ib.get("listen") == "127.0.0.1" or ib.get("protocol") != "vless"
        inbound_rows.append({
            "tag": ib.get("tag", "—"),
            "port": ib.get("port"),
            "proto": ib.get("protocol", "—"),
            "transport": ss.get("network", "—"),
            "mode": xs.get("mode"),
            "sni": sns[0] if sns else None,
            "clients": len((ib.get("settings") or {}).get("clients", [])),
            "service": is_service,
            "file": ib.get("_file", "—"),
        })
    return render_template("dashboard.html",
                           xray_active=is_xray_active(),
                           xray_version=xray_version(),
                           xray_uptime=xray_uptime(),
                           xray_pid=xray_pid(),
                           inbounds=inbound_rows,
                           vless_count=len(vless_inbounds),
                           service_count=len(inbounds) - len(vless_inbounds),
                           users=users,
                           users_count=len(users),
                           top_users=top_users,
                           total_up=total_up,
                           total_down=total_down,
                           config_count=len(list_config_files()),
                           sys_stats=sys_stats,
                           alerts=alerts,
                           activity=activity)


# ===== Inbounds =====

@app.route("/inbounds")
@login_required
def inbounds_list():
    all_inbounds = collect_inbounds()
    filter_kind = request.args.get("filter", "all")
    rows = []
    for ib in all_inbounds:
        ss = ib.get("streamSettings", {}) or {}
        rs = ss.get("realitySettings", {}) or {}
        xs = ss.get("xhttpSettings", {}) or {}
        sns = rs.get("serverNames") or []
        is_service = ib.get("listen") == "127.0.0.1" or ib.get("protocol") != "vless"
        rows.append({
            "tag": ib.get("tag", "—"),
            "port": ib.get("port"),
            "proto": ib.get("protocol", "—"),
            "transport": ss.get("network", "—"),
            "mode": xs.get("mode"),
            "sni": sns[0] if sns else None,
            "clients": len((ib.get("settings") or {}).get("clients", [])),
            "service": is_service,
            "file": ib.get("_file", "—"),
        })
    user_rows = [r for r in rows if not r["service"]]
    service_rows = [r for r in rows if r["service"]]
    if filter_kind == "user":
        visible = user_rows
    elif filter_kind == "service":
        visible = service_rows
    else:
        visible = rows
    return render_template("inbounds.html",
                           rows=visible,
                           total=len(rows),
                           user_count=len(user_rows),
                           service_count=len(service_rows),
                           filter=filter_kind)


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
            fingerprint = request.form.get("fingerprint", "chrome")
            if fingerprint not in FINGERPRINTS:
                fingerprint = "chrome"
            if find_inbound_by_tag(tag):
                raise ValueError(f"inbound с tag «{tag}» уже существует")
            inbound = build_inbound(tag, port, transport, sni, dest,
                                    xhttp_mode=xhttp_mode, fingerprint=fingerprint)
            filename = f"20-vless-{tag}.json"
            file_path = CONFIG_DIR / filename
            write_config_file(file_path, {"inbounds": [inbound]})
            ufw_ok, ufw_msg = ufw_allow(port, f"vless-{tag}")
            if not ufw_ok:
                flash(f"⚠ ufw allow {port}/tcp не сработал — клиенты не подключатся "
                      f"пока порт закрыт: {ufw_msg}", "error")
            ok, msg = systemctl("restart")
            if ok:
                flash(f"inbound «{tag}» создан, xray перезапущен", "success")
                push_activity("inbound", f"Создан inbound", tag)
            else:
                flash(f"inbound создан, но xray не стартует: {msg}", "error")
            return redirect(url_for("inbounds_list"))
        except Exception as e:
            flash(f"ошибка: {e}", "error")
    return render_template("inbound_form.html",
                           mode="create",
                           inbound=None,
                           sni_options=DEFAULT_SNI_OPTIONS,
                           xhttp_modes=XHTTP_MODES,
                           fingerprints=FINGERPRINTS)


@app.route("/inbounds/<tag>/edit", methods=["GET", "POST"])
@login_required
def inbounds_edit(tag: str):
    found = find_inbound_by_tag(tag)
    if not found:
        flash(f"inbound «{tag}» не найден", "error")
        return redirect(url_for("inbounds_list"))
    file_path, file_data, idx = found
    inbound = file_data["inbounds"][idx]
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
            fingerprint = request.form.get("fingerprint", "chrome")
            if fingerprint not in FINGERPRINTS:
                fingerprint = "chrome"

            old_port = inbound.get("port")
            current_clients = inbound.get("settings", {}).get("clients", [])
            current_rs = inbound.get("streamSettings", {}).get("realitySettings", {})
            current_xhttp = inbound.get("streamSettings", {}).get("xhttpSettings", {})
            regen_keys = request.form.get("regen_keys") == "1"

            new_inbound = build_inbound(
                tag=tag,
                port=new_port,
                transport=transport,
                sni=sni,
                dest=dest,
                xhttp_mode=xhttp_mode,
                fingerprint=fingerprint,
                private_key=None if regen_keys else current_rs.get("privateKey"),
                short_ids=None if regen_keys else current_rs.get("shortIds"),
                xhttp_path=current_xhttp.get("path"),
                clients=current_clients,
            )
            if transport == "tcp":
                for c in new_inbound["settings"]["clients"]:
                    c["flow"] = "xtls-rprx-vision"
            else:
                for c in new_inbound["settings"]["clients"]:
                    c.pop("flow", None)

            file_data["inbounds"][idx] = new_inbound
            write_config_file(file_path, file_data)
            if new_port != old_port:
                ufw_delete(old_port)
                ufw_ok, ufw_msg = ufw_allow(new_port, f"vless-{tag}")
                if not ufw_ok:
                    flash(f"⚠ ufw allow {new_port}/tcp не сработал: {ufw_msg}", "error")
            ok, msg = systemctl("restart")
            if ok:
                flash(f"inbound «{tag}» обновлён", "success")
                push_activity("inbound", "Изменён inbound", tag)
            else:
                flash(f"inbound сохранён, но xray не стартует: {msg}", "error")
            return redirect(url_for("inbounds_list"))
        except Exception as e:
            flash(f"ошибка: {e}", "error")

    ss = inbound.get("streamSettings", {})
    rs = ss.get("realitySettings", {})
    xs = ss.get("xhttpSettings", {})
    priv = rs.get("privateKey", "")
    public_key = ""
    try:
        if priv:
            public_key = derive_public_key(priv)
    except Exception:
        pass
    inbound_view = {
        "tag": inbound.get("tag"),
        "port": inbound.get("port"),
        "transport": ss.get("network", "xhttp"),
        "sni": (rs.get("serverNames") or [""])[0],
        "dest": rs.get("dest", ""),
        "xhttp_mode": xs.get("mode", "stream-one"),
        "xhttp_path": xs.get("path", ""),
        "fingerprint": rs.get("fingerprint", "chrome"),
        "private_key": priv,
        "public_key": public_key,
        "short_ids": rs.get("shortIds", []),
        "file": file_path.name,
        "clients": len(inbound.get("settings", {}).get("clients", [])),
    }
    return render_template("inbound_form.html",
                           mode="edit",
                           inbound=inbound_view,
                           sni_options=DEFAULT_SNI_OPTIONS,
                           xhttp_modes=XHTTP_MODES,
                           fingerprints=FINGERPRINTS)


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
        ufw_delete(port)
    systemctl("restart")
    flash(f"inbound «{tag}» удалён", "success")
    push_activity("inbound", "Удалён inbound", tag)
    return redirect(url_for("inbounds_list"))


# ===== Users =====

@app.route("/users")
@login_required
def users_list():
    q = request.args.get("q", "").strip().lower()
    users = collect_users()
    stats = get_xray_stats()
    total_up = total_down = 0
    for u in users:
        s = stats.get(u["email"], {})
        u["uplink"] = s.get("uplink", 0)
        u["downlink"] = s.get("downlink", 0)
        total_up += u["uplink"]
        total_down += u["downlink"]
    if q:
        users = [u for u in users if q in u["email"].lower() or q in u["id"].lower()]
    avg = (total_up + total_down) // max(len(users), 1)
    return render_template("users.html",
                           users=users,
                           total=len(collect_users()),
                           filtered=len(users),
                           total_up=total_up,
                           total_down=total_down,
                           avg=avg,
                           q=request.args.get("q", ""))


@app.route("/users/new", methods=["GET", "POST"])
@login_required
def users_new():
    available_inbounds = collect_vless_inbounds()
    if request.method == "POST":
        try:
            email = validate_email(request.form.get("email", ""))
            uid = request.form.get("uuid", "").strip()
            uid = validate_uuid(uid) if uid else str(uuid_module.uuid4())
            selected = request.form.getlist("inbounds")
            if not selected:
                raise ValueError("выбери хотя бы один inbound")
            for u in collect_users():
                if u["email"] == email:
                    raise ValueError(f"юзер с email «{email}» уже существует")
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
            push_activity("user", "Создан юзер", email)
            return redirect(url_for("users_list"))
        except Exception as e:
            flash(f"ошибка: {e}", "error")
    return render_template("user_form.html",
                           mode="create",
                           user=None,
                           available_inbounds=available_inbounds,
                           selected_inbounds=[ib.get("tag") for ib in available_inbounds])


@app.route("/users/<uid>/edit", methods=["GET", "POST"])
@login_required
def users_edit(uid: str):
    user = get_user_by_uuid(uid)
    if not user:
        flash("юзер не найден", "error")
        return redirect(url_for("users_list"))
    available_inbounds = collect_vless_inbounds()
    if request.method == "POST":
        try:
            new_email = validate_email(request.form.get("email", ""))
            new_uid = request.form.get("uuid", "").strip()
            new_uid = validate_uuid(new_uid)
            selected = request.form.getlist("inbounds")
            if not selected:
                raise ValueError("выбери хотя бы один inbound")
            for other in collect_users():
                if other["id"] != uid and other["email"] == new_email:
                    raise ValueError(f"юзер с email «{new_email}» уже существует")
            old_uid = user["id"]
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
            push_activity("user", "Изменён юзер", new_email)
            return redirect(url_for("users_detail", uid=new_uid))
        except Exception as e:
            flash(f"ошибка: {e}", "error")
    return render_template("user_form.html",
                           mode="edit",
                           user=user,
                           available_inbounds=available_inbounds,
                           selected_inbounds=user["inbounds"])


@app.route("/users/<uid>")
@login_required
def users_detail(uid: str):
    user = get_user_by_uuid(uid)
    if not user:
        flash("юзер не найден", "error")
        return redirect(url_for("users_list"))
    stats = get_xray_stats().get(user["email"], {})
    user["uplink"] = stats.get("uplink", 0)
    user["downlink"] = stats.get("downlink", 0)
    items = collect_user_links(uid)
    recent = [c for c in collect_recent_connections(limit=200) if c.get("user") == user["email"]][:10]
    return render_template("user_detail.html",
                           user=user,
                           items=items,
                           recent=recent,
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
        push_activity("user", "Удалён юзер", user["email"])
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


@app.route("/api/system/stats")
@login_required
def api_system_stats():
    return jsonify(get_system_stats())


@app.route("/api/logs/<kind>")
@login_required
def api_logs(kind: str):
    if kind not in ("access", "error"):
        return jsonify({"error": "unknown log"}), 400
    path = ACCESS_LOG if kind == "access" else ERROR_LOG
    n = int(request.args.get("n", 200))
    n = max(10, min(n, 2000))
    raw = tail_file(path, n=n)
    if kind == "access":
        parsed = [parse_access_line(line) for line in raw]
    else:
        parsed = [parse_error_line(line) for line in raw]
    parsed = [p for p in parsed if p]
    return jsonify({"lines": parsed, "exists": path.exists()})


# ===== Connections =====

@app.route("/connections")
@login_required
def connections_list():
    period = request.args.get("period", "today")  # today/yesterday/7d
    user_f = request.args.get("user", "")
    inbound_f = request.args.get("inbound", "")
    status_f = request.args.get("status", "")
    ip_f = request.args.get("ip", "").strip()

    all_conns = collect_recent_connections(limit=500)
    if user_f:
        all_conns = [c for c in all_conns if c.get("user") == user_f]
    if inbound_f:
        all_conns = [c for c in all_conns if c.get("inbound") == inbound_f]
    if status_f:
        all_conns = [c for c in all_conns if c.get("kind") == status_f]
    if ip_f:
        all_conns = [c for c in all_conns if ip_f in (c.get("src") or "")]

    users = sorted({u["email"] for u in collect_users()})
    inbounds = sorted({ib.get("tag") for ib in collect_vless_inbounds() if ib.get("tag")})

    if request.args.get("export") == "csv":
        sio = io.StringIO()
        w = csv.writer(sio)
        w.writerow(["timestamp", "src", "dst", "user", "inbound", "outbound", "kind"])
        for c in all_conns:
            w.writerow([c.get("ts", ""), c.get("src", ""), c.get("dst", ""),
                        c.get("user", ""), c.get("inbound", ""),
                        c.get("outbound", ""), c.get("kind", "")])
        return Response(sio.getvalue(),
                        mimetype="text/csv",
                        headers={"Content-Disposition":
                                 "attachment; filename=connections.csv"})

    return render_template("connections.html",
                           connections=all_conns,
                           users=users,
                           inbounds=inbounds,
                           period=period,
                           f_user=user_f,
                           f_inbound=inbound_f,
                           f_status=status_f,
                           f_ip=ip_f)


# ===== Logs =====

@app.route("/logs")
@login_required
def logs_view():
    kind = request.args.get("kind", "access")
    if kind not in ("access", "error"):
        kind = "access"
    if request.args.get("download") == "1":
        path = ACCESS_LOG if kind == "access" else ERROR_LOG
        if not path.exists():
            abort(404)
        return send_file(str(path), as_attachment=True,
                         download_name=f"{kind}.log")
    return render_template("logs.html",
                           kind=kind,
                           access_path=str(ACCESS_LOG),
                           error_path=str(ERROR_LOG))


# ===== Outbounds =====

@app.route("/outbounds")
@login_required
def outbounds_list():
    obs = read_outbounds()
    rows = [outbound_summary(o) for o in obs]
    return render_template("outbounds.html", outbounds=rows, raw=obs)


@app.route("/outbounds/new", methods=["GET", "POST"])
@login_required
def outbounds_new():
    if request.method == "POST":
        return _outbound_save(None)
    return render_template("outbound_form.html",
                           mode="create",
                           outbound=None,
                           protocols=OUTBOUND_PROTOCOLS)


@app.route("/outbounds/<tag>/edit", methods=["GET", "POST"])
@login_required
def outbounds_edit(tag: str):
    obs = read_outbounds()
    idx = next((i for i, o in enumerate(obs) if o.get("tag") == tag), None)
    if idx is None:
        flash(f"outbound «{tag}» не найден", "error")
        return redirect(url_for("outbounds_list"))
    if request.method == "POST":
        return _outbound_save(tag)
    ob = obs[idx]
    s = ob.get("settings", {}) or {}
    proto = ob.get("protocol", "freedom")
    view = {
        "tag": ob.get("tag", ""),
        "protocol": proto,
        "domain_strategy": s.get("domainStrategy", "UseIPv4"),
        "address": "",
        "port": "",
        "user": "",
        "password": "",
        "uuid": "",
        "flow": "xtls-rprx-vision",
        "sni": "",
        "public_key": "",
        "short_id": "",
        "fingerprint": "chrome",
        "network": "tcp",
        "security": "reality",
    }
    if proto in ("socks", "http"):
        servers = s.get("servers", [])
        if servers:
            view["address"] = servers[0].get("address", "")
            view["port"] = str(servers[0].get("port", ""))
            users = servers[0].get("users", [])
            if users:
                view["user"] = users[0].get("user", "")
                view["password"] = users[0].get("pass", "")
    elif proto in ("vless", "vmess", "trojan"):
        servers = s.get("vnext", []) or s.get("servers", [])
        if servers:
            view["address"] = servers[0].get("address", "")
            view["port"] = str(servers[0].get("port", ""))
            users = servers[0].get("users", [])
            if users:
                view["uuid"] = users[0].get("id", "") or users[0].get("password", "")
                view["flow"] = users[0].get("flow", "")
        ss = ob.get("streamSettings", {}) or {}
        view["network"] = ss.get("network", "tcp")
        view["security"] = ss.get("security", "reality")
        rs = ss.get("realitySettings", {}) or {}
        sns = rs.get("serverNames") or []
        view["sni"] = sns[0] if sns else ""
        view["public_key"] = rs.get("publicKey", "")
        sids = rs.get("shortIds") or []
        view["short_id"] = sids[0] if sids else ""
        view["fingerprint"] = rs.get("fingerprint", "chrome")
    return render_template("outbound_form.html",
                           mode="edit",
                           outbound=view,
                           protocols=OUTBOUND_PROTOCOLS)


def _outbound_save(existing_tag: str | None):
    """Общая логика создания/редактирования outbound. Возвращает redirect."""
    try:
        tag = validate_tag(request.form.get("tag", ""))
        proto = request.form.get("protocol", "freedom")
        valid_protos = [p[0] for p in OUTBOUND_PROTOCOLS]
        if proto not in valid_protos:
            raise ValueError(f"неподдерживаемый protocol: {proto}")
        obs = read_outbounds()
        # check tag collision
        if existing_tag != tag:
            if any(o.get("tag") == tag for o in obs):
                raise ValueError(f"outbound с tag «{tag}» уже существует")

        new_ob: dict = {"tag": tag, "protocol": proto}

        if proto == "freedom":
            ds = request.form.get("domain_strategy", "UseIPv4")
            if ds not in ("UseIPv4", "UseIPv6", "AsIs"):
                ds = "UseIPv4"
            new_ob["settings"] = {"domainStrategy": ds}
        elif proto == "blackhole":
            new_ob["settings"] = {"response": {"type": "http"}}
        elif proto in ("socks", "http"):
            addr = request.form.get("address", "").strip()
            port = request.form.get("port", "").strip()
            if not addr or not port:
                raise ValueError("address и port обязательны")
            user = request.form.get("user", "").strip()
            pwd = request.form.get("password", "").strip()
            srv = {"address": addr, "port": int(port)}
            if user:
                srv["users"] = [{"user": user, "pass": pwd}]
            new_ob["settings"] = {"servers": [srv]}
        elif proto in ("vless", "vmess", "trojan"):
            addr = request.form.get("address", "").strip()
            port = request.form.get("port", "").strip()
            if not addr or not port:
                raise ValueError("address и port обязательны")
            uid = request.form.get("uuid", "").strip()
            if proto in ("vless", "vmess"):
                user_obj = {"id": uid, "encryption": "none"}
                flow = request.form.get("flow", "")
                if flow and flow != "none":
                    user_obj["flow"] = flow
            else:  # trojan
                user_obj = {"password": uid}
            new_ob["settings"] = {"vnext": [{
                "address": addr,
                "port": int(port),
                "users": [user_obj],
            }]}
            network = request.form.get("network", "tcp")
            security = request.form.get("security", "reality")
            ss: dict = {"network": network, "security": security}
            if security == "reality":
                ss["realitySettings"] = {
                    "serverNames": [request.form.get("sni", "")],
                    "publicKey": request.form.get("public_key", ""),
                    "shortIds": [request.form.get("short_id", "")],
                    "fingerprint": request.form.get("fingerprint", "chrome"),
                }
            new_ob["streamSettings"] = ss
        elif proto == "wireguard":
            endpoint = request.form.get("address", "").strip()
            new_ob["settings"] = {
                "secretKey": request.form.get("uuid", ""),
                "peers": [{
                    "endpoint": endpoint,
                    "publicKey": request.form.get("public_key", ""),
                    "preSharedKey": "",
                }],
            }

        if existing_tag is None:
            obs.append(new_ob)
        else:
            for i, o in enumerate(obs):
                if o.get("tag") == existing_tag:
                    obs[i] = new_ob
                    break
        write_outbounds(obs)
        ok, msg = systemctl("restart")
        if ok:
            flash(f"outbound «{tag}» сохранён", "success")
            push_activity("outbound", "Сохранён outbound", tag)
        else:
            flash(f"outbound сохранён, но xray не стартует: {msg}", "error")
        return redirect(url_for("outbounds_list"))
    except Exception as e:
        flash(f"ошибка: {e}", "error")
        return redirect(request.path)


@app.route("/outbounds/<tag>/delete", methods=["POST"])
@login_required
def outbounds_delete(tag: str):
    if tag in ("direct", "block", "api", "metrics"):
        flash(f"служебный outbound «{tag}» нельзя удалить", "error")
        return redirect(url_for("outbounds_list"))
    obs = read_outbounds()
    new = [o for o in obs if o.get("tag") != tag]
    if len(new) == len(obs):
        flash(f"outbound «{tag}» не найден", "error")
        return redirect(url_for("outbounds_list"))
    # Проверим что не используется в routing
    for r in read_routing_rules():
        if r.get("outboundTag") == tag:
            flash(f"outbound «{tag}» используется в routing-правилах — сначала удалите их", "error")
            return redirect(url_for("outbounds_list"))
    write_outbounds(new)
    systemctl("restart")
    flash(f"outbound «{tag}» удалён", "success")
    push_activity("outbound", "Удалён outbound", tag)
    return redirect(url_for("outbounds_list"))


# ===== Routing =====

@app.route("/routing")
@login_required
def routing_list():
    rules = read_routing_rules()
    rows = []
    for i, r in enumerate(rules):
        summary = rule_summary(r)
        summary["idx"] = i
        rows.append(summary)
    outbounds_available = [o.get("tag") for o in read_outbounds()]
    return render_template("routing.html",
                           rules=rows,
                           rules_count=len(rules),
                           outbounds=outbounds_available)


@app.route("/routing/new", methods=["GET", "POST"])
@login_required
def routing_new():
    if request.method == "POST":
        return _routing_save(None)
    outbounds_available = [o.get("tag") for o in read_outbounds()]
    inbounds_available = [ib.get("tag") for ib in collect_inbounds() if ib.get("tag")]
    return render_template("routing_form.html",
                           mode="create",
                           rule=None,
                           outbounds=outbounds_available,
                           inbounds=inbounds_available)


@app.route("/routing/<int:idx>/edit", methods=["GET", "POST"])
@login_required
def routing_edit(idx: int):
    rules = read_routing_rules()
    if idx < 0 or idx >= len(rules):
        flash("правило не найдено", "error")
        return redirect(url_for("routing_list"))
    if request.method == "POST":
        return _routing_save(idx)
    r = rules[idx]
    view = {
        "domains": "\n".join(r.get("domain", [])) if isinstance(r.get("domain"), list) else "",
        "ips": "\n".join(r.get("ip", [])) if isinstance(r.get("ip"), list) else "",
        "ports": str(r.get("port", "")),
        "source_inbound": (r.get("inboundTag") or [""])[0] if isinstance(r.get("inboundTag"), list) else (r.get("inboundTag") or ""),
        "protocols": r.get("protocol", []) if isinstance(r.get("protocol"), list) else ([r["protocol"]] if r.get("protocol") else []),
        "outbound": r.get("outboundTag", "block"),
        "enabled": r.get("_enabled", True),
    }
    outbounds_available = [o.get("tag") for o in read_outbounds()]
    inbounds_available = [ib.get("tag") for ib in collect_inbounds() if ib.get("tag")]
    return render_template("routing_form.html",
                           mode="edit",
                           rule=view,
                           idx=idx,
                           outbounds=outbounds_available,
                           inbounds=inbounds_available)


def _routing_save(idx: int | None):
    try:
        rules = read_routing_rules()
        domains_raw = request.form.get("domains", "")
        ips_raw = request.form.get("ips", "")
        ports = request.form.get("ports", "").strip()
        source_inbound = request.form.get("source_inbound", "").strip()
        protocols = request.form.getlist("protocols")
        outbound = request.form.get("outbound", "").strip()
        enabled = request.form.get("enabled", "1") == "1"
        if not outbound:
            raise ValueError("Outbound (action) обязателен")
        domains = [s.strip() for s in domains_raw.splitlines() if s.strip()]
        ips = [s.strip() for s in ips_raw.splitlines() if s.strip()]

        rule: dict = {"type": "field"}
        if domains:
            rule["domain"] = domains
        if ips:
            rule["ip"] = ips
        if ports:
            rule["port"] = ports
        if source_inbound:
            rule["inboundTag"] = [source_inbound]
        if protocols:
            rule["protocol"] = protocols
        rule["outboundTag"] = outbound
        if not enabled:
            rule["_enabled"] = False
        if not (domains or ips or ports or source_inbound or protocols):
            raise ValueError("укажи хотя бы одно условие")
        if idx is None:
            rules.append(rule)
        else:
            if idx < 0 or idx >= len(rules):
                raise ValueError("правило не найдено")
            rules[idx] = rule
        write_routing_rules(rules)
        ok, msg = systemctl("restart")
        if ok:
            flash("правило сохранено", "success")
            push_activity("routing", "Сохранено правило", outbound)
        else:
            flash(f"правило сохранено, но xray не стартует: {msg}", "error")
        return redirect(url_for("routing_list"))
    except Exception as e:
        flash(f"ошибка: {e}", "error")
        return redirect(request.path)


@app.route("/routing/<int:idx>/delete", methods=["POST"])
@login_required
def routing_delete(idx: int):
    rules = read_routing_rules()
    if 0 <= idx < len(rules):
        rules.pop(idx)
        write_routing_rules(rules)
        systemctl("restart")
        flash("правило удалено", "success")
        push_activity("routing", "Удалено правило", str(idx))
    return redirect(url_for("routing_list"))


@app.route("/routing/<int:idx>/toggle", methods=["POST"])
@login_required
def routing_toggle(idx: int):
    rules = read_routing_rules()
    if 0 <= idx < len(rules):
        rules[idx]["_enabled"] = not rules[idx].get("_enabled", True)
        write_routing_rules(rules)
        systemctl("restart")
    if request.is_json or request.headers.get("Accept", "").startswith("application/json"):
        return jsonify({"ok": True})
    return redirect(url_for("routing_list"))


@app.route("/api/routing/reorder", methods=["POST"])
@login_required
def api_routing_reorder():
    data = request.get_json(silent=True) or {}
    order = data.get("order")
    if not isinstance(order, list):
        return jsonify({"error": "bad order"}), 400
    rules = read_routing_rules()
    if sorted(order) != list(range(len(rules))):
        return jsonify({"error": "order doesn't cover all rules"}), 400
    new_rules = [rules[i] for i in order]
    write_routing_rules(new_rules)
    systemctl("restart")
    return jsonify({"ok": True})


# ===== Alerts =====

@app.route("/alerts")
@login_required
def alerts_view():
    state = evaluate_alerts()
    active = [a for a in state.get("active", [])
              if isinstance(a, dict) and a.get("id") and a.get("title")]
    history = [h for h in state.get("history", []) if isinstance(h, dict)]
    return render_template("alerts.html",
                           active=active,
                           history=list(reversed(history[-50:])))


@app.route("/alerts/<alert_id>/ack", methods=["POST"])
@login_required
def alerts_ack(alert_id: str):
    state = load_alerts_state()
    target = next((a for a in state["active"] if a["id"] == alert_id), None)
    if target:
        state["history"].append({
            "t": datetime.now().isoformat(timespec="seconds"),
            "sev": target.get("severity", "warning"),
            "title": target.get("title", alert_id),
            "status": "Acknowledged",
            "by": session.get("login", "admin"),
        })
        state["active"] = [a for a in state["active"] if a["id"] != alert_id]
        save_alerts_state(state)
        flash("алёрт подтверждён", "success")
    return redirect(url_for("alerts_view"))


@app.route("/alerts/<alert_id>/dismiss", methods=["POST"])
@login_required
def alerts_dismiss(alert_id: str):
    state = load_alerts_state()
    target = next((a for a in state["active"] if a["id"] == alert_id), None)
    if target:
        state["history"].append({
            "t": datetime.now().isoformat(timespec="seconds"),
            "sev": target.get("severity", "warning"),
            "title": target.get("title", alert_id),
            "status": "Dismissed",
            "by": session.get("login", "admin"),
        })
        state["active"] = [a for a in state["active"] if a["id"] != alert_id]
        save_alerts_state(state)
        flash("алёрт скрыт", "info")
    return redirect(url_for("alerts_view"))


@app.route("/alerts/<alert_id>/snooze", methods=["POST"])
@login_required
def alerts_snooze(alert_id: str):
    state = load_alerts_state()
    target = next((a for a in state["active"] if a["id"] == alert_id), None)
    if target:
        until = datetime.now() + timedelta(hours=1)
        state.setdefault("snoozed", {})[alert_id] = until.isoformat(timespec="seconds")
        state["active"] = [a for a in state["active"] if a["id"] != alert_id]
        save_alerts_state(state)
        flash("алёрт отложен на 1 час", "info")
    return redirect(url_for("alerts_view"))


# ===== Settings =====

@app.route("/settings")
@login_required
def settings():
    tab = request.args.get("tab", "infra")
    state = load_alerts_state()
    notify = PANEL_CONFIG.get("notify", {})
    geoip_info = {
        "exists": GEOIP_FILE.exists(),
        "size": GEOIP_FILE.stat().st_size if GEOIP_FILE.exists() else 0,
        "mtime": datetime.fromtimestamp(GEOIP_FILE.stat().st_mtime).isoformat(timespec="seconds")
                 if GEOIP_FILE.exists() else None,
        "geosite_exists": GEOSITE_FILE.exists(),
        "geosite_size": GEOSITE_FILE.stat().st_size if GEOSITE_FILE.exists() else 0,
    }
    backups = []
    if BACKUPS_DIR.exists():
        for f in sorted(BACKUPS_DIR.glob("backup-*.tar.gz"), reverse=True):
            try:
                backups.append({
                    "name": f.name,
                    "size": f.stat().st_size,
                    "mtime": datetime.fromtimestamp(f.stat().st_mtime),
                })
            except OSError:
                continue
    return render_template("settings.html",
                           tab=tab,
                           files=base_infra_status(),
                           xray_active=is_xray_active(),
                           api_port=DEFAULT_API_PORT,
                           metrics_port=DEFAULT_METRICS_PORT,
                           socks_port=DEFAULT_SOCKS_PORT,
                           thresholds=state.get("thresholds", DEFAULT_THRESHOLDS),
                           threshold_defs=DEFAULT_THRESHOLDS,
                           notify=notify,
                           geoip=geoip_info,
                           backups=backups[:10])


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
        push_activity("infra", "Пересоздана базовая инфраструктура", ", ".join(written))
    if skipped:
        flash(f"пропущены (уже есть, overwrite не выбран): {', '.join(skipped)}", "info")
    if not written and not skipped:
        flash("ничего не записано", "info")
    return redirect(url_for("settings", tab="infra"))


@app.route("/settings/thresholds", methods=["POST"])
@login_required
def settings_thresholds():
    state = load_alerts_state()
    thr = state.setdefault("thresholds", DEFAULT_THRESHOLDS)
    for key in DEFAULT_THRESHOLDS:
        try:
            warn = float(request.form.get(f"{key}_warn", thr.get(key, {}).get("warn", 0)))
            crit = float(request.form.get(f"{key}_crit", thr.get(key, {}).get("crit", 0)))
            unit = DEFAULT_THRESHOLDS[key].get("unit", "")
            thr[key] = {"warn": warn, "crit": crit, "unit": unit,
                        "label": DEFAULT_THRESHOLDS[key].get("label", key)}
        except (TypeError, ValueError):
            pass
    save_alerts_state(state)
    flash("пороги обновлены", "success")
    push_activity("settings", "Обновлены пороги алёртов")
    return redirect(url_for("settings", tab="thresholds"))


@app.route("/settings/notify", methods=["POST"])
@login_required
def settings_notify():
    notify = PANEL_CONFIG.setdefault("notify", {})
    notify["telegram_enabled"] = request.form.get("telegram_enabled") == "1"
    notify["telegram_token"] = request.form.get("telegram_token", "").strip()
    notify["telegram_chat_id"] = request.form.get("telegram_chat_id", "").strip()
    notify["send_xray_stopped"] = request.form.get("send_xray_stopped") == "1"
    notify["send_critical"] = request.form.get("send_critical") == "1"
    notify["send_warning"] = request.form.get("send_warning") == "1"
    notify["send_user_added"] = request.form.get("send_user_added") == "1"
    notify["send_failed_login"] = request.form.get("send_failed_login") == "1"
    try:
        with CONFIG_FILE.open("w") as f:
            json.dump(PANEL_CONFIG, f, indent=2, ensure_ascii=False)
        flash("настройки нотификаций сохранены", "success")
        push_activity("settings", "Обновлены настройки нотификаций")
    except OSError as e:
        flash(f"ошибка записи config.json: {e}", "error")
    return redirect(url_for("settings", tab="notify"))


@app.route("/settings/notify/test", methods=["POST"])
@login_required
def settings_notify_test():
    if requests is None:
        flash("модуль requests не установлен", "error")
        return redirect(url_for("settings", tab="notify"))
    notify = PANEL_CONFIG.get("notify", {})
    token = notify.get("telegram_token", "")
    chat_id = notify.get("telegram_chat_id", "")
    if not token or not chat_id:
        flash("сначала укажи token и chat_id и сохрани", "error")
        return redirect(url_for("settings", tab="notify"))
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": "xray-admin: тестовое сообщение ✅"},
            timeout=8,
        )
        if r.ok:
            flash("отправлено в Telegram", "success")
        else:
            flash(f"Telegram вернул {r.status_code}: {r.text[:200]}", "error")
    except Exception as e:
        flash(f"ошибка: {e}", "error")
    return redirect(url_for("settings", tab="notify"))


@app.route("/settings/geoip/update", methods=["POST"])
@login_required
def settings_geoip_update():
    if requests is None:
        flash("модуль requests не установлен", "error")
        return redirect(url_for("settings", tab="geoip"))
    urls = {
        "geoip.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
        "geosite.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    }
    updated = []
    for name, url in urls.items():
        target = GEOIP_FILE.parent / name
        try:
            r = requests.get(url, timeout=60, stream=True)
            if not r.ok:
                flash(f"скачивание {name} вернуло {r.status_code}", "error")
                continue
            tmp = target.with_suffix(".tmp")
            with tmp.open("wb") as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
            tmp.replace(target)
            updated.append(name)
        except Exception as e:
            flash(f"ошибка скачивания {name}: {e}", "error")
    if updated:
        ok, msg = systemctl("restart")
        if ok:
            flash(f"обновлены: {', '.join(updated)}; xray перезапущен", "success")
        else:
            flash(f"скачаны: {', '.join(updated)}, но xray не стартует: {msg}", "error")
        push_activity("settings", "Обновлена GeoIP-база", ", ".join(updated))
    return redirect(url_for("settings", tab="geoip"))


@app.route("/settings/backup/create", methods=["POST"])
@login_required
def settings_backup_create():
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = BACKUPS_DIR / f"backup-{ts}.tar.gz"
    try:
        with tarfile.open(target, "w:gz") as tar:
            if CONFIG_DIR.exists():
                tar.add(CONFIG_DIR, arcname="conf.d")
            if CONFIG_FILE.exists():
                tar.add(CONFIG_FILE, arcname="admin-config.json")
            if ALERTS_FILE.exists():
                tar.add(ALERTS_FILE, arcname="alerts.json")
        flash(f"backup создан: {target.name}", "success")
        push_activity("backup", "Создан backup", target.name)
    except Exception as e:
        flash(f"ошибка создания backup: {e}", "error")
    return redirect(url_for("settings", tab="backup"))


@app.route("/settings/backup/<name>")
@login_required
def settings_backup_download(name: str):
    if "/" in name or ".." in name:
        abort(400)
    target = BACKUPS_DIR / name
    if not target.exists():
        abort(404)
    return send_file(str(target), as_attachment=True, download_name=name)


@app.route("/settings/backup/restore", methods=["POST"])
@login_required
def settings_backup_restore():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("файл не выбран", "error")
        return redirect(url_for("settings", tab="backup"))
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = BACKUPS_DIR / f"restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    file.save(str(tmp))
    try:
        # Pre-restore snapshot
        snap_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        pre_snapshot = BACKUPS_DIR / f"pre-restore-{snap_ts}.tar.gz"
        with tarfile.open(pre_snapshot, "w:gz") as tar:
            if CONFIG_DIR.exists():
                tar.add(CONFIG_DIR, arcname="conf.d")
        with tarfile.open(tmp, "r:gz") as tar:
            for m in tar.getmembers():
                if "/.." in m.name or m.name.startswith("/"):
                    raise ValueError("backup содержит подозрительные пути")
            # restore conf.d
            for m in tar.getmembers():
                if m.name.startswith("conf.d/"):
                    tar.extract(m, str(CONFIG_DIR.parent))
        ok, msg = systemctl("restart")
        if ok:
            flash(f"восстановлено; pre-restore snapshot: {pre_snapshot.name}", "success")
            push_activity("backup", "Восстановлен backup", file.filename)
        else:
            flash(f"восстановлено, но xray не стартует: {msg}", "error")
    except Exception as e:
        flash(f"ошибка восстановления: {e}", "error")
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    return redirect(url_for("settings", tab="backup"))


@app.route("/settings/password", methods=["POST"])
@login_required
def settings_password():
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    confirm = request.form.get("confirm", "")
    if not check_password_hash(PANEL_CONFIG["admin_password_hash"], current):
        flash("текущий пароль неверный", "error")
        return redirect(url_for("settings", tab="admin"))
    if len(new) < 8:
        flash("новый пароль должен быть не короче 8 символов", "error")
        return redirect(url_for("settings", tab="admin"))
    if new != confirm:
        flash("новый пароль и подтверждение не совпадают", "error")
        return redirect(url_for("settings", tab="admin"))
    PANEL_CONFIG["admin_password_hash"] = generate_password_hash(new)
    try:
        with CONFIG_FILE.open("w") as f:
            json.dump(PANEL_CONFIG, f, indent=2, ensure_ascii=False)
        flash("пароль изменён", "success")
        push_activity("settings", "Изменён пароль панели")
    except OSError as e:
        flash(f"ошибка записи: {e}", "error")
    return redirect(url_for("settings", tab="admin"))


# ===== System =====

def _invalidate_xray_caches():
    _XRAY_ACTIVE_CACHE["ts"] = 0.0
    _USER_STATS_CACHE["ts"] = 0.0
    _INBOUND_STATS_CACHE["ts"] = 0.0


@app.route("/system/restart", methods=["POST"])
@login_required
def system_restart():
    ok, msg = systemctl("restart")
    _invalidate_xray_caches()
    flash("xray перезапущен" if ok else f"ошибка: {msg}", "success" if ok else "error")
    push_activity("xray", "xray перезапущен")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/system/start", methods=["POST"])
@login_required
def system_start():
    ok, msg = systemctl("start")
    _invalidate_xray_caches()
    flash("xray запущен" if ok else f"ошибка: {msg}", "success" if ok else "error")
    push_activity("xray", "xray запущен")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/system/stop", methods=["POST"])
@login_required
def system_stop():
    ok, msg = systemctl("stop")
    _invalidate_xray_caches()
    flash("xray остановлен" if ok else f"ошибка: {msg}", "success" if ok else "error")
    push_activity("xray", "xray остановлен")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/health")
def health():
    return {"status": "ok", "xray": is_xray_active()}


if __name__ == "__main__":
    app.run(host=PANEL_CONFIG.get("host", "0.0.0.0"),
            port=PANEL_CONFIG.get("port", 8088),
            debug=False)

"""Чтение / запись JSON-конфигов xray, валидаторы и build_inbound."""
from __future__ import annotations

import json
import os
import re
import secrets
import socket
import uuid as uuid_module
from pathlib import Path

from .config import CONFIG_DIR, TRANSPORT_CHOICES, XHTTP_MODES, FINGERPRINTS
from .system import run_xray


DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,30}$")
EMAIL_LOCAL_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


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


# ---- Validators ----
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
            "sockopt": {"tcpKeepAliveIdle": 60, "tcpKeepAliveInterval": 30},
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

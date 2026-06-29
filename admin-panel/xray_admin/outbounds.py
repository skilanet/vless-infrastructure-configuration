"""Outbounds: CRUD в 02-outbounds.json."""
from __future__ import annotations

from pathlib import Path

from .config import CONFIG_DIR
from .state import read_config_file, write_config_file


def outbounds_file_path() -> Path:
    return CONFIG_DIR / "02-outbounds.json"


def read_outbounds() -> list[dict]:
    path = outbounds_file_path()
    if not path.exists():
        return []
    data = read_config_file(path)
    # "_all_outbounds" — полный список (вкл. выключенные) для панели; xray его
    # игнорирует. Fallback на "outbounds" для конфигов, записанных до этого ключа.
    return data.get("_all_outbounds", data.get("outbounds", []))


def write_outbounds(outbounds: list[dict]) -> None:
    path = outbounds_file_path()
    data = read_config_file(path) if path.exists() else {}
    data["_all_outbounds"] = outbounds
    # xray читает "outbounds": только включённые, без панельного ключа _enabled
    data["outbounds"] = [
        {k: v for k, v in o.items() if k != "_enabled"}
        for o in outbounds if o.get("_enabled", True)
    ]
    write_config_file(path, data)


def outbound_summary(ob: dict) -> dict:
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

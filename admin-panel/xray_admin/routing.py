"""Routing rules: CRUD в 01-routing.json."""
from __future__ import annotations

from pathlib import Path

from .config import CONFIG_DIR
from .state import read_config_file, write_config_file


def routing_file_path() -> Path:
    return CONFIG_DIR / "01-routing.json"


def read_routing_rules() -> list[dict]:
    path = routing_file_path()
    if not path.exists():
        return []
    data = read_config_file(path)
    # "_all_rules" — полный упорядоченный список (вкл. выключенные) для панели;
    # xray его игнорирует. Fallback на routing.rules для старых конфигов.
    return data.get("_all_rules", data.get("routing", {}).get("rules", []))


def write_routing_rules(rules: list[dict], domain_strategy: str = "IPIfNonMatch") -> None:
    path = routing_file_path()
    data = read_config_file(path) if path.exists() else {}
    data["_all_rules"] = rules
    routing = data.setdefault("routing", {})
    routing["domainStrategy"] = domain_strategy
    # xray читает routing.rules: только включённые, без панельного ключа _enabled.
    # Порядок сохраняется — first-match не ломается при включении/выключении.
    routing["rules"] = [
        {k: v for k, v in r.items() if k != "_enabled"}
        for r in rules if r.get("_enabled", True)
    ]
    write_config_file(path, data)


def rule_summary(rule: dict) -> dict:
    match_keys = ["inboundTag", "outboundTag", "domain", "ip",
                  "port", "network", "protocol", "user", "source"]
    matches = []
    for k in match_keys:
        v = rule.get(k)
        if v is None:
            continue
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

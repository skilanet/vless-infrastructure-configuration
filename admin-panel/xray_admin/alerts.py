"""Alerts state и evaluate_alerts (CPU/RAM/Disk/FD/etc → thresholds)."""
from __future__ import annotations

import json
from datetime import datetime

from .config import ALERTS_FILE, DEFAULT_THRESHOLDS
from .stats import get_system_stats
from .system import is_xray_active


def load_alerts_state() -> dict:
    if not ALERTS_FILE.exists():
        return {
            "thresholds": dict(DEFAULT_THRESHOLDS),
            "active": [], "history": [], "snoozed": {},
        }
    try:
        with ALERTS_FILE.open() as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        state = {}
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

    new_actives = []
    if not is_xray_active():
        new_actives.append({
            "id": "xray-down", "severity": "critical",
            "title": "xray service is not running",
            "sub": "systemctl is-active xray вернул не active",
            "metric": "xray", "value": "stopped",
            "first_seen": now, "last_seen": now,
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
                "metric": key, "value": v,
                "first_seen": now, "last_seen": now,
                "label": label,
            })

    snoozed = state.get("snoozed", {})
    filtered = []
    for a in new_actives:
        until = snoozed.get(a["id"])
        if until:
            try:
                if datetime.fromisoformat(until) > datetime.now():
                    continue
            except ValueError:
                pass
        filtered.append(a)

    prev_by_id = {
        a["id"]: a
        for a in state.get("active", [])
        if isinstance(a, dict) and a.get("id")
    }
    for a in filtered:
        prev = prev_by_id.get(a["id"])
        if prev:
            a["first_seen"] = prev.get("first_seen", a["first_seen"])

    history = state.get("history", [])
    for prev_id, prev in prev_by_id.items():
        if not any(a["id"] == prev_id for a in filtered):
            history.append({
                "t": now,
                "sev": prev.get("severity", "warning"),
                "title": prev.get("title", prev_id),
                "status": "Resolved", "by": "Auto",
            })
    history = history[-200:]
    state["active"] = filtered
    state["history"] = history
    save_alerts_state(state)
    return state

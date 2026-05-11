"""Журнал действий админа: /var/lib/xray-admin/activity.json (append-only ring)."""
from __future__ import annotations

import json
from datetime import datetime

from .config import ACTIVITY_FILE


def push_activity(kind: str, title: str, sub: str = "") -> None:
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

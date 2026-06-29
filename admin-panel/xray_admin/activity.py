"""Журнал действий админа: /var/lib/xray-admin/activity.json (append-only ring)."""
from __future__ import annotations

import json
import os
import tempfile
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
    # tmp + replace → файл не обрежется, если воркер упадёт на середине записи.
    # ponytail: read-modify-write всё ещё без лока — при одновременной записи двух
    # воркеров возможна потеря одной записи; для best-effort ring-лога приемлемо.
    try:
        fd, tmp = tempfile.mkstemp(dir=str(ACTIVITY_FILE.parent),
                                   prefix="activity.", suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(items, f, indent=2, ensure_ascii=False)
        os.replace(tmp, ACTIVITY_FILE)
    except OSError:
        try:
            os.unlink(tmp)
        except (OSError, NameError):
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

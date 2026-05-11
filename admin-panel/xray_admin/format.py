"""Форматтеры для шаблонов: bytes, uuid, humans-ago."""
from __future__ import annotations

from datetime import datetime


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

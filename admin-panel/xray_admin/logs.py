"""Парсинг access.log / error.log + aggregate-helpers."""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from .config import ACCESS_LOG
from .geo import geo_lookup, country_flag


def tail_file(path: Path, n: int = 200) -> list[str]:
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
    """Поддерживаем два формата xray access.log:
      a) <ts> <src> accepted <rest>
      b) <ts> from <src> accepted <rest>
    """
    if not line.strip():
        return None
    head = line.split(maxsplit=2)
    if len(head) < 3:
        return {"raw": line}
    ts = f"{head[0]} {head[1]}"
    tail = head[2]
    if tail.startswith("from "):
        tail = tail[5:]
    sub = tail.split(maxsplit=2)
    if len(sub) < 2:
        return {"ts": ts, "raw": line}
    src = sub[0]
    action = sub[1].lower()
    rest = sub[2] if len(sub) > 2 else ""

    inbound = outbound = email = dst = None
    m = re.search(r"\[([^\]]+)\s*->\s*([^\]]+)\]", rest)
    if m:
        inbound = m.group(1).strip()
        outbound = m.group(2).strip()
    me = re.search(r"email:\s*(\S+)", rest)
    if me:
        email = me.group(1).strip()
    md = re.search(r"(tcp|udp):([^\s\[]+)", rest)
    if md:
        dst = md.group(2).strip()
    kind = "ACCEPT"
    if "block" in action or "reject" in action or outbound == "block":
        kind = "BLOCK"
    elif "fail" in action:
        kind = "ERROR"
    elif "close" in action:
        kind = "CLOSE"
    return {
        "ts": ts, "src": src, "dst": dst, "kind": kind,
        "inbound": inbound, "outbound": outbound,
        "user": email, "raw": line,
    }


def parse_error_line(line: str) -> dict:
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
    return {"ts": ts, "level": level, "body": rest, "raw": line}


def collect_recent_connections(limit: int = 200) -> list[dict]:
    lines = tail_file(ACCESS_LOG, n=limit * 4)
    out = []
    for line in lines:
        parsed = parse_access_line(line)
        if not parsed or parsed.get("kind") != "ACCEPT":
            continue
        out.append(parsed)
    return list(reversed(out))[:limit]


def aggregate_user_meta(connections: list[dict]) -> dict:
    out: dict[str, dict] = {}
    cutoff = datetime.now() - timedelta(minutes=5)
    for c in connections:
        email = c.get("user")
        if not email:
            continue
        ts_raw = c.get("ts", "")
        try:
            ts = datetime.strptime(ts_raw.split(".")[0], "%Y/%m/%d %H:%M:%S")
        except ValueError:
            ts = None
        prev = out.get(email)
        if prev and prev.get("_dt") and ts and ts <= prev["_dt"]:
            continue
        out[email] = {
            "_dt": ts,
            "last_ts": ts_raw,
            "last_src": c.get("src"),
            "online": bool(ts and ts > cutoff),
        }
    for v in out.values():
        v["geo"] = geo_lookup(v.get("last_src"))
        v.pop("_dt", None)
    return out


def aggregate_top_cities(connections: list[dict], top_n: int = 5) -> list[dict]:
    counts: dict[tuple[str, str], int] = {}
    for c in connections:
        info = geo_lookup(c.get("src"))
        if not info.get("city"):
            continue
        key = (info["country"], info["city"])
        counts[key] = counts.get(key, 0) + 1
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return [{"country": k[0], "city": k[1], "count": v,
             "flag": country_flag(k[0])} for k, v in items]


def read_connections_per_hour(hours: int = 24) -> list[dict]:
    conns = collect_recent_connections(limit=2000)
    now = datetime.now()
    cutoff = now - timedelta(hours=hours)
    counts: dict[str, int] = {}
    for c in conns:
        try:
            ts = datetime.strptime(c.get("ts", "").split(".")[0],
                                   "%Y/%m/%d %H:%M:%S")
        except ValueError:
            continue
        if ts < cutoff:
            continue
        bucket = ts.replace(minute=0, second=0, microsecond=0).isoformat()
        counts[bucket] = counts.get(bucket, 0) + 1
    out = []
    for i in range(hours):
        h = (now - timedelta(hours=hours - 1 - i)).replace(
            minute=0, second=0, microsecond=0)
        out.append({"hour": h.strftime("%H:%M"),
                    "count": counts.get(h.isoformat(), 0)})
    return out

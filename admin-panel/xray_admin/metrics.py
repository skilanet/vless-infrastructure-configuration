"""SQLite временной ряд + background sampler."""
from __future__ import annotations

import sqlite3
import threading
import time

from .config import METRICS_DB
from .stats import get_xray_stats, get_inbound_stats, get_system_stats


_INIT_LOCK = threading.Lock()
_STARTED = False


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(METRICS_DB), timeout=5.0)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def _init():
    METRICS_DB.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS samples (
                ts        INTEGER NOT NULL,
                kind      TEXT NOT NULL,
                key       TEXT NOT NULL,
                uplink    INTEGER DEFAULT 0,
                downlink  INTEGER DEFAULT 0,
                value     REAL DEFAULT 0
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_samples_kind_key_ts ON samples(kind, key, ts)")


def _record(now: int):
    try:
        user_stats = get_xray_stats()
        inbound_stats = get_inbound_stats()
    except Exception:
        user_stats, inbound_stats = {}, {}
    sys = get_system_stats()
    rows = []
    for email, ud in user_stats.items():
        rows.append((now, "user", email,
                     int(ud.get("uplink", 0)),
                     int(ud.get("downlink", 0)), 0.0))
    for tag, ud in inbound_stats.items():
        rows.append((now, "inbound", tag,
                     int(ud.get("uplink", 0)),
                     int(ud.get("downlink", 0)), 0.0))
    for key, val in (
        ("cpu", sys.get("cpu", 0.0)),
        ("memory_percent", sys.get("memory", {}).get("percent", 0.0)),
        ("disk_percent", sys.get("disk", {}).get("percent", 0.0)),
        ("connections", sys.get("connections", 0)),
        ("net_in", sys.get("net", {}).get("in", 0)),
        ("net_out", sys.get("net", {}).get("out", 0)),
    ):
        rows.append((now, "system", key, 0, 0, float(val)))
    if not rows:
        return
    with _conn() as c:
        c.executemany(
            "INSERT INTO samples (ts,kind,key,uplink,downlink,value) "
            "VALUES (?,?,?,?,?,?)", rows)
        c.execute("DELETE FROM samples WHERE ts < ?", (now - 30 * 86400,))


def _loop():
    while True:
        try:
            _record(int(time.time()))
        except Exception:
            pass
        time.sleep(60)


def ensure_sampler():
    global _STARTED
    with _INIT_LOCK:
        if _STARTED:
            return
        try:
            _init()
        except Exception:
            return
        t = threading.Thread(target=_loop, daemon=True, name="metrics-sampler")
        t.start()
        _STARTED = True


def read_traffic_series(hours: int = 24) -> dict:
    """Сумма по всем юзерам — для overview chart."""
    try:
        now = int(time.time())
        since = now - hours * 3600
        with _conn() as c:
            cur = c.execute(
                "SELECT ts, SUM(uplink), SUM(downlink) FROM samples "
                "WHERE kind='user' AND ts>=? GROUP BY ts ORDER BY ts ASC",
                (since,),
            )
            rows = cur.fetchall()
    except Exception:
        return {"points": [], "total_up": 0, "total_down": 0}
    if not rows:
        return {"points": [], "total_up": 0, "total_down": 0}
    bucket_sec = max(900, (hours * 3600) // 24)
    points = []
    prev_up = prev_down = None
    bucket_start = rows[0][0]
    bucket_up = bucket_down = 0
    total_up = total_down = 0
    for ts, up, dn in rows:
        if prev_up is not None:
            d_up = max(0, (up or 0) - prev_up)
            d_down = max(0, (dn or 0) - prev_down)
            total_up += d_up
            total_down += d_down
        else:
            d_up = d_down = 0
        prev_up, prev_down = (up or 0), (dn or 0)
        while ts >= bucket_start + bucket_sec:
            points.append({"ts": bucket_start, "up": bucket_up, "down": bucket_down})
            bucket_start += bucket_sec
            bucket_up = bucket_down = 0
        bucket_up += d_up
        bucket_down += d_down
    points.append({"ts": bucket_start, "up": bucket_up, "down": bucket_down})
    return {"points": points, "total_up": total_up,
            "total_down": total_down, "bucket_sec": bucket_sec}


def read_user_series(email: str, hours: int = 24) -> dict:
    """Трафик одного юзера."""
    try:
        now = int(time.time())
        since = now - hours * 3600
        with _conn() as c:
            cur = c.execute(
                "SELECT ts, uplink, downlink FROM samples "
                "WHERE kind='user' AND key=? AND ts>=? ORDER BY ts ASC",
                (email, since),
            )
            rows = cur.fetchall()
    except Exception:
        return {"points": [], "total_up": 0, "total_down": 0}
    if not rows:
        return {"points": [], "total_up": 0, "total_down": 0}
    bucket_sec = max(900, (hours * 3600) // 24)
    points = []
    prev_up = prev_down = None
    bucket_start = rows[0][0]
    bucket_up = bucket_down = 0
    total_up = total_down = 0
    for ts, up, dn in rows:
        if prev_up is not None:
            d_up = max(0, up - prev_up)
            d_down = max(0, dn - prev_down)
            total_up += d_up
            total_down += d_down
        else:
            d_up = d_down = 0
        prev_up, prev_down = up, dn
        while ts >= bucket_start + bucket_sec:
            points.append({"ts": bucket_start, "up": bucket_up, "down": bucket_down})
            bucket_start += bucket_sec
            bucket_up = bucket_down = 0
        bucket_up += d_up
        bucket_down += d_down
    points.append({"ts": bucket_start, "up": bucket_up, "down": bucket_down})
    return {"points": points, "total_up": total_up,
            "total_down": total_down, "bucket_sec": bucket_sec}

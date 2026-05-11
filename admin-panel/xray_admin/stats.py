"""Кэшированные системные и xray-метрики."""
from __future__ import annotations

import json
import os
import time

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore

from .system import is_xray_active, run_xray


_SYS_CACHE: dict = {"data": None, "ts": 0.0}
_SYS_TTL = 10.0
_FD_CACHE: dict = {"value": 0, "ts": 0.0}
_FD_TTL = 30.0

_USER_STATS_CACHE: dict = {"data": None, "ts": 0.0}
_INBOUND_STATS_CACHE: dict = {"data": None, "ts": 0.0}
_XRAY_STATS_TTL = 8.0


def _count_fds_cached() -> int:
    now = time.time()
    if now - _FD_CACHE["ts"] < _FD_TTL:
        return _FD_CACHE["value"]
    if psutil is None:
        return 0
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
        return _FD_CACHE["value"]


def get_system_stats(force: bool = False) -> dict:
    now = time.time()
    if not force and _SYS_CACHE["data"] is not None and (now - _SYS_CACHE["ts"]) < _SYS_TTL:
        return _SYS_CACHE["data"]
    out = {
        "cpu": 0.0,
        "memory": {"used": 0, "total": 0, "percent": 0.0},
        "disk": {"used": 0, "total": 0, "percent": 0.0},
        "net": {"in": 0, "out": 0},
        "fd": 0, "steal": 0.0, "connections": 0, "uptime_sec": 0,
        "load_avg": (0.0, 0.0, 0.0), "available": False,
    }
    if psutil is None:
        _SYS_CACHE["data"] = out
        _SYS_CACHE["ts"] = now
        return out
    try:
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


def get_xray_stats(reset: bool = False) -> dict[str, dict]:
    now = time.time()
    if not reset and _USER_STATS_CACHE["data"] is not None \
            and (now - _USER_STATS_CACHE["ts"]) < _XRAY_STATS_TTL:
        return _USER_STATS_CACHE["data"]
    if not is_xray_active():
        return {}
    try:
        args = ["api", "statsquery", "--server=127.0.0.1:10085",
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
        out = run_xray("api", "statsquery", "--server=127.0.0.1:10085",
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


def invalidate_xray_stats():
    _USER_STATS_CACHE["ts"] = 0.0
    _INBOUND_STATS_CACHE["ts"] = 0.0

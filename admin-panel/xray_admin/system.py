"""Обёртки над sudo systemctl / xray CLI / ufw + кэш is_xray_active."""
from __future__ import annotations

import re
import subprocess
import time


def systemctl(action: str, service: str = "xray") -> tuple[bool, str]:
    result = subprocess.run(
        ["sudo", "/bin/systemctl", action, service],
        capture_output=True, text=True, timeout=15,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def systemctl_show(service: str, field: str) -> str:
    """systemctl show — без sudo, тоже работает."""
    try:
        result = subprocess.run(
            ["/bin/systemctl", "show", service, f"--property={field}", "--value"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def ufw_allow(port: int, comment: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["sudo", "/usr/sbin/ufw", "allow", f"{port}/tcp", "comment", comment],
        capture_output=True, text=True, timeout=10,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def ufw_delete(port: int) -> tuple[bool, str]:
    result = subprocess.run(
        ["sudo", "/usr/sbin/ufw", "delete", "allow", f"{port}/tcp"],
        capture_output=True, text=True, timeout=10,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def run_xray(*args: str) -> str:
    result = subprocess.run(
        ["sudo", "/usr/local/bin/xray", *args],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"xray failed: {result.stderr}")
    return result.stdout


_XRAY_ACTIVE_CACHE: dict = {"value": False, "ts": 0.0}
_XRAY_ACTIVE_TTL = 5.0


def is_xray_active(force: bool = False) -> bool:
    now = time.time()
    if not force and (now - _XRAY_ACTIVE_CACHE["ts"]) < _XRAY_ACTIVE_TTL:
        return _XRAY_ACTIVE_CACHE["value"]
    ok, _ = systemctl("is-active", "xray")
    _XRAY_ACTIVE_CACHE["value"] = ok
    _XRAY_ACTIVE_CACHE["ts"] = now
    return ok


def invalidate_xray_caches():
    """Сбрасывает кэш is_xray_active + stats. Используется после start/stop/restart."""
    from . import stats as _stats
    _XRAY_ACTIVE_CACHE["ts"] = 0.0
    _stats.invalidate_xray_stats()


def xray_version() -> str:
    try:
        out = subprocess.run(
            ["/usr/local/bin/xray", "-version"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout:
            first = out.stdout.splitlines()[0]
            m = re.search(r"Xray\s+(\S+)", first)
            if m:
                return f"v{m.group(1)}"
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return "—"


def xray_uptime() -> str:
    from datetime import datetime
    raw = systemctl_show("xray", "ActiveEnterTimestamp")
    if not raw:
        return "—"
    parts = raw.split()
    if len(parts) < 3:
        return "—"
    try:
        dt = datetime.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
        delta = datetime.now() - dt
        days = delta.days
        hours = delta.seconds // 3600
        if days > 0:
            return f"{days}д {hours}ч"
        mins = (delta.seconds % 3600) // 60
        return f"{hours}ч {mins}м"
    except ValueError:
        return "—"


def xray_pid() -> str:
    raw = systemctl_show("xray", "MainPID")
    return raw if raw and raw != "0" else "—"

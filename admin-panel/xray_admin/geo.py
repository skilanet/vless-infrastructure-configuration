"""GeoIP-lookup (MaxMind GeoLite2-City). In-memory cache."""
from __future__ import annotations

from pathlib import Path

try:
    import geoip2.database  # type: ignore
except ImportError:
    geoip2 = None  # type: ignore

from .config import GEOIP_MMDB_CANDIDATES


_GEO_READER = None
_GEO_PATH: Path | None = None
_GEO_CACHE: dict[str, dict] = {}
_GEO_CACHE_MAX = 4096

_COUNTRY_FLAG = {
    "RU": "🇷🇺", "BY": "🇧🇾", "UA": "🇺🇦", "KZ": "🇰🇿", "DE": "🇩🇪",
    "NL": "🇳🇱", "US": "🇺🇸", "GB": "🇬🇧", "FR": "🇫🇷", "PL": "🇵🇱",
    "FI": "🇫🇮", "TR": "🇹🇷", "JP": "🇯🇵", "CN": "🇨🇳", "HK": "🇭🇰",
    "SG": "🇸🇬", "AE": "🇦🇪", "IL": "🇮🇱", "GE": "🇬🇪", "AM": "🇦🇲",
    "AZ": "🇦🇿", "EE": "🇪🇪", "LV": "🇱🇻", "LT": "🇱🇹", "MD": "🇲🇩",
    "CA": "🇨🇦", "BR": "🇧🇷", "IN": "🇮🇳", "ID": "🇮🇩", "IT": "🇮🇹",
    "ES": "🇪🇸", "SE": "🇸🇪", "NO": "🇳🇴", "DK": "🇩🇰", "CZ": "🇨🇿",
    "AT": "🇦🇹", "BE": "🇧🇪", "CH": "🇨🇭", "GR": "🇬🇷", "RO": "🇷🇴",
}


def _open_reader():
    global _GEO_READER, _GEO_PATH
    if geoip2 is None:
        return None
    if _GEO_READER is not None:
        return _GEO_READER
    for p in GEOIP_MMDB_CANDIDATES:
        if p.exists():
            try:
                _GEO_READER = geoip2.database.Reader(str(p))
                _GEO_PATH = p
                return _GEO_READER
            except Exception:
                continue
    return None


def geo_metadata() -> dict:
    r = _open_reader()
    if r is None or _GEO_PATH is None:
        return {"exists": False, "path": None}
    try:
        meta = r.metadata()
        return {
            "exists": True,
            "path": str(_GEO_PATH),
            "size": _GEO_PATH.stat().st_size,
            "build_epoch": getattr(meta, "build_epoch", 0),
            "database_type": getattr(meta, "database_type", ""),
            "ip_version": getattr(meta, "ip_version", 0),
        }
    except Exception:
        return {"exists": True, "path": str(_GEO_PATH)}


def _strip_port(ip_with_port: str) -> str:
    if not ip_with_port:
        return ""
    s = ip_with_port.strip()
    if s.startswith("[") and "]" in s:
        return s[1:s.index("]")]
    if s.count(":") > 1:
        return s
    return s.split(":", 1)[0]


def geo_lookup(ip_with_port: str | None) -> dict:
    if not ip_with_port:
        return {}
    ip = _strip_port(ip_with_port)
    if not ip:
        return {}
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    reader = _open_reader()
    if reader is None:
        return {}
    try:
        resp = reader.city(ip)
        country = resp.country.iso_code or ""
        city = resp.city.names.get("ru") or resp.city.name or ""
        info = {
            "country": country,
            "city": city,
            "flag": _COUNTRY_FLAG.get(country, "🌐") if country else "🌐",
        }
    except Exception:
        info = {}
    if len(_GEO_CACHE) > _GEO_CACHE_MAX:
        _GEO_CACHE.clear()
    _GEO_CACHE[ip] = info
    return info


def country_flag(country_code: str) -> str:
    return _COUNTRY_FLAG.get(country_code, "🌐")

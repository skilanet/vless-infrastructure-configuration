"""Глобальные пути и константы. PANEL_CONFIG загружается лениво."""
from __future__ import annotations

import json
from pathlib import Path

CONFIG_DIR = Path("/usr/local/etc/xray/conf.d")
CONFIG_FILE = Path("/etc/xray-admin/config.json")
STATE_DIR = Path("/var/lib/xray-admin")
ALERTS_FILE = STATE_DIR / "alerts.json"
ACTIVITY_FILE = STATE_DIR / "activity.json"
BACKUPS_DIR = STATE_DIR / "backups"
METRICS_DB = STATE_DIR / "metrics.db"

GEOIP_FILE = Path("/usr/local/share/xray/geoip.dat")
GEOSITE_FILE = Path("/usr/local/share/xray/geosite.dat")
GEOIP_MMDB_CANDIDATES = [
    Path("/var/lib/GeoIP/GeoLite2-City.mmdb"),
    Path("/var/lib/xray-admin/GeoLite2-City.mmdb"),
    Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
]

XRAY_LOG_DIR = Path("/var/log/xray")
ACCESS_LOG = XRAY_LOG_DIR / "access.log"
ERROR_LOG = XRAY_LOG_DIR / "error.log"

DEFAULT_SNI_OPTIONS = [
    "yahoo.com",
    "www.lovelive-anime.jp",
    "gateway.icloud.com",
    "www.amazon.com",
    "aws.amazon.com",
    "www.cloudflare.com",
    "www.microsoft.com",
    "www.spotify.com",
]

TRANSPORT_CHOICES = ["xhttp", "tcp"]
XHTTP_MODES = ["stream-one", "packet-up", "auto"]
FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android", "random"]

BASE_INFRA_FILES = [
    "00-base.json",
    "01-routing.json",
    "02-outbounds.json",
    "10-service-inbounds.json",
]
DEFAULT_API_PORT = 10085
DEFAULT_METRICS_PORT = 10086
DEFAULT_SOCKS_PORT = 10808

OUTBOUND_PROTOCOLS = [
    ("freedom", "freedom — прямой выход"),
    ("blackhole", "blackhole — заблокировать"),
    ("socks", "socks — SOCKS5-прокси"),
    ("http", "http — HTTP-прокси"),
    ("vless", "vless — proxy-chain"),
    ("vmess", "vmess"),
    ("trojan", "trojan"),
    ("wireguard", "wireguard"),
]

DEFAULT_THRESHOLDS = {
    "cpu":         {"warn": 60,   "crit": 85,   "unit": "%",  "label": "CPU"},
    "memory":      {"warn": 70,   "crit": 90,   "unit": "%",  "label": "Memory"},
    "disk":        {"warn": 70,   "crit": 90,   "unit": "%",  "label": "Disk"},
    "fd":          {"warn": 3000, "crit": 5000, "unit": "",   "label": "FD count"},
    "steal":       {"warn": 15,   "crit": 30,   "unit": "%",  "label": "Steal time"},
    "connections": {"warn": 2000, "crit": 5000, "unit": "",   "label": "Connections"},
}


_PANEL_CONFIG: dict | None = None


def get_panel_config() -> dict:
    global _PANEL_CONFIG
    if _PANEL_CONFIG is None:
        if not CONFIG_FILE.exists():
            raise RuntimeError(f"Файл конфига не найден: {CONFIG_FILE}")
        with CONFIG_FILE.open() as f:
            _PANEL_CONFIG = json.load(f)
    return _PANEL_CONFIG


def save_panel_config():
    cfg = get_panel_config()
    with CONFIG_FILE.open("w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

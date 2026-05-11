"""Шаблоны базовой инфраструктуры xray для settings → bootstrap."""
from __future__ import annotations

from .config import ACCESS_LOG, ERROR_LOG, BASE_INFRA_FILES, CONFIG_DIR, \
    DEFAULT_API_PORT, DEFAULT_METRICS_PORT, DEFAULT_SOCKS_PORT
from datetime import datetime


def base_config_template() -> dict:
    return {
        "log": {
            "loglevel": "info",
            "access": str(ACCESS_LOG),
            "error": str(ERROR_LOG),
        },
        "api": {
            "tag": "api",
            "services": ["StatsService", "LoggerService", "HandlerService"],
        },
        "metrics": {"tag": "metrics"},
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "handshake": 4, "connIdle": 120,
                    "uplinkOnly": 2, "downlinkOnly": 5,
                    "statsUserUplink": True, "statsUserDownlink": True,
                    "bufferSize": 512,
                },
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "dns": {
            "servers": [
                {"address": "https+local://1.1.1.1/dns-query",
                 "domains": ["geosite:geolocation-!cn"], "skipFallback": True},
                {"address": "https+local://9.9.9.9/dns-query",
                 "skipFallback": True},
                "localhost",
            ],
            "queryStrategy": "UseIP",
            "disableCache": False, "disableFallback": False,
            "tag": "dns_inbound",
        },
    }


def routing_config_template() -> dict:
    return {
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "inboundTag": ["metrics"], "outboundTag": "metrics"},
                {"type": "field", "inboundTag": ["dns_inbound"], "outboundTag": "direct"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:ru", "geoip:by"], "outboundTag": "block"},
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
            ],
        },
    }


def outbounds_config_template() -> dict:
    return {
        "outbounds": [
            {"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"},
             "tag": "direct", "streamSettings": {"sockopt": {
                "tcpFastOpen": True, "tcpCongestion": "bbr",
                "tcpNoDelay": True, "tcpKeepAliveInterval": 30, "mark": 255,
            }}},
            {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
            {"protocol": "freedom", "tag": "api"},
            {"protocol": "freedom", "tag": "metrics"},
        ],
    }


def service_inbounds_template(socks_port: int = DEFAULT_SOCKS_PORT,
                              api_port: int = DEFAULT_API_PORT,
                              metrics_port: int = DEFAULT_METRICS_PORT) -> dict:
    return {
        "inbounds": [
            {"tag": "socks-in", "port": socks_port, "listen": "127.0.0.1",
             "protocol": "socks", "settings": {"auth": "noauth"}},
            {"listen": "127.0.0.1", "port": api_port,
             "protocol": "dokodemo-door",
             "settings": {"address": "127.0.0.1"}, "tag": "api"},
            {"listen": "127.0.0.1", "port": metrics_port,
             "protocol": "dokodemo-door",
             "settings": {"address": "127.0.0.1"}, "tag": "metrics"},
        ],
    }


def base_infra_status() -> list[dict]:
    out = []
    for name in BASE_INFRA_FILES:
        path = CONFIG_DIR / name
        stat = {
            "name": name, "path": str(path),
            "exists": path.exists(),
            "size": path.stat().st_size if path.exists() else 0,
            "mtime": None,
        }
        if path.exists():
            try:
                stat["mtime"] = datetime.fromtimestamp(path.stat().st_mtime)
            except OSError:
                pass
        out.append(stat)
    return out

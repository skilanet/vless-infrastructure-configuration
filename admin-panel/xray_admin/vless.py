"""VLESS-ссылка и QR для конкретного user'а."""
from __future__ import annotations

import base64
import io
from urllib.parse import quote

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from qrcode.image.svg import SvgPathImage

from .config import get_panel_config
from .state import collect_vless_inbounds


def derive_public_key(private_b64: str) -> str:
    pad = "=" * (-len(private_b64) % 4)
    raw = base64.urlsafe_b64decode(private_b64 + pad)
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode()


def get_server_ip() -> str:
    sip = get_panel_config().get("server_ip")
    if sip:
        return str(sip)
    return "<server_ip-не-задан-в-config.json>"


def build_vless_link(inbound: dict, client: dict, server_ip: str,
                     public_key: str) -> str:
    ss = inbound.get("streamSettings", {})
    rs = ss.get("realitySettings", {})
    network = ss.get("network", "tcp")
    port = inbound.get("port")
    sni = (rs.get("serverNames") or [""])[0]
    fp = rs.get("fingerprint", "chrome")
    sids = [s for s in rs.get("shortIds", []) if s]
    sid = sids[0] if sids else ""
    uid = client["id"]
    name = client.get("email", "user").split("@")[0] or "user"
    label = f"{name}:{port}-{network}"
    qs = [
        ("encryption", "none"), ("security", "reality"),
        ("sni", sni), ("fp", fp), ("pbk", public_key),
        ("sid", sid), ("type", network),
    ]
    if network == "xhttp":
        xs = ss.get("xhttpSettings", {})
        qs.extend([
            ("path", xs.get("path", "/")),
            ("mode", xs.get("mode", "auto")),
            ("host", xs.get("host", sni)),
        ])
    elif network == "tcp":
        flow = client.get("flow", "")
        if flow:
            qs.append(("flow", flow))
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in qs)
    return f"vless://{uid}@{server_ip}:{port}?{query}#{quote(label)}"


def make_qr_svg(data: str) -> str:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10, border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(image_factory=SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


def collect_user_links(uid: str) -> list[dict]:
    server_ip = get_server_ip()
    items: list[dict] = []
    for ib in collect_vless_inbounds():
        clients = ib.get("settings", {}).get("clients", [])
        client = next((c for c in clients if c.get("id") == uid), None)
        if not client:
            continue
        rs = ib.get("streamSettings", {}).get("realitySettings", {})
        priv = rs.get("privateKey", "")
        if not priv:
            continue
        try:
            pub = derive_public_key(priv)
        except Exception:
            continue
        link = build_vless_link(ib, client, server_ip, pub)
        items.append({
            "tag": ib.get("tag"),
            "port": ib.get("port"),
            "network": ib.get("streamSettings", {}).get("network", "tcp"),
            "sni": (rs.get("serverNames") or [""])[0],
            "link": link,
            "qr_svg": make_qr_svg(link),
        })
    return items

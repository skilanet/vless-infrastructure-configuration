"""Inbounds / Outbounds / Routing CRUD."""
from __future__ import annotations

from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, url_for)

from ..auth import login_required
from ..activity import push_activity
from ..config import (CONFIG_DIR, DEFAULT_SNI_OPTIONS,
                      FINGERPRINTS, OUTBOUND_PROTOCOLS,
                      TRANSPORT_CHOICES, XHTTP_MODES)
from ..outbounds import read_outbounds, write_outbounds, outbound_summary
from ..routing import (read_routing_rules, write_routing_rules, rule_summary)
from ..state import (build_inbound, collect_inbounds, collect_vless_inbounds,
                     find_inbound_by_tag, list_config_files,
                     read_config_file, write_config_file,
                     resolve_dest, validate_port, validate_sni, validate_tag)
from ..system import systemctl, ufw_allow, ufw_delete
from ..vless import derive_public_key


bp = Blueprint("config", __name__)


# ===== Inbounds =====

@bp.route("/inbounds")
@login_required
def inbounds_list():
    all_inbounds = collect_inbounds()
    filter_kind = request.args.get("filter", "all")
    rows = []
    for ib in all_inbounds:
        ss = ib.get("streamSettings", {}) or {}
        rs = ss.get("realitySettings", {}) or {}
        xs = ss.get("xhttpSettings", {}) or {}
        sns = rs.get("serverNames") or []
        is_service = ib.get("listen") == "127.0.0.1" or ib.get("protocol") != "vless"
        rows.append({
            "tag": ib.get("tag", "—"),
            "port": ib.get("port"),
            "proto": ib.get("protocol", "—"),
            "transport": ss.get("network", "—"),
            "mode": xs.get("mode"),
            "sni": sns[0] if sns else None,
            "clients": len((ib.get("settings") or {}).get("clients", [])),
            "service": is_service,
            "file": ib.get("_file", "—"),
        })
    user_rows = [r for r in rows if not r["service"]]
    service_rows = [r for r in rows if r["service"]]
    if filter_kind == "user":
        visible = user_rows
    elif filter_kind == "service":
        visible = service_rows
    else:
        visible = rows
    return render_template("inbounds.html",
                           rows=visible,
                           total=len(rows),
                           user_count=len(user_rows),
                           service_count=len(service_rows),
                           filter=filter_kind)


@bp.route("/inbounds/new", methods=["GET", "POST"])
@login_required
def inbounds_new():
    if request.method == "POST":
        try:
            tag = validate_tag(request.form.get("tag", ""))
            port = validate_port(request.form.get("port", ""))
            transport = request.form.get("transport", "")
            if transport not in TRANSPORT_CHOICES:
                raise ValueError(f"transport должен быть один из: {TRANSPORT_CHOICES}")
            sni = validate_sni(request.form.get("sni", ""))
            dest = resolve_dest(sni, request.form.get("dest", ""))
            xhttp_mode = request.form.get("xhttp_mode", "stream-one")
            if transport == "xhttp" and xhttp_mode not in XHTTP_MODES:
                raise ValueError("неверный xhttp_mode")
            fingerprint = request.form.get("fingerprint", "chrome")
            if fingerprint not in FINGERPRINTS:
                fingerprint = "chrome"
            if find_inbound_by_tag(tag):
                raise ValueError(f"inbound с tag «{tag}» уже существует")
            inbound = build_inbound(tag, port, transport, sni, dest,
                                    xhttp_mode=xhttp_mode, fingerprint=fingerprint)
            filename = f"20-vless-{tag}.json"
            file_path = CONFIG_DIR / filename
            write_config_file(file_path, {"inbounds": [inbound]})
            ufw_ok, ufw_msg = ufw_allow(port, f"vless-{tag}")
            if not ufw_ok:
                flash(f"⚠ ufw allow {port}/tcp не сработал: {ufw_msg}", "error")
            ok, msg = systemctl("restart")
            if ok:
                flash(f"inbound «{tag}» создан, xray перезапущен", "success")
                push_activity("inbound", "Создан inbound", tag)
            else:
                flash(f"inbound создан, но xray не стартует: {msg}", "error")
            return redirect(url_for("config.inbounds_list"))
        except Exception as e:
            flash(f"ошибка: {e}", "error")
    return render_template("inbound_form.html",
                           mode="create", inbound=None,
                           sni_options=DEFAULT_SNI_OPTIONS,
                           xhttp_modes=XHTTP_MODES,
                           fingerprints=FINGERPRINTS)


@bp.route("/inbounds/<tag>/edit", methods=["GET", "POST"])
@login_required
def inbounds_edit(tag: str):
    found = find_inbound_by_tag(tag)
    if not found:
        flash(f"inbound «{tag}» не найден", "error")
        return redirect(url_for("config.inbounds_list"))
    file_path, file_data, idx = found
    inbound = file_data["inbounds"][idx]
    if inbound.get("protocol") != "vless":
        flash("служебные inbound'ы не редактируются через форму", "error")
        return redirect(url_for("config.inbounds_list"))

    if request.method == "POST":
        try:
            new_port = validate_port(request.form.get("port", ""), exclude_tag=tag)
            transport = request.form.get("transport", "")
            if transport not in TRANSPORT_CHOICES:
                raise ValueError(f"transport должен быть один из: {TRANSPORT_CHOICES}")
            sni = validate_sni(request.form.get("sni", ""))
            dest = resolve_dest(sni, request.form.get("dest", ""))
            xhttp_mode = request.form.get("xhttp_mode", "stream-one")
            if transport == "xhttp" and xhttp_mode not in XHTTP_MODES:
                raise ValueError("неверный xhttp_mode")
            fingerprint = request.form.get("fingerprint", "chrome")
            if fingerprint not in FINGERPRINTS:
                fingerprint = "chrome"
            old_port = inbound.get("port")
            current_clients = inbound.get("settings", {}).get("clients", [])
            current_rs = inbound.get("streamSettings", {}).get("realitySettings", {})
            current_xhttp = inbound.get("streamSettings", {}).get("xhttpSettings", {})
            regen_keys = request.form.get("regen_keys") == "1"
            new_inbound = build_inbound(
                tag=tag, port=new_port, transport=transport, sni=sni, dest=dest,
                xhttp_mode=xhttp_mode, fingerprint=fingerprint,
                private_key=None if regen_keys else current_rs.get("privateKey"),
                short_ids=None if regen_keys else current_rs.get("shortIds"),
                xhttp_path=current_xhttp.get("path"),
                clients=current_clients,
            )
            if transport == "tcp":
                for c in new_inbound["settings"]["clients"]:
                    c["flow"] = "xtls-rprx-vision"
            else:
                for c in new_inbound["settings"]["clients"]:
                    c.pop("flow", None)
            file_data["inbounds"][idx] = new_inbound
            write_config_file(file_path, file_data)
            if new_port != old_port:
                ufw_delete(old_port)
                ufw_ok, ufw_msg = ufw_allow(new_port, f"vless-{tag}")
                if not ufw_ok:
                    flash(f"⚠ ufw allow {new_port}/tcp не сработал: {ufw_msg}", "error")
            ok, msg = systemctl("restart")
            if ok:
                flash(f"inbound «{tag}» обновлён", "success")
                push_activity("inbound", "Изменён inbound", tag)
            else:
                flash(f"inbound сохранён, но xray не стартует: {msg}", "error")
            return redirect(url_for("config.inbounds_list"))
        except Exception as e:
            flash(f"ошибка: {e}", "error")

    ss = inbound.get("streamSettings", {})
    rs = ss.get("realitySettings", {})
    xs = ss.get("xhttpSettings", {})
    priv = rs.get("privateKey", "")
    public_key = ""
    try:
        if priv:
            public_key = derive_public_key(priv)
    except Exception:
        pass
    inbound_view = {
        "tag": inbound.get("tag"),
        "port": inbound.get("port"),
        "transport": ss.get("network", "xhttp"),
        "sni": (rs.get("serverNames") or [""])[0],
        "dest": rs.get("dest", ""),
        "xhttp_mode": xs.get("mode", "stream-one"),
        "xhttp_path": xs.get("path", ""),
        "fingerprint": rs.get("fingerprint", "chrome"),
        "private_key": priv,
        "public_key": public_key,
        "short_ids": rs.get("shortIds", []),
        "file": file_path.name,
        "clients": len(inbound.get("settings", {}).get("clients", [])),
    }
    return render_template("inbound_form.html",
                           mode="edit", inbound=inbound_view,
                           sni_options=DEFAULT_SNI_OPTIONS,
                           xhttp_modes=XHTTP_MODES,
                           fingerprints=FINGERPRINTS)


@bp.route("/inbounds/<tag>/delete", methods=["POST"])
@login_required
def inbounds_delete(tag: str):
    found = find_inbound_by_tag(tag)
    if not found:
        flash(f"inbound «{tag}» не найден", "error")
        return redirect(url_for("config.inbounds_list"))
    file_path, file_data, idx = found
    inbound = file_data["inbounds"][idx]
    if inbound.get("protocol") != "vless":
        flash("служебные inbound'ы нельзя удалять через UI", "error")
        return redirect(url_for("config.inbounds_list"))
    port = inbound.get("port")
    file_data["inbounds"].pop(idx)
    if file_data["inbounds"]:
        write_config_file(file_path, file_data)
    else:
        file_path.unlink()
    if port:
        ufw_delete(port)
    systemctl("restart")
    flash(f"inbound «{tag}» удалён", "success")
    push_activity("inbound", "Удалён inbound", tag)
    return redirect(url_for("config.inbounds_list"))


# ===== Outbounds =====

@bp.route("/outbounds")
@login_required
def outbounds_list():
    obs = read_outbounds()
    rows = [outbound_summary(o) for o in obs]
    return render_template("outbounds.html", outbounds=rows, raw=obs)


@bp.route("/outbounds/new", methods=["GET", "POST"])
@login_required
def outbounds_new():
    if request.method == "POST":
        return _outbound_save(None)
    return render_template("outbound_form.html",
                           mode="create", outbound=None,
                           protocols=OUTBOUND_PROTOCOLS)


@bp.route("/outbounds/<tag>/edit", methods=["GET", "POST"])
@login_required
def outbounds_edit(tag: str):
    obs = read_outbounds()
    idx = next((i for i, o in enumerate(obs) if o.get("tag") == tag), None)
    if idx is None:
        flash(f"outbound «{tag}» не найден", "error")
        return redirect(url_for("config.outbounds_list"))
    if request.method == "POST":
        return _outbound_save(tag)
    ob = obs[idx]
    s = ob.get("settings", {}) or {}
    proto = ob.get("protocol", "freedom")
    view = {
        "tag": ob.get("tag", ""), "protocol": proto,
        "domain_strategy": s.get("domainStrategy", "UseIPv4"),
        "address": "", "port": "", "user": "", "password": "",
        "uuid": "", "flow": "xtls-rprx-vision", "sni": "",
        "public_key": "", "short_id": "", "fingerprint": "chrome",
        "network": "tcp", "security": "reality",
    }
    if proto in ("socks", "http"):
        servers = s.get("servers", [])
        if servers:
            view["address"] = servers[0].get("address", "")
            view["port"] = str(servers[0].get("port", ""))
            users = servers[0].get("users", [])
            if users:
                view["user"] = users[0].get("user", "")
                view["password"] = users[0].get("pass", "")
    elif proto in ("vless", "vmess", "trojan"):
        servers = s.get("vnext", []) or s.get("servers", [])
        if servers:
            view["address"] = servers[0].get("address", "")
            view["port"] = str(servers[0].get("port", ""))
            users = servers[0].get("users", [])
            if users:
                view["uuid"] = users[0].get("id", "") or users[0].get("password", "")
                view["flow"] = users[0].get("flow", "")
        ss2 = ob.get("streamSettings", {}) or {}
        view["network"] = ss2.get("network", "tcp")
        view["security"] = ss2.get("security", "reality")
        rs2 = ss2.get("realitySettings", {}) or {}
        sns = rs2.get("serverNames") or []
        view["sni"] = sns[0] if sns else ""
        view["public_key"] = rs2.get("publicKey", "")
        sids = rs2.get("shortIds") or []
        view["short_id"] = sids[0] if sids else ""
        view["fingerprint"] = rs2.get("fingerprint", "chrome")
    return render_template("outbound_form.html",
                           mode="edit", outbound=view,
                           protocols=OUTBOUND_PROTOCOLS)


def _outbound_save(existing_tag):
    try:
        tag = validate_tag(request.form.get("tag", ""))
        proto = request.form.get("protocol", "freedom")
        valid_protos = [p[0] for p in OUTBOUND_PROTOCOLS]
        if proto not in valid_protos:
            raise ValueError(f"неподдерживаемый protocol: {proto}")
        obs = read_outbounds()
        if existing_tag != tag and any(o.get("tag") == tag for o in obs):
            raise ValueError(f"outbound с tag «{tag}» уже существует")

        new_ob: dict = {"tag": tag, "protocol": proto}
        if proto == "freedom":
            ds = request.form.get("domain_strategy", "UseIPv4")
            if ds not in ("UseIPv4", "UseIPv6", "AsIs"):
                ds = "UseIPv4"
            new_ob["settings"] = {"domainStrategy": ds}
        elif proto == "blackhole":
            new_ob["settings"] = {"response": {"type": "http"}}
        elif proto in ("socks", "http"):
            addr = request.form.get("address", "").strip()
            port = request.form.get("port", "").strip()
            if not addr or not port:
                raise ValueError("address и port обязательны")
            user = request.form.get("user", "").strip()
            pwd = request.form.get("password", "").strip()
            srv = {"address": addr, "port": int(port)}
            if user:
                srv["users"] = [{"user": user, "pass": pwd}]
            new_ob["settings"] = {"servers": [srv]}
        elif proto in ("vless", "vmess", "trojan"):
            addr = request.form.get("address", "").strip()
            port = request.form.get("port", "").strip()
            if not addr or not port:
                raise ValueError("address и port обязательны")
            uid = request.form.get("uuid", "").strip()
            if proto in ("vless", "vmess"):
                user_obj = {"id": uid, "encryption": "none"}
                flow = request.form.get("flow", "")
                if flow and flow != "none":
                    user_obj["flow"] = flow
            else:
                user_obj = {"password": uid}
            new_ob["settings"] = {"vnext": [{
                "address": addr, "port": int(port), "users": [user_obj],
            }]}
            network = request.form.get("network", "tcp")
            security = request.form.get("security", "reality")
            ss: dict = {"network": network, "security": security}
            if security == "reality":
                ss["realitySettings"] = {
                    "serverNames": [request.form.get("sni", "")],
                    "publicKey": request.form.get("public_key", ""),
                    "shortIds": [request.form.get("short_id", "")],
                    "fingerprint": request.form.get("fingerprint", "chrome"),
                }
            new_ob["streamSettings"] = ss
        elif proto == "wireguard":
            endpoint = request.form.get("address", "").strip()
            new_ob["settings"] = {
                "secretKey": request.form.get("uuid", ""),
                "peers": [{
                    "endpoint": endpoint,
                    "publicKey": request.form.get("public_key", ""),
                    "preSharedKey": "",
                }],
            }
        if existing_tag is None:
            obs.append(new_ob)
        else:
            for i, o in enumerate(obs):
                if o.get("tag") == existing_tag:
                    obs[i] = new_ob
                    break
        write_outbounds(obs)
        ok, msg = systemctl("restart")
        if ok:
            flash(f"outbound «{tag}» сохранён", "success")
            push_activity("outbound", "Сохранён outbound", tag)
        else:
            flash(f"outbound сохранён, но xray не стартует: {msg}", "error")
        return redirect(url_for("config.outbounds_list"))
    except Exception as e:
        flash(f"ошибка: {e}", "error")
        return redirect(request.path)


@bp.route("/outbounds/<tag>/delete", methods=["POST"])
@login_required
def outbounds_delete(tag: str):
    if tag in ("direct", "block", "api", "metrics"):
        flash(f"служебный outbound «{tag}» нельзя удалить", "error")
        return redirect(url_for("config.outbounds_list"))
    obs = read_outbounds()
    new = [o for o in obs if o.get("tag") != tag]
    if len(new) == len(obs):
        flash(f"outbound «{tag}» не найден", "error")
        return redirect(url_for("config.outbounds_list"))
    for r in read_routing_rules():
        if r.get("outboundTag") == tag:
            flash(f"outbound «{tag}» используется в routing-правилах — сначала удалите их", "error")
            return redirect(url_for("config.outbounds_list"))
    write_outbounds(new)
    systemctl("restart")
    flash(f"outbound «{tag}» удалён", "success")
    push_activity("outbound", "Удалён outbound", tag)
    return redirect(url_for("config.outbounds_list"))


@bp.route("/outbounds/<tag>/toggle", methods=["POST"])
@login_required
def outbounds_toggle(tag: str):
    obs = read_outbounds()
    for o in obs:
        if o.get("tag") == tag:
            o["_enabled"] = not o.get("_enabled", True)
            break
    write_outbounds(obs)
    systemctl("restart")
    return redirect(url_for("config.outbounds_list"))


# ===== Routing =====

@bp.route("/routing")
@login_required
def routing_list():
    rules = read_routing_rules()
    rows = []
    for i, r in enumerate(rules):
        summary = rule_summary(r)
        summary["idx"] = i
        rows.append(summary)
    outbounds_available = [o.get("tag") for o in read_outbounds()]
    return render_template("routing.html",
                           rules=rows,
                           rules_count=len(rules),
                           outbounds=outbounds_available)


@bp.route("/routing/new", methods=["GET", "POST"])
@login_required
def routing_new():
    if request.method == "POST":
        return _routing_save(None)
    outbounds_available = [o.get("tag") for o in read_outbounds()]
    inbounds_available = [ib.get("tag") for ib in collect_inbounds() if ib.get("tag")]
    return render_template("routing_form.html",
                           mode="create", rule=None,
                           outbounds=outbounds_available,
                           inbounds=inbounds_available)


@bp.route("/routing/<int:idx>/edit", methods=["GET", "POST"])
@login_required
def routing_edit(idx: int):
    rules = read_routing_rules()
    if idx < 0 or idx >= len(rules):
        flash("правило не найдено", "error")
        return redirect(url_for("config.routing_list"))
    if request.method == "POST":
        return _routing_save(idx)
    r = rules[idx]
    view = {
        "domains": "\n".join(r.get("domain", [])) if isinstance(r.get("domain"), list) else "",
        "ips": "\n".join(r.get("ip", [])) if isinstance(r.get("ip"), list) else "",
        "ports": str(r.get("port", "")),
        "source_inbound": (r.get("inboundTag") or [""])[0] if isinstance(r.get("inboundTag"), list) else (r.get("inboundTag") or ""),
        "protocols": r.get("protocol", []) if isinstance(r.get("protocol"), list) else ([r["protocol"]] if r.get("protocol") else []),
        "outbound": r.get("outboundTag", "block"),
        "enabled": r.get("_enabled", True),
    }
    outbounds_available = [o.get("tag") for o in read_outbounds()]
    inbounds_available = [ib.get("tag") for ib in collect_inbounds() if ib.get("tag")]
    return render_template("routing_form.html",
                           mode="edit", rule=view, idx=idx,
                           outbounds=outbounds_available,
                           inbounds=inbounds_available)


def _routing_save(idx):
    try:
        rules = read_routing_rules()
        domains_raw = request.form.get("domains", "")
        ips_raw = request.form.get("ips", "")
        ports = request.form.get("ports", "").strip()
        source_inbound = request.form.get("source_inbound", "").strip()
        protocols = request.form.getlist("protocols")
        outbound = request.form.get("outbound", "").strip()
        enabled = request.form.get("enabled", "1") == "1"
        if not outbound:
            raise ValueError("Outbound (action) обязателен")
        domains = [s.strip() for s in domains_raw.splitlines() if s.strip()]
        ips = [s.strip() for s in ips_raw.splitlines() if s.strip()]

        rule: dict = {"type": "field"}
        if domains: rule["domain"] = domains
        if ips: rule["ip"] = ips
        if ports: rule["port"] = ports
        if source_inbound: rule["inboundTag"] = [source_inbound]
        if protocols: rule["protocol"] = protocols
        rule["outboundTag"] = outbound
        if not enabled: rule["_enabled"] = False
        if not (domains or ips or ports or source_inbound or protocols):
            raise ValueError("укажи хотя бы одно условие")
        if idx is None:
            rules.append(rule)
        else:
            if idx < 0 or idx >= len(rules):
                raise ValueError("правило не найдено")
            rules[idx] = rule
        write_routing_rules(rules)
        ok, msg = systemctl("restart")
        if ok:
            flash("правило сохранено", "success")
            push_activity("routing", "Сохранено правило", outbound)
        else:
            flash(f"правило сохранено, но xray не стартует: {msg}", "error")
        return redirect(url_for("config.routing_list"))
    except Exception as e:
        flash(f"ошибка: {e}", "error")
        return redirect(request.path)


@bp.route("/routing/<int:idx>/delete", methods=["POST"])
@login_required
def routing_delete(idx: int):
    rules = read_routing_rules()
    if 0 <= idx < len(rules):
        rules.pop(idx)
        write_routing_rules(rules)
        systemctl("restart")
        flash("правило удалено", "success")
        push_activity("routing", "Удалено правило", str(idx))
    return redirect(url_for("config.routing_list"))


@bp.route("/routing/<int:idx>/toggle", methods=["POST"])
@login_required
def routing_toggle(idx: int):
    rules = read_routing_rules()
    if 0 <= idx < len(rules):
        rules[idx]["_enabled"] = not rules[idx].get("_enabled", True)
        write_routing_rules(rules)
        systemctl("restart")
    if request.is_json or request.headers.get("Accept", "").startswith("application/json"):
        return jsonify({"ok": True})
    return redirect(url_for("config.routing_list"))

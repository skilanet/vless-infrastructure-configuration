"""Dashboard / Users / Connections / Logs / Alerts."""
from __future__ import annotations

import csv
import io
import uuid as uuid_module
from datetime import datetime, timedelta

from flask import (Blueprint, Response, abort, flash, jsonify, redirect,
                   render_template, request, send_file, session, url_for)

from ..auth import login_required
from ..activity import push_activity, read_activity
from ..alerts import evaluate_alerts, load_alerts_state, save_alerts_state
from ..config import ACCESS_LOG, ERROR_LOG
from ..geo import geo_lookup
from ..logs import (tail_file, parse_access_line, parse_error_line,
                    collect_recent_connections, aggregate_user_meta,
                    aggregate_top_cities, read_connections_per_hour)
from ..metrics import read_traffic_series, read_user_series
from ..stats import get_xray_stats, get_inbound_stats, get_system_stats
from ..state import (collect_inbounds, collect_users, collect_vless_inbounds,
                     get_user_by_uuid, list_config_files,
                     read_config_file, write_config_file,
                     validate_email, validate_uuid)
from ..system import (is_xray_active, systemctl, invalidate_xray_caches,
                      xray_version, xray_uptime, xray_pid)
from ..vless import collect_user_links, get_server_ip


bp = Blueprint("core", __name__)


@bp.route("/")
@login_required
def dashboard():
    inbounds = collect_inbounds()
    users = collect_users()
    stats = get_xray_stats()
    total_up = total_down = 0
    for u in users:
        s = stats.get(u["email"], {})
        u["uplink"] = s.get("uplink", 0)
        u["downlink"] = s.get("downlink", 0)
        total_up += u["uplink"]
        total_down += u["downlink"]
    top_users = sorted(users, key=lambda u: u["uplink"] + u["downlink"], reverse=True)[:5]
    sys_stats = get_system_stats()
    alerts = evaluate_alerts().get("active", [])
    activity = read_activity()
    vless_inbounds = [ib for ib in inbounds if ib.get("protocol") == "vless"]
    top_cities = aggregate_top_cities(collect_recent_connections(limit=500))
    inbound_rows = []
    for ib in inbounds:
        ss = ib.get("streamSettings", {}) or {}
        rs = ss.get("realitySettings", {}) or {}
        xs = ss.get("xhttpSettings", {}) or {}
        sns = rs.get("serverNames") or []
        is_service = ib.get("listen") == "127.0.0.1" or ib.get("protocol") != "vless"
        inbound_rows.append({
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
    return render_template("dashboard.html",
                           xray_active=is_xray_active(),
                           xray_version=xray_version(),
                           xray_uptime=xray_uptime(),
                           xray_pid=xray_pid(),
                           inbounds=inbound_rows,
                           vless_count=len(vless_inbounds),
                           service_count=len(inbounds) - len(vless_inbounds),
                           users=users,
                           users_count=len(users),
                           top_users=top_users,
                           total_up=total_up,
                           total_down=total_down,
                           config_count=len(list_config_files()),
                           sys_stats=sys_stats,
                           alerts=alerts,
                           activity=activity,
                           top_cities=top_cities,
                           traffic_series=read_traffic_series(hours=24))


# ===== Users =====

@bp.route("/users")
@login_required
def users_list():
    q = request.args.get("q", "").strip().lower()
    users = collect_users()
    stats = get_xray_stats()
    meta = aggregate_user_meta(collect_recent_connections(limit=500))
    total_up = total_down = 0
    online_count = 0
    for u in users:
        s = stats.get(u["email"], {})
        u["uplink"] = s.get("uplink", 0)
        u["downlink"] = s.get("downlink", 0)
        m = meta.get(u["email"], {})
        u["last_ts"] = m.get("last_ts")
        u["last_src"] = m.get("last_src")
        u["last_geo"] = m.get("geo", {})
        u["online"] = m.get("online", False)
        if u["online"]:
            online_count += 1
        total_up += u["uplink"]
        total_down += u["downlink"]
    if q:
        users = [u for u in users if q in u["email"].lower() or q in u["id"].lower()]
    avg = (total_up + total_down) // max(len(users), 1)
    return render_template("users.html",
                           users=users,
                           total=len(collect_users()),
                           filtered=len(users),
                           online_count=online_count,
                           total_up=total_up,
                           total_down=total_down,
                           avg=avg,
                           q=request.args.get("q", ""))


@bp.route("/users/new", methods=["GET", "POST"])
@login_required
def users_new():
    available_inbounds = collect_vless_inbounds()
    if request.method == "POST":
        try:
            email = validate_email(request.form.get("email", ""))
            uid = request.form.get("uuid", "").strip()
            uid = validate_uuid(uid) if uid else str(uuid_module.uuid4())
            selected = request.form.getlist("inbounds")
            if not selected:
                raise ValueError("выбери хотя бы один inbound")
            for u in collect_users():
                if u["email"] == email:
                    raise ValueError(f"юзер с email «{email}» уже существует")
            for f in list_config_files():
                data = read_config_file(f)
                modified = False
                for ib in data.get("inbounds", []):
                    if ib.get("protocol") != "vless":
                        continue
                    if ib.get("tag") not in selected:
                        continue
                    clients = ib.setdefault("settings", {}).setdefault("clients", [])
                    client = {"id": uid, "email": email, "level": 0}
                    if ib.get("streamSettings", {}).get("network") == "tcp":
                        client["flow"] = "xtls-rprx-vision"
                    clients.append(client)
                    modified = True
                if modified:
                    write_config_file(f, data)
            systemctl("restart")
            flash(f"юзер «{email}» создан", "success")
            push_activity("user", "Создан юзер", email)
            return redirect(url_for("core.users_list"))
        except Exception as e:
            flash(f"ошибка: {e}", "error")
    return render_template("user_form.html",
                           mode="create",
                           user=None,
                           available_inbounds=available_inbounds,
                           selected_inbounds=[ib.get("tag") for ib in available_inbounds])


@bp.route("/users/<uid>/edit", methods=["GET", "POST"])
@login_required
def users_edit(uid: str):
    user = get_user_by_uuid(uid)
    if not user:
        flash("юзер не найден", "error")
        return redirect(url_for("core.users_list"))
    available_inbounds = collect_vless_inbounds()
    if request.method == "POST":
        try:
            new_email = validate_email(request.form.get("email", ""))
            new_uid = request.form.get("uuid", "").strip()
            new_uid = validate_uuid(new_uid)
            selected = request.form.getlist("inbounds")
            if not selected:
                raise ValueError("выбери хотя бы один inbound")
            for other in collect_users():
                if other["id"] != uid and other["email"] == new_email:
                    raise ValueError(f"юзер с email «{new_email}» уже существует")
            old_uid = user["id"]
            for f in list_config_files():
                data = read_config_file(f)
                modified = False
                for ib in data.get("inbounds", []):
                    if ib.get("protocol") != "vless":
                        continue
                    tag = ib.get("tag")
                    clients = ib.setdefault("settings", {}).setdefault("clients", [])
                    existing_idx = next(
                        (i for i, c in enumerate(clients) if c.get("id") == old_uid),
                        None,
                    )
                    if tag in selected:
                        if existing_idx is not None:
                            clients[existing_idx]["id"] = new_uid
                            clients[existing_idx]["email"] = new_email
                        else:
                            new_client = {"id": new_uid, "email": new_email, "level": 0}
                            if ib.get("streamSettings", {}).get("network") == "tcp":
                                new_client["flow"] = "xtls-rprx-vision"
                            clients.append(new_client)
                        modified = True
                    else:
                        if existing_idx is not None:
                            clients.pop(existing_idx)
                            modified = True
                if modified:
                    write_config_file(f, data)
            systemctl("restart")
            flash(f"юзер «{new_email}» обновлён", "success")
            push_activity("user", "Изменён юзер", new_email)
            return redirect(url_for("core.users_detail", uid=new_uid))
        except Exception as e:
            flash(f"ошибка: {e}", "error")
    return render_template("user_form.html",
                           mode="edit",
                           user=user,
                           available_inbounds=available_inbounds,
                           selected_inbounds=user["inbounds"])


@bp.route("/users/<uid>")
@login_required
def users_detail(uid: str):
    user = get_user_by_uuid(uid)
    if not user:
        flash("юзер не найден", "error")
        return redirect(url_for("core.users_list"))
    stats = get_xray_stats().get(user["email"], {})
    user["uplink"] = stats.get("uplink", 0)
    user["downlink"] = stats.get("downlink", 0)
    items = collect_user_links(uid)
    recent = [c for c in collect_recent_connections(limit=300)
              if c.get("user") == user["email"]][:10]
    for c in recent:
        info = geo_lookup(c.get("src"))
        c["geo_city"] = info.get("city")
        c["geo_flag"] = info.get("flag", "🌐")
    last_seen = recent[0]["ts"] if recent else None
    last_ip = recent[0]["src"] if recent else None
    last_geo = geo_lookup(last_ip) if last_ip else {}
    return render_template("user_detail.html",
                           user=user,
                           items=items,
                           recent=recent,
                           last_seen=last_seen,
                           last_ip=last_ip,
                           last_geo=last_geo,
                           traffic_series=read_user_series(user["email"], hours=24),
                           server_ip=get_server_ip())


@bp.route("/users/<uid>/delete", methods=["POST"])
@login_required
def users_delete(uid: str):
    user = get_user_by_uuid(uid)
    if not user:
        flash("юзер не найден", "error")
        return redirect(url_for("core.users_list"))
    removed = 0
    for f in list_config_files():
        data = read_config_file(f)
        modified = False
        for ib in data.get("inbounds", []):
            clients = ib.get("settings", {}).get("clients", [])
            new_clients = [c for c in clients if c.get("id") != uid]
            if len(new_clients) != len(clients):
                ib["settings"]["clients"] = new_clients
                removed += len(clients) - len(new_clients)
                modified = True
        if modified:
            write_config_file(f, data)
    if removed > 0:
        systemctl("restart")
        flash(f"юзер «{user['email']}» удалён из {removed} inbound'ов", "success")
        push_activity("user", "Удалён юзер", user["email"])
    return redirect(url_for("core.users_list"))


# ===== Connections =====

@bp.route("/connections")
@login_required
def connections_list():
    period = request.args.get("period", "today")
    user_f = request.args.get("user", "")
    inbound_f = request.args.get("inbound", "")
    status_f = request.args.get("status", "")
    ip_f = request.args.get("ip", "").strip()

    all_conns = collect_recent_connections(limit=500)
    if user_f:
        all_conns = [c for c in all_conns if c.get("user") == user_f]
    if inbound_f:
        all_conns = [c for c in all_conns if c.get("inbound") == inbound_f]
    if status_f:
        all_conns = [c for c in all_conns if c.get("kind") == status_f]
    if ip_f:
        all_conns = [c for c in all_conns if ip_f in (c.get("src") or "")]
    for c in all_conns:
        info = geo_lookup(c.get("src"))
        c["geo_city"] = info.get("city")
        c["geo_country"] = info.get("country")
        c["geo_flag"] = info.get("flag", "🌐")

    users = sorted({u["email"] for u in collect_users()})
    inbounds = sorted({ib.get("tag") for ib in collect_vless_inbounds() if ib.get("tag")})

    if request.args.get("export") == "csv":
        sio = io.StringIO()
        w = csv.writer(sio)
        w.writerow(["timestamp", "src", "dst", "user", "inbound", "outbound", "kind",
                    "geo_country", "geo_city"])
        for c in all_conns:
            w.writerow([c.get("ts", ""), c.get("src", ""), c.get("dst", ""),
                        c.get("user", ""), c.get("inbound", ""),
                        c.get("outbound", ""), c.get("kind", ""),
                        c.get("geo_country", ""), c.get("geo_city", "")])
        return Response(sio.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition":
                                 "attachment; filename=connections.csv"})

    return render_template("connections.html",
                           connections=all_conns,
                           users=users,
                           inbounds=inbounds,
                           hourly=read_connections_per_hour(hours=24),
                           period=period,
                           f_user=user_f,
                           f_inbound=inbound_f,
                           f_status=status_f,
                           f_ip=ip_f)


# ===== Logs =====

@bp.route("/logs")
@login_required
def logs_view():
    kind = request.args.get("kind", "access")
    if kind not in ("access", "error"):
        kind = "access"
    if request.args.get("download") == "1":
        path = ACCESS_LOG if kind == "access" else ERROR_LOG
        if not path.exists():
            abort(404)
        return send_file(str(path), as_attachment=True,
                         download_name=f"{kind}.log")
    return render_template("logs.html",
                           kind=kind,
                           access_path=str(ACCESS_LOG),
                           error_path=str(ERROR_LOG))


# ===== Alerts =====

@bp.route("/alerts")
@login_required
def alerts_view():
    state = evaluate_alerts()
    active = [a for a in state.get("active", [])
              if isinstance(a, dict) and a.get("id") and a.get("title")]
    history = [h for h in state.get("history", []) if isinstance(h, dict)]
    return render_template("alerts.html",
                           active=active,
                           history=list(reversed(history[-50:])))


@bp.route("/alerts/<alert_id>/ack", methods=["POST"])
@login_required
def alerts_ack(alert_id: str):
    state = load_alerts_state()
    target = next((a for a in state["active"] if a["id"] == alert_id), None)
    if target:
        state["history"].append({
            "t": datetime.now().isoformat(timespec="seconds"),
            "sev": target.get("severity", "warning"),
            "title": target.get("title", alert_id),
            "status": "Acknowledged",
            "by": session.get("login", "admin"),
        })
        state["active"] = [a for a in state["active"] if a["id"] != alert_id]
        save_alerts_state(state)
        flash("алёрт подтверждён", "success")
    return redirect(url_for("core.alerts_view"))


@bp.route("/alerts/<alert_id>/dismiss", methods=["POST"])
@login_required
def alerts_dismiss(alert_id: str):
    state = load_alerts_state()
    target = next((a for a in state["active"] if a["id"] == alert_id), None)
    if target:
        state["history"].append({
            "t": datetime.now().isoformat(timespec="seconds"),
            "sev": target.get("severity", "warning"),
            "title": target.get("title", alert_id),
            "status": "Dismissed",
            "by": session.get("login", "admin"),
        })
        state["active"] = [a for a in state["active"] if a["id"] != alert_id]
        save_alerts_state(state)
        flash("алёрт скрыт", "info")
    return redirect(url_for("core.alerts_view"))


@bp.route("/alerts/<alert_id>/snooze", methods=["POST"])
@login_required
def alerts_snooze(alert_id: str):
    state = load_alerts_state()
    target = next((a for a in state["active"] if a["id"] == alert_id), None)
    if target:
        until = datetime.now() + timedelta(hours=1)
        state.setdefault("snoozed", {})[alert_id] = until.isoformat(timespec="seconds")
        state["active"] = [a for a in state["active"] if a["id"] != alert_id]
        save_alerts_state(state)
        flash("алёрт отложен на 1 час", "info")
    return redirect(url_for("core.alerts_view"))

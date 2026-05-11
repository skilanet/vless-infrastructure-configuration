"""Settings и system start/stop/restart."""
from __future__ import annotations

import json
import tarfile
from datetime import datetime
from pathlib import Path

from flask import (Blueprint, abort, flash, redirect, render_template,
                   request, send_file, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import requests  # type: ignore
except ImportError:
    requests = None  # type: ignore

from ..activity import push_activity
from ..alerts import load_alerts_state, save_alerts_state
from ..auth import login_required
from ..config import (ALERTS_FILE, BACKUPS_DIR, CONFIG_DIR, CONFIG_FILE,
                      DEFAULT_API_PORT, DEFAULT_METRICS_PORT,
                      DEFAULT_SOCKS_PORT, DEFAULT_THRESHOLDS,
                      GEOIP_FILE, GEOSITE_FILE,
                      get_panel_config, save_panel_config)
from ..geo import geo_metadata, reset_reader as reset_geo_reader
from ..state import write_config_file
from ..system import invalidate_xray_caches, is_xray_active, systemctl
from ..templates_base import (base_config_template, base_infra_status,
                              outbounds_config_template,
                              routing_config_template,
                              service_inbounds_template)


bp = Blueprint("sys", __name__)


@bp.route("/settings")
@login_required
def settings():
    tab = request.args.get("tab", "infra")
    state = load_alerts_state()
    notify = get_panel_config().get("notify", {})
    geoip_info = {
        "exists": GEOIP_FILE.exists(),
        "size": GEOIP_FILE.stat().st_size if GEOIP_FILE.exists() else 0,
        "mtime": datetime.fromtimestamp(GEOIP_FILE.stat().st_mtime).isoformat(timespec="seconds")
                 if GEOIP_FILE.exists() else None,
        "geosite_exists": GEOSITE_FILE.exists(),
        "geosite_size": GEOSITE_FILE.stat().st_size if GEOSITE_FILE.exists() else 0,
    }
    backups = []
    if BACKUPS_DIR.exists():
        for f in sorted(BACKUPS_DIR.glob("backup-*.tar.gz"), reverse=True):
            try:
                backups.append({
                    "name": f.name,
                    "size": f.stat().st_size,
                    "mtime": datetime.fromtimestamp(f.stat().st_mtime),
                })
            except OSError:
                continue
    return render_template("settings.html",
                           tab=tab,
                           files=base_infra_status(),
                           xray_active=is_xray_active(),
                           api_port=DEFAULT_API_PORT,
                           metrics_port=DEFAULT_METRICS_PORT,
                           socks_port=DEFAULT_SOCKS_PORT,
                           thresholds=state.get("thresholds", DEFAULT_THRESHOLDS),
                           threshold_defs=DEFAULT_THRESHOLDS,
                           notify=notify,
                           geoip=geoip_info,
                           mmdb=geo_metadata(),
                           backups=backups[:10])


@bp.route("/settings/bootstrap", methods=["POST"])
@login_required
def settings_bootstrap():
    overwrite = request.form.get("overwrite") == "1"
    targets = {
        "00-base.json": base_config_template(),
        "01-routing.json": routing_config_template(),
        "02-outbounds.json": outbounds_config_template(),
        "10-service-inbounds.json": service_inbounds_template(),
    }
    written, skipped = [], []
    for name, data in targets.items():
        path = CONFIG_DIR / name
        if path.exists() and not overwrite:
            skipped.append(name)
            continue
        write_config_file(path, data)
        written.append(name)
    if written:
        ok, msg = systemctl("restart")
        if ok:
            flash(f"созданы: {', '.join(written)}; xray перезапущен", "success")
        else:
            flash(f"созданы: {', '.join(written)}, но xray не стартует: {msg}", "error")
        push_activity("infra", "Пересоздана базовая инфраструктура", ", ".join(written))
    if skipped:
        flash(f"пропущены: {', '.join(skipped)}", "info")
    if not written and not skipped:
        flash("ничего не записано", "info")
    return redirect(url_for("sys.settings", tab="infra"))


@bp.route("/settings/thresholds", methods=["POST"])
@login_required
def settings_thresholds():
    state = load_alerts_state()
    thr = state.setdefault("thresholds", DEFAULT_THRESHOLDS)
    for key in DEFAULT_THRESHOLDS:
        try:
            warn = float(request.form.get(f"{key}_warn", thr.get(key, {}).get("warn", 0)))
            crit = float(request.form.get(f"{key}_crit", thr.get(key, {}).get("crit", 0)))
            thr[key] = {
                "warn": warn, "crit": crit,
                "unit": DEFAULT_THRESHOLDS[key].get("unit", ""),
                "label": DEFAULT_THRESHOLDS[key].get("label", key),
            }
        except (TypeError, ValueError):
            pass
    save_alerts_state(state)
    flash("пороги обновлены", "success")
    push_activity("settings", "Обновлены пороги алёртов")
    return redirect(url_for("sys.settings", tab="thresholds"))


@bp.route("/settings/notify", methods=["POST"])
@login_required
def settings_notify():
    cfg = get_panel_config()
    notify = cfg.setdefault("notify", {})
    notify["telegram_enabled"] = request.form.get("telegram_enabled") == "1"
    notify["telegram_token"] = request.form.get("telegram_token", "").strip()
    notify["telegram_chat_id"] = request.form.get("telegram_chat_id", "").strip()
    notify["send_xray_stopped"] = request.form.get("send_xray_stopped") == "1"
    notify["send_critical"] = request.form.get("send_critical") == "1"
    notify["send_warning"] = request.form.get("send_warning") == "1"
    notify["send_user_added"] = request.form.get("send_user_added") == "1"
    notify["send_failed_login"] = request.form.get("send_failed_login") == "1"
    try:
        save_panel_config()
        flash("настройки нотификаций сохранены", "success")
        push_activity("settings", "Обновлены настройки нотификаций")
    except OSError as e:
        flash(f"ошибка записи config.json: {e}", "error")
    return redirect(url_for("sys.settings", tab="notify"))


@bp.route("/settings/notify/test", methods=["POST"])
@login_required
def settings_notify_test():
    if requests is None:
        flash("модуль requests не установлен", "error")
        return redirect(url_for("sys.settings", tab="notify"))
    notify = get_panel_config().get("notify", {})
    token = notify.get("telegram_token", "")
    chat_id = notify.get("telegram_chat_id", "")
    if not token or not chat_id:
        flash("сначала укажи token и chat_id и сохрани", "error")
        return redirect(url_for("sys.settings", tab="notify"))
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": "xray-admin: тестовое сообщение ✅"},
            timeout=8,
        )
        if r.ok:
            flash("отправлено в Telegram", "success")
        else:
            flash(f"Telegram вернул {r.status_code}: {r.text[:200]}", "error")
    except Exception as e:
        flash(f"ошибка: {e}", "error")
    return redirect(url_for("sys.settings", tab="notify"))


@bp.route("/settings/geoip/update", methods=["POST"])
@login_required
def settings_geoip_update():
    if requests is None:
        flash("модуль requests не установлен", "error")
        return redirect(url_for("sys.settings", tab="geoip"))
    urls = {
        "geoip.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
        "geosite.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    }
    updated = []
    for name, url in urls.items():
        target = GEOIP_FILE.parent / name
        try:
            r = requests.get(url, timeout=60, stream=True)
            if not r.ok:
                flash(f"скачивание {name} вернуло {r.status_code}", "error")
                continue
            tmp = target.with_suffix(".tmp")
            with tmp.open("wb") as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
            tmp.replace(target)
            updated.append(name)
        except Exception as e:
            flash(f"ошибка скачивания {name}: {e}", "error")
    if updated:
        ok, msg = systemctl("restart")
        if ok:
            flash(f"обновлены: {', '.join(updated)}; xray перезапущен", "success")
        else:
            flash(f"скачаны: {', '.join(updated)}, но xray не стартует: {msg}", "error")
        push_activity("settings", "Обновлена GeoIP-база", ", ".join(updated))
    return redirect(url_for("sys.settings", tab="geoip"))


@bp.route("/settings/mmdb/update", methods=["POST"])
@login_required
def settings_mmdb_update():
    """Качаем GeoLite2-City.mmdb из публичного зеркала P3TERX/GeoLite.mmdb
    (github, без регистрации, ежедневный auto-update)."""
    if requests is None:
        flash("модуль requests не установлен", "error")
        return redirect(url_for("sys.settings", tab="geoip"))
    target = Path("/var/lib/xray-admin/GeoLite2-City.mmdb")
    url = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"
    try:
        r = requests.get(url, timeout=120, stream=True,
                         allow_redirects=True,
                         headers={"User-Agent": "xray-admin-panel"})
        if not r.ok:
            flash(f"скачивание вернуло HTTP {r.status_code}", "error")
            return redirect(url_for("sys.settings", tab="geoip"))
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        with tmp.open("wb") as f:
            for chunk in r.iter_content(65536):
                f.write(chunk)
        tmp.replace(target)
        reset_geo_reader()
        flash(f"GeoLite2-City.mmdb обновлён ({target.stat().st_size // 1024} KB)", "success")
        push_activity("settings", "Обновлена GeoLite2-City.mmdb",
                      "из P3TERX/GeoLite.mmdb")
    except Exception as e:
        flash(f"ошибка скачивания: {e}", "error")
    return redirect(url_for("sys.settings", tab="geoip"))


@bp.route("/settings/backup/create", methods=["POST"])
@login_required
def settings_backup_create():
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = BACKUPS_DIR / f"backup-{ts}.tar.gz"
    try:
        with tarfile.open(target, "w:gz") as tar:
            if CONFIG_DIR.exists():
                tar.add(CONFIG_DIR, arcname="conf.d")
            if CONFIG_FILE.exists():
                tar.add(CONFIG_FILE, arcname="admin-config.json")
            if ALERTS_FILE.exists():
                tar.add(ALERTS_FILE, arcname="alerts.json")
        flash(f"backup создан: {target.name}", "success")
        push_activity("backup", "Создан backup", target.name)
    except Exception as e:
        flash(f"ошибка создания backup: {e}", "error")
    return redirect(url_for("sys.settings", tab="backup"))


@bp.route("/settings/backup/<name>")
@login_required
def settings_backup_download(name: str):
    if "/" in name or ".." in name:
        abort(400)
    target = BACKUPS_DIR / name
    if not target.exists():
        abort(404)
    return send_file(str(target), as_attachment=True, download_name=name)


@bp.route("/settings/backup/restore", methods=["POST"])
@login_required
def settings_backup_restore():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("файл не выбран", "error")
        return redirect(url_for("sys.settings", tab="backup"))
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = BACKUPS_DIR / f"restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    file.save(str(tmp))
    try:
        snap_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        pre_snapshot = BACKUPS_DIR / f"pre-restore-{snap_ts}.tar.gz"
        with tarfile.open(pre_snapshot, "w:gz") as tar:
            if CONFIG_DIR.exists():
                tar.add(CONFIG_DIR, arcname="conf.d")
        with tarfile.open(tmp, "r:gz") as tar:
            for m in tar.getmembers():
                if "/.." in m.name or m.name.startswith("/"):
                    raise ValueError("backup содержит подозрительные пути")
            for m in tar.getmembers():
                if m.name.startswith("conf.d/"):
                    tar.extract(m, str(CONFIG_DIR.parent))
        ok, msg = systemctl("restart")
        if ok:
            flash(f"восстановлено; pre-restore snapshot: {pre_snapshot.name}", "success")
            push_activity("backup", "Восстановлен backup", file.filename)
        else:
            flash(f"восстановлено, но xray не стартует: {msg}", "error")
    except Exception as e:
        flash(f"ошибка восстановления: {e}", "error")
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    return redirect(url_for("sys.settings", tab="backup"))


@bp.route("/settings/password", methods=["POST"])
@login_required
def settings_password():
    cfg = get_panel_config()
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    confirm = request.form.get("confirm", "")
    if not check_password_hash(cfg["admin_password_hash"], current):
        flash("текущий пароль неверный", "error")
        return redirect(url_for("sys.settings", tab="admin"))
    if len(new) < 8:
        flash("новый пароль должен быть не короче 8 символов", "error")
        return redirect(url_for("sys.settings", tab="admin"))
    if new != confirm:
        flash("новый пароль и подтверждение не совпадают", "error")
        return redirect(url_for("sys.settings", tab="admin"))
    cfg["admin_password_hash"] = generate_password_hash(new)
    try:
        save_panel_config()
        flash("пароль изменён", "success")
        push_activity("settings", "Изменён пароль панели")
    except OSError as e:
        flash(f"ошибка записи: {e}", "error")
    return redirect(url_for("sys.settings", tab="admin"))


# ===== System control =====

@bp.route("/system/restart", methods=["POST"])
@login_required
def system_restart():
    ok, msg = systemctl("restart")
    invalidate_xray_caches()
    flash("xray перезапущен" if ok else f"ошибка: {msg}", "success" if ok else "error")
    push_activity("xray", "xray перезапущен")
    return redirect(request.referrer or url_for("core.dashboard"))


@bp.route("/system/start", methods=["POST"])
@login_required
def system_start():
    ok, msg = systemctl("start")
    invalidate_xray_caches()
    flash("xray запущен" if ok else f"ошибка: {msg}", "success" if ok else "error")
    push_activity("xray", "xray запущен")
    return redirect(request.referrer or url_for("core.dashboard"))


@bp.route("/system/stop", methods=["POST"])
@login_required
def system_stop():
    ok, msg = systemctl("stop")
    invalidate_xray_caches()
    flash("xray остановлен" if ok else f"ошибка: {msg}", "success" if ok else "error")
    push_activity("xray", "xray остановлен")
    return redirect(request.referrer or url_for("core.dashboard"))


@bp.route("/health")
def health():
    return {"status": "ok", "xray": is_xray_active()}

"""Entry-point. gunicorn запускается с `app:app` — фабрика собирает приложение
из пакета xray_admin/."""
from xray_admin import create_app

app = create_app()


if __name__ == "__main__":
    from xray_admin.config import get_panel_config
    cfg = get_panel_config()
    app.run(host=cfg.get("host", "0.0.0.0"),
            port=cfg.get("port", 8088),
            debug=False)

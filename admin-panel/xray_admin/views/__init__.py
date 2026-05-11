"""Регистрация всех blueprints."""
from flask import Flask

from . import auth as _auth
from . import core as _core
from . import config as _config
from . import system as _system
from . import api as _api


def register_blueprints(app: Flask):
    app.register_blueprint(_auth.bp)
    app.register_blueprint(_core.bp)
    app.register_blueprint(_config.bp)
    app.register_blueprint(_system.bp)
    app.register_blueprint(_api.bp)

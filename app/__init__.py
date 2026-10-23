"""Northstar Cybersecurity Program Platform - application factory."""
import logging
from datetime import timedelta
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from .config import Config
from .db import close_db, init_schema
from .security import ApiError, check_csrf, register_error_handlers

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


def create_app(overrides=None):
    cfg = Config(overrides)
    cfg.ensure_dirs()
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=cfg.SECRET_KEY, DATABASE=str(cfg.DATABASE), UPLOAD_DIR=str(cfg.UPLOAD_DIR),
        MAX_CONTENT_LENGTH=cfg.MAX_UPLOAD_MB * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=(cfg.ENVIRONMENT == "production"),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=cfg.SESSION_HOURS), JSON_SORT_KEYS=False,
        MAX_FAILED_LOGINS=cfg.MAX_FAILED_LOGINS, LOCKOUT_MINUTES=cfg.LOCKOUT_MINUTES,
        LOGIN_RATE_PER_MIN=cfg.LOGIN_RATE_PER_MIN, ENVIRONMENT=cfg.ENVIRONMENT,
    )
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    init_schema(app.config["DATABASE"])
    from .seed import seed_all
    seed_all(app.config["DATABASE"], with_demo=cfg.SEED_DEMO_DATA)
    _seed_users(app, cfg)

    app.teardown_appcontext(close_db)
    register_error_handlers(app)

    from .routes import register_blueprints
    register_blueprints(app)

    @app.before_request
    def _csrf():
        if request.path.startswith("/api/"):
            check_csrf()

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if "Content-Security-Policy" not in resp.headers:
            resp.headers["Content-Security-Policy"] = CSP
        resp.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "no-cache"
        return resp

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/<path:path>")
    def static_files(path):
        if path.startswith("api/"):
            raise ApiError(404, "NOT_FOUND", "Resource not found.")
        return send_from_directory(STATIC_DIR, path)

    return app


def _seed_users(app, cfg):
    import sqlite3
    from werkzeug.security import generate_password_hash
    from .db import connect_standalone, now_iso
    conn = connect_standalone(app.config["DATABASE"])
    try:
        if cfg.SEED_DEMO_USERS and conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            pw = generate_password_hash(cfg.DEMO_PASSWORD)
            for u, n, r in (("admin", "Priya Sharma (CISO)", "admin"), ("analyst", "Arjun Mehta (Security analyst)", "analyst"),
                            ("auditor", "Neha Rao (Audit lead)", "auditor"), ("viewer", "Executive Sponsor", "viewer")):
                conn.execute("INSERT INTO users(username,full_name,password_hash,role,active,created_at) VALUES(?,?,?,?,1,?)",
                             (u, n, pw, r, now_iso()))
            conn.commit()
    finally:
        conn.close()

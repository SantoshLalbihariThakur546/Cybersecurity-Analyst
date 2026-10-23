"""Configuration (environment variables override defaults)."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]


def _bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


class Config:
    def __init__(self, overrides=None):
        env = os.environ.get
        self.DATA_DIR = Path(env("DATA_DIR", str(BASE_DIR / "data")))
        self.DATABASE = env("DATABASE", str(self.DATA_DIR / "northstar.db"))
        self.UPLOAD_DIR = Path(env("UPLOAD_DIR", str(self.DATA_DIR / "evidence")))
        self.ENVIRONMENT = env("APP_ENV", "development")
        self.SEED_DEMO_USERS = _bool("SEED_DEMO_USERS", True)
        self.SEED_DEMO_DATA = _bool("SEED_DEMO_DATA", True)
        self.DEMO_PASSWORD = env("DEMO_PASSWORD", "Northstar!2026")
        self.SESSION_HOURS = int(env("SESSION_HOURS", "8"))
        self.MAX_FAILED_LOGINS = int(env("MAX_FAILED_LOGINS", "5"))
        self.LOCKOUT_MINUTES = int(env("LOCKOUT_MINUTES", "15"))
        self.MAX_UPLOAD_MB = int(env("MAX_UPLOAD_MB", "5"))
        self.LOGIN_RATE_PER_MIN = int(env("LOGIN_RATE_PER_MIN", "30"))
        self.SECRET_KEY = env("SECRET_KEY", "")
        for k, v in (overrides or {}).items():
            setattr(self, k, v)
        self.DATA_DIR = Path(self.DATA_DIR)
        self.UPLOAD_DIR = Path(self.UPLOAD_DIR)

    def ensure_dirs(self):
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.UPLOAD_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.SECRET_KEY:
            keyfile = self.DATA_DIR / "secret.key"
            if not keyfile.exists():
                keyfile.write_text(secrets.token_hex(32))
                try:
                    keyfile.chmod(0o600)
                except OSError:
                    pass
            self.SECRET_KEY = keyfile.read_text().strip()
        if self.ENVIRONMENT == "production" and self.SEED_DEMO_USERS:
            raise RuntimeError("SEED_DEMO_USERS must be false when APP_ENV=production")

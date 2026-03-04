"""Application configuration."""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY           = os.environ.get("SECRET_KEY", "replace-this-in-production-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'hospital.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session
    SESSION_COOKIE_HTTPONLY  = True
    SESSION_COOKIE_SAMESITE  = "Lax"
    REMEMBER_COOKIE_DURATION = 3600   # 1 hour

    # Crypto
    # Key rotation policy: keys older than KEY_MAX_AGE_DAYS are flagged for rotation
    KEY_MAX_AGE_DAYS = 90

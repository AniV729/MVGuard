"""
SecureHealth PQC — Main Application Entry Point
================================================
A post-quantum encrypted patient records system for hospitals, using
Unbalanced Oil-and-Vinegar (UOV) multivariate cryptography over GF(256).

Run:
    python main.py

First run will:
  1. Create the SQLite database at instance/hospital.db
  2. Prompt you to create the first admin account (or set env vars)

Environment Variables:
  SECRET_KEY   – Flask session secret (override with a random 32-byte string!)
  DATABASE_URL – SQLAlchemy DB URI (e.g. postgresql://user:pass@host/db)
  ADMIN_USER   – Username for auto-created admin (default: admin)
  ADMIN_PASS   – Password for auto-created admin (default: ChangeMe!123)
  ADMIN_EMAIL  – Email for auto-created admin
"""

import os
import logging
from flask import Flask
from flask_login import LoginManager

from config import Config
from models import db, User
from routes import auth_bp, patients_bp, admin_bp


def create_app(config_class=Config) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    # Ensure the instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)

    # ── Extensions ────────────────────────────────────────────────────────
    db.init_app(app)

    login_manager = LoginManager(app)
    login_manager.login_view          = "auth.login"
    login_manager.login_message       = "Please sign in to access this page."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── Blueprints ────────────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(patients_bp)
    app.register_blueprint(admin_bp)

    # ── DB init + first-run admin seed ────────────────────────────────────
    with app.app_context():
        db.create_all()
        _seed_admin(app)

    return app


def _seed_admin(app: Flask):
    """Create the initial admin account (and its UOV key pair) if no users exist."""
    if User.query.count() > 0:
        return

    from crypto.uov import generate_keypair, serialize_key
    from models import EncryptionKey

    username  = os.environ.get("ADMIN_USER",  "admin")
    password  = os.environ.get("ADMIN_PASS",  "ChangeMe!123")
    email     = os.environ.get("ADMIN_EMAIL", "admin@hospital.local")
    full_name = "System Administrator"

    app.logger.info("=== First run: creating admin account ===")
    admin = User(
        username   = username,
        email      = email,
        full_name  = full_name,
        role       = Role.ADMIN,
        department = "IT Security",
    )
    admin.set_password(password)
    db.session.add(admin)
    db.session.flush()

    app.logger.info("Generating UOV key pair for admin (this may take ~10s)…")
    public_key, private_key = generate_keypair()
    enc_key = EncryptionKey(
        user_id         = admin.id,
        key_label       = f"{username}-uov-key-1",
        public_key_b64  = serialize_key(public_key),
        private_key_b64 = serialize_key(private_key),
        algorithm       = "UOV-GF256-v12-o8",
    )
    db.session.add(enc_key)
    db.session.commit()

    app.logger.warning(
        f"\n{'='*55}\n"
        f"  Admin account created:\n"
        f"    Username : {username}\n"
        f"    Password : {password}\n"
        f"  CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION!\n"
        f"{'='*55}"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    application = create_app()
    application.run(
        host    = "127.0.0.1",
        port    = 5000,
        debug   = True,
        use_reloader = False,   # Reloader would regenerate keys on each reload
    )

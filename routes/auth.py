"""
Authentication Routes
=====================
  GET/POST  /login
  POST      /logout
  GET/POST  /register        (admin only)
"""

from datetime import datetime
from flask import render_template, redirect, url_for, request, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user

from . import auth_bp
from models import db, User, EncryptionKey, AccessLog, Role
from crypto.uov import generate_keypair, serialize_key


def _log(action: str, detail: str = ""):
    log = AccessLog(
        user_id    = current_user.id if current_user.is_authenticated else 0,
        action     = action,
        detail     = detail,
        ip_address = request.remote_addr,
        user_agent = request.user_agent.string[:256],
        user_role  = current_user.role if current_user.is_authenticated else None,
    )
    db.session.add(log)
    db.session.commit()


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@auth_bp.route("/", methods=["GET"])
def index():
    if current_user.is_authenticated:
        return redirect(url_for("patients.dashboard"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("patients.dashboard"))
    # No users at all → first-run setup
    if User.query.count() == 0:
        return redirect(url_for("auth.setup"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(username=username).first()

        if user and user.is_active and user.check_password(password):
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()

            log = AccessLog(
                user_id    = user.id,
                action     = "login",
                detail     = f"Successful login from {request.remote_addr}",
                ip_address = request.remote_addr,
                user_agent = request.user_agent.string[:256],
                user_role  = user.role,
            )
            db.session.add(log)
            db.session.commit()

            next_page = request.args.get("next")
            return redirect(next_page or url_for("patients.dashboard"))
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    _log("logout")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# Register (admin-only)
# ---------------------------------------------------------------------------

@auth_bp.route("/register", methods=["GET", "POST"])
@login_required
def register():
    if not current_user.is_admin:
        flash("Access denied — admin only.", "danger")
        return redirect(url_for("patients.dashboard"))

    error = None
    if request.method == "POST":
        username   = request.form.get("username", "").strip()
        email      = request.form.get("email", "").strip()
        full_name  = request.form.get("full_name", "").strip()
        role       = request.form.get("role", Role.NURSE)
        department = request.form.get("department", "").strip()
        password   = request.form.get("password", "")
        confirm    = request.form.get("confirm_password", "")

        if not all([username, email, full_name, password]):
            error = "All fields are required."
        elif password != confirm:
            error = "Passwords do not match."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif User.query.filter_by(username=username).first():
            error = "Username already taken."
        elif User.query.filter_by(email=email).first():
            error = "Email already registered."
        elif role not in Role.ALL:
            error = "Invalid role."
        else:
            user = User(
                username   = username,
                email      = email,
                full_name  = full_name,
                role       = role,
                department = department,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.flush()   # get user.id before key generation

            # Generate UOV key pair for this user
            current_app.logger.info(f"Generating UOV key pair for new user '{username}'…")
            public_key, private_key = generate_keypair()
            enc_key = EncryptionKey(
                user_id        = user.id,
                key_label      = f"{username}-uov-key-1",
                public_key_b64  = serialize_key(public_key),
                private_key_b64 = serialize_key(private_key),
                algorithm      = "UOV-GF256-v12-o8",
            )
            db.session.add(enc_key)
            db.session.commit()

            _log("create",  f"Registered new user '{username}' with role '{role}'")
            flash(f"Account created for {full_name}. UOV key pair generated.", "success")
            return redirect(url_for("admin.users"))

    return render_template("register.html", roles=Role.ALL, error=error)


# ---------------------------------------------------------------------------
# First-run setup  (only accessible when DB has zero users)
# ---------------------------------------------------------------------------

@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    """One-time admin account creation. Redirects away once any user exists."""
    if User.query.count() > 0:
        flash("Setup is already complete. Please log in.", "info")
        return redirect(url_for("auth.login"))

    error = None
    if request.method == "POST":
        username  = request.form.get("username", "").strip()
        email     = request.form.get("email", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password  = request.form.get("password", "")
        confirm   = request.form.get("confirm_password", "")

        if not all([username, email, full_name, password]):
            error = "All fields are required."
        elif password != confirm:
            error = "Passwords do not match."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        else:
            admin = User(
                username   = username,
                email      = email,
                full_name  = full_name,
                role       = Role.ADMIN,
                department = "Administration",
            )
            admin.set_password(password)
            db.session.add(admin)
            db.session.flush()

            current_app.logger.info(f"First-run setup: generating UOV key pair for '{username}'…")
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

            flash("Admin account created. Welcome to SecureHealth!", "success")
            return redirect(url_for("auth.login"))

    return render_template("setup.html", error=error)

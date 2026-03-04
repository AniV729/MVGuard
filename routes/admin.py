"""
Admin Routes
============
  GET   /admin/                – admin dashboard (anomaly summary, key status)
  GET   /admin/users           – list all users
  POST  /admin/users/<id>/toggle  – activate / deactivate user
  GET   /admin/logs            – full access log browser
  GET   /admin/logs/anomalies  – flagged anomalies only
  POST  /admin/users/<id>/rotate-key  – regenerate UOV key pair for a user
"""

from datetime import datetime
from flask import render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user

from . import admin_bp
from models import db, User, EncryptionKey, AccessLog, Patient
from crypto.uov import generate_keypair, serialize_key
from ai.anomaly import get_detector


def _require_admin():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("patients.dashboard"))
    return None


# ---------------------------------------------------------------------------
# Admin Dashboard
# ---------------------------------------------------------------------------

@admin_bp.route("/")
@login_required
def dashboard():
    redir = _require_admin()
    if redir:
        return redir

    total_users     = User.query.count()
    total_patients  = Patient.query.count()
    total_logs      = AccessLog.query.count()
    anomaly_count   = AccessLog.query.filter_by(is_anomalous=True).count()
    recent_anomalies = (AccessLog.query
                         .filter_by(is_anomalous=True)
                         .order_by(AccessLog.timestamp.desc())
                         .limit(10).all())
    keys_status     = EncryptionKey.query.all()

    return render_template(
        "admin.html",
        total_users      = total_users,
        total_patients   = total_patients,
        total_logs       = total_logs,
        anomaly_count    = anomaly_count,
        recent_anomalies = recent_anomalies,
        keys_status      = keys_status,
    )


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------

@admin_bp.route("/users")
@login_required
def users():
    redir = _require_admin()
    if redir:
        return redir
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=all_users)


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
def toggle_user(user_id):
    redir = _require_admin()
    if redir:
        return redir
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("admin.users"))
    user.is_active = not user.is_active
    db.session.commit()
    state = "activated" if user.is_active else "deactivated"
    flash(f"User {user.username} has been {state}.", "success")
    return redirect(url_for("admin.users"))


# ---------------------------------------------------------------------------
# Key Rotation
# ---------------------------------------------------------------------------

@admin_bp.route("/users/<int:user_id>/rotate-key", methods=["POST"])
@login_required
def rotate_key(user_id):
    redir = _require_admin()
    if redir:
        return redir

    user = User.query.get_or_404(user_id)
    old_key = EncryptionKey.query.filter_by(user_id=user_id).first()
    if old_key:
        db.session.delete(old_key)

    public_key, private_key = generate_keypair()
    new_count = (EncryptionKey.query
                 .filter(EncryptionKey.key_label.like(f"{user.username}-uov-key-%"))
                 .count()) + 2
    enc_key = EncryptionKey(
        user_id         = user_id,
        key_label       = f"{user.username}-uov-key-{new_count}",
        public_key_b64  = serialize_key(public_key),
        private_key_b64 = serialize_key(private_key),
        algorithm       = "UOV-GF256-v12-o8",
        rotated_at      = datetime.utcnow(),
    )
    db.session.add(enc_key)
    db.session.commit()

    flash(f"New UOV key pair generated for {user.username}. "
          f"Note: existing encrypted records cannot be decrypted with the new key.", "warning")
    return redirect(url_for("admin.users"))


# ---------------------------------------------------------------------------
# Access Logs
# ---------------------------------------------------------------------------

@admin_bp.route("/logs")
@login_required
def logs():
    redir = _require_admin()
    if redir:
        return redir

    page      = request.args.get("page", 1, type=int)
    per_page  = 50
    anomalies_only = request.args.get("anomalies", "0") == "1"

    query = AccessLog.query.order_by(AccessLog.timestamp.desc())
    if anomalies_only:
        query = query.filter_by(is_anomalous=True)

    paginated = query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template("admin_logs.html", logs=paginated, anomalies_only=anomalies_only)


# ---------------------------------------------------------------------------
# Trigger full anomaly re-fit (admin API)
# ---------------------------------------------------------------------------

@admin_bp.route("/fit-anomaly-model", methods=["POST"])
@login_required
def fit_anomaly_model():
    redir = _require_admin()
    if redir:
        return redir

    all_logs = AccessLog.query.order_by(AccessLog.timestamp).all()
    detector = get_detector()
    fitted   = detector.fit(all_logs)

    if fitted:
        # Re-score all logs
        for log in all_logs:
            result = detector.score_log(log, all_logs)
            log.is_anomalous   = result["is_anomaly"]
            log.anomaly_score  = result["score"]
            log.anomaly_reason = result["reason"][:512] if result["reason"] else None
        db.session.commit()
        flash(f"Anomaly model fitted on {len(all_logs)} log entries and all logs re-scored.", "success")
    else:
        flash(f"Not enough data to fit anomaly model (need ≥ 30 entries, have {len(all_logs)}).", "warning")

    return redirect(url_for("admin.dashboard"))

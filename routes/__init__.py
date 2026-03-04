from flask import Blueprint

auth_bp     = Blueprint("auth",     __name__)
patients_bp = Blueprint("patients", __name__, url_prefix="/patients")
admin_bp    = Blueprint("admin",    __name__, url_prefix="/admin")

from . import auth, patients, admin   # noqa: E402, F401

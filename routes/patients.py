"""
Patient Routes
==============
  GET        /patients/              – patient list (MRN + non-PHI metadata)
  GET        /patients/dashboard     – summary dashboard
  GET/POST   /patients/add           – enroll new patient
  GET        /patients/<id>          – patient profile (encrypted fields hidden)
  POST       /patients/<id>/decrypt  – decrypt & view PHI (logged access)
  GET/POST   /patients/<id>/record   – add a new medical record
  GET        /patients/<id>/assess   – AI risk assessment
  POST       /patients/<id>/phi-scan – AJAX: PHI scan of field text
"""

import json
from datetime import datetime
from flask import (
    render_template, redirect, url_for, request,
    flash, jsonify, abort, current_app
)
from flask_login import login_required, current_user

from . import patients_bp
from models import db, Patient, MedicalRecord, AccessLog, EncryptionKey, User
from crypto.uov import encrypt_to_b64, decrypt_from_b64, deserialize_key
from crypto.phi_detector import PHIDetector
from ai.diagnosis import DiagnosisAssistant
from ai.anomaly import get_detector

_phi_detector = PHIDetector()
_diag_ai      = DiagnosisAssistant()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(action: str, patient_id=None, detail: str = ""):
    """Append an AccessLog entry and run anomaly check."""
    log = AccessLog(
        user_id    = current_user.id,
        patient_id = patient_id,
        action     = action,
        detail     = detail[:256],
        ip_address = request.remote_addr,
        user_agent = request.user_agent.string[:256],
        user_role  = current_user.role,
    )
    db.session.add(log)
    db.session.flush()  # get log.id

    # Lightweight anomaly check (rule-based, always fast)
    detector = get_detector()
    all_logs = AccessLog.query.order_by(AccessLog.timestamp).all()
    result   = detector.score_log(log, all_logs)
    if result["is_anomaly"]:
        log.is_anomalous   = True
        log.anomaly_score  = result["score"]
        log.anomaly_reason = result["reason"][:512]

    db.session.commit()
    return log


def _get_user_key(user_id: int):
    """Return deserialized (public_key, private_key) for a user."""
    enc_key = EncryptionKey.query.filter_by(user_id=user_id).first()
    if not enc_key:
        return None, None
    return (
        deserialize_key(enc_key.public_key_b64),
        deserialize_key(enc_key.private_key_b64),
    )


def _enc(text: str, public_key: dict) -> str:
    """Encrypt a string; return empty string if text is empty."""
    if not text:
        return ""
    return encrypt_to_b64(text.encode("utf-8"), public_key)


def _dec(b64_cipher: str, private_key: dict) -> str:
    """Decrypt a base64 ciphertext; return placeholder if empty/error."""
    if not b64_cipher:
        return ""
    try:
        return decrypt_from_b64(b64_cipher, private_key).decode("utf-8")
    except Exception as e:
        current_app.logger.error(f"Decryption error: {e}")
        return "[DECRYPTION ERROR]"


def _next_mrn() -> str:
    """Generate next sequential MRN."""
    last = Patient.query.order_by(Patient.id.desc()).first()
    n = (last.id + 1) if last else 1
    return f"MRN{n:07d}"


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@patients_bp.route("/dashboard")
@login_required
def dashboard():
    total_patients = Patient.query.count()
    total_records  = MedicalRecord.query.count()
    recent_logs    = (AccessLog.query
                      .filter_by(user_id=current_user.id)
                      .order_by(AccessLog.timestamp.desc())
                      .limit(10).all())
    anomaly_count  = AccessLog.query.filter_by(is_anomalous=True).count()

    _log("view", detail="dashboard")
    return render_template(
        "dashboard.html",
        total_patients = total_patients,
        total_records  = total_records,
        recent_logs    = recent_logs,
        anomaly_count  = anomaly_count,
    )


# ---------------------------------------------------------------------------
# Patient list
# ---------------------------------------------------------------------------

@patients_bp.route("/")
@login_required
def list_patients():
    q = request.args.get("q", "").strip()
    query = Patient.query
    if q:
        query = query.filter(Patient.mrn.ilike(f"%{q}%"))
    patients = query.order_by(Patient.created_at.desc()).all()
    _log("view", detail=f"patient list (query='{q}')")
    return render_template("patients.html", patients=patients, query=q)


# ---------------------------------------------------------------------------
# Add patient
# ---------------------------------------------------------------------------

@patients_bp.route("/add", methods=["GET", "POST"])
@login_required
def add_patient():
    error = None
    phi_warnings = {}

    if request.method == "POST":
        # Gather form fields
        fields = {
            "name":    request.form.get("name", "").strip(),
            "dob":     request.form.get("dob", "").strip(),
            "ssn":     request.form.get("ssn", "").strip(),
            "address": request.form.get("address", "").strip(),
            "phone":   request.form.get("phone", "").strip(),
            "email":   request.form.get("email_addr", "").strip(),
        }
        blood_type       = request.form.get("blood_type", "").strip()
        sex              = request.form.get("sex", "").strip()
        age_at_admission = request.form.get("age", type=int)

        # PHI scan
        phi_reports = _phi_detector.analyze_fields(fields)
        for fname, report in phi_reports.items():
            if report.phi_found:
                phi_warnings[fname] = report.summary()

        if not fields["name"]:
            error = "Patient name is required."
        else:
            # Encrypt using the current user's public key
            pub_key, _ = _get_user_key(current_user.id)
            if not pub_key:
                error = "No encryption key found for your account. Contact an administrator."
            else:
                patient = Patient(
                    mrn              = _next_mrn(),
                    enc_name         = _enc(fields["name"],    pub_key),
                    enc_dob          = _enc(fields["dob"],     pub_key),
                    enc_ssn          = _enc(fields["ssn"],     pub_key),
                    enc_address      = _enc(fields["address"], pub_key),
                    enc_phone        = _enc(fields["phone"],   pub_key),
                    enc_email        = _enc(fields["email"],   pub_key),
                    blood_type       = blood_type or None,
                    sex              = sex[:1].upper() if sex else None,
                    age_at_admission = age_at_admission,
                    added_by         = current_user.id,
                )
                db.session.add(patient)
                db.session.commit()
                _log("create", patient_id=patient.id,
                     detail=f"Enrolled patient MRN={patient.mrn}")
                flash(f"Patient enrolled. MRN: {patient.mrn}", "success")
                return redirect(url_for("patients.patient_detail", patient_id=patient.id))

    return render_template("add_patient.html", error=error, phi_warnings=phi_warnings)


# ---------------------------------------------------------------------------
# Patient detail (encrypted view)
# ---------------------------------------------------------------------------

@patients_bp.route("/<int:patient_id>")
@login_required
def patient_detail(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    records = (MedicalRecord.query
               .filter_by(patient_id=patient_id)
               .order_by(MedicalRecord.recorded_at.desc())
               .all())
    _log("view", patient_id=patient_id, detail="viewed patient profile")
    return render_template("patient_detail.html", patient=patient, records=records,
                            decrypted=None)


# ---------------------------------------------------------------------------
# Decrypt & view PHI (access-controlled, always logged)
# ---------------------------------------------------------------------------

@patients_bp.route("/<int:patient_id>/decrypt", methods=["POST"])
@login_required
def decrypt_patient(patient_id):
    if not current_user.can_decrypt:
        flash("You do not have permission to decrypt patient records.", "danger")
        return redirect(url_for("patients.patient_detail", patient_id=patient_id))

    patient = Patient.query.get_or_404(patient_id)
    _, priv_key = _get_user_key(current_user.id)

    if not priv_key:
        flash("No decryption key found for your account.", "danger")
        return redirect(url_for("patients.patient_detail", patient_id=patient_id))

    decrypted = {
        "name":    _dec(patient.enc_name,    priv_key),
        "dob":     _dec(patient.enc_dob,     priv_key),
        "ssn":     _dec(patient.enc_ssn,     priv_key),
        "address": _dec(patient.enc_address, priv_key),
        "phone":   _dec(patient.enc_phone,   priv_key),
        "email":   _dec(patient.enc_email,   priv_key),
    }

    records = (MedicalRecord.query
               .filter_by(patient_id=patient_id)
               .order_by(MedicalRecord.recorded_at.desc())
               .all())

    # Decrypt record content too
    decrypted_records = []
    for rec in records:
        decrypted_records.append({
            "id":          rec.id,
            "type":        rec.record_type,
            "date":        rec.recorded_at,
            "diagnosis":   _dec(rec.enc_diagnosis,   priv_key),
            "medications": _dec(rec.enc_medications, priv_key),
            "notes":       _dec(rec.enc_notes,       priv_key),
            "lab_results": _dec(rec.enc_lab_results, priv_key),
            "vitals": {
                "systolic_bp":   rec.systolic_bp,
                "diastolic_bp":  rec.diastolic_bp,
                "heart_rate":    rec.heart_rate,
                "spo2":          rec.spo2,
                "temperature_c": rec.temperature_c,
                "weight_kg":     rec.weight_kg,
            },
        })

    _log("decrypt", patient_id=patient_id, detail="Decrypted full PHI record")
    return render_template("patient_detail.html", patient=patient, records=records,
                            decrypted=decrypted, decrypted_records=decrypted_records)


# ---------------------------------------------------------------------------
# Add medical record
# ---------------------------------------------------------------------------

@patients_bp.route("/<int:patient_id>/record", methods=["GET", "POST"])
@login_required
def add_record(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    error   = None

    if request.method == "POST":
        record_type = request.form.get("record_type", "Note").strip()
        diagnosis   = request.form.get("diagnosis",   "").strip()
        medications = request.form.get("medications", "").strip()
        notes       = request.form.get("notes",       "").strip()
        lab_results = request.form.get("lab_results", "").strip()

        systolic_bp   = request.form.get("systolic_bp",   type=int)
        diastolic_bp  = request.form.get("diastolic_bp",  type=int)
        heart_rate    = request.form.get("heart_rate",    type=int)
        spo2          = request.form.get("spo2",          type=float)
        temperature_c = request.form.get("temperature_c", type=float)
        weight_kg     = request.form.get("weight_kg",     type=float)

        # PHI scan on free-text fields
        phi_report = _phi_detector.analyze(f"{diagnosis} {medications} {notes}")
        phi_fields = phi_report.categories if phi_report.phi_found else []

        pub_key, _ = _get_user_key(current_user.id)
        if not pub_key:
            error = "No encryption key found for your account."
        else:
            enc_key = EncryptionKey.query.filter_by(user_id=current_user.id).first()
            record = MedicalRecord(
                patient_id         = patient.id,
                record_type        = record_type,
                recorded_by        = current_user.id,
                enc_diagnosis      = _enc(diagnosis,   pub_key),
                enc_medications    = _enc(medications, pub_key),
                enc_notes          = _enc(notes,       pub_key),
                enc_lab_results    = _enc(lab_results, pub_key),
                systolic_bp        = systolic_bp,
                diastolic_bp       = diastolic_bp,
                heart_rate         = heart_rate,
                spo2               = spo2,
                temperature_c      = temperature_c,
                weight_kg          = weight_kg,
                phi_fields_detected = json.dumps(phi_fields),
                encryption_key_id  = enc_key.id if enc_key else None,
            )
            db.session.add(record)
            db.session.commit()
            _log("create", patient_id=patient.id,
                 detail=f"Added {record_type} record")
            flash("Medical record saved and encrypted.", "success")
            return redirect(url_for("patients.patient_detail", patient_id=patient.id))

    return render_template("add_record.html", patient=patient, error=error)


# ---------------------------------------------------------------------------
# AI Risk Assessment
# ---------------------------------------------------------------------------

@patients_bp.route("/<int:patient_id>/assess", methods=["POST"])
@login_required
def assess_patient(patient_id):
    if not current_user.can_decrypt:
        return jsonify({"error": "Permission denied"}), 403

    patient = Patient.query.get_or_404(patient_id)
    _, priv_key = _get_user_key(current_user.id)
    if not priv_key:
        return jsonify({"error": "No decryption key"}), 500

    # Get the most recent record with diagnosis and medications
    latest = (MedicalRecord.query
               .filter_by(patient_id=patient_id)
               .order_by(MedicalRecord.recorded_at.desc())
               .first())

    diagnosis   = _dec(latest.enc_diagnosis,   priv_key) if latest else ""
    medications = _dec(latest.enc_medications, priv_key) if latest else ""
    notes       = _dec(latest.enc_notes,       priv_key) if latest else ""

    assessment = _diag_ai.assess(
        age          = patient.age_at_admission,
        diagnoses    = diagnosis,
        medications  = medications,
        notes        = notes,
        systolic_bp  = latest.systolic_bp  if latest else None,
        diastolic_bp = latest.diastolic_bp if latest else None,
        heart_rate   = latest.heart_rate   if latest else None,
        spo2         = latest.spo2         if latest else None,
    )

    _log("view", patient_id=patient_id, detail="AI risk assessment run")
    return jsonify(assessment.to_dict())


# ---------------------------------------------------------------------------
# PHI Scan (AJAX)
# ---------------------------------------------------------------------------

@patients_bp.route("/phi-scan", methods=["POST"])
@login_required
def phi_scan():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"phi_found": False, "summary": "No text provided"})
    report = _phi_detector.analyze(text)
    return jsonify({
        "phi_found":  report.phi_found,
        "summary":    report.summary(),
        "categories": report.categories,
        "risk_score": report.risk_score,
    })

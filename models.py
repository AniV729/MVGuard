"""
SQLAlchemy Models
=================
Tables:
  User            – Hospital staff accounts (admin / doctor / nurse / analyst)
  Patient         – Patient demographic info (all PHI stored encrypted)
  MedicalRecord   – One-to-many clinical records per patient (encrypted)
  EncryptionKey   – UOV key pairs generated per user at account creation
  AccessLog       – Immutable audit trail for every patient data access
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

class Role:
    ADMIN    = "admin"
    DOCTOR   = "doctor"
    NURSE    = "nurse"
    ANALYST  = "analyst"

    ALL = [ADMIN, DOCTOR, NURSE, ANALYST]


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    """Hospital staff account."""
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64),  unique=True, nullable=False, index=True)
    email         = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name     = db.Column(db.String(128), nullable=False)
    role          = db.Column(db.String(16),  nullable=False, default=Role.NURSE)
    department    = db.Column(db.String(64))
    is_active     = db.Column(db.Boolean, default=True, nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login    = db.Column(db.DateTime)

    # Relationships
    encryption_key = db.relationship("EncryptionKey", back_populates="user",
                                     uselist=False, cascade="all, delete-orphan")
    access_logs    = db.relationship("AccessLog", back_populates="user",
                                     lazy="dynamic", cascade="all, delete-orphan")
    patients_added = db.relationship("Patient", back_populates="added_by_user",
                                     lazy="dynamic")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == Role.ADMIN

    @property
    def can_decrypt(self):
        """Only doctors and admins can decrypt full records."""
        return self.role in (Role.ADMIN, Role.DOCTOR)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


# ---------------------------------------------------------------------------
# EncryptionKey
# ---------------------------------------------------------------------------

class EncryptionKey(db.Model):
    """
    Stores a user's UOV public/private key pair.

    The public key is shared freely (used to encrypt records meant for this user).
    The private key is stored encrypted at rest – in a production system it would
    be AES-256-GCM wrapped with the user's login-derived key; here we store it
    server-side in the DB for demo simplicity.
    """
    __tablename__ = "encryption_keys"

    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)
    key_label       = db.Column(db.String(64), nullable=False)
    public_key_b64  = db.Column(db.Text, nullable=False)   # base64-JSON
    private_key_b64 = db.Column(db.Text, nullable=False)   # base64-JSON (keep secret)
    algorithm       = db.Column(db.String(32), default="UOV-GF256", nullable=False)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    rotated_at      = db.Column(db.DateTime)

    # Relationship
    user = db.relationship("User", back_populates="encryption_key")

    def __repr__(self):
        return f"<EncryptionKey {self.key_label} for user_id={self.user_id}>"


# ---------------------------------------------------------------------------
# Patient
# ---------------------------------------------------------------------------

class Patient(db.Model):
    """
    Patient demographic record.
    All PHI fields are stored UOV-encrypted (base64-encoded ciphertext).
    The 'added_by' foreign key links to the doctor/nurse who enrolled the patient.
    """
    __tablename__ = "patients"

    id               = db.Column(db.Integer, primary_key=True)
    # Encrypted PHI fields
    enc_name         = db.Column(db.Text, nullable=False)    # full name
    enc_dob          = db.Column(db.Text, nullable=False)    # date of birth
    enc_ssn          = db.Column(db.Text)                    # SSN (optional)
    enc_address      = db.Column(db.Text)                    # home address
    enc_phone        = db.Column(db.Text)                    # contact phone
    enc_email        = db.Column(db.Text)                    # email

    # Non-PHI metadata (plaintext, used for search/display without decryption)
    mrn              = db.Column(db.String(16), unique=True, nullable=False, index=True)
    blood_type       = db.Column(db.String(4))               # e.g. "O+"
    sex              = db.Column(db.String(1))               # M / F / O
    age_at_admission = db.Column(db.Integer)

    # Which user encrypted the data (links to their public key used)
    added_by         = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at       = db.Column(db.DateTime, default=datetime.utcnow,
                                  onupdate=datetime.utcnow)

    # Relationships
    added_by_user    = db.relationship("User", back_populates="patients_added",
                                        foreign_keys=[added_by])
    records          = db.relationship("MedicalRecord", back_populates="patient",
                                        lazy="dynamic", cascade="all, delete-orphan")
    access_logs      = db.relationship("AccessLog", back_populates="patient",
                                        lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Patient MRN={self.mrn}>"


# ---------------------------------------------------------------------------
# MedicalRecord
# ---------------------------------------------------------------------------

class MedicalRecord(db.Model):
    """
    Individual clinical record attached to a patient.
    Clinical text fields encrypted; record type and dates stored plaintext.
    """
    __tablename__ = "medical_records"

    id               = db.Column(db.Integer, primary_key=True)
    patient_id       = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False, index=True)
    record_type      = db.Column(db.String(32), nullable=False)  # e.g. "Admission", "Lab", "Note"
    recorded_at      = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    recorded_by      = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Encrypted clinical content
    enc_diagnosis    = db.Column(db.Text)
    enc_medications  = db.Column(db.Text)
    enc_notes        = db.Column(db.Text)
    enc_lab_results  = db.Column(db.Text)

    # Vital signs stored as structured (not encrypted — for AI analytics)
    systolic_bp      = db.Column(db.Integer)
    diastolic_bp     = db.Column(db.Integer)
    heart_rate       = db.Column(db.Integer)
    spo2             = db.Column(db.Float)
    temperature_c    = db.Column(db.Float)
    weight_kg        = db.Column(db.Float)

    # Metadata
    phi_fields_detected  = db.Column(db.Text)  # JSON list of PHI field names
    encryption_key_id    = db.Column(db.Integer, db.ForeignKey("encryption_keys.id"))

    # Relationships
    patient       = db.relationship("Patient", back_populates="records")
    recorder_user = db.relationship("User", foreign_keys=[recorded_by])
    encryption_key = db.relationship("EncryptionKey")

    def __repr__(self):
        return f"<MedicalRecord type={self.record_type} patient_id={self.patient_id}>"


# ---------------------------------------------------------------------------
# AccessLog
# ---------------------------------------------------------------------------

ACTION_TYPES = ["view", "decrypt", "edit", "create", "delete", "export", "login", "logout", "key_gen"]

class AccessLog(db.Model):
    """
    Immutable audit trail: every patient data access / mutation is logged.
    Used by the anomaly detection module.
    """
    __tablename__ = "access_logs"

    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    patient_id    = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=True, index=True)
    action        = db.Column(db.String(32), nullable=False)  # from ACTION_TYPES
    detail        = db.Column(db.String(256))                  # free-text context
    ip_address    = db.Column(db.String(45))                   # IPv4/IPv6
    user_agent    = db.Column(db.String(256))
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    is_anomalous  = db.Column(db.Boolean, default=False)
    anomaly_score = db.Column(db.Float)
    anomaly_reason = db.Column(db.String(512))

    # User role at time of access (denormalised for audit resilience)
    user_role     = db.Column(db.String(16))

    # Relationships
    user    = db.relationship("User",    back_populates="access_logs")
    patient = db.relationship("Patient", back_populates="access_logs")

    def __repr__(self):
        return f"<AccessLog {self.action} by user_id={self.user_id} at {self.timestamp}>"

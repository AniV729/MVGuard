# SecureHealth PQC

A hospital patient records system secured with **post-quantum cryptography**. All PHI (Protected Health Information) is encrypted using an **Unbalanced Oil and Vinegar (UOV)** multivariate scheme over GF(256) — resistant to both classical and quantum attacks — before it ever touches the database.

> Built as a proof-of-concept demonstrating that post-quantum cryptographic primitives can be applied to real healthcare data protection requirements today, ahead of the anticipated *"harvest now, decrypt later"* threat from future quantum hardware.

---

## Why Post-Quantum?

Standard RSA and ECC encryption are broken by Shor's algorithm on a sufficiently powerful quantum computer. The UOV scheme used here is based on the hardness of the **Multivariate Quadratic (MQ) problem** — no known quantum algorithm achieves a meaningful speedup against it. NIST has recognised multivariate cryptography as a post-quantum candidate family.

---

## Features

### 🔐 UOV Encryption (from scratch)
- Implemented entirely in Python with no external crypto libraries
- Finite field arithmetic over GF(2⁸) with primitive generator 3, irreducible polynomial x⁸+x⁴+x³+x+1
- Hand-built exp/log tables, Gaussian elimination, and matrix inversion over GF(256)
- Per-user UOV key pairs (VIN=12, OIL=8, N=20)
- PKCS#7 block padding; ciphertext stored as base64 JSON in SQLite

### 🏥 Patient Records
- All PHI fields (name, DOB, SSN, address, phone, email) encrypted at enrolment — never stored plaintext
- Non-PHI metadata (blood type, MRN, sex, age) stored plaintext for clinical workflows
- Medical records with encrypted diagnosis, medications, notes, lab results + plaintext vitals

### 🤖 AI Modules
| Module | Description |
|---|---|
| **PHI Detector** | Live HIPAA field scanner — regex + keyword matching for SSNs, ICD-10 codes, MRNs, NPIs, medications. Runs in-browser as you type. |
| **Anomaly Detector** | IsolationForest trained on access logs. Flags bulk record access, after-hours decryption, and role-unusual actions. |
| **Diagnosis Risk Scorer** | Rule-based clinical risk assessment (Low → Critical) with per-factor recommendations from diagnoses, medications, vitals, and age. |

### 👥 Role-Based Access Control
| Role | Permissions |
|---|---|
| **Admin** | Full access — user management, key rotation, audit logs, anomaly model refit |
| **Doctor** | View + decrypt patient PHI, add medical records, run AI assessment |
| **Nurse** | View patients and records (encrypted), add medical records |
| **Analyst** | Read-only access |

### 📋 Audit Trail
Every login, page view, decrypt action, and record mutation is logged with timestamp, IP address, user role, and anomaly score. Anomalous entries are highlighted in the admin log view.

---

## Tech Stack

- **Backend:** Python 3.10+ · Flask · Flask-SQLAlchemy · Flask-Login
- **Crypto:** Custom GF(256) arithmetic · NumPy (key generation RNG)
- **AI:** scikit-learn (IsolationForest)
- **Database:** SQLite via SQLAlchemy
- **Frontend:** Bootstrap 5 · Bootstrap Icons

---

## Project Structure

```
├── crypto/
│   ├── gf256.py          # GF(256) finite field arithmetic
│   ├── uov.py            # UOV encryption / decryption
│   └── phi_detector.py   # HIPAA PHI scanner
├── ai/
│   ├── anomaly.py        # IsolationForest access log anomaly detection
│   └── diagnosis.py      # Clinical risk scoring engine
├── routes/
│   ├── auth.py           # Login, logout, register, first-run setup
│   ├── patients.py       # Patient CRUD, decrypt, AI assessment
│   └── admin.py          # Admin dashboard, user mgmt, logs
├── templates/            # Bootstrap 5 Jinja2 templates
├── models.py             # SQLAlchemy models (User, Patient, MedicalRecord, ...)
├── main.py               # App factory + entry point
├── config.py             # Flask configuration
├── seed_demo.py          # Demo data seeder (staff + 10 patients)
└── requirements.txt
```

---

## Getting Started

### 1. Clone & install dependencies

```bash
git clone https://github.com/AniV729/MVGuard.git
cd MVGuard
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
```

### 2. Run the app

```bash
python main.py
```

On first run, visit **http://127.0.0.1:5000** — you'll be taken to a setup page to create your admin account. A UOV key pair is generated automatically (takes ~10–30 seconds).

### 3. (Optional) Load demo data

```bash
python seed_demo.py
```

Creates 4 staff accounts, 10 realistic patients with encrypted PHI, clinical records, and ~80 access log entries (including 4 flagged as anomalous).

**Demo credentials** (password: `Demo1234!`):

| Username | Role | Department |
|---|---|---|
| `dr.patel` | Doctor | Cardiology |
| `nurse.chen` | Nurse | Cardiology |
| `dr.okonkwo` | Doctor | Oncology |
| `analyst1` | Analyst | Data & Research |

---

## How the Encryption Works

```
Encrypt a block (8 bytes of plaintext):
  1. x_oil ← plaintext block (8 bytes = oil variables)
  2. x_vin ← random 12 bytes (vinegar variables)
  3. y     ← P(x_vin ‖ x_oil)   [evaluate public key polynomial]
  4. ciphertext block = y ‖ x_vin   (20 bytes)

Decrypt a block:
  1. Split: y = block[:8], x_vin = block[8:]
  2. y' = T⁻¹ · y              [apply inverse output mixer]
  3. Substitute x_vin into central map → linear system M·x_oil = y'
  4. Gauss-eliminate over GF(256) → recover x_oil = plaintext
```

The public key is the composition `P(z) = T·F(z)` where `F` is the central UOV map and `T` is a random invertible output-mixing matrix. Without knowledge of `T` and the central map coefficients, recovering `x_oil` from `y` requires solving the MQ problem.

---

## Notes

- This is a **proof-of-concept** — not audited for production use
- Private keys are stored server-side in the DB (production would wrap them with a user-derived key)
- Key generation takes 10–30 seconds due to the pure-Python GF(256) implementation

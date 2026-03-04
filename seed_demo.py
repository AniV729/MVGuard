"""
seed_demo.py  —  Populate SecureHealth with realistic demo data
===============================================================
Run once after wiping / fresh-creating the DB:

    python seed_demo.py

What it creates
---------------
  Staff accounts  (all passwords = "Demo1234!")
    • dr.patel    – Doctor  / Cardiology
    • nurse.chen  – Nurse   / Cardiology
    • dr.okonkwo  – Doctor  / Oncology
    • analyst1    – Analyst / Data & Research

  10 patients with encrypted PHI + 2-4 medical records each
  ~80 access log entries, some flagged as anomalous
"""

import sys, os, random
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(__file__))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from main import create_app
from models import db, User, EncryptionKey, Patient, MedicalRecord, AccessLog, Role
from crypto.uov import generate_keypair, serialize_key, encrypt_to_b64

app = create_app()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DEMO_PASSWORD = "Demo1234!"

def make_user(username, full_name, role, department, email):
    if User.query.filter_by(username=username).first():
        print(f"  [skip] user '{username}' already exists")
        return None
    print(f"  Creating user '{username}' ({role})…", end=" ", flush=True)
    u = User(username=username, email=email, full_name=full_name,
             role=role, department=department)
    u.set_password(DEMO_PASSWORD)
    db.session.add(u)
    db.session.flush()

    print("keygen…", end=" ", flush=True)
    pk, sk = generate_keypair()
    key = EncryptionKey(
        user_id=u.id,
        key_label=f"{username}-uov-key-1",
        public_key_b64=serialize_key(pk),
        private_key_b64=serialize_key(sk),
        algorithm="UOV-GF256-v12-o8",
    )
    db.session.add(key)
    db.session.commit()
    print("done.")
    return u


def enc(text, pk):
    """Encrypt a string using a UOV public key."""
    return encrypt_to_b64(text.encode(), pk)


def rdt(days_ago_min, days_ago_max):
    """Random datetime within a past window."""
    delta = random.randint(days_ago_min, days_ago_max)
    minutes = random.randint(0, 60 * 16)          # 0–16 h into the day
    return datetime.utcnow() - timedelta(days=delta, minutes=minutes)


# ---------------------------------------------------------------------------
# Demo patients data
# ---------------------------------------------------------------------------

PATIENTS = [
    dict(
        name="Margaret O'Brien", dob="1948-03-12", ssn="321-54-9870",
        address="14 Elm Street, Boston MA 02101",
        phone="617-555-0142", email="mobrien@email.com",
        mrn="MRN-001", blood_type="A+", sex="F", age=76,
        records=[
            dict(rtype="Admission", dx="Hypertensive heart disease (I11.0)",
                 meds="Lisinopril 10mg, Amlodipine 5mg",
                 notes="Patient admitted with elevated BP (178/102). No chest pain. ECG normal.",
                 labs="Troponin <0.01, BNP 142 pg/mL, eGFR 58",
                 sbp=178, dbp=102, hr=88, spo2=96.0, temp=36.9, wt=72.4),
            dict(rtype="Follow-up", dx="Hypertensive heart disease (I11.0)",
                 meds="Lisinopril 10mg, Amlodipine 5mg, Furosemide 20mg",
                 notes="BP improved to 145/88. Added low-dose furosemide for oedema.",
                 labs="",
                 sbp=145, dbp=88, hr=76, spo2=97.5, temp=36.7, wt=71.0),
        ]
    ),
    dict(
        name="James Whitfield", dob="1955-07-22", ssn="456-78-1230",
        address="89 Oak Ave, Cambridge MA 02139",
        phone="617-555-0281", email="jwhitfield@mail.net",
        mrn="MRN-002", blood_type="O-", sex="M", age=69,
        records=[
            dict(rtype="Admission", dx="Type 2 diabetes mellitus (E11.9), Diabetic nephropathy (E11.21)",
                 meds="Metformin 500mg, Insulin glargine 20U nightly",
                 notes="HbA1c 9.2%. Moderate microalbuminuria. Retinal screening overdue.",
                 labs="HbA1c 9.2, Creatinine 1.6 mg/dL, eGFR 44, Urine ACR 45 mg/g",
                 sbp=152, dbp=94, hr=82, spo2=97.0, temp=37.0, wt=94.2),
            dict(rtype="Lab", dx="Type 2 diabetes mellitus (E11.9)",
                 meds="Metformin 1000mg, Insulin glargine 24U nightly, Empagliflozin 10mg",
                 notes="Escalated Metformin dose. Added SGLT2 inhibitor for renoprotection.",
                 labs="HbA1c 8.4, Creatinine 1.5, eGFR 46",
                 sbp=140, dbp=86, hr=78, spo2=98.0, temp=36.8, wt=93.1),
            dict(rtype="Note", dx="Diabetic foot ulcer (E11.621)",
                 meds="Metformin 1000mg, Insulin glargine 26U, Empagliflozin 10mg, Amoxicillin-Clavulanate",
                 notes="Grade 2 plantar ulcer left foot. Wound care initiated. Podiatry referral.",
                 labs="WBC 11.2, CRP 18 mg/L",
                 sbp=138, dbp=84, hr=80, spo2=97.5, temp=37.4, wt=92.8),
        ]
    ),
    dict(
        name="Priya Nair", dob="1982-11-03", ssn="567-89-2341",
        address="22 Maple Rd, Somerville MA 02143",
        phone="617-555-0394", email="priya.nair@gmail.com",
        mrn="MRN-003", blood_type="B+", sex="F", age=42,
        records=[
            dict(rtype="Admission", dx="Breast cancer, right, stage II (C50.911)",
                 meds="Anastrozole 1mg daily",
                 notes="Right breast IDC 2.1cm, ER+ PR+ HER2−. Lumpectomy + SLNB planned.",
                 labs="CA 15-3 38 U/mL, CBC normal, LFTs normal",
                 sbp=118, dbp=74, hr=72, spo2=99.0, temp=36.6, wt=61.3),
            dict(rtype="Follow-up", dx="Breast cancer, right, stage II (C50.911)",
                 meds="Anastrozole 1mg, Tamoxifen 20mg",
                 notes="Post-lumpectomy. Radiation therapy cycle 3/15. Tolerating well.",
                 labs="CA 15-3 22 U/mL",
                 sbp=114, dbp=70, hr=68, spo2=99.5, temp=36.5, wt=60.8),
        ]
    ),
    dict(
        name="Robert Tanaka", dob="1940-01-30", ssn="678-90-3452",
        address="5 Birch Lane, Brookline MA 02446",
        phone="617-555-0513", email="rtanaka@oldmail.com",
        mrn="MRN-004", blood_type="AB+", sex="M", age=85,
        records=[
            dict(rtype="Admission", dx="Atrial fibrillation (I48.91), Heart failure (I50.9)",
                 meds="Warfarin 5mg, Digoxin 0.125mg, Furosemide 40mg, Spironolactone 25mg",
                 notes="Decompensated CHF. JVD present. Bilateral crackles. Admitted for IV diuresis.",
                 labs="BNP 1840 pg/mL, Na 132, K 3.6, Creatinine 1.8, INR 2.4",
                 sbp=96, dbp=58, hr=104, spo2=91.0, temp=36.4, wt=88.0),
            dict(rtype="Note", dx="Atrial fibrillation (I48.91)",
                 meds="Warfarin 5mg, Digoxin 0.125mg, Furosemide 80mg IV, Spironolactone 25mg",
                 notes="IV Furosemide started. -2.1L fluid balance at 24h. O2 improved to 96% on 2L NC.",
                 labs="BNP 920, K 3.4 — replaced",
                 sbp=108, dbp=64, hr=92, spo2=96.0, temp=36.5, wt=85.9),
            dict(rtype="Follow-up", dx="Heart failure with reduced ejection fraction (I50.20)",
                 meds="Warfarin 4mg, Furosemide 40mg PO, Carvedilol 3.125mg, Enalapril 5mg",
                 notes="Echo: EF 32%. Clinically improved, discharge planned. Cardiology follow-up in 2 weeks.",
                 labs="INR 2.1, BNP 410",
                 sbp=118, dbp=70, hr=78, spo2=97.5, temp=36.6, wt=83.5),
        ]
    ),
    dict(
        name="Susan Delacroix", dob="1975-05-19", ssn="789-01-4563",
        address="301 Pine St, Newton MA 02458",
        phone="617-555-0627", email="sdelacroix@workmail.com",
        mrn="MRN-005", blood_type="O+", sex="F", age=49,
        records=[
            dict(rtype="Admission", dx="Pulmonary embolism (I26.99)",
                 meds="Heparin infusion, Apixaban 10mg BID",
                 notes="Submassive PE. Right heart strain on echo. CT: bilateral PE. Haemodynamically stable.",
                 labs="D-dimer 8400, Troponin 0.12, BNP 280, O2 sat 89% on RA",
                 sbp=104, dbp=62, hr=118, spo2=89.0, temp=37.2, wt=68.5),
            dict(rtype="Follow-up", dx="Pulmonary embolism (I26.99)",
                 meds="Apixaban 10mg BID x7d then 5mg BID",
                 notes="Therapeutic transition to Apixaban. O2 sats normalised. Discharged day 4.",
                 labs="Repeat echo: RV strain resolved",
                 sbp=118, dbp=72, hr=84, spo2=97.0, temp=36.8, wt=68.0),
        ]
    ),
    dict(
        name="Daniel Osei", dob="1990-08-14", ssn="890-12-5674",
        address="77 Cedar Blvd, Malden MA 02148",
        phone="617-555-0739", email="d.osei@webmail.org",
        mrn="MRN-006", blood_type="A-", sex="M", age=34,
        records=[
            dict(rtype="Admission", dx="Acute appendicitis (K35.89)",
                 meds="Ceftriaxone 1g IV, Metronidazole 500mg IV",
                 notes="Acute RLQ pain, fever, Rovsing positive. CT confirmed. Gen surgery notified.",
                 labs="WBC 18.4, CRP 94 mg/L, Lactate 1.8",
                 sbp=122, dbp=78, hr=104, spo2=98.0, temp=38.6, wt=78.0),
            dict(rtype="Note", dx="Post-laparoscopic appendicectomy",
                 meds="Paracetamol 1g QDS, Ibuprofen 400mg TDS",
                 notes="Laparoscopic appendicectomy completed. No perforation. Tolerating liquids.",
                 labs="WBC 10.2, CRP 24",
                 sbp=118, dbp=74, hr=80, spo2=99.0, temp=37.2, wt=77.6),
        ]
    ),
    dict(
        name="Helen Kowalczyk", dob="1963-12-07", ssn="901-23-6785",
        address="48 Willow Way, Waltham MA 02452",
        phone="617-555-0841", email="hkowalczyk@domain.net",
        mrn="MRN-007", blood_type="B-", sex="F", age=61,
        records=[
            dict(rtype="Admission", dx="COPD exacerbation (J44.1)",
                 meds="Salbutamol neb, Ipratropium neb, Prednisolone 40mg, Doxycycline 200mg",
                 notes="Purulent sputum, wheeze. SpO2 84% on RA. Started on controlled O2 therapy.",
                 labs="ABG: pH 7.33, pCO2 56, pO2 54, HCO3 28. CRP 78",
                 sbp=142, dbp=88, hr=98, spo2=84.0, temp=37.8, wt=82.0),
            dict(rtype="Follow-up", dx="COPD (J44.1)",
                 meds="Tiotropium, Salbutamol PRN, Prednisolone taper",
                 notes="Improved on treatment. Sputum culture: H. influenzae. Antibiotic continued.",
                 labs="CRP 18, ABG improved",
                 sbp=134, dbp=82, hr=86, spo2=93.0, temp=37.0, wt=81.5),
        ]
    ),
    dict(
        name="Samuel Reyes", dob="1998-04-25", ssn="012-34-7896",
        address="9 Spruce Court, Quincy MA 02169",
        phone="617-555-0952", email="samuelr@personalmail.com",
        mrn="MRN-008", blood_type="O+", sex="M", age=26,
        records=[
            dict(rtype="Admission", dx="Asthma, acute severe (J45.51)",
                 meds="Salbutamol 2.5mg neb q20min, Magnesium sulfate 2g IV, Hydrocortisone 200mg IV",
                 notes="Peak flow 28% predicted. PEFR not improving after initial nebulisers.",
                 labs="",
                 sbp=136, dbp=84, hr=122, spo2=92.0, temp=37.0, wt=70.0),
            dict(rtype="Note", dx="Asthma (J45.51) — improving",
                 meds="Salbutamol 2.5mg neb q4h, Prednisolone 40mg, Fluticasone/Salmeterol inhaler",
                 notes="PEFR improved to 72% predicted at 6h. Will step down if maintained.",
                 labs="",
                 sbp=124, dbp=76, hr=88, spo2=97.0, temp=36.9, wt=70.0),
        ]
    ),
    dict(
        name="Florence Nduka", dob="1970-09-01", ssn="123-45-8907",
        address="60 Rosewood Crescent, Somerville MA 02145",
        phone="617-555-1063", email="fnduka@nhs-email.org",
        mrn="MRN-009", blood_type="A+", sex="F", age=54,
        records=[
            dict(rtype="Admission", dx="Ischaemic stroke, left MCA (I63.40)",
                 meds="Aspirin 300mg, Atorvastatin 80mg, Alteplase 0.9mg/kg IV",
                 notes="Acute onset right arm weakness + dysphasia. NIHSS 12. CT: no bleed. tPA given.",
                 labs="Glucose 7.2, INR 1.0, Plt 218, CT perfusion: mismatch 68%",
                 sbp=178, dbp=100, hr=86, spo2=95.0, temp=37.1, wt=74.0),
            dict(rtype="Follow-up", dx="Ischaemic stroke (I63.40), Hypertension (I10)",
                 meds="Clopidogrel 75mg, Atorvastatin 80mg, Ramipril 5mg",
                 notes="NIHSS improved to 6 at 24h. Swallow assessment passed. Physio and SALT input.",
                 labs="MRI: left MCA territory infarct 3.2cm",
                 sbp=148, dbp=88, hr=80, spo2=97.0, temp=36.8, wt=74.0),
            dict(rtype="Note", dx="Rehabilitation — post-stroke",
                 meds="Clopidogrel 75mg, Atorvastatin 80mg, Ramipril 5mg, Escitalopram 10mg",
                 notes="Transferred to stroke rehab unit. Good progress with OT. Mood low — started SSRI.",
                 labs="",
                 sbp=136, dbp=80, hr=74, spo2=98.0, temp=36.6, wt=73.5),
        ]
    ),
    dict(
        name="Arthur Beaumont", dob="1952-06-18", ssn="234-56-9018",
        address="12 Chestnut Hill Ave, Brighton MA 02135",
        phone="617-555-1174", email="ab@beaumont-family.com",
        mrn="MRN-010", blood_type="AB-", sex="M", age=72,
        records=[
            dict(rtype="Admission", dx="Colorectal cancer stage III (C18.9), Anaemia (D50.9)",
                 meds="FOLFOX regimen, Ondansetron 8mg, Dexamethasone 8mg",
                 notes="Cycle 4 of FOLFOX. Adequate response on CT. Grade 2 peripheral neuropathy.",
                 labs="CEA 12.4, Hb 9.8, WBC 3.2, Plt 142, LFTs normal",
                 sbp=128, dbp=80, hr=76, spo2=97.5, temp=36.7, wt=68.0),
            dict(rtype="Lab", dx="Colorectal cancer (C18.9)",
                 meds="FOLFOX, Filgrastim 300mcg SC, Ondansetron",
                 notes="Cycle 5. Neutropenia post cycle 4 — G-CSF added. Tolerating better.",
                 labs="CEA 8.1, Hb 10.4, WBC 5.6 post G-CSF",
                 sbp=124, dbp=76, hr=72, spo2=98.0, temp=36.6, wt=68.4),
            dict(rtype="Note", dx="Post-FOLFOX toxicity review",
                 meds="Capecitabine 1000mg BID (oral switch)",
                 notes="Switched to oral Capecitabine for convenience. Neuropathy grade 1, improving.",
                 labs="",
                 sbp=122, dbp=74, hr=70, spo2=98.5, temp=36.5, wt=68.9),
        ]
    ),
]


# ---------------------------------------------------------------------------
# Staff to create
# ---------------------------------------------------------------------------

STAFF = [
    ("dr.patel",   "Dr. Arjun Patel",     Role.DOCTOR,  "Cardiology",     "a.patel@hospital.local"),
    ("nurse.chen", "Mei-Lin Chen",         Role.NURSE,   "Cardiology",     "m.chen@hospital.local"),
    ("dr.okonkwo", "Dr. Chidi Okonkwo",   Role.DOCTOR,  "Oncology",       "c.okonkwo@hospital.local"),
    ("analyst1",   "Rebecca Sloane",       Role.ANALYST, "Data & Research","r.sloane@hospital.local"),
]


# ---------------------------------------------------------------------------
# Access log helpers
# ---------------------------------------------------------------------------

IPS = ["10.0.1.12", "10.0.1.34", "10.0.2.88", "192.168.1.55"]
UA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121"

def add_log(user, action, detail, patient=None, days_ago=0, hours=None, anomalous=False, reason=""):
    ts = datetime.utcnow() - timedelta(days=days_ago,
                                        hours=hours if hours is not None else random.randint(8, 18))
    log = AccessLog(
        user_id=user.id, patient_id=patient.id if patient else None,
        action=action, detail=detail,
        ip_address=random.choice(IPS), user_agent=UA,
        timestamp=ts, user_role=user.role,
        is_anomalous=anomalous,
        anomaly_score=-0.45 if anomalous else random.uniform(0.05, 0.35),
        anomaly_reason=reason if anomalous else None,
    )
    db.session.add(log)


# ---------------------------------------------------------------------------
# Main seed
# ---------------------------------------------------------------------------

def seed():
    with app.app_context():
        # ── Staff ────────────────────────────────────────────────────────
        print("\n== Creating demo staff accounts ==")
        staff_users = {}
        for uname, fname, role, dept, email in STAFF:
            u = make_user(uname, fname, role, dept, email)
            if u is None:
                u = User.query.filter_by(username=uname).first()
            staff_users[uname] = u

        # Pick a doctor to be the primary enroller
        doctor    = staff_users["dr.patel"]
        dk_record = doctor.encryption_key
        from crypto.uov import deserialize_key
        doctor_pk = deserialize_key(dk_record.public_key_b64)

        # ── Patients ─────────────────────────────────────────────────────
        print("\n== Creating demo patients ==")
        db_patients = []
        for i, p in enumerate(PATIENTS):
            if Patient.query.filter_by(mrn=p["mrn"]).first():
                print(f"  [skip] patient {p['mrn']} already exists")
                db_patients.append(Patient.query.filter_by(mrn=p["mrn"]).first())
                continue

            print(f"  Encrypting & saving {p['name']} ({p['mrn']})…")
            pat = Patient(
                enc_name    = enc(p["name"],    doctor_pk),
                enc_dob     = enc(p["dob"],     doctor_pk),
                enc_ssn     = enc(p["ssn"],     doctor_pk),
                enc_address = enc(p["address"], doctor_pk),
                enc_phone   = enc(p["phone"],   doctor_pk),
                enc_email   = enc(p["email"],   doctor_pk),
                mrn              = p["mrn"],
                blood_type       = p["blood_type"],
                sex              = p["sex"],
                age_at_admission = p["age"],
                added_by         = doctor.id,
                created_at       = rdt(60, 180),
            )
            db.session.add(pat)
            db.session.flush()
            db_patients.append(pat)

            # Medical records
            for j, r in enumerate(p.get("records", [])):
                enroller = doctor if j % 2 == 0 else staff_users.get("nurse.chen", doctor)
                rec = MedicalRecord(
                    patient_id      = pat.id,
                    record_type     = r["rtype"],
                    recorded_by     = enroller.id,
                    recorded_at     = rdt(0, 60),
                    enc_diagnosis   = enc(r["dx"],   doctor_pk) if r.get("dx")   else None,
                    enc_medications = enc(r["meds"], doctor_pk) if r.get("meds") else None,
                    enc_notes       = enc(r["notes"],doctor_pk) if r.get("notes")else None,
                    enc_lab_results = enc(r["labs"], doctor_pk) if r.get("labs") else None,
                    systolic_bp     = r.get("sbp"),
                    diastolic_bp    = r.get("dbp"),
                    heart_rate      = r.get("hr"),
                    spo2            = r.get("spo2"),
                    temperature_c   = r.get("temp"),
                    weight_kg       = r.get("wt"),
                    encryption_key_id = dk_record.id,
                )
                db.session.add(rec)

        db.session.commit()
        print(f"  {len(db_patients)} patients saved.")

        # ── Access logs ──────────────────────────────────────────────────
        print("\n== Generating access logs ==")

        dr    = staff_users["dr.patel"]
        nurse = staff_users["nurse.chen"]
        onc   = staff_users["dr.okonkwo"]
        ana   = staff_users["analyst1"]

        # Normal activity over the past 30 days
        for day in range(1, 30):
            for pat in random.sample(db_patients, k=min(4, len(db_patients))):
                add_log(dr,    "view",    f"Viewed patient {pat.mrn}", pat, days_ago=day)
                add_log(nurse, "view",    f"Viewed patient {pat.mrn}", pat, days_ago=day)

            if day % 3 == 0:
                pat = random.choice(db_patients)
                add_log(dr, "decrypt", f"Decrypted PHI for {pat.mrn}", pat, days_ago=day)

            if day % 5 == 0:
                pat = random.choice(db_patients)
                add_log(dr, "create", f"Added medical record for {pat.mrn}", pat, days_ago=day)

        # Login events
        for u in [dr, nurse, onc, ana]:
            for day in range(0, 30, 2):
                add_log(u, "login", "Successful login", days_ago=day)

        # ── Anomalous events ─────────────────────────────────────────────
        # 1. Bulk record access in a short window (nurse accessing many patients)
        for pat in db_patients:
            add_log(nurse, "view", f"Bulk access: {pat.mrn}", pat,
                    days_ago=3, hours=2,
                    anomalous=True, reason="Bulk access: 10 patients within 5 minutes")

        # 2. After-hours decrypt by nurse (nurses shouldn't decrypt)
        add_log(nurse, "decrypt", f"After-hours PHI access", db_patients[4],
                days_ago=5, hours=1,
                anomalous=True, reason="Outside business hours (01:00); unusual action for role")

        # 3. Analyst accessing sensitive decrypt (analysts are read-only)
        add_log(ana, "decrypt", "Analyst attempted PHI decrypt", db_patients[2],
                days_ago=8, hours=14,
                anomalous=True, reason="decrypt action unusual for analyst role")

        # 4. Unusual IP / late-night oncologist access
        add_log(onc, "view", f"Accessed {db_patients[0].mrn} — unusual IP",
                db_patients[0], days_ago=2, hours=3,
                anomalous=True, reason="Access at 03:00 from previously unseen IP")

        db.session.commit()
        print(f"  Access logs written.")

        # ── Summary ──────────────────────────────────────────────────────
        print(f"""
╔══════════════════════════════════════════════════╗
║           Demo data seeded successfully!         ║
╠══════════════════════════════════════════════════╣
║  Staff accounts  (password: Demo1234!)           ║
║    admin        – System Administrator           ║
║    dr.patel     – Doctor  / Cardiology           ║
║    nurse.chen   – Nurse   / Cardiology           ║
║    dr.okonkwo   – Doctor  / Oncology             ║
║    analyst1     – Analyst / Data & Research      ║
╠══════════════════════════════════════════════════╣
║  {len(db_patients):2d} demo patients with encrypted PHI          ║
║   4 anomalous access log entries flagged         ║
╚══════════════════════════════════════════════════╝

  Login at http://127.0.0.1:5000
""")


if __name__ == "__main__":
    seed()

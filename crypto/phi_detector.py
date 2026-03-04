"""
PHI Detector — Protected Health Information Scanner
====================================================
Identifies HIPAA-regulated PHI fields before encryption using a combination
of:
  - Regex patterns (SSN, DOB, phone, email, MRN, ICD-10 codes, ZIP codes)
  - Keyword vocabulary (diagnosis terms, medication names, body parts)
  - Structural heuristics (field labels, context clues)

Results are used by the UI to:
  1. Warn staff that a field contains PHI before it is saved.
  2. Force encryption of any detected PHI field.
  3. Log detection events for audit purposes.
"""

import re
from dataclasses import dataclass, field
from typing import List

# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

_PATTERNS = {
    "SSN":          re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
    "DOB":          re.compile(
                        r'\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b'
                    ),
    "Phone":        re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b'),
    "Email":        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    "MRN":          re.compile(r'\b(?:MRN|mrn|Medical Record Number|Patient ID)[:\s#]*\d{5,12}\b'),
    "ZIP":          re.compile(r'\b\d{5}(?:-\d{4})?\b'),
    "ICD10":        re.compile(r'\b[A-Z]\d{2}(?:\.\d{1,4})?\b'),
    "NPI":          re.compile(r'\bNPI[:\s]*\d{10}\b'),
    "CreditCard":   re.compile(r'\b(?:\d[ -]?){13,16}\b'),
    "IPAddress":    re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
}

# Diagnosis / medication keyword sets (abridged — extend as needed)
_DIAGNOSIS_KEYWORDS = {
    "diabetes", "hypertension", "cancer", "tumor", "carcinoma", "melanoma",
    "leukemia", "lymphoma", "stroke", "myocardial infarction", "heart attack",
    "depression", "anxiety", "schizophrenia", "dementia", "alzheimer",
    "parkinson", "epilepsy", "seizure", "hiv", "aids", "hepatitis",
    "cirrhosis", "pneumonia", "asthma", "copd", "emphysema", "tuberculosis",
    "sepsis", "covid", "influenza", "hypothyroidism", "hyperthyroidism",
    "rheumatoid", "lupus", "crohn", "ulcerative colitis", "appendicitis",
    "cholecystitis", "pancreatitis", "chronic kidney", "renal failure",
    "dialysis", "transplant", "anemia", "hemophilia", "thrombosis",
    "embolism", "arrhythmia", "atrial fibrillation", "obesity", "bmi",
}

_MEDICATION_KEYWORDS = {
    "metformin", "insulin", "lisinopril", "atorvastatin", "omeprazole",
    "amlodipine", "metoprolol", "losartan", "simvastatin", "levothyroxine",
    "albuterol", "gabapentin", "hydrochlorothiazide", "furosemide",
    "sertraline", "fluoxetine", "citalopram", "amoxicillin", "azithromycin",
    "doxycycline", "prednisone", "ibuprofen", "acetaminophen", "aspirin",
    "warfarin", "clopidogrel", "apixaban", "rivaroxaban", "oxycodone",
    "hydrocodone", "morphine", "tramadol", "alprazolam", "lorazepam",
    "clonazepam", "zolpidem", "quetiapine", "risperidone", "olanzapine",
    "lithium", "valproate", "carbamazepine", "phenytoin", "levetiracetam",
    "tamoxifen", "chemotherapy", "immunosuppressant",
}

_PHI_FIELD_LABELS = {
    "name", "first name", "last name", "full name", "patient name",
    "date of birth", "dob", "birth date", "address", "street", "city",
    "state", "zip", "zipcode", "phone", "telephone", "mobile", "fax",
    "email", "social security", "ssn", "medical record", "mrn",
    "account number", "insurance", "policy number", "license",
    "vehicle", "device", "biometric", "photograph", "ip address",
    "url", "web", "diagnosis", "condition", "medication", "prescription",
    "allergy", "treatment", "procedure", "lab result", "test result",
    "vital", "blood pressure", "heart rate", "weight", "height",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PHIMatch:
    category:   str
    match_text: str
    start:      int
    end:        int
    confidence: float   # 0.0 – 1.0

@dataclass
class PHIReport:
    text:        str
    matches:     List[PHIMatch] = field(default_factory=list)
    phi_found:   bool = False
    risk_score:  float = 0.0   # Aggregate 0–1
    categories:  List[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.phi_found:
            return "No PHI detected."
        cats = ", ".join(sorted(set(self.categories)))
        return f"PHI detected — categories: {cats} (risk score: {self.risk_score:.2f})"


# ---------------------------------------------------------------------------
# Core detector
# ---------------------------------------------------------------------------

class PHIDetector:
    """
    Stateless PHI detection engine.
    Usage:
        detector = PHIDetector()
        report = detector.analyze("Patient John Doe, DOB 12/03/1982, SSN 123-45-6789")
    """

    def analyze(self, text: str) -> PHIReport:
        report = PHIReport(text=text)
        lower  = text.lower()

        # ── Regex scans ──────────────────────────────────────────────────
        for name, pattern in _PATTERNS.items():
            for m in pattern.finditer(text):
                confidence = 0.95 if name in {"SSN", "Email", "MRN", "NPI"} else 0.75
                report.matches.append(PHIMatch(
                    category   = name,
                    match_text = m.group(),
                    start      = m.start(),
                    end        = m.end(),
                    confidence = confidence,
                ))

        # ── Keyword scans ─────────────────────────────────────────────────
        for kw in _DIAGNOSIS_KEYWORDS:
            idx = lower.find(kw)
            if idx != -1:
                report.matches.append(PHIMatch(
                    category   = "Diagnosis",
                    match_text = text[idx:idx + len(kw)],
                    start      = idx,
                    end        = idx + len(kw),
                    confidence = 0.80,
                ))

        for kw in _MEDICATION_KEYWORDS:
            idx = lower.find(kw)
            if idx != -1:
                report.matches.append(PHIMatch(
                    category   = "Medication",
                    match_text = text[idx:idx + len(kw)],
                    start      = idx,
                    end        = idx + len(kw),
                    confidence = 0.80,
                ))

        # ── Field label heuristic ─────────────────────────────────────────
        for label in _PHI_FIELD_LABELS:
            if label in lower:
                report.matches.append(PHIMatch(
                    category   = "PHI Field Label",
                    match_text = label,
                    start      = lower.find(label),
                    end        = lower.find(label) + len(label),
                    confidence = 0.60,
                ))

        # ── Aggregate ────────────────────────────────────────────────────
        if report.matches:
            report.phi_found  = True
            report.categories = list({m.category for m in report.matches})
            report.risk_score = min(
                1.0,
                sum(m.confidence for m in report.matches) / max(len(report.matches), 1)
                * (1 + 0.1 * (len(report.categories) - 1))
            )

        return report

    def analyze_fields(self, fields: dict) -> dict:
        """
        Analyze a dict of {field_name: value} pairs.
        Returns {field_name: PHIReport}.
        """
        return {k: self.analyze(str(v)) for k, v in fields.items()}

    def flag_required_encryption(self, fields: dict) -> List[str]:
        """
        Return which field names MUST be encrypted (phi_found == True).
        """
        reports = self.analyze_fields(fields)
        return [k for k, r in reports.items() if r.phi_found]

"""
detector.py
-----------
Regex + heuristic based sensitive-data detector.

Design notes (worth mentioning in the interview):
- A pure regex approach is used instead of a heavy NLP/NER model so the tool
  stays lightweight, fast, and has zero external dependency at inference
  time (no GPU, no API key required to get a baseline result).
- Each pattern carries a "severity weight" used to compute an overall risk
  score for the document, rather than just a raw count of matches.
- Values are masked before ever being displayed/stored, so the tool itself
  does not become a new leak vector.
"""

from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Finding:
    category: str
    matches: list = field(default_factory=list)   # masked values
    count: int = 0
    severity: int = 1                              # 1=low 2=medium 3=high


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------
# severity: 3 = high risk on its own, 2 = medium, 1 = low/context-dependent
PATTERNS = {
    "Aadhaar Number": {
        # exactly 3 groups of 4 digits, and NOT immediately followed/preceded
        # by another digit group (which would indicate a longer number, e.g.
        # a 16-digit credit card, rather than a 12-digit Aadhaar number)
        "regex": r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\s?\d)",
        "severity": 3,
    },
    "PAN Number": {
        "regex": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "severity": 3,
    },
    "Credit Card Number": {
        # 16-digit (Visa/Mastercard/RuPay) or 15-digit (Amex) card numbers,
        # optionally grouped with spaces or dashes
        "regex": r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)"
                 r"|(?<!\d)\d{4}[ -]?\d{6}[ -]?\d{5}(?!\d)",
        "severity": 3,
    },
    "Bank Account / IFSC": {
        "regex": r"\b[A-Z]{4}0[A-Z0-9]{6}\b|\b\d{9,18}\b",
        "severity": 3,
    },
    "Email Address": {
        "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "severity": 2,
    },
    "Phone Number": {
        "regex": r"(?:(?:\+91|0)?[6-9]\d{9})\b",
        "severity": 2,
    },
    "API Key / Secret": {
        "regex": r"(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}['\"]?",
        "severity": 3,
    },
    "Password": {
        "regex": r"(?i)\bpassword\s*[:=]\s*['\"]?\S{4,}['\"]?",
        "severity": 3,
    },
    "Employee ID": {
        "regex": r"\b(?:EMP|EMPID|EID)[-_]?\d{3,6}\b",
        "severity": 1,
    },
    "Confidential Business Info": {
        "regex": r"(?i)\b(confidential|internal use only|proprietary|do not distribute|trade secret|strictly private)\b",
        "severity": 2,
    },
}

# Numeric patterns overlap a lot (a 12-digit Aadhaar is also a 12-digit
# "bank account" match). We resolve overlaps by priority order below so a
# given span of text is only counted once, under its most specific label.
PRIORITY_ORDER = [
    "PAN Number",
    "API Key / Secret",
    "Password",
    "Email Address",
    "Employee ID",
    "Credit Card Number",   # claim longer digit runs before Aadhaar/bank patterns can
    "Aadhaar Number",
    "Bank Account / IFSC",
    "Phone Number",
    "Confidential Business Info",
]


def _mask(value: str, category: str) -> str:
    """Mask a matched value, keeping just enough for the user to recognise it."""
    value = value.strip()
    if category == "Email Address":
        name, _, domain = value.partition("@")
        return f"{name[:2]}{'*' * max(len(name) - 2, 1)}@{domain}"
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def detect_sensitive_data(text: str) -> dict:
    """
    Scan text against all patterns and return a dict of category -> Finding.
    Overlapping numeric spans are de-duplicated using PRIORITY_ORDER so a
    single number isn't double counted as both Aadhaar and bank account.
    """
    claimed_spans = []  # list of (start, end)
    findings: dict[str, Finding] = {}

    for category in PRIORITY_ORDER:
        cfg = PATTERNS[category]
        pattern = re.compile(cfg["regex"])
        for m in pattern.finditer(text):
            start, end = m.span()
            if any(start < c_end and end > c_start for c_start, c_end in claimed_spans):
                continue  # overlaps a higher-priority match already claimed
            claimed_spans.append((start, end))
            f = findings.setdefault(
                category, Finding(category=category, severity=cfg["severity"])
            )
            f.matches.append(_mask(m.group(), category))
            f.count += 1

    return findings


def classify_risk(findings: dict) -> tuple[str, int]:
    """
    Compute an overall document risk score and Low/Medium/High label.
    Score = sum(count * severity) across all categories, then bucketed.
    """
    score = sum(f.count * f.severity for f in findings.values())
    if score == 0:
        return "Low Risk", score
    elif score <= 6:
        return "Low Risk", score
    elif score <= 20:
        return "Medium Risk", score
    else:
        return "High Risk", score


def findings_to_table(findings: dict) -> list:
    """Flatten findings into row dicts for display in a Streamlit dataframe."""
    rows = []
    for category, f in sorted(findings.items(), key=lambda x: -x[1].severity):
        rows.append(
            {
                "Category": category,
                "Occurrences": f.count,
                "Severity": {1: "Low", 2: "Medium", 3: "High"}[f.severity],
                "Sample (masked)": ", ".join(f.matches[:3]) + ("..." if f.count > 3 else ""),
            }
        )
    return rows

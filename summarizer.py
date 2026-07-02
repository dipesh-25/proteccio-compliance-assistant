"""
summarizer.py
-------------
Generates a compliance/security summary for a scanned document.

If a GEMINI_API_KEY is present in the environment, Google's Gemini (free
tier) is used to write a richer, more natural-language summary grounded in
the detected findings. If no key is configured, a deterministic rule-based
summary is generated instead so the app is still fully usable out of the box.
"""

from __future__ import annotations
import os


def _rule_based_summary(findings: dict, risk_label: str, score: int) -> str:
    if not findings:
        return (
            "No sensitive data patterns were detected in this document. "
            "Based on the scanned content, this document appears to be Low Risk. "
            "No immediate remediation action is required, but periodic re-scanning "
            "is still recommended as documents are updated."
        )

    categories = ", ".join(sorted(findings.keys()))
    high_sev = [c for c, f in findings.items() if f.severity == 3]
    med_sev = [c for c, f in findings.items() if f.severity == 2]

    lines = [
        f"This document has been classified as **{risk_label}** (risk score: {score}).",
        f"The following categories of sensitive data were detected: {categories}.",
    ]

    if high_sev:
        lines.append(
            "High-severity items were found (" + ", ".join(high_sev) + "). "
            "These pose direct identity-theft, financial fraud, or credential-leak "
            "risk if this document is shared or stored insecurely."
        )
    if med_sev:
        lines.append(
            "Medium-severity items were found (" + ", ".join(med_sev) + "). "
            "These are personally identifiable but lower direct financial risk on "
            "their own; however, combined with other data they can enable "
            "re-identification."
        )

    lines.append(
        "Suggested remediation steps: (1) Redact or mask the identified fields "
        "before sharing this document externally. (2) Restrict access to "
        "authorized personnel only, ideally via role-based access control. "
        "(3) Store the document encrypted at rest. (4) Maintain an audit log of "
        "who accessed or downloaded this file. (5) If this data is no longer "
        "needed, delete it in line with your data-retention policy."
    )
    return "\n\n".join(lines)


def _llm_summary(text: str, findings: dict, risk_label: str, score: int) -> str | None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        findings_desc = "\n".join(
            f"- {cat}: {f.count} occurrence(s), severity {f.severity}/3"
            for cat, f in findings.items()
        ) or "No sensitive data detected."

        prompt = f"""You are a data compliance assistant. A document scan found:

{findings_desc}

Overall risk classification: {risk_label} (score {score})

Write a concise compliance & security summary (150-250 words) covering:
1. Compliance observations
2. Security risks
3. Suggested remediation steps

Do not invent findings beyond what is listed above."""

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        return response.text
    except Exception:
        return None  # fall back silently to rule-based summary


def generate_summary(text: str, findings: dict, risk_label: str, score: int) -> str:
    llm_result = _llm_summary(text, findings, risk_label, score)
    if llm_result:
        return llm_result
    return _rule_based_summary(findings, risk_label, score)
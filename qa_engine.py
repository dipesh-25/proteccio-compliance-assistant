"""
qa_engine.py
------------
Lets the user ask free-form questions about the scanned document.

Two modes:
1. LLM mode (preferred) - if GEMINI_API_KEY is set, the question, the
   detected findings, and a truncated version of the document text are sent
   to Gemini for a grounded answer.
2. Fallback keyword mode - handles the common question patterns mentioned in
   the assignment brief ("what sensitive data exists", "how many emails",
   "summarize this document", "what are the compliance risks") without
   requiring any API key, so the app is always demoable offline.
"""

from __future__ import annotations
import os
import re


MAX_CONTEXT_CHARS = 6000  # keep LLM prompts small/cheap


def _llm_answer(question: str, text: str, findings: dict) -> str | None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        findings_desc = "\n".join(
            f"- {cat}: {f.count} occurrence(s)" for cat, f in findings.items()
        ) or "No sensitive data detected."

        prompt = f"""Document excerpt (may be truncated):
---
{text[:MAX_CONTEXT_CHARS]}
---

Detected sensitive-data findings:
{findings_desc}

Answer the user's question using only the information above. If the answer
isn't determinable from this context, say so honestly.

Question: {question}"""

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        return response.text
    except Exception:
        return None


def _keyword_answer(question: str, text: str, findings: dict, risk_label: str, score: int) -> str:
    q = question.lower()

    # "how many <category>" style questions
    count_match = re.search(r"how many ([a-z ]+)", q)
    if count_match:
        target = count_match.group(1).strip()
        for category, f in findings.items():
            if target in category.lower() or category.lower().split()[0] in target:
                return f"There are {f.count} occurrence(s) of {category} in this document."
        return f"I couldn't find a matching category for '{target}'. Detected categories: " + \
               (", ".join(findings.keys()) if findings else "none")

    if "summar" in q:
        if not findings:
            return "This document contains no detected sensitive data and is classified as Low Risk."
        cats = ", ".join(findings.keys())
        return (
            f"Summary: The document is classified as {risk_label} (score {score}). "
            f"Detected categories: {cats}. Total flagged items: "
            f"{sum(f.count for f in findings.values())}."
        )

    if "what sensitive" in q or "what data" in q or "exists" in q:
        if not findings:
            return "No sensitive data was detected in this document."
        lines = [f"- {cat}: {f.count} occurrence(s)" for cat, f in findings.items()]
        return "Detected sensitive data:\n" + "\n".join(lines)

    if "compliance" in q or "risk" in q:
        high = [c for c, f in findings.items() if f.severity == 3]
        if not findings:
            return "No compliance risks identified — no sensitive data detected."
        risk_text = f"Overall risk: {risk_label} (score {score})."
        if high:
            risk_text += " High-severity categories requiring immediate remediation: " + ", ".join(high) + "."
        return risk_text

    # generic fallback
    if findings:
        cats = ", ".join(findings.keys())
        return (
            "I can answer questions about detected sensitive data categories "
            f"({cats}), counts, risk level, and remediation. Try asking things like "
            "'How many email addresses are present?' or 'Summarize this document.'"
        )
    return "No sensitive data was detected, so there isn't much to report for this document."


def answer_question(question: str, text: str, findings: dict, risk_label: str, score: int) -> str:
    llm_result = _llm_answer(question, text, findings)
    if llm_result:
        return llm_result
    return _keyword_answer(question, text, findings, risk_label, score)
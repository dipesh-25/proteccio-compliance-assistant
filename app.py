"""
app.py
------
Streamlit front-end for the Sensitive Data Detection & Compliance Assistant.

Run with:  streamlit run app.py
"""

import csv
import datetime
import os

import streamlit as st
from dotenv import load_dotenv

from document_parser import extract_text
from detector import detect_sensitive_data, classify_risk, findings_to_table
from summarizer import generate_summary
from qa_engine import answer_question

load_dotenv()

st.set_page_config(
    page_title="Sensitive Data Detection & Compliance Assistant",
    page_icon="🛡️",
    layout="wide",
)

AUDIT_LOG_PATH = "audit_log.csv"


def log_audit_event(filename: str, risk_label: str, score: int, findings: dict):
    """Bonus feature: append a row to a local audit log every time a document is scanned."""
    is_new = not os.path.exists(AUDIT_LOG_PATH)
    with open(AUDIT_LOG_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(["timestamp", "filename", "risk_label", "score", "categories_detected"])
        writer.writerow(
            [
                datetime.datetime.now().isoformat(timespec="seconds"),
                filename,
                risk_label,
                score,
                ";".join(findings.keys()),
            ]
        )


def risk_badge(risk_label: str) -> str:
    color = {"Low Risk": "🟢", "Medium Risk": "🟡", "High Risk": "🔴"}.get(risk_label, "⚪")
    return f"{color} **{risk_label}**"


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ Compliance Assistant")
    st.caption("Sensitive Data Detection & Compliance Assistant")
    st.markdown("---")
    st.markdown(
        "**Supported formats:** PDF, TXT, CSV\n\n"
        "**Detects:** Aadhaar, PAN, Email, Phone, Credit Card, Bank Details, "
        "API Keys/Passwords, Employee IDs, Confidential Business Info"
    )
    has_key = bool(os.environ.get("GEMINI_API_KEY"))
    st.markdown("---")
    if has_key:
        st.success("LLM mode: ON (GEMINI_API_KEY detected)")
    else:
        st.info(
            "LLM mode: OFF — running in rule-based mode. "
            "Set a GEMINI_API_KEY environment variable to enable richer, "
            "LLM-generated summaries and Q&A."
        )
    st.markdown("---")
    if os.path.exists(AUDIT_LOG_PATH):
        with open(AUDIT_LOG_PATH, "rb") as f:
            st.download_button("⬇️ Download audit log", f, file_name="audit_log.csv")

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
if "history" not in st.session_state:
    st.session_state.history = []  # chat history for Q&A

# ---------------------------------------------------------------------------
# Main: file upload
# ---------------------------------------------------------------------------
st.header("📄 Upload a document to scan")
uploaded_file = st.file_uploader("Choose a PDF, TXT, or CSV file", type=["pdf", "txt", "csv"])

if uploaded_file is not None:
    file_bytes = uploaded_file.read()

    with st.spinner("Extracting text..."):
        try:
            text = extract_text(uploaded_file.name, file_bytes)
        except Exception as e:
            st.error(f"Could not read file: {e}")
            st.stop()

    with st.spinner("Scanning for sensitive data..."):
        findings = detect_sensitive_data(text)
        risk_label, score = classify_risk(findings)

    # cache results in session so the Q&A section below doesn't re-run detection
    st.session_state.current_text = text
    st.session_state.current_findings = findings
    st.session_state.current_risk_label = risk_label
    st.session_state.current_score = score
    st.session_state.current_filename = uploaded_file.name

    log_audit_event(uploaded_file.name, risk_label, score, findings)

    st.success(f"Scan complete for **{uploaded_file.name}**")

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Level", risk_label.replace(" Risk", ""))
    col2.metric("Risk Score", score)
    col3.metric("Categories Flagged", len(findings))

    st.markdown(risk_badge(risk_label))

    # ---- Findings table --------------------------------------------------
    st.subheader("🔍 Detected Sensitive Data (masked)")
    if findings:
        st.dataframe(findings_to_table(findings), width="stretch", hide_index=True)
    else:
        st.info("No sensitive data patterns were detected in this document.")

    # ---- Summary -----------------------------------------------------------
    st.subheader("📋 Compliance & Security Summary")
    with st.spinner("Generating summary..."):
        summary = generate_summary(text, findings, risk_label, score)
    st.markdown(summary)

    # ---- Raw text preview ---------------------------------------------------
    with st.expander("View extracted text (raw)"):
        st.text_area("Extracted text", text, height=250, label_visibility="collapsed")

    st.markdown("---")

    # ---- Q&A -----------------------------------------------------------------
    st.subheader("💬 Ask a question about this document")
    for role, msg in st.session_state.history:
        with st.chat_message(role):
            st.markdown(msg)

    question = st.chat_input("e.g. How many email addresses are present?")
    if question:
        st.session_state.history.append(("user", question))
        with st.chat_message("user"):
            st.markdown(question)

        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                answer = answer_question(
                    question,
                    st.session_state.current_text,
                    st.session_state.current_findings,
                    st.session_state.current_risk_label,
                    st.session_state.current_score,
                )
            st.markdown(answer)
        st.session_state.history.append(("assistant", answer))

else:
    st.info("👆 Upload a PDF, TXT, or CSV file to begin scanning.")
    st.caption("Tip: try `sample_data/sample.txt` included in this repo for a quick demo.")
# Sensitive Data Detection & Compliance Assistant

An AI-powered Streamlit application that scans uploaded documents (PDF / TXT / CSV),
detects sensitive/confidential information, classifies overall document risk,
generates a compliance & security summary, and lets you ask follow-up
questions about the document.

Built as an assignment submission for the AI Innovation Internship at Proteccio Data.

## Demo

[Add your 2–5 minute demo video link here]
[https://proteccio-compliance-assistant-fpouyv9fyyikjxgu4cuevp.streamlit.app/]

---

## Features

- **Multi-format upload**: PDF, TXT, CSV
- **Sensitive data detection**: Aadhaar numbers, PAN numbers, email addresses,
  phone numbers, credit card numbers, bank account/IFSC details, API
  keys/passwords, employee IDs, and confidential-business-info keywords
- **Risk classification**: Low / Medium / High, based on a weighted severity
  score (not just a raw match count)
- **AI-generated compliance summary**: observations, security risks, and
  remediation steps
- **Conversational Q&A**: ask things like *"How many email addresses are
  present?"* or *"Summarize this document"*
- **Data masking**: all detected values are masked before being displayed or
  logged — the tool never surfaces raw PII on screen
- **Audit logging**: every scan is appended to a local `audit_log.csv`
  (timestamp, filename, risk level, categories found), downloadable from the
  sidebar
- **Dockerized**: ready to containerize and deploy
- **Graceful degradation**: works fully offline/without any API key
  (rule-based summary + keyword Q&A); automatically upgrades to LLM-generated
  answers if a `GEMINI_API_KEY` is configured

---

## Architecture Overview

```
                ┌─────────────────┐
   Upload  ───► │  document_parser │  → extracts raw text from PDF/TXT/CSV
                └────────┬─────────┘
                         │ text
                         ▼
                ┌─────────────────┐
                │    detector      │  → regex + severity-weighted scan
                │  (PII patterns)  │  → de-duplicates overlapping matches
                └────────┬─────────┘
                         │ findings + risk score
             ┌───────────┴────────────┐
             ▼                        ▼
   ┌──────────────────┐     ┌──────────────────┐
   │   summarizer      │     │    qa_engine      │
   │ (LLM w/ fallback) │     │ (LLM w/ fallback) │
   └──────────────────┘     └──────────────────┘
             │                        │
             └───────────┬────────────┘
                          ▼
                 ┌─────────────────┐
                 │     app.py       │  → Streamlit UI: upload, dashboard,
                 │  (Streamlit UI)  │    chat, audit log download
                 └─────────────────┘
```

**Module responsibilities**

| File | Responsibility |
|---|---|
| `document_parser.py` | Extracts plain text from PDF (`pdfplumber`), TXT, and CSV (`pandas`, flattened row-by-row) |
| `detector.py` | Regex pattern bank for each sensitive-data category, overlap resolution, masking, and weighted risk scoring |
| `summarizer.py` | Produces the compliance/security summary — LLM-backed if a key is present, deterministic rule-based otherwise |
| `qa_engine.py` | Answers free-form questions — LLM-backed if a key is present, keyword-pattern matching otherwise |
| `app.py` | Streamlit front-end wiring everything together, plus the audit log |

---

## AI/ML Approach Used

1. **Detection layer — deterministic, not ML.** Sensitive data detection uses
   hand-written regex patterns rather than a trained NER model. This was a
   deliberate trade-off: regex is fast, has zero cold-start/GPU cost, is
   fully explainable (every match can be traced to the exact pattern that
   fired), and works well for the highly structured formats specified in the
   brief (Aadhaar, PAN, credit card numbers, emails, etc., all follow strict
   formats). A pure ML/NER approach (e.g. spaCy's `en_core_web_trf` or a
   fine-tuned transformer) would generalize better to *unstructured* PII like
   free-text names or addresses, but adds latency, model download size, and
   non-determinism that isn't justified for this structured-data-heavy use
   case.

2. **Overlap resolution.** Several patterns can match the same span of text
   (e.g. a 12-digit Aadhaar number is also a valid-length "bank account
   number"). A priority-ordered claim system ensures each character span is
   only attributed to its most specific category, avoiding inflated risk
   scores from double-counting.

3. **Risk scoring.** Rather than simple `if count > 0: risk = High`, each
   category carries a severity weight (1–3). The overall score is
   `Σ(count × severity)`, bucketed into Low/Medium/High. This means one
   Aadhaar number pushes risk up faster than ten generic "confidential"
   keyword mentions — reflecting real-world compliance impact.

4. **Generative layer (LLM).** The compliance summary and the conversational
   Q&A are the actual "AI" components. When a `GEMINI_API_KEY` is
   present, both features call Google Gemini (`gemini-2.0-flash`) via the
   `google-genai` SDK, with the *detected findings* (never the full raw
   document, to limit blast radius) as grounding context, so the model
   summarizes and answers strictly from what was actually detected instead
   of hallucinating findings. If no key is configured, both features fall
   back to deterministic logic so the app is always demoable.

5. **Data masking.** All matched values are masked (`ab***yz`) before ever
   being rendered, logged, or sent to an LLM prompt, so the compliance tool
   doesn't itself become a new source of exposure.

---

## Setup Instructions

### 1. Clone and install

```bash
git clone https://github.com/dipesh-25/proteccio-compliance-assistant.git
cd proteccio-compliance-assistant
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. (Optional) Enable LLM mode

Copy `.env.example` to `.env` and add a free Google Gemini API key
(get one at https://aistudio.google.com/apikey — no card required) to unlock
LLM-generated summaries and richer Q&A:

```bash
cp .env.example .env
# then edit .env and set GEMINI_API_KEY=...
```

The app works fully without this step, in rule-based mode.

### 3. Run

```bash
streamlit run app.py
```

Open the URL Streamlit prints (usually `http://localhost:8501`) and upload
`sample_data/sample.txt` for a quick demo.

### 4. Run with Docker (optional)

```bash
docker build -t compliance-assistant .
docker run -p 8501:8501 --env-file .env compliance-assistant
```

---

## Challenges Faced

- **Overlapping regex matches**: numeric PII formats overlap heavily (a
  16-digit credit card number substring can also match generic "bank account
  number" patterns). Solved with a priority-ordered span-claiming system so
  each character range is attributed to exactly one category.
- **CSV structure loss**: naively converting a CSV to text loses which
  column a value came from, which matters for compliance reporting. Solved
  by flattening each row as `column=value` pairs so context is preserved.
- **Keeping the app usable without an API key**: since a grader may not have
  (or want to share) an API key, every AI-generated feature needed a
  deterministic fallback path so the tool is never a dead end.
- **Avoiding false positives on generic 9–18 digit numbers** (the bank
  account pattern is intentionally broad): mitigated by giving it the lowest
  priority in the overlap-resolution order so more specific patterns (PAN,
  Aadhaar, credit card) are always preferred first.

---

## Future Improvements

- Add a proper NER model (e.g. spaCy or a fine-tuned transformer) to catch
  unstructured PII like names, addresses, and physical locations that regex
  can't reliably capture.
- Add OCR support (e.g. `pytesseract`) for scanned/image-based PDFs.
- Add a redaction/export feature that outputs a sanitized copy of the
  original document with sensitive spans blacked out.
- Add multi-document / batch upload support with an aggregate risk dashboard
  across a whole folder.
- Add a lightweight RAG index (ChromaDB/FAISS) over the document so Q&A can
  scale to very large documents beyond a single LLM context window.
- Add role-based access control and encrypt the audit log at rest for real
  production use.
- Add automated tests (`pytest`) for the regex pattern bank and risk-scoring
  logic.

---

## Tech Stack

- **Frontend**: Streamlit
- **Document parsing**: `pdfplumber`, `pandas`
- **Detection engine**: Python `re` (regex) with a custom severity-weighted
  risk model
- **Generative AI**: Google Gemini API (`gemini-2.0-flash`, free tier,
  optional, with rule-based fallback)
- **Deployment**: Docker

---

## Author

Dipesh — B.Tech CSE (AI), Mandsaur Institute of Technology
GitHub: [github.com/dipesh-25](https://github.com/dipesh-25)

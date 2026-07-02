"""
document_parser.py
-------------------
Handles extraction of raw text from the three supported input formats:
PDF, TXT and CSV. CSV files are flattened row-by-row so the same regex-based
detector used for free text can be reused without a separate code path.
"""

from __future__ import annotations
import io
import pandas as pd
import pdfplumber


def extract_text_from_pdf(file_bytes: bytes) -> str:
    """Extract text from a PDF using pdfplumber (page by page)."""
    text_chunks = []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        for i, page in enumerate(pdf.pages):
            page_text = page.extract_text() or ""
            text_chunks.append(f"\n--- Page {i + 1} ---\n{page_text}")
    return "\n".join(text_chunks)


def extract_text_from_txt(file_bytes: bytes) -> str:
    """Decode a plain text file, falling back gracefully on odd encodings."""
    try:
        return file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return file_bytes.decode("latin-1", errors="ignore")


def extract_text_from_csv(file_bytes: bytes) -> str:
    """
    Flatten a CSV into pseudo-text so the same detection pipeline can scan it.
    Column headers are preserved so findings can (optionally) be traced back
    to a column name, which is useful for the compliance summary.
    """
    df = pd.read_csv(io.BytesIO(file_bytes))
    lines = [f"Columns: {', '.join(df.columns.astype(str))}"]
    for idx, row in df.iterrows():
        row_text = " | ".join(f"{col}={val}" for col, val in row.items())
        lines.append(f"Row {idx + 1}: {row_text}")
    return "\n".join(lines)


def extract_text(filename: str, file_bytes: bytes) -> str:
    """Dispatch to the correct extractor based on file extension."""
    ext = filename.lower().rsplit(".", 1)[-1]
    if ext == "pdf":
        return extract_text_from_pdf(file_bytes)
    elif ext == "txt":
        return extract_text_from_txt(file_bytes)
    elif ext == "csv":
        return extract_text_from_csv(file_bytes)
    else:
        raise ValueError(f"Unsupported file type: .{ext}")

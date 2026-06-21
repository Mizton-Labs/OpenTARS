"""PDF text extraction using PyMuPDF (fitz).

Parser: `pymupdf` — preferred for structured documents, mixed content, tables.
Parser: `marker` — higher-quality markdown output for article-like PDFs
  (placeholder, requires marker-pdf package not yet installed).

The active parser is selected by the dispatcher based on user config or auto
heuristics. This module implements the PyMuPDF path.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_PYMUPDF_VERSION: str | None = None

try:
    import fitz  # type: ignore[import-untyped]  # pymupdf

    _PYMUPDF_VERSION = fitz.version[0]
except ImportError:  # pragma: no cover
    fitz = None  # type: ignore[assignment]


def is_available() -> bool:
    return fitz is not None


def extract_pdf(data: bytes) -> tuple[str, str, list[str]]:
    """Extract text from PDF bytes using PyMuPDF.

    Returns (extracted_text, parser_version, warnings).
    Raises RuntimeError when PyMuPDF is not installed.
    """
    if fitz is None:
        raise RuntimeError("PyMuPDF (pymupdf) is not installed")

    warnings: list[str] = []
    version = _PYMUPDF_VERSION or "unknown"

    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:
        raise ValueError(f"Cannot open PDF: {exc}") from exc

    pages: list[str] = []
    for page_num in range(len(doc)):
        try:
            page = doc.load_page(page_num)
            page_text = page.get_text("text")  # plain text extraction
            if page_text.strip():
                pages.append(f"--- Page {page_num + 1} ---\n{page_text.strip()}")
        except Exception as exc:
            warnings.append(f"Page {page_num + 1} extraction error: {exc}")
            logger.warning("PDF page %d extraction error: %s", page_num + 1, exc)

    doc.close()

    if not pages:
        warnings.append("No extractable text found in PDF (may be scanned/image-only)")

    return "\n\n".join(pages), version, warnings

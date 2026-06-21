"""PDF text extraction — PyMuPDF (fitz) and Docling.

Parser: ``pymupdf`` — fast, reliable plain-text extraction with per-page
  delimiters.  Fallback when Docling is unavailable or disabled.

Parser: ``docling`` — high-quality Markdown output via the Docling ML pipeline.
  Preserves document structure: headings, tables, reading order, code blocks,
  and equations.  Requires ``docling>=2.104.0`` (pulled automatically via
  requirements.txt; PyTorch + IBM DocLayNet models, ~2-3 GB first install).
  ML models are prefetched at startup by the ``mizton-threatbox`` launcher
  (idempotent; models cached under ``~/.cache/docling/``).

  Docling is chosen over marker-pdf because:
    - pillow constraint: ``pillow<13.0.0,>=10.0.0`` is COMPATIBLE with our
      ``pillow>=12.2.0`` security pin.  marker-pdf capped ``pillow<11.0.0``
      which forced a downgrade reintroducing 3 High-severity Pillow CVEs.
    - ``is_docling_available()`` reflects runtime import; the catalog endpoint
      surfaces this to the frontend.

Both parsers are selected by the dispatcher (``dispatcher.py``) based on the
requested ``parser_mode`` (``auto`` | ``pymupdf`` | ``docling``) AND the
``agent_tools["docling"]`` config toggle.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ── PyMuPDF ──────────────────────────────────────────────────────────────────

_PYMUPDF_VERSION: str | None = None

try:
    import fitz  # type: ignore[import-untyped]  # pymupdf

    _PYMUPDF_VERSION = fitz.version[0]
except ImportError:  # pragma: no cover
    fitz = None  # type: ignore[assignment]


def is_available() -> bool:
    """Return True when PyMuPDF is installed."""
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


# ── Docling ───────────────────────────────────────────────────────────────────

_DOCLING_VERSION: str | None = None

try:
    import docling  # type: ignore[import-untyped]

    _DOCLING_VERSION = getattr(docling, "__version__", "unknown")
    _DOCLING_AVAILABLE = True
except ImportError:
    docling = None  # type: ignore[assignment]
    _DOCLING_AVAILABLE = False


def is_docling_available() -> bool:
    """Return True when docling is installed and importable."""
    return _DOCLING_AVAILABLE


def extract_pdf_docling(data: bytes) -> tuple[str, str, list[str]]:
    """Extract Markdown from PDF bytes using the Docling ML pipeline.

    Returns (markdown_text, parser_version, warnings).

    Raises:
        RuntimeError: when docling is not installed.
        ValueError:   when the PDF cannot be converted.

    Notes:
        - Docling uses the DocLayNet layout model + TableFormer table-structure
          model.  Models are prefetched at startup by ``mizton-threatbox`` and
          cached under ``~/.cache/docling/``.
        - Output is structured Markdown: headings, tables, lists, code blocks,
          and reading order are preserved by the ML pipeline.
        - CPU inference is used by default; CUDA/MPS are auto-detected if
          available.
    """
    if not _DOCLING_AVAILABLE or docling is None:
        raise RuntimeError(
            "docling is not installed. It should be installed automatically via requirements.txt."
        )

    warnings_out: list[str] = []
    version = _DOCLING_VERSION or "unknown"

    try:
        import io  # noqa: PLC0415

        from docling.datamodel.document import DocumentStream  # type: ignore[import-untyped]
        from docling.document_converter import DocumentConverter  # type: ignore[import-untyped]

        # DocumentStream avoids writing a temp file — passes bytes directly
        stream = DocumentStream(name="document.pdf", stream=io.BytesIO(data))
        converter = DocumentConverter()
        result = converter.convert(stream)

        status_val = getattr(result.status, "value", str(result.status))
        if status_val not in ("success", "partial_success"):
            raise ValueError(f"Docling conversion status: {status_val}")

        if status_val == "partial_success":
            warnings_out.append("Docling partial success — some pages may not have been converted")

        markdown = result.document.export_to_markdown()

    except ImportError as exc:
        raise RuntimeError(
            f"docling is installed but a required sub-module is missing: {exc}"
        ) from exc
    except Exception as exc:
        raise ValueError(f"Docling PDF conversion failed: {exc}") from exc

    if not markdown or not markdown.strip():
        warnings_out.append(
            "Docling produced no text (PDF may be image-only, encrypted, or incompatible)"
        )

    return markdown or "", version, warnings_out

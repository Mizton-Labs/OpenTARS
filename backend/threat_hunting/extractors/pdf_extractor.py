"""PDF text extraction — PyMuPDF (fitz) and Marker (marker-pdf).

Parser: ``pymupdf`` — fast, reliable plain-text extraction with per-page
  delimiters.  Default for all modes unless Marker is installed + enabled.

Parser: ``marker`` — higher-quality Markdown output for article-like PDFs.
  Preserves layout, tables, equations, and headings via the marker-pdf ML
  library (requires ``pip install marker-pdf``, which pulls PyTorch and
  surya-ocr models; first-use model download is several GB).

  ``is_marker_available()`` checks whether marker-pdf is installed at runtime.
  The catalog endpoint reports this to the frontend so the UI can reflect
  actual availability without a hard dependency.

Both parsers are selected by the dispatcher (``dispatcher.py``) based on the
requested ``parser_mode`` (``auto`` | ``pymupdf`` | ``marker``) AND the
``agent_tools["marker"]`` config toggle.
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


# ── Marker (marker-pdf) ───────────────────────────────────────────────────────

_MARKER_VERSION: str | None = None

try:
    import marker  # type: ignore[import-untyped]  # marker-pdf

    _MARKER_VERSION = getattr(marker, "__version__", "unknown")
    _MARKER_AVAILABLE = True
except ImportError:
    marker = None  # type: ignore[assignment]
    _MARKER_AVAILABLE = False


def is_marker_available() -> bool:
    """Return True when marker-pdf is installed and importable."""
    return _MARKER_AVAILABLE


def extract_pdf_marker(data: bytes) -> tuple[str, str, list[str]]:
    """Extract Markdown text from PDF bytes using marker-pdf.

    Returns (markdown_text, parser_version, warnings).

    Raises:
        RuntimeError: when marker-pdf is not installed.
        ValueError:   when the PDF cannot be parsed.

    Notes:
        - marker-pdf downloads ML models (surya-ocr, layout model) on first
          use.  This may take several minutes and requires internet access.
        - The output is structured Markdown: headings, tables, inline code,
          and equation blocks are preserved where the model recognises them.
        - CPU-only inference is used by default.  GPU acceleration is
          available automatically when torch detects CUDA/MPS.
    """
    if not _MARKER_AVAILABLE or marker is None:
        raise RuntimeError("marker-pdf is not installed. Run: pip install marker-pdf")

    warnings: list[str] = []
    version = _MARKER_VERSION or "unknown"

    try:
        # marker-pdf ≥ 0.3: PdfConverter API
        import os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        from marker.converters.pdf import PdfConverter  # type: ignore[import-untyped]
        from marker.models import create_model_dict  # type: ignore[import-untyped]
        from marker.output import text_from_rendered  # type: ignore[import-untyped]

        # marker-pdf operates on file paths, not bytes — write to a temp file
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            model_dict = create_model_dict()
            converter = PdfConverter(artifact_dict=model_dict)
            rendered = converter(tmp_path)
            markdown, _, _ = text_from_rendered(rendered)
        finally:
            os.unlink(tmp_path)

    except ImportError:
        # Fallback: try the older marker-pdf 0.2.x API
        try:
            import os
            import tempfile

            from marker.convert import convert_single_pdf  # type: ignore[import-untyped]
            from marker.models import load_all_models  # type: ignore[import-untyped]

            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            try:
                model_lst = load_all_models()
                markdown, _images, _metadata = convert_single_pdf(tmp_path, model_lst)
            finally:
                os.unlink(tmp_path)

        except Exception as exc:
            raise ValueError(f"marker-pdf conversion failed: {exc}") from exc

    except Exception as exc:
        raise ValueError(f"marker-pdf conversion failed: {exc}") from exc

    if not markdown or not markdown.strip():
        warnings.append("marker-pdf produced no text (PDF may be image-only or incompatible)")

    return markdown or "", version, warnings

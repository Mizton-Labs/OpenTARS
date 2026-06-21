"""Artifact extraction dispatcher for Threat Hunting evidence items.

Selects the appropriate extractor based on MIME type / file extension and
the configured parser_mode (auto | pymupdf | docling).

parser_mode routing for PDFs (issue-007):
  - ``pymupdf``  — always use PyMuPDF (plain text, fast).
  - ``docling``  — use Docling ML pipeline when available + enabled in
                   agent_tools config; otherwise fall back to PyMuPDF + warning.
  - ``auto``     — **default: prefers Docling** when it is installed AND the
                   "docling" agent_tools toggle is enabled; otherwise PyMuPDF.
"""

from __future__ import annotations

import hashlib
import logging
import mimetypes

logger = logging.getLogger(__name__)

# Parser mode constants
PARSER_AUTO = "auto"
PARSER_PYMUPDF = "pymupdf"
PARSER_DOCLING = "docling"

# Keep backward-compat alias — any stored parser_mode="marker" is treated as "docling"
PARSER_MARKER = "docling"

# File size limits for in-process extraction (50 MiB)
_MAX_FILE_BYTES = 50 * 1024 * 1024

# MIME type routing
_PDF_TYPES = frozenset({"application/pdf", "application/x-pdf"})
_DOCX_TYPES = frozenset(
    {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/msword",
    }
)
_TEXT_TYPES = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/x-markdown",
        "text/html",
        "text/xml",
        "application/xml",
        "application/json",
        "application/ld+json",
        "application/ndjson",
        "text/csv",
        "text/tab-separated-values",
    }
)
_CSV_TYPES = frozenset({"text/csv", "text/tab-separated-values"})
_JSON_TYPES = frozenset({"application/json", "application/ld+json", "application/ndjson"})


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _guess_mime(filename: str) -> str:
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def extract_file(
    data: bytes,
    filename: str,
    mime_type: str = "",
    parser_mode: str = PARSER_AUTO,
) -> dict:
    """Extract text from file bytes.

    Returns a dict with:
        extracted_text  str
        parser_used     str
        parser_version  str
        parse_status    'ok' | 'partial' | 'error'
        parse_warnings  list[str]
        content_hash    str (sha256 hex)
        mime_type       str (effective MIME)
    """
    warnings: list[str] = []

    if len(data) > _MAX_FILE_BYTES:
        warnings.append(
            f"File truncated to {_MAX_FILE_BYTES // (1024 * 1024)} MiB limit "
            f"(original size: {len(data) // (1024 * 1024)} MiB)"
        )
        data = data[:_MAX_FILE_BYTES]

    content_hash = _sha256(data)
    effective_mime = mime_type or _guess_mime(filename)

    # Decompress if gzip or zip
    if filename.endswith(".gz") or effective_mime == "application/gzip":
        import gzip

        try:
            data = gzip.decompress(data)
            effective_mime = (
                _guess_mime(filename[:-3]) if filename.endswith(".gz") else "text/plain"
            )
            warnings.append("Decompressed gzip layer")
        except Exception as exc:
            warnings.append(f"gzip decompression failed: {exc}")

    elif filename.endswith(".zip") or effective_mime == "application/zip":
        import io
        import zipfile

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                members = [m for m in zf.namelist() if not m.endswith("/")]
                if len(members) == 1:
                    data = zf.read(members[0])
                    effective_mime = _guess_mime(members[0])
                    warnings.append(f"Decompressed zip: {members[0]}")
                else:
                    warnings.append(
                        f"ZIP contains {len(members)} members; reading first member only"
                    )
                    data = zf.read(members[0])
                    effective_mime = _guess_mime(members[0])
        except Exception as exc:
            warnings.append(f"ZIP decompression failed: {exc}")

    # Route to extractor
    extracted_text = ""
    parser_used = "none"
    parser_version = ""
    parse_status = "ok"

    try:
        if effective_mime in _PDF_TYPES or filename.lower().endswith(".pdf"):
            extracted_text, parser_used, parser_version, warnings = _extract_pdf(
                data, parser_mode, warnings
            )

        elif effective_mime in _DOCX_TYPES or filename.lower().endswith((".docx", ".doc")):
            extracted_text, parser_used, parser_version, warnings = _extract_docx(data, warnings)

        elif effective_mime in _CSV_TYPES or filename.lower().endswith((".csv", ".tsv")):
            from backend.threat_hunting.extractors.text_extractor import extract_csv_text

            extracted_text, w = extract_csv_text(data)
            warnings.extend(w)
            parser_used = "csv"
            parser_version = "stdlib"

        elif effective_mime in _JSON_TYPES or filename.lower().endswith((".json", ".ndjson")):
            from backend.threat_hunting.extractors.text_extractor import extract_json_text

            extracted_text, w = extract_json_text(data)
            warnings.extend(w)
            parser_used = "json"
            parser_version = "stdlib"

        else:
            from backend.threat_hunting.extractors.text_extractor import extract_text

            extracted_text, w = extract_text(data, effective_mime)
            warnings.extend(w)
            parser_used = "text"
            parser_version = "stdlib"

        if not extracted_text.strip():
            parse_status = "partial"
            warnings.append("Extraction produced no text content")

    except Exception as exc:
        parse_status = "error"
        warnings.append(f"Extraction failed: {exc}")
        logger.exception("Extraction error for %r (mime=%r)", filename, effective_mime)

    return {
        "extracted_text": extracted_text,
        "parser_used": parser_used,
        "parser_version": parser_version,
        "parse_status": parse_status,
        "parse_warnings": warnings,
        "content_hash": content_hash,
        "mime_type": effective_mime,
    }


def _extract_pdf(
    data: bytes, parser_mode: str, warnings: list[str]
) -> tuple[str, str, str, list[str]]:
    """Route PDF extraction to PyMuPDF or Docling based on parser_mode.

    Routing logic (issue-007):
      - ``pymupdf``  - always PyMuPDF (fast, plain text).
      - ``docling``  - Docling ML pipeline when installed + toggle enabled;
                       else PyMuPDF + warning.
      - ``marker``   - treated identically to ``docling`` (backward compat alias).
      - ``auto``     - **prefers Docling** when installed + enabled; else PyMuPDF.
    """
    from backend.threat_hunting.extractors.pdf_extractor import (
        extract_pdf,
        extract_pdf_docling,
        is_available,
        is_docling_available,
    )

    def _docling_toggle_enabled() -> bool:
        """Return whether the Docling toggle is on in agent_tools config."""
        try:
            from backend.config.loader import load_agent_tools

            return bool(load_agent_tools().get("docling", True))
        except Exception:  # noqa: BLE001
            return True  # conservative default: enabled if config unreadable

    use_docling = is_docling_available() and _docling_toggle_enabled()

    # ``docling`` and legacy ``marker`` both route to Docling
    if parser_mode in (PARSER_DOCLING, "marker"):
        if not is_docling_available():
            warnings.append(
                "Docling parser selected but docling is not installed; falling back to PyMuPDF."
            )
        elif not _docling_toggle_enabled():
            warnings.append(
                "Docling parser selected but disabled in agent tools configuration; "
                "falling back to PyMuPDF."
            )
        else:
            try:
                text, version, parse_warnings = extract_pdf_docling(data)
                warnings.extend(parse_warnings)
                return text, "docling", version, warnings
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Docling extraction failed ({exc}); falling back to PyMuPDF")

    elif parser_mode == PARSER_AUTO and use_docling:
        # Auto-mode prefers Docling when available + enabled (issue-007)
        try:
            text, version, parse_warnings = extract_pdf_docling(data)
            warnings.extend(parse_warnings)
            warnings.append("auto: used Docling for high-quality Markdown extraction")
            return text, "docling", version, warnings
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Docling auto-mode failed ({exc}); falling back to PyMuPDF")

    # Fall through: PyMuPDF
    if not is_available():
        warnings.append("PyMuPDF not available; returning raw bytes as text")
        return data.decode("utf-8", errors="replace"), "none", "", warnings

    text, version, parse_warnings = extract_pdf(data)
    warnings.extend(parse_warnings)
    return text, "pymupdf", version, warnings


def _extract_docx(data: bytes, warnings: list[str]) -> tuple[str, str, str, list[str]]:
    """Extract DOCX content using python-docx."""
    from backend.threat_hunting.extractors.docx_extractor import extract_docx, is_available

    if not is_available():
        warnings.append("python-docx not available; returning empty text")
        return "", "none", "", warnings

    text, version, parse_warnings = extract_docx(data)
    warnings.extend(parse_warnings)
    return text, "python-docx", version, warnings

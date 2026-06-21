"""Plain-text and Markdown extraction for .txt/.md/.json/.ndjson/.xml files."""

from __future__ import annotations

import csv
import io
import json


def extract_text(data: bytes, mime_type: str = "") -> tuple[str, list[str]]:
    """Return (extracted_text, warnings) for plain/text-like content.

    Handles UTF-8 and falls back to latin-1 on decode errors.
    """
    warnings: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
        warnings.append("File decoded as latin-1 (not valid UTF-8)")
    return text.strip(), warnings


def extract_csv_text(data: bytes) -> tuple[str, list[str]]:
    """Convert CSV/TSV bytes to readable text for LLM context.

    Returns a markdown table representation if the CSV has headers,
    otherwise a plain newline-separated dump.
    """
    warnings: list[str] = []
    text = data.decode("utf-8", errors="replace")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",\t;|")
    except csv.Error:
        dialect = csv.excel

    reader = csv.reader(io.StringIO(text), dialect=dialect)
    rows = list(reader)
    if not rows:
        return "", ["CSV appears empty"]

    # Build a markdown table
    headers = rows[0]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows[1:]:
        # Pad/truncate to header width
        padded = row[: len(headers)] + [""] * max(0, len(headers) - len(row))
        lines.append("| " + " | ".join(padded) + " |")
    return "\n".join(lines), warnings


def extract_json_text(data: bytes) -> tuple[str, list[str]]:
    """Pretty-print JSON for LLM context."""
    warnings: list[str] = []
    try:
        obj = json.loads(data.decode("utf-8", errors="replace"))
        return json.dumps(obj, indent=2, ensure_ascii=False), warnings
    except json.JSONDecodeError as exc:
        warnings.append(f"JSON parse error: {exc}")
        return data.decode("utf-8", errors="replace"), warnings

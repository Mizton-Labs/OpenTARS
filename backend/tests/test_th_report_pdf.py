"""
Tests for the Threat Hunting report follow-up (issue-local-018 further
follow-up):

  - assemble_report / render_report_markdown now include the full
    extracted/parsed evidence items, not just an aggregate count.
  - render_report_pdf produces a professional, print-friendly PDF, and
    embeds the configured branding (app title + logo) when present.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from unittest.mock import patch

from backend.threat_hunting.agents.nodes.report_writer import (
    _evidence_items_full,
    assemble_report,
    render_report_markdown,
    render_report_pdf,
)

EVIDENCE_ITEMS = [
    {
        "id": "e1",
        "label": "phish.eml",
        "item_type": "email",
        "source_ref": "inbox/phish.eml",
        "parser_used": "eml",
        "parse_status": "ok",
        "extracted_text": "Subject: urgent wire transfer\n\nClick here: http://evil.example",
    },
    {
        "id": "e2",
        "label": None,
        "source_ref": "http://suspicious.example",
        "item_type": "url",
        "parser_used": "html",
        "parse_status": "ok",
        "extracted_text": "",
    },
]


def _make_png(tmp_path: Path) -> Path:
    """Write a minimal valid 1x1 PNG for branding tests."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00" + b"\xff\x00\x00")
    png = sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")
    fp = tmp_path / "logo.png"
    fp.write_bytes(png)
    return fp


def _base_report(**overrides: object) -> dict:
    report = assemble_report(
        hunt_package={"name": "Test Hunt", "id": "pkg-1", "status": "completed"},
        generation_record={},
        evidence_items=EVIDENCE_ITEMS,
        task_results=[],
        executive_summary="Executive summary text.",
    )
    report.update(overrides)
    return report


class TestEvidenceItemsFull:
    def test_returns_per_item_detail(self) -> None:
        items = _evidence_items_full(EVIDENCE_ITEMS)
        assert len(items) == 2
        assert items[0]["label"] == "phish.eml"
        assert (
            items[0]["extracted_text"]
            == "Subject: urgent wire transfer\n\nClick here: http://evil.example"
        )
        assert items[0]["parser_used"] == "eml"
        assert items[0]["parse_status"] == "ok"

    def test_falls_back_to_source_ref_then_item_type_for_label(self) -> None:
        items = _evidence_items_full(EVIDENCE_ITEMS)
        # e2 has no label -> falls back to source_ref
        assert items[1]["label"] == "http://suspicious.example"

    def test_handles_missing_extracted_text(self) -> None:
        items = _evidence_items_full([{"id": "e3", "item_type": "note"}])
        assert items[0]["extracted_text"] == ""
        assert items[0]["label"] == "note"


class TestAssembleReportIncludesEvidenceItems:
    def test_full_report_has_evidence_items_key(self) -> None:
        report = _base_report()
        assert "evidence_items" in report
        assert len(report["evidence_items"]) == 2

    def test_evidence_summary_still_present_alongside_full_items(self) -> None:
        report = _base_report()
        assert report["evidence_summary"]["total_items"] == 2


class TestMarkdownIncludesEvidenceItems:
    def test_renders_evidence_items_section_with_extracted_text(self) -> None:
        report = _base_report()
        md = render_report_markdown(report)
        assert "Evidence Items (2)" in md
        assert "phish.eml" in md
        assert "Click here: http://evil.example" in md

    def test_renders_no_extracted_text_placeholder(self) -> None:
        report = _base_report()
        md = render_report_markdown(report)
        assert "(no extracted text)" in md


class TestPdfGeneration:
    def test_produces_valid_pdf_bytes(self) -> None:
        report = _base_report()
        pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:4] == b"%PDF"
        assert len(pdf_bytes) > 500

    def test_pdf_generation_with_no_branding_configured(self) -> None:
        report = _base_report()
        with (
            patch("backend.config.loader.load_app_title", return_value=""),
            patch("backend.config.loader.resolve_logo_file", return_value=None),
        ):
            pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:4] == b"%PDF"

    def test_pdf_generation_embeds_branding_logo_and_title(self, tmp_path: Path) -> None:
        logo_path = _make_png(tmp_path)
        report = _base_report()
        with (
            patch("backend.config.loader.load_app_title", return_value="Acme Security"),
            patch("backend.config.loader.resolve_logo_file", return_value=logo_path),
        ):
            pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:4] == b"%PDF"
        # The branded run should differ from (be at least as large as) the
        # unbranded one, since it embeds an extra image + title line.
        with (
            patch("backend.config.loader.load_app_title", return_value=""),
            patch("backend.config.loader.resolve_logo_file", return_value=None),
        ):
            unbranded_bytes = render_report_pdf(report)
        assert len(pdf_bytes) >= len(unbranded_bytes)

    def test_pdf_generation_survives_a_broken_logo_file(self, tmp_path: Path) -> None:
        """A corrupt/unreadable logo must not crash report generation."""
        broken = tmp_path / "broken.png"
        broken.write_bytes(b"not a real png")
        report = _base_report()
        with (
            patch("backend.config.loader.load_app_title", return_value="Acme"),
            patch("backend.config.loader.resolve_logo_file", return_value=broken),
        ):
            pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:4] == b"%PDF"

    def test_pdf_includes_evidence_items_section(self) -> None:
        report = _base_report()
        pdf_bytes = render_report_pdf(report)
        # Evidence item content should appear in the raw PDF stream (reportlab
        # deflates content streams, so just assert generation succeeds with
        # the evidence_items populated vs. empty producing different sizes).
        empty_report = _base_report(evidence_items=[])
        empty_pdf = render_report_pdf(empty_report)
        assert len(pdf_bytes) > len(empty_pdf)

"""
Tests for issue-local-023: Evidence content viewer backend support —
GET .../evidence/{item_id}/pdf (inline PDF preview) and
GET .../evidence/{item_id}/download (generic download, any file type).

Security focus: the stored `mime_type` on an evidence item is client-
supplied at upload time and never validated — these tests specifically
guard against trusting it for the response Content-Type, and against
Content-Disposition header injection via an attacker-controlled filename.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.threat_hunting import db as th_db


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", path):
        await th_db.init_threat_hunting_db()
        yield path


async def _seed_evidence(
    pkg_id: str,
    *,
    label: str = "report.pdf",
    mime_type: str = "application/pdf",
    blob_data: bytes | None = b"%PDF-1.4\n...",
) -> dict:
    return await th_db.add_evidence_item(
        pkg_id,
        item_type="file",
        label=label,
        source_ref=label,
        mime_type=mime_type,
        extracted_text="",
        parse_status="pending",
        blob_data=blob_data,
    )


class TestEvidencePdfRoute:
    @pytest.mark.asyncio
    async def test_serves_pdf_with_hardcoded_media_type(self, db_path: Path) -> None:
        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            item = await _seed_evidence(pkg["id"])

            client = TestClient(app)
            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/evidence/{item['id']}/pdf")
            assert resp.status_code == 200
            assert resp.headers["content-type"] == "application/pdf"
            assert resp.headers["x-content-type-options"] == "nosniff"
            assert "inline" in resp.headers["content-disposition"]
            assert resp.content == b"%PDF-1.4\n..."

    @pytest.mark.asyncio
    async def test_ignores_stored_mime_type_that_claims_pdf_but_is_not(self, db_path: Path) -> None:
        """Security: a mislabeled/hostile upload whose mime_type claims
        application/pdf but whose actual bytes are not a PDF must be
        rejected (415), not served — the stored mime_type is never trusted,
        only the blob's own magic bytes."""
        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            item = await _seed_evidence(
                pkg["id"],
                mime_type="application/pdf",
                blob_data=b"<html><script>alert(1)</script></html>",
            )

            client = TestClient(app)
            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/evidence/{item['id']}/pdf")
            assert resp.status_code == 415

    @pytest.mark.asyncio
    async def test_404_when_no_blob_stored(self, db_path: Path) -> None:
        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            item = await _seed_evidence(pkg["id"], blob_data=None)

            client = TestClient(app)
            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/evidence/{item['id']}/pdf")
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_404_for_item_in_a_different_package(self, db_path: Path) -> None:
        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("A", "")
            pkg_b = await th_db.create_hunt_package("B", "")
            item = await _seed_evidence(pkg_a["id"])

            client = TestClient(app)
            resp = client.get(
                f"/api/threat-hunting/packages/{pkg_b['id']}/evidence/{item['id']}/pdf"
            )
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_sanitizes_quote_and_crlf_in_filename(self, db_path: Path) -> None:
        """Security: item.label is the raw, attacker-controlled original
        upload filename. A label containing a quote or CRLF must not be
        able to break out of the Content-Disposition header value."""
        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            item = await _seed_evidence(
                pkg["id"],
                label='evil".pdf\r\nX-Injected: yes',
            )

            client = TestClient(app)
            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/evidence/{item['id']}/pdf")
            assert resp.status_code == 200
            disposition = resp.headers["content-disposition"]
            # No CR/LF (header injection) and no stray quote breaking the
            # filename="..." parameter out early.
            assert "\r" not in disposition and "\n" not in disposition
            assert disposition.count('"') == 2
            assert "X-Injected" not in resp.headers


class TestEvidenceDownloadRoute:
    @pytest.mark.asyncio
    async def test_downloads_any_file_type_as_octet_stream(self, db_path: Path) -> None:
        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            item = await _seed_evidence(
                pkg["id"],
                label="notes.docx",
                mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                blob_data=b"PK\x03\x04binary-docx-bytes",
            )

            client = TestClient(app)
            resp = client.get(
                f"/api/threat-hunting/packages/{pkg['id']}/evidence/{item['id']}/download"
            )
            assert resp.status_code == 200
            # Always octet-stream + attachment, regardless of the stored
            # (client-supplied, unvalidated) mime_type.
            assert resp.headers["content-type"] == "application/octet-stream"
            assert "attachment" in resp.headers["content-disposition"]
            assert resp.headers["x-content-type-options"] == "nosniff"
            assert resp.content == b"PK\x03\x04binary-docx-bytes"

    @pytest.mark.asyncio
    async def test_404_when_no_blob_stored(self, db_path: Path) -> None:
        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            item = await _seed_evidence(pkg["id"], blob_data=None)

            client = TestClient(app)
            resp = client.get(
                f"/api/threat-hunting/packages/{pkg['id']}/evidence/{item['id']}/download"
            )
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_sanitizes_quote_in_filename(self, db_path: Path) -> None:
        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            item = await _seed_evidence(pkg["id"], label='weird"name.txt', blob_data=b"hello")

            client = TestClient(app)
            resp = client.get(
                f"/api/threat-hunting/packages/{pkg['id']}/evidence/{item['id']}/download"
            )
            assert resp.status_code == 200
            assert resp.headers["content-disposition"].count('"') == 2


class TestSafeDispositionFilename:
    def test_strips_quotes_and_control_chars(self) -> None:
        from backend.api.routes_threat_hunting import _safe_disposition_filename

        assert _safe_disposition_filename('evil".pdf\r\nX-Injected: yes', "fallback") == (
            "evil.pdfX-Injected: yes"
        )

    def test_falls_back_when_nothing_usable_remains(self) -> None:
        from backend.api.routes_threat_hunting import _safe_disposition_filename

        assert _safe_disposition_filename('"""', "fallback") == "fallback"
        assert _safe_disposition_filename("", "fallback") == "fallback"

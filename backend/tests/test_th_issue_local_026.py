"""Tests for issue-local-026: IOC total consistency, URL->domain derivation,
model-selector RBAC (covered separately in test_routes_auth.py), and
hunt run created_by / default-model display."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.nodes import comparison_analyst
from backend.threat_hunting.agents.nodes.report_writer import (
    render_comparison_markdown,
    render_comparison_pdf,
)
from backend.threat_hunting.iocs import extract_iocs_from_text, normalize_ioc_csv


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", path):
        await th_db.init_threat_hunting_db()
        yield path


async def _seed_run(
    pkg_id: str,
    run_id: str,
    *,
    deep_retrohunt: dict | None = None,
    generation_status: str = "completed",
    llm_model: str = "gpt-test",
    created_at: str = "2026-01-01T00:00:00Z",
) -> None:
    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO hunting_packages (id, hunt_package_id, deep_retrohunt, "
            "generation_status, llm_model, created_at) VALUES (?,?,?,?,?,?)",
            (
                run_id,
                pkg_id,
                json.dumps(deep_retrohunt) if deep_retrohunt is not None else None,
                generation_status,
                llm_model,
                created_at,
            ),
        )
        await db.commit()


class TestUrlToDomainDerivation:
    def test_url_also_produces_a_domain_ioc(self):
        results = extract_iocs_from_text(
            "Payload fetched from https://evil-c2.example.com/payload.bin"
        )
        types = {(r["ioc_type"], r["ioc"]) for r in results}
        assert ("url", "evil-c2.example.com/payload.bin") in types
        assert ("domain", "evil-c2.example.com") in types

    def test_original_url_ioc_is_kept_alongside_derived_domain(self):
        results = extract_iocs_from_text("See https://bad.example.net/x for details")
        url_iocs = [r for r in results if r["ioc_type"] == "url"]
        domain_iocs = [r for r in results if r["ioc_type"] == "domain"]
        assert len(url_iocs) == 1
        assert any(d["ioc"] == "bad.example.net" for d in domain_iocs)

    def test_derived_domain_not_duplicated_with_a_bare_domain_mention(self):
        text = "Contacted https://evil.example.com/x — evil.example.com is the C2 host."
        results = extract_iocs_from_text(text)
        domain_iocs = [
            r for r in results if r["ioc_type"] == "domain" and r["ioc"] == "evil.example.com"
        ]
        assert len(domain_iocs) == 1

    def test_defanged_url_still_derives_domain(self):
        results = extract_iocs_from_text("Beacon to hxxps://evil[.]example[.]com/beacon")
        domain_iocs = {r["ioc"] for r in results if r["ioc_type"] == "domain"}
        assert "evil.example.com" in domain_iocs

    def test_url_with_port_derives_domain_without_port(self):
        results = extract_iocs_from_text("C2 at https://evil.example.com:8443/gate.php")
        domain_iocs = {r["ioc"] for r in results if r["ioc_type"] == "domain"}
        assert "evil.example.com" in domain_iocs

    def test_derived_domain_ioc_description_notes_origin(self):
        results = extract_iocs_from_text("https://evil.example.org/x")
        domain = next(r for r in results if r["ioc_type"] == "domain")
        assert "URL" in domain["ioc_description"]

    def test_csv_url_row_also_derives_domain(self):
        results = normalize_ioc_csv(
            [{"ioc": "https://evil.example.io/path", "ioc_type": "url", "ioc_description": ""}]
        )
        types = {(r["ioc_type"], r["ioc"]) for r in results}
        assert ("domain", "evil.example.io") in types

    def test_csv_url_row_without_scheme_still_derives_domain(self):
        results = normalize_ioc_csv(
            [{"ioc": "evil.example.dev/path", "ioc_type": "url", "ioc_description": ""}]
        )
        domain_iocs = {r["ioc"] for r in results if r["ioc_type"] == "domain"}
        assert "evil.example.dev" in domain_iocs

    def test_non_url_csv_rows_unaffected(self):
        results = normalize_ioc_csv([{"ioc": "1.2.3.4", "ioc_type": "ip", "ioc_description": ""}])
        assert len(results) == 1
        assert results[0]["ioc_type"] == "ip"


class TestBarePathUrlBecomesDomainOnly:
    """issue-local-035: a URL with no path/query/fragment (just scheme://host
    or scheme://host/) is stored as domain only — the live case reported was
    TH67-X03, where a bare domain was stored redundantly as both types."""

    def test_bare_https_no_path_is_domain_only(self):
        results = extract_iocs_from_text("Beaconing to https://evil-c2.example.com observed.")
        types = {(r["ioc_type"], r["ioc"]) for r in results}
        assert ("domain", "evil-c2.example.com") in types
        assert not any(t == "url" for t, _ in types)

    def test_bare_https_trailing_slash_is_domain_only(self):
        results = extract_iocs_from_text("Beaconing to https://evil-c2.example.com/ observed.")
        types = {(r["ioc_type"], r["ioc"]) for r in results}
        assert ("domain", "evil-c2.example.com") in types
        assert not any(t == "url" for t, _ in types)

    def test_url_with_real_path_keeps_both_types(self):
        results = extract_iocs_from_text("Payload at https://evil-c2.example.com/payload.bin")
        types = {(r["ioc_type"], r["ioc"]) for r in results}
        assert ("domain", "evil-c2.example.com") in types
        assert ("url", "evil-c2.example.com/payload.bin") in types

    def test_url_with_only_query_string_keeps_both_types(self):
        results = extract_iocs_from_text("Beacon at https://evil-c2.example.com?id=1")
        types = {(r["ioc_type"], r["ioc"]) for r in results}
        assert ("domain", "evil-c2.example.com") in types
        assert any(t == "url" for t, _ in types)

    def test_csv_bare_url_row_becomes_domain_only(self):
        results = normalize_ioc_csv(
            [{"ioc": "https://evil.example.com", "ioc_type": "url", "ioc_description": ""}]
        )
        types = {(r["ioc_type"], r["ioc"]) for r in results}
        assert ("domain", "evil.example.com") in types
        assert not any(t == "url" for t, _ in types)

    def test_csv_url_row_with_path_keeps_both_types(self):
        results = normalize_ioc_csv(
            [{"ioc": "https://evil.example.com/path", "ioc_type": "url", "ioc_description": ""}]
        )
        types = {(r["ioc_type"], r["ioc"]) for r in results}
        assert ("domain", "evil.example.com") in types
        assert ("url", "evil.example.com/path") in types


def _sanitized_iocs(kept: int, removed: int) -> dict:
    items = [{"ioc": f"k{i}", "ioc_type": "domain", "action": "keep"} for i in range(kept)]
    items += [{"ioc": f"r{i}", "ioc_type": "domain", "action": "remove"} for i in range(removed)]
    return {"sanitized_iocs": items}


class TestComparisonTotalIocCount:
    @pytest.mark.asyncio
    async def test_diff_row_total_is_sum_of_kept_and_removed(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", deep_retrohunt=_sanitized_iocs(3, 1))
            result = await comparison_analyst.compare_runs(pkg["id"])
            row = result["full_report"]["diff_table"][0]
            assert row["sanitized_ioc_count"] == 3
            assert row["removed_ioc_count"] == 1
            assert row["total_ioc_count"] == 4

    @pytest.mark.asyncio
    async def test_diff_row_total_is_zero_when_no_deep_retrohunt_yet(self, db_path: Path) -> None:
        """Regression: sanitized/removed counts come back as None (not 0) when
        a run has no deep_retrohunt lead yet — summing them must not crash."""
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", deep_retrohunt=None)
            result = await comparison_analyst.compare_runs(pkg["id"])
            row = result["full_report"]["diff_table"][0]
            assert row["total_ioc_count"] == 0


class TestIocOverviewDedup:
    """issue-local-035: ioc_overview is one row per UNIQUE (ioc_type, ioc)
    across all compared runs, not one row per (run, ioc) occurrence."""

    @pytest.mark.asyncio
    async def test_same_ioc_across_runs_collapses_to_one_row(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            shared = {
                "sanitized_iocs": [
                    {"ioc": "evil.example.com", "ioc_type": "domain", "action": "keep"},
                ]
            }
            await _seed_run(pkg["id"], "run-1", deep_retrohunt=shared)
            await _seed_run(pkg["id"], "run-2", deep_retrohunt=shared)

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value="{}"),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"])

            overview = result["full_report"]["ioc_overview"]
            matching = [r for r in overview if r["ioc"] == "evil.example.com"]
            assert len(matching) == 1
            row = matching[0]
            assert row["run_count"] == 2
            assert {o["run_id"] for o in row["occurrences"]} == {"run-1", "run-2"}

    @pytest.mark.asyncio
    async def test_conflicting_verdicts_across_runs_both_surfaced(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(
                pkg["id"],
                "run-1",
                deep_retrohunt={
                    "sanitized_iocs": [
                        {"ioc": "evil.example.com", "ioc_type": "domain", "action": "keep"}
                    ]
                },
            )
            await _seed_run(
                pkg["id"],
                "run-2",
                deep_retrohunt={
                    "sanitized_iocs": [
                        {"ioc": "evil.example.com", "ioc_type": "domain", "action": "remove"}
                    ]
                },
            )

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value="{}"),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"])

            row = next(
                r for r in result["full_report"]["ioc_overview"] if r["ioc"] == "evil.example.com"
            )
            assert row["verdict_summary"] == "kept in 1, removed in 1"
            verdicts = {o["run_id"]: o["verdict"] for o in row["occurrences"]}
            assert verdicts == {"run-1": "keep", "run-2": "remove"}

    @pytest.mark.asyncio
    async def test_distinct_iocs_remain_distinct_rows(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", deep_retrohunt=_sanitized_iocs(2, 1))

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value="{}"),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"])

            overview = result["full_report"]["ioc_overview"]
            assert len(overview) == 3
            assert all(row["run_count"] == 1 for row in overview)


class TestComparisonRenderersTotalIocColumn:
    def test_markdown_includes_total_iocs_column(self) -> None:
        full_report = {
            "hunt_name": "Test Hunt",
            "compared_run_ids": ["run-1"],
            "diff_table": [
                {
                    "run_id_display": "TH01-X01",
                    "model": "gpt-test",
                    "sanitized_ioc_count": 3,
                    "removed_ioc_count": 1,
                    "total_ioc_count": 4,
                }
            ],
            "summary": "Summary text",
        }
        markdown = render_comparison_markdown(full_report)
        assert "Total IOCs" in markdown
        assert "| 4 |" in markdown

    def test_markdown_falls_back_to_computed_total_when_field_missing(self) -> None:
        """Older persisted comparison reports won't have total_ioc_count —
        the renderer must still show a correct total, not crash or omit it."""
        full_report = {
            "hunt_name": "Test Hunt",
            "compared_run_ids": ["run-1"],
            "diff_table": [
                {
                    "run_id_display": "TH01-X01",
                    "model": "gpt-test",
                    "sanitized_ioc_count": 5,
                    "removed_ioc_count": 2,
                }
            ],
            "summary": "Summary text",
        }
        markdown = render_comparison_markdown(full_report)
        assert "| 7 |" in markdown

    def test_pdf_with_total_iocs_column_returns_bytes(self) -> None:
        full_report = {
            "hunt_name": "Test Hunt",
            "compared_run_ids": ["run-1"],
            "diff_table": [
                {
                    "run_id_display": "TH01-X01",
                    "model": "gpt-test",
                    "sanitized_ioc_count": 2,
                    "removed_ioc_count": 0,
                    "total_ioc_count": 2,
                }
            ],
            "summary": "Summary text",
        }
        pdf_bytes = render_comparison_pdf(full_report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes[:4] == b"%PDF"

# T13 — Generate the hunt report

Manually trigger report generation. The executive summary has a deterministic fallback when no LLM is configured, so this succeeds either way.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** report-generate 09684569-82be-40dd-8281-ecec80fe0916
```

## Response

```json
{
    "id": "b07279a0-4ec1-48e8-90d3-9b0a63bdf9f0",
    "hunt_package_id": "09684569-82be-40dd-8281-ecec80fe0916",
    "executive_summary": "Threat hunt 'th-client-demo-1785289667' has been completed with 0 hypothesis(es) generated. The deep retrohunt searched 1 IOC(s) against the SIEM, returning 0 event(s). Review the full report for detailed findings and recommendations.",
    "full_report": {
        "executive_summary": "Threat hunt 'th-client-demo-1785289667' has been completed with 0 hypothesis(es) generated. The deep retrohunt searched 1 IOC(s) against the SIEM, returning 0 event(s). Review the full report for detailed findings and recommendations.",
        "hunt_name": "th-client-demo-1785289667",
        "hunt_id": "09684569-82be-40dd-8281-ecec80fe0916",
        "hunt_id_display": "TH03",
        "run_id_display": "TH03-X01",
        "generated_at": "2026-07-29T01:47:51.318674+00:00",
        "generated_by": null,
        "package_status": "approved",
        "evidence_summary": {
            "total_items": 2,
            "ioc_count": 0,
            "item_types": [
                "manual_text",
                "file"
            ]
        },
        "evidence_items": [
            {
                "id": "19b36e4a-3a42-458e-8233-be2a55467915",
                "label": "Demo note",
                "item_type": "manual_text",
                "source_ref": "",
                "parser_used": "text",
                "parse_status": "ok",
                "extracted_text": "Demo evidence: suspicious login attempts from 203.0.113.10."
            },
            {
                "id": "31a4ad9d-d4eb-4dd7-a38d-5db9c1d97c9a",
                "label": "sample-evidence.txt",
                "item_type": "file",
                "source_ref": "sample-evidence.txt",
                "parser_used": "text",
                "parse_status": "ok",
                "extracted_text": "Threat hunting demo evidence file.\nExample indicators for local verification only: 203.0.113.10, evil-example.test"
            }
        ],
        "sanitized_iocs": [
            {
                "ioc": "203.0.113.10",
                "ioc_type": "ip",
                "ioc_description": "",
                "noise_score": 0.95,
                "noise_reasons": [],
                "search_token": "203.0.113.10",
                "action": "keep"
            }
        ],
        "threat_context": null,
        "hypotheses": [],
        "hunting_leads": [],
        "deep_retrohunt_summary": {
            "total_iocs": 1,
            "noisy_iocs": 1,
            "high_noise_iocs": 1,
            "spl_macro_name": "threathunt_ioc_09684569",
            "search_hint": ""
        },
        "ttp_analysis": null,
        "query_drafts_count": 0,
        "execution_results": [],
        "recommendations": [],
        "findings": "FINDINGS AND CONCLUSION \u2014 TH-CLIENT-DEMO-1785289667\n\nThis hunt assessed 0 hypothesis(es) based on the collected threat intelligence evidence.\nThe deep retrohunt searched 1 IOCs (1 flagged as noisy).\nNo SIEM execution events matched the hunt criteria at the time of report generation. This may indicate the threat has not been active in this environment, or that the search time range or IOC set requires adjustment.\n\nThis report was generated automatically. The findings and recommendations should be reviewed by a qualified threat analyst before any action is taken.",
        "_report_formats": {
            "pdf": true,
            "markdown": true
        },
        "_markdown": "# [TH03] Threat Hunt Report: th-client-demo-1785289667\n\n**HuntID:** TH03\n**RunID:** TH03-X01\n**Internal ID:** 09684569-82be-40dd-8281-ecec80fe0916\n**Generated At:** 2026-07-29T01:47:51.318674+00:00\n**Status:** approved\n\n## Executive Summary\n\nThreat hunt 'th-client-demo-1785289667' has been completed with 0 hypothesis(es) generated. The deep retrohunt searched 1 IOC(s) against the SIEM, returning 0 event(s). Review the full report for detailed findings and recommendations.\n\n## Evidence Summary\n\n- Evidence items: 2\n- IOCs extracted: 0\n- Item types: manual_text, file\n\n## Evidence Items (2)\n\n### Demo note\n\n*Type: manual_text  |  Parser: text  |  Status: ok*\n\n```\nDemo evidence: suspicious login attempts from 203.0.113.10.\n```\n\n### sample-evidence.txt\n\n*Type: file  |  Parser: text  |  Status: ok*\n\nSource: `sample-evidence.txt`\n\n```\nThreat hunting demo evidence file.\nExample indicators for local verification only: 203.0.113.10, evil-example.test\n```\n\n## Deep Retrohunt Summary\n\n- IOCs: 1 total, 1 noisy, 1 high-noise\n- SPL Macro: `threathunt_ioc_09684569`\n\n## IOC Table (1 total, 1 kept, 0 removed)\n\n| IOC | Type | Verdict | Noise | Description | Reasons |\n|---|---|---|---|---|---|\n| `203.0.113.10` | ip | Keep | 95% |  |  |\n\n## Findings and Conclusion\n\nFINDINGS AND CONCLUSION \u2014 TH-CLIENT-DEMO-1785289667\n\nThis hunt assessed 0 hypothesis(es) based on the collected threat intelligence evidence.\nThe deep retrohunt searched 1 IOCs (1 flagged as noisy).\nNo SIEM execution events matched the hunt criteria at the time of report generation. This may indicate the threat has not been active in this environment, or that the search time range or IOC set requires adjustment.\n\nThis report was generated automatically. The findings and recommendations should be reviewed by a qualified threat analyst before any action is taken.\n\n"
    },
    "created_at": "2026-07-29T01:47:51.319156+00:00",
    "created_by": null,
    "run_id": null
}
```

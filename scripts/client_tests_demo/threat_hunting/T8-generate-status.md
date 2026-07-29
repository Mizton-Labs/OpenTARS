# T8 — Poll generation status

Poll the generation status once, immediately after starting it.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** generate-status 09684569-82be-40dd-8281-ecec80fe0916
```

## Response

```json
{
    "id": "fc434905-1868-4449-8059-d6b88e89d910",
    "hunt_package_id": "09684569-82be-40dd-8281-ecec80fe0916",
    "threat_context": null,
    "hypotheses": null,
    "hunting_leads": null,
    "deep_retrohunt": {
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
        "ioc_csv": "ioc,ioc_type,ioc_description\r\n203.0.113.10,ip,\r\n",
        "total_ioc_count": 1,
        "noisy_ioc_count": 1,
        "high_noise_ioc_count": 1,
        "spl_draft": "",
        "spl_macro_name": "threathunt_ioc_09684569",
        "search_hint": "",
        "analyst_notes": "",
        "llm_parse_error": true
    },
    "ttp_analysis": null,
    "query_drafts": null,
    "llm_provider": null,
    "llm_model": null,
    "generation_status": "awaiting_approval",
    "generation_errors": [
        "threat_context_builder: LLM is disabled (enabled=false in llm-providers.yaml)",
        "hypothesis_generator: LLM is disabled (enabled=false in llm-providers.yaml)",
        "hunting_lead_planner: LLM is disabled (enabled=false in llm-providers.yaml)",
        "ttp_analyst: LLM is disabled (enabled=false in llm-providers.yaml)",
        "query_drafting_agent: LLM is disabled (enabled=false in llm-providers.yaml)"
    ],
    "created_at": "2026-07-29T01:47:49.575512+00:00",
    "current_step": "approval_gate",
    "completed_steps": [
        "intake_classifier",
        "deep_retrohunt_planner"
    ],
    "step_logs": [
        {
            "step": "intake_classifier",
            "status": "ok",
            "elapsed_s": 0.01,
            "ioc_count": 1,
            "noisy_count": 1,
            "item_count": 2,
            "tools_used": [],
            "decision": "",
            "debug_lines": [
                "FILE_PARSE_START: sample-evidence.txt mode=auto",
                "FILE_PARSE_OK: sample-evidence.txt \u2192 114 chars (text)",
                "IOC_EXTRACT: extracted 2 raw \u2192 1 unique stored",
                "TOOL_LLM_ERROR: LLM is disabled (enabled=false in llm-providers.yaml)"
            ],
            "intake_sources": [
                {
                    "label": "Demo note",
                    "item_type": "manual_text",
                    "text_length": 59,
                    "parse_status": "ok",
                    "sub_status": "ok",
                    "parser_used": "text"
                },
                {
                    "label": "sample-evidence.txt",
                    "item_type": "file",
                    "text_length": 114,
                    "parse_status": "ok",
                    "sub_status": "ok",
                    "parser_used": "text"
                }
            ],
            "fetched_url_count": 0,
            "parsed_file_count": 1
        },
        {
            "step": "deep_retrohunt_planner",
            "status": "partial",
            "elapsed_s": 0.0,
            "ioc_count": 1,
            "noisy_count": 1,
            "effort": "high",
            "tools_used": [],
            "decision": "",
            "debug_lines": []
        },
        {
            "step": "threat_context_builder",
            "status": "error",
            "elapsed_s": 0.0,
            "error": "LLM is disabled (enabled=false in llm-providers.yaml)",
            "tools_used": [],
            "debug_lines": [
                "TOOL_LLM_ERROR: LLM is disabled (enabled=false in llm-providers.yaml)"
            ]
        },
        {
            "step": "hypothesis_generator",
            "status": "error",
            "elapsed_s": 0.0,
            "error": "LLM is disabled (enabled=false in llm-providers.yaml)",
            "debug_lines": [
                "LLM_CALL: requesting 5-8 hypotheses",
                "LLM_DISABLED: skipping hypothesis generation"
            ]
        },
        {
            "step": "hunting_lead_planner",
            "status": "error",
            "elapsed_s": 0.0,
            "error": "LLM is disabled (enabled=false in llm-providers.yaml)",
            "debug_lines": [
                "LLM_CALL: requesting 4-6 hunting leads",
                "LLM_DISABLED: skipping hunting lead planning"
            ]
        },
        {
            "step": "ttp_analyst",
            "status": "error",
            "elapsed_s": 0.0,
            "error": "LLM is disabled (enabled=false in llm-providers.yaml)",
            "debug_lines": [
                "LLM_CALL: TTP analysis requested (effort=high)",
                "LLM_DISABLED: skipping TTP analysis"
            ]
        },
        {
            "step": "query_drafting_agent",
            "status": "error",
            "elapsed_s": 0.0,
            "error": "LLM is disabled (enabled=false in llm-providers.yaml)",
            "tools_used": [],
            "debug_lines": []
        },
        {
            "step": "threat_intel_preliminary",
            "status": "ok",
            "decision": "0 actor(s), 0 cross-package IOC match(es)",
            "debug_lines": [
                "LLM_CALL: [preliminary] threat intel enrichment requested",
                "LLM_DISABLED: using deterministic fields only"
            ]
        }
    ],
    "research_effort": "high",
    "run_config": {},
    "run_seq": 1,
    "threat_intel_status": null,
    "created_by": "th-demo-runner-local",
    "is_running": false,
    "run_id": "fc434905-1868-4449-8059-d6b88e89d910"
}
```

# T5 — List evidence items

Confirm both evidence items were attached.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** evidence-list 09684569-82be-40dd-8281-ecec80fe0916
```

## Response

```json
[
    {
        "id": "19b36e4a-3a42-458e-8233-be2a55467915",
        "hunt_package_id": "09684569-82be-40dd-8281-ecec80fe0916",
        "item_type": "manual_text",
        "label": "Demo note",
        "source_ref": "",
        "content_hash": "00431aed6fbd982d482e91cabc601a43d5529ae35031454948a4762c8ae11c7a",
        "mime_type": "",
        "fetch_url": "",
        "final_url": "",
        "extracted_text": "Demo evidence: suspicious login attempts from 203.0.113.10.",
        "parser_used": "text",
        "parser_version": "stdlib",
        "parse_status": "ok",
        "parse_warnings": [],
        "fetch_metadata": {},
        "created_at": "2026-07-29T01:47:48.047412+00:00",
        "provenance_notes": ""
    },
    {
        "id": "31a4ad9d-d4eb-4dd7-a38d-5db9c1d97c9a",
        "hunt_package_id": "09684569-82be-40dd-8281-ecec80fe0916",
        "item_type": "file",
        "label": "sample-evidence.txt",
        "source_ref": "sample-evidence.txt",
        "content_hash": "ecf2d0e4bb23e5f39a4544454dac0b1c57053193a83ac589594ea3f6d6688671",
        "mime_type": "text/plain",
        "fetch_url": "",
        "final_url": "",
        "extracted_text": "",
        "parser_used": "",
        "parser_version": "",
        "parse_status": "pending",
        "parse_warnings": [
            "File will be parsed during the analysis pipeline run."
        ],
        "fetch_metadata": {
            "parser_mode": "auto",
            "original_size_bytes": 115
        },
        "created_at": "2026-07-29T01:47:48.335705+00:00",
        "provenance_notes": ""
    }
]
```

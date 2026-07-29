# T3 — Add manual text evidence

Attach a manual text note as evidence to the package.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** evidence-add-text 09684569-82be-40dd-8281-ecec80fe0916 --text Demo evidence: suspicious login attempts from 203.0.113.10. --label Demo note
```

## Response

```json
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
}
```

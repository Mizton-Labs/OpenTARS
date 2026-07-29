# T4 — Upload a file as evidence

Upload a small local text file as evidence (parsed later, during generation).

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** evidence-add-file 09684569-82be-40dd-8281-ecec80fe0916 sample-evidence.txt
```

## Response

```json
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
```

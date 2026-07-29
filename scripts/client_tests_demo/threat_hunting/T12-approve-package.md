# T12 — Move the package to approved

Reports require the package to be approved or completed — update its status directly for this demo (normally reached via the approve-generation flow).

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** packages-update 09684569-82be-40dd-8281-ecec80fe0916 --status approved
```

## Response

```json
{
    "id": "09684569-82be-40dd-8281-ecec80fe0916",
    "name": "th-client-demo-1785289667",
    "description": "Local demo run, safe to delete.",
    "status": "approved",
    "created_by": "th-demo-runner-local",
    "created_at": "2026-07-29T01:47:47.476177+00:00",
    "updated_at": "2026-07-29T01:47:51.021561+00:00",
    "evidence_count": 2,
    "generation_status": null,
    "phases": null,
    "total_elapsed_s": null,
    "run_created_at": null,
    "runs": [],
    "run_count": 0,
    "hunt_id_display": "TH03"
}
```

# T2 — List packages, filtered by deep search

List packages, searching for this run's own package name (issue-local-020 deep search).

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** packages-list --search th-client-demo-1785289667
```

## Response

```json
[
    {
        "id": "09684569-82be-40dd-8281-ecec80fe0916",
        "name": "th-client-demo-1785289667",
        "description": "Local demo run, safe to delete.",
        "status": "draft",
        "created_by": "th-demo-runner-local",
        "created_at": "2026-07-29T01:47:47.476177+00:00",
        "updated_at": "2026-07-29T01:47:47.476177+00:00",
        "evidence_count": 0,
        "generation_status": null,
        "phases": null,
        "total_elapsed_s": null,
        "run_created_at": null,
        "runs": [],
        "run_count": 0,
        "hunt_id_display": "TH03"
    }
]
```

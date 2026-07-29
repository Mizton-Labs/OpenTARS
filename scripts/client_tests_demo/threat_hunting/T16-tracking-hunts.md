# T16 — Threat Intel Tracking hunts list

List every non-archived hunt with its correlation-inclusion state — the demo package should appear here.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** tracking-hunts
```

## Response

```json
[
    {
        "id": "09684569-82be-40dd-8281-ecec80fe0916",
        "name": "th-client-demo-1785289667",
        "hunt_id_display": "TH03",
        "status": "completed",
        "excluded_from_correlation": false,
        "ioc_count": 1,
        "has_threat_intel": true
    }
]
```

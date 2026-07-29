# T9 — Create a SIEM connector

Register a Splunk connector profile pointing at a placeholder URL (not a real SIEM — connection will fail; see T10).

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** connectors-create --data {"name": "demo-splunk", "kind": "splunk", "base_url": "https://splunk.example.test:8089", "auth_method": "token", "api_token": "placeholder"}
```

## Response

```json
{
    "id": "8c77fc4a-768f-4a2f-806e-c2f33a7db64e",
    "name": "demo-splunk",
    "kind": "splunk",
    "base_url": "https://splunk.example.test:8089",
    "auth_method": "token",
    "api_token_hash": null,
    "config_json": "{\"verify_tls\": true, \"default_index\": \"main\", \"retrohunt_macro\": \"threathunt_ioc_search\", \"api_token\": \"***\"}",
    "verified": 0,
    "created_at": "2026-07-29T01:47:50.166440+00:00",
    "updated_at": "2026-07-29T01:47:50.166440+00:00"
}
```

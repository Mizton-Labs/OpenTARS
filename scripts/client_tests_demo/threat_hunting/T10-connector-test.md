# T10 — Test the SIEM connector

Test the connector's connection. Expected to report ok:false — the base_url is a non-routable placeholder, not a real SIEM.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** connectors-test 8c77fc4a-768f-4a2f-806e-c2f33a7db64e
```

## Response

```json
{
    "ok": false,
    "message": "Error: httpx.Timeout must either include a default, or set all four parameters explicitly.",
    "server_info": null
}
```

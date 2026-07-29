# T11 — Delete the SIEM connector

Clean up the demo connector.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** connectors-delete 8c77fc4a-768f-4a2f-806e-c2f33a7db64e
```

## Response

```json
{
    "status": "deleted"
}
```

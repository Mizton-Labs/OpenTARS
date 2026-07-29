# T17 — Archive (delete) the demo package

Clean up — archive the package created by this run.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** packages-delete 09684569-82be-40dd-8281-ecec80fe0916
```

## Response

```json
{
    "status": "deleted"
}
```

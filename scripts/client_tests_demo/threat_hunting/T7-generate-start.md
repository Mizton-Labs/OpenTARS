# T7 — Start hunt generation

Start the LLM analysis pipeline. Requires an LLM provider configured on the server for a full run; without one the run still starts and its status reflects the failure.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** generate-start 09684569-82be-40dd-8281-ecec80fe0916
```

## Response

```json
{
    "id": "fc434905-1868-4449-8059-d6b88e89d910",
    "run_id": "fc434905-1868-4449-8059-d6b88e89d910",
    "hunt_package_id": "09684569-82be-40dd-8281-ecec80fe0916",
    "generation_status": "running",
    "provider_name": null,
    "model_name": null,
    "research_effort": "high",
    "run_config": {},
    "created_by": "th-demo-runner-local"
}
```

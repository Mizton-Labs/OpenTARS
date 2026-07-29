# T6 — List IOCs before generation

IOC extraction happens during the analysis pipeline run, not at evidence-upload time — expect an empty list here.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** iocs-list 09684569-82be-40dd-8281-ecec80fe0916
```

## Response

```json
[]
```

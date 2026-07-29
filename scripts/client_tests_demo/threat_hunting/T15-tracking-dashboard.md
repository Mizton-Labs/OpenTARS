# T15 — Threat Intel Tracking dashboard

Cross-hunt aggregation: IOCs, CVEs, threat actors, campaigns, malware families, TTPs.

- **Account:** `th-demo-runner-local`
- **Base URL:** `http://<test-server>:8000`
- **Exit code:** `0`

## Command

```bash
api_client_threat_hunting.py --url http://<test-server>:8000 --username th-demo-runner-local --password *** tracking-dashboard
```

## Response

```json
{
    "iocs": [
        {
            "ioc": "203.0.113.10",
            "ioc_type": "ip",
            "hunt_count": 1,
            "hunt_packages": [
                {
                    "id": "09684569-82be-40dd-8281-ecec80fe0916",
                    "name": "th-client-demo-1785289667",
                    "hunt_id_display": "TH03"
                }
            ]
        }
    ],
    "cves": [],
    "threat_actors": [],
    "campaigns": [],
    "malware_families": [],
    "ttps": []
}
```

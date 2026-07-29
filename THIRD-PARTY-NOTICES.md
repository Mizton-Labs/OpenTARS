# Third-Party Notices

OpenTARS bundles or depends on the third-party open-source packages
listed below. Each package remains under its own license; the full license
texts are distributed with the respective packages in their source
repositories and installed distribution metadata.

This file lists only direct runtime dependencies. Transitive dependencies are
installed automatically and carry their own compatible open-source licenses.

The information below was generated from the installed package metadata
(`node_modules/*/package.json` and `.venv/.../*.dist-info/METADATA`).

## Frontend (npm)

| Package | Version | License |
|---|---|---|
| react | 18.3.1 | MIT |
| react-dom | 18.3.1 | MIT |
| react-router-dom | 6.30.3 | MIT |
| @tanstack/react-query | 5.100.14 | MIT |
| lucide-react | 0.390.0 | ISC |
| clsx | 2.1.1 | MIT |
| tailwind-merge | 2.6.1 | MIT |
| react-markdown | 10.1.0 | MIT |
| remark-gfm | 4.0.1 | MIT |

## Backend (Python)

| Package | Version | License |
|---|---|---|
| fastapi | 0.136.3 | MIT |
| uvicorn | 0.48.0 | BSD-3-Clause |
| pydantic | 2.13.4 | MIT |
| PyYAML | 6.0.3 | MIT |
| aiosqlite | 0.22.1 | MIT |
| feedparser | 6.0.12 | BSD-2-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| APScheduler | 3.11.2 | MIT |
| python-multipart | 0.0.29 | Apache-2.0 |
| aiofiles | 25.1.0 | Apache-2.0 |
| bcrypt | 5.0.0 | Apache-2.0 |

## Vendored assets (checked into this repository)

Unlike the dependencies above — which are fetched by `npm install` / `uv sync`
— these files are committed under `backend/static/api-docs/` and served
directly by the application at `/docs-assets`. They back the interactive API
documentation (`/docs`, `/redoc`, and the About page's API Swagger tab).

They are vendored rather than loaded from a CDN so the documentation renders
on isolated and air-gapped deployments, and so an authenticated page carries
no third-party runtime dependency. Each is redistributed unmodified, with its
upstream license text alongside it.

| Asset | Package | Version | License | License text |
|---|---|---|---|---|
| `swagger-ui-bundle.js`, `swagger-ui.css` | swagger-ui-dist | 5.32.11 | Apache-2.0 | `backend/static/api-docs/LICENSE.swagger-ui.txt` |
| `redoc.standalone.js` | redoc | 2.5.3 | MIT | `backend/static/api-docs/LICENSE.redoc.txt` |

To refresh them, re-fetch the pinned versions from the npm registry and copy
the same files into place:

```bash
npm pack swagger-ui-dist@<version> redoc@<version>
# swagger-ui-dist: package/swagger-ui-bundle.js, package/swagger-ui.css, package/LICENSE
# redoc:           package/bundles/redoc.standalone.js, package/LICENSE
```

Then update the versions in this table. `backend/tests/test_main_spa.py`
asserts the files are present, are served, and that the docs pages reference
no external hosts.

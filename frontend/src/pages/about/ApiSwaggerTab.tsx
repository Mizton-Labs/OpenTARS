/**
 * About -> API Swagger tab (issue-local-030).
 *
 * FastAPI's own interactive Swagger UI, embedded via <iframe> pointing at
 * swaggerUiSrc(). Same-origin, so the session cookie authenticates it exactly
 * like any other page (see backend/main.py's _DOCS_PATHS gate).
 *
 * Defaults to the API-key-reachable subset of the API rather than the full
 * ~220-operation schema: someone reading this tab is usually integrating with
 * a scoped key, and the majority of the application's endpoints can never be
 * called with one. The checkbox switches to the complete application API.
 * Both variants are produced server-side from backend.auth.api_scopes, the
 * same source the auth middleware enforces against.
 *
 * The embedded page is served by backend/main.py's custom /docs route, which
 * references the OpenAPI schema RELATIVELY — without that, a deployment behind
 * a reverse-proxy alias renders the *parent* application's endpoints here (see
 * that route's comment for the full explanation).
 */
import { useState } from 'react'
import { ExternalLink, Code2 } from 'lucide-react'
import { swaggerUiSrc } from '../../api/client'

export default function ApiSwaggerTab() {
  const [showAll, setShowAll] = useState(false)
  const src = swaggerUiSrc({ apiKeysOnly: !showAll })

  return (
    <div className="card space-y-3">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <Code2 className="w-4 h-4 text-brand-400 shrink-0" />
          <h2 className="text-sm font-semibold text-gray-200">API Swagger</h2>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showAll}
              onChange={(e) => setShowAll(e.target.checked)}
            />
            Show all endpoints
          </label>
          <a
            href={src}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300"
          >
            Open in a new tab <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>

      <p className="text-xs text-gray-500">
        {showAll
          ? "Every endpoint in the application, generated from the running server's OpenAPI schema. Most of these require the session cookie and cannot be called with an API key."
          : 'Endpoints reachable with a scoped API access key. Tick “Show all endpoints” for the complete application API, including the session-only surfaces.'}
      </p>

      <iframe
        title="OpenTARS API Swagger UI"
        src={src}
        className="w-full h-[80vh] rounded-lg border border-gray-800 bg-white"
      />
    </div>
  )
}

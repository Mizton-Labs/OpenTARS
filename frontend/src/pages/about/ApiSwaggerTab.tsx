/**
 * About -> API Swagger tab (issue-local-030).
 *
 * FastAPI's own interactive Swagger UI, embedded via <iframe> pointing at
 * swaggerUiSrc(). Same-origin, so the session cookie authenticates it exactly
 * like any other page (see backend/main.py's _DOCS_PATHS gate).
 *
 * The embedded page is served by backend/main.py's custom /docs route, which
 * references the OpenAPI schema RELATIVELY — without that, a deployment behind
 * a reverse-proxy alias renders the *parent* application's endpoints here (see
 * that route's comment for the full explanation).
 */
import { ExternalLink, Code2 } from 'lucide-react'
import { swaggerUiSrc } from '../../api/client'

export default function ApiSwaggerTab() {
  return (
    <div className="card space-y-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 min-w-0">
          <Code2 className="w-4 h-4 text-brand-400 shrink-0" />
          <h2 className="text-sm font-semibold text-gray-200">API Swagger</h2>
        </div>
        <a
          href={swaggerUiSrc()}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300 shrink-0"
        >
          Open in a new tab <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </div>
      <p className="text-xs text-gray-500">
        Interactive documentation for every available endpoint, generated directly from the running
        server's OpenAPI schema.
      </p>
      <iframe
        title="OpenTARS API Swagger UI"
        src={swaggerUiSrc()}
        className="w-full h-[80vh] rounded-lg border border-gray-800 bg-white"
      />
    </div>
  )
}

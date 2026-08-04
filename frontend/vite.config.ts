import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Emit asset URLs as relative paths (./assets/...) so the same build
  // serves correctly under any backend-side prefix without rebuilding.
  // The runtime prefix is supplied at request time via the
  // <meta name="app-base-prefix"> tag injected by backend/main.py.
  base: './',
  server: {
    port: 5173,
    proxy: {
      // Match any request path ending in '/api/...' (or '/api') and rewrite
      // it to the backend's literal '/api/...'.
      // issue-local-035 follow-up: index.html now carries a root-anchored
      // <base href="/"> (mirroring what backend/main.py injects in
      // production — see _render_index_html's docstring), so
      // fetch('api/health') always resolves to '/api/health' regardless of
      // which route the page was loaded/refreshed at — this rewrite is now
      // effectively a no-op safety net (matches and passes '/api/...'
      // through unchanged) rather than something the app depends on for
      // deep-route reloads to work, as it previously was when dev had no
      // <base href> at all and relative fetches resolved against whatever
      // deep path the browser happened to be on.
      '^.*/api(/.*)?$': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path: string) => path.replace(/^.*?\/api/, '/api'),
      },
      // FastAPI's own interactive docs/redoc/openapi.json (issue-local-030's
      // About -> API Docs tab), embedded via <iframe swaggerUiSrc()>. These
      // live outside /api/, so they need their own proxy rule — same
      // relative-URL-under-any-prefix strategy as the rule above.
      '^.*/(docs|redoc|openapi\\.json)$': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path: string) => path.replace(/^.*?\/(docs|redoc|openapi\.json)$/, '/$1'),
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  define: {
    // Injected at build time — populated by the runner script via env var
    __GIT_COMMIT__: JSON.stringify(process.env.GIT_COMMIT || 'dev'),
    // issue-local-016: which branch the build was made from, so the About
    // page always shows the explicit version (commit) AND its branch —
    // same env-var-at-build-time pattern as __GIT_COMMIT__.
    __GIT_BRANCH__: JSON.stringify(process.env.GIT_BRANCH || 'unknown'),
    // When the commit itself was made (ISO-8601), so the About page can show
    // how stale a deployment is at a glance — same pattern as __GIT_BRANCH__.
    __GIT_COMMIT_DATE__: JSON.stringify(process.env.GIT_COMMIT_DATE || 'unknown'),
    __APP_VERSION__: JSON.stringify('0.1.0'),
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
  },
})

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
      // it to the backend's literal '/api/...'. This supports two cases:
      //   1. Root mount, relative client: fetch('api/health') from '/'
      //      resolves to '/api/health' — matched directly.
      //   2. Deep-route reload, relative client: fetch('api/health') from
      //      '/configuration' resolves to '/configuration/api/health';
      //      the rewrite strips the leading segments back to '/api/...'.
      // Note: Vite does NOT inject a <base href> in dev, so deep-route
      // reloads in dev rely on this rewrite to reach the backend. In
      // production the backend injects <base href="./">, so the browser
      // resolves to '/api/...' without depending on rewrites.
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

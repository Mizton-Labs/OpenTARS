/**
 * Resolves the application's effective base URL prefix.
 *
 * Three-tier precedence (prompts-020):
 *   1. EXPLICIT — the backend-injected <meta name="app-base-prefix" content="/x">.
 *      Used as a *forcing* override for environments where the operator wants
 *      to pin a specific prefix regardless of how the document was loaded.
 *   2. AUTO-DETECT — derived from window.location.pathname. Handles the
 *      zero-config reverse-proxy alias case: nginx mounts the app under
 *      /feeds/ → the operator sets nothing, the frontend infers /feeds at
 *      runtime and feeds it to React Router as basename.
 *   3. EMPTY — when neither yields a prefix (true root mount, or SSR).
 *
 * Auto-detection algorithm (strategy delta):
 *   - Split window.location.pathname into segments and scan left to right
 *     for the FIRST one that matches a KNOWN_ROUTES entry; the prefix is
 *     everything before that segment (the "first-known-route-segment
 *     strip"). This handles both the deep-route-reload case such as
 *     https://host/feeds/configuration → prefix "/feeds" AND routes nested
 *     arbitrarily deep under a known top-level route — e.g.
 *     https://host/threat-hunting/<uuid> (no alias: the match is at
 *     segment 0, so the prefix is "") and
 *     https://host/feeds/threat-hunting/<uuid> (aliased: match at segment
 *     1, prefix "/feeds") — without needing every nested sub-route name
 *     (tracking, explorer, packages, :id, ...) enumerated here too.
 *     issue-local-035 follow-up: the previous version only matched when a
 *     known route was the FINAL segment, so any nested Threat Hunting
 *     route (.../threat-hunting/<uuid>, .../threat-hunting/tracking, ...)
 *     fell through to the fallback below and was misdetected as if the
 *     entire path were a reverse-proxy alias — corrupting both the API
 *     client's BASE and React Router's basename on a hard refresh.
 *   - Otherwise (no known-route segment anywhere in the path) the prefix is
 *     window.location.pathname with the trailing slash stripped (the
 *     "trailing-slash strip"). This handles the index-load case such as
 *     https://host/feeds/ → prefix "/feeds".
 *
 * Behaviour matrix:
 *   URL                              meta   detected   final
 *   https://host/                    —      ""         ""
 *   https://host/viewer              —      ""         ""    (route stripped)
 *   https://host/feeds/              —      "/feeds"   "/feeds"
 *   https://host/feeds/configuration —      "/feeds"   "/feeds" (route stripped)
 *   https://host/feeds/              "/x"   —          "/x"  (explicit wins)
 *
 * Documented limitation: a URL with an unknown final segment such as
 *   https://host/feeds/garbage
 * cannot be distinguished from a legitimate sub-mount; the auto-detect
 * yields basename "/feeds/garbage", which is stable (Sidebar links remain
 * consistent within that mount) but suboptimal. Operators with such URL
 * shapes should set app_base_prefix explicitly.
 *
 * The KNOWN_ROUTES constant is the single source of truth for the SPA's
 * top-level routes and is consumed both here (for detection) and by
 * src/App.tsx (for the Route table). Adding a new top-level route
 * therefore updates auto-detection in lockstep.
 *
 * The prefix is consumed by:
 *   - React Router's <BrowserRouter basename=...>
 *   - the API client BASE (relative "api" when empty, "<prefix>/api" otherwise)
 *   - the Configuration UI display of the push URL
 *
 * The result is memoised on first read; _resetAppBasePrefixCache() is
 * provided for tests that need to mutate window.location between cases.
 */

// NOTE: 'login' (prompts-045) is a top-level route rendered OUTSIDE the sidebar
// shell, but it is still listed here so reverse-proxy alias auto-detection
// recognises e.g. https://host/feeds/login → prefix "/feeds". App.tsx derives
// the in-shell SHELL_ROUTES by excluding 'login'.
export const KNOWN_ROUTES = ['home', 'viewer', 'configuration', 'normalizer', 'watchers', 'threat-hunting', 'assistant', 'audit', 'account', 'about', 'login'] as const

let cached: string | null = null

function _normalise(v: string): string {
  let out = v.trim()
  while (out.endsWith('/')) out = out.slice(0, -1)
  if (out && !out.startsWith('/')) out = '/' + out
  return out
}

function _readMetaTag(): string {
  if (typeof document === 'undefined') return ''
  const tag = document.querySelector('meta[name="app-base-prefix"]')
  const raw = tag?.getAttribute('content') ?? ''
  return _normalise(raw)
}

function _detectFromLocation(): string {
  if (typeof window === 'undefined' || !window.location) return ''
  const path = window.location.pathname || '/'
  // First-known-route-segment strip: scan segments left to right and stop
  // at the first one that names a top-level SPA route — everything before
  // it is the prefix, regardless of how deeply the route is nested past
  // that point (issue-local-035 follow-up).
  const segments = path.split('/').filter(Boolean)
  const knownRoutes: readonly string[] = KNOWN_ROUTES
  for (let i = 0; i < segments.length; i++) {
    if (knownRoutes.includes(segments[i])) {
      return _normalise('/' + segments.slice(0, i).join('/'))
    }
  }
  // No known-route segment anywhere in the path — trailing-slash strip
  // fallback (e.g. the alias index load "https://host/feeds/").
  return _normalise(path)
}

export function getAppBasePrefix(): string {
  if (cached !== null) return cached
  // 1. Explicit meta tag wins.
  const meta = _readMetaTag()
  if (meta) {
    cached = meta
    return cached
  }
  // 2. Auto-detect from window.location.
  cached = _detectFromLocation()
  return cached
}

/** Test-only escape hatch: clears the memoised value. */
export function _resetAppBasePrefixCache(): void {
  cached = null
}

/**
 * Behavioral test for the client-side base-detect script injected by
 * backend.main._render_index_html when app_base_prefix is unset
 * (issue-local-035, 2nd follow-up).
 *
 * That script is vanilla JS embedded in a Python string — it can't be
 * imported here, so this file keeps its own literal copy and actually
 * EXECUTES it via jsdom (not just asserts on its source text) to prove the
 * detection algorithm produces the right <base href> at real URLs, across
 * both deployment shapes that motivated this fix:
 *   - true root, nested SPA route (the original bug: /threat-hunting/<id>)
 *   - unconfigured reverse-proxy alias, at any depth (the regression this
 *     script exists to avoid: a fixed absolute "/" broke this case)
 *
 * Keeping the two copies of KNOWN_ROUTES in sync is covered separately, in
 * backend/tests/test_main_spa.py's test_base_detect_script_known_routes_matches_frontend
 * (a text-based cross-check against frontend/src/utils/basePrefix.ts —
 * the actual source of truth). This file is deliberately NOT that
 * cross-check; it exists to prove the ALGORITHM itself resolves correctly,
 * which a text comparison alone can't do.
 */
import { JSDOM } from 'jsdom'
import { describe, it, expect } from 'vitest'

// Mirrors backend.main._BASE_DETECT_SCRIPT exactly (see that constant's
// docstring for the full rationale). Update both together.
const DETECT_SCRIPT = `
(function () {
  var KNOWN_ROUTES = ["home","viewer","configuration","normalizer","watchers","threat-hunting","assistant","audit","account","about","login"];
  function normalise(v) {
    var out = v;
    while (out.length && out.charAt(out.length - 1) === "/") out = out.slice(0, -1);
    if (out && out.charAt(0) !== "/") out = "/" + out;
    return out;
  }
  var path = window.location.pathname || "/";
  var segments = path.split("/").filter(function (s) { return s.length > 0; });
  var prefix = "";
  var matched = false;
  for (var i = 0; i < segments.length; i++) {
    if (KNOWN_ROUTES.indexOf(segments[i]) !== -1) {
      prefix = normalise("/" + segments.slice(0, i).join("/"));
      matched = true;
      break;
    }
  }
  if (!matched) prefix = normalise(path);
  var base = document.createElement("base");
  base.setAttribute("href", prefix + "/");
  document.head.appendChild(base);
})();
`

/** Loads a minimal document at `url` with the detect script as the FIRST
 *  thing in <head> (matching where _render_index_html injects it — before
 *  any asset tag), then resolves a relative URL against the resulting
 *  document to prove the <base> actually affects resolution, not just that
 *  it exists with the expected attribute value. */
function resolvedAssetUrl(url: string): string {
  const dom = new JSDOM(
    `<!doctype html><html><head><script>${DETECT_SCRIPT}</script></head><body></body></html>`,
    { url, runScripts: 'dangerously' },
  )
  const anchor = dom.window.document.createElement('a')
  anchor.setAttribute('href', './assets/index-X.js')
  dom.window.document.body.appendChild(anchor)
  return anchor.href
}

describe('index.html base-detect script (issue-local-035, 2nd follow-up)', () => {
  it('resolves assets at true root, single-segment route', () => {
    expect(resolvedAssetUrl('https://host/viewer')).toBe('https://host/assets/index-X.js')
  })

  it('resolves assets at true root, NESTED route — the original bug', () => {
    expect(resolvedAssetUrl('https://host/threat-hunting/abc123')).toBe(
      'https://host/assets/index-X.js',
    )
  })

  it('resolves assets at true root, deeply nested route', () => {
    expect(resolvedAssetUrl('https://host/threat-hunting/tracking')).toBe(
      'https://host/assets/index-X.js',
    )
  })

  it('resolves assets under an unconfigured alias, shallow load — the regression this script fixes', () => {
    expect(resolvedAssetUrl('https://host/tars/')).toBe('https://host/tars/assets/index-X.js')
  })

  it('resolves assets under an unconfigured alias, nested route', () => {
    expect(resolvedAssetUrl('https://host/tars/threat-hunting/abc123')).toBe(
      'https://host/tars/assets/index-X.js',
    )
  })

  it('resolves assets under a multi-segment unconfigured alias', () => {
    expect(resolvedAssetUrl('https://host/proxy/tars/threat-hunting/abc123')).toBe(
      'https://host/proxy/tars/assets/index-X.js',
    )
  })

  it('resolves at the true root index load', () => {
    expect(resolvedAssetUrl('https://host/')).toBe('https://host/assets/index-X.js')
  })
})

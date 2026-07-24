/**
 * asDisplayText (issue-local-017) — defensive coercion for LLM-generated
 * array-of-string fields (key_observations, suggested_actions,
 * detection_opportunities). Backend nodes now normalize these at the
 * source (coerce_string_list in llm_bridge.py), but already-persisted
 * historical runs can still have a per-item object instead of a string
 * (observed live: Mistral returning {observation, confidence, evidence}
 * for a key_observations entry) — rendering an object directly as a React
 * child crashes the whole page (minified error #31), and a backend fix
 * can't retroactively repair already-stored data without a re-run. This
 * mirrors AnalysisTab.tsx's existing asQueryText() pattern for the same
 * failure class on a different field.
 */
export function asDisplayText(value: unknown, preferredKeys: string[] = []): string {
  if (typeof value === 'string') return value
  if (value && typeof value === 'object') {
    for (const key of preferredKeys) {
      const candidate = (value as Record<string, unknown>)[key]
      if (typeof candidate === 'string' && candidate) return candidate
    }
    try {
      return JSON.stringify(value)
    } catch {
      return String(value)
    }
  }
  return value == null ? '' : String(value)
}

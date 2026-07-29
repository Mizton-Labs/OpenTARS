/**
 * Splitting a Markdown reference document into per-topic sections
 * (issue-local-030's About -> API Docs tab).
 *
 * Kept in its own module rather than beside the component: mixing
 * non-component exports into a component file breaks React Fast Refresh (and
 * trips eslint's react-refresh/only-export-components), and it lets the
 * parsing be unit-tested without rendering anything.
 *
 * Splitting happens here, at render time, rather than in the source file so
 * the committed Markdown stays a normal, readable document that also renders
 * correctly on GitHub.
 */

export interface DocSection {
  id: string
  title: string
  body: string
}

/** Trailing issue references are useful provenance in the repository file but
 *  are noise in a reader-facing contents list, so they are dropped from the
 *  displayed heading only — the Markdown source is left untouched. */
export function cleanTitle(raw: string): string {
  return raw.replace(/\s*\((?:issue|prompts)-[^)]*\)\s*$/i, '').trim()
}

export function slugify(title: string): string {
  return (
    title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'section'
  )
}

/**
 * Split Markdown on its `##` headings.
 *
 * Fenced code blocks are tracked so a `## ...` line *inside* a fence (or any
 * `#`-prefixed shell comment) can never be mistaken for a heading.
 */
export function splitSections(markdown: string): { intro: string; sections: DocSection[] } {
  const introLines: string[] = []
  const sections: DocSection[] = []
  const usedIds = new Set<string>()
  let current: { title: string; lines: string[] } | null = null
  let inFence = false

  function finalise(sec: { title: string; lines: string[] }): DocSection {
    const title = cleanTitle(sec.title)
    let id = slugify(title)
    // Defensive: identical topic names would otherwise produce colliding
    // anchors and the contents links would all jump to the first one.
    let n = 2
    while (usedIds.has(id)) id = `${slugify(title)}-${n++}`
    usedIds.add(id)
    return { id, title, body: sec.lines.join('\n').trim() }
  }

  for (const line of markdown.split('\n')) {
    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence

    const heading = !inFence ? /^##\s+(.*\S)\s*$/.exec(line) : null
    if (heading) {
      if (current) sections.push(finalise(current))
      current = { title: heading[1], lines: [] }
      continue
    }
    if (current) current.lines.push(line)
    else introLines.push(line)
  }
  if (current) sections.push(finalise(current))

  return { intro: introLines.join('\n').trim(), sections }
}

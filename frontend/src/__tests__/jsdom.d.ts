// Minimal ambient types for the `jsdom` package, scoped to what
// indexHtmlBaseDetect.test.ts actually uses. jsdom ships no bundled types
// and @types/jsdom isn't installed — this avoids adding a new dependency
// for a single test file's narrow usage.
declare module 'jsdom' {
  export class JSDOM {
    constructor(html?: string, options?: { url?: string; runScripts?: 'dangerously' | 'outside-only' })
    readonly window: Window & typeof globalThis
  }
}

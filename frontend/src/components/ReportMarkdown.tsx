/**
 * ReportMarkdown — markdown renderer for narrative LLM-authored report/
 * analysis text (issue-local-042, item 4b): executive summaries, findings,
 * threat context, and hypothesis descriptions/justifications. Previously
 * rendered as plain <p> text, so any code/query the model happened to
 * inline (fenced ```spl blocks etc.) showed as literal backticks instead of
 * the code-card treatment structured query data already gets (see
 * AnalysisTab.tsx's Query Drafts card / ReportPanel.tsx's mirror of it).
 *
 * Same security policy as components/MarkdownMessage.tsx, and for the same
 * reason — this text ultimately derives from evidence a hunt is
 * investigating (phishing emails, scraped pages, threat-intel writeups),
 * which an attacker may have authored:
 *   - No raw HTML (no rehype-raw).
 *   - No images (an image URL is an outbound request the moment it renders).
 *   - No links (a clickable link in an analyst's report is a footgun when
 *     the surrounding text is *about* malicious infrastructure).
 * Only the typography/spacing differs — full-page report prose, not a
 * ~420px chat bubble, and code blocks use the same bordered/monospace card
 * look as the app's other query/artifact cards (bg-gray-950, green-400)
 * instead of MarkdownMessage's neutral chat-code styling.
 */
import type { ComponentPropsWithoutRef } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const components = {
  p: (p: ComponentPropsWithoutRef<'p'>) => <p className="text-sm text-gray-300 leading-relaxed mb-2 last:mb-0" {...p} />,
  ul: (p: ComponentPropsWithoutRef<'ul'>) => (
    <ul className="text-sm text-gray-300 mb-2 list-disc list-outside space-y-1 pl-5 last:mb-0" {...p} />
  ),
  ol: (p: ComponentPropsWithoutRef<'ol'>) => (
    <ol className="text-sm text-gray-300 mb-2 list-decimal list-outside space-y-1 pl-5 last:mb-0" {...p} />
  ),
  li: (p: ComponentPropsWithoutRef<'li'>) => <li className="marker:text-gray-600" {...p} />,
  strong: (p: ComponentPropsWithoutRef<'strong'>) => (
    <strong className="font-semibold text-gray-100" {...p} />
  ),
  em: (p: ComponentPropsWithoutRef<'em'>) => <em className="italic" {...p} />,
  // Matches the code-card look already used for structured query drafts
  // (AnalysisTab.tsx / ReportPanel.tsx) — same colors, so a fenced code
  // block inline in an executive summary reads as the same kind of thing.
  code: (p: ComponentPropsWithoutRef<'code'>) => (
    <code className="rounded bg-gray-950 border border-gray-800 px-1 py-0.5 font-mono text-[13px] text-green-400" {...p} />
  ),
  pre: (p: ComponentPropsWithoutRef<'pre'>) => (
    <pre
      className="mb-2 overflow-x-auto rounded border border-gray-800 bg-gray-950 p-2 font-mono text-sm text-green-400 last:mb-0 [&>code]:border-0 [&>code]:bg-transparent [&>code]:p-0 [&>code]:text-green-400"
      {...p}
    />
  ),
  blockquote: (p: ComponentPropsWithoutRef<'blockquote'>) => (
    <blockquote className="mb-2 border-l-2 border-gray-700 pl-3 text-gray-400 last:mb-0" {...p} />
  ),
  h1: (p: ComponentPropsWithoutRef<'h1'>) => (
    <p className="mt-3 mb-1 text-base font-semibold text-gray-200 first:mt-0" {...p} />
  ),
  h2: (p: ComponentPropsWithoutRef<'h2'>) => (
    <p className="mt-3 mb-1 text-base font-semibold text-gray-200 first:mt-0" {...p} />
  ),
  h3: (p: ComponentPropsWithoutRef<'h3'>) => (
    <p className="mt-2 mb-1 text-sm font-semibold text-gray-200 first:mt-0" {...p} />
  ),
  hr: () => <hr className="my-3 border-gray-800" />,
  table: (p: ComponentPropsWithoutRef<'table'>) => (
    <div className="mb-2 overflow-x-auto rounded border border-gray-800 last:mb-0">
      <table className="w-full text-sm" {...p} />
    </div>
  ),
  thead: (p: ComponentPropsWithoutRef<'thead'>) => <thead className="bg-gray-800/60" {...p} />,
  th: (p: ComponentPropsWithoutRef<'th'>) => (
    <th className="border-b border-gray-800 px-2 py-1 text-left font-semibold text-gray-300" {...p} />
  ),
  td: (p: ComponentPropsWithoutRef<'td'>) => (
    <td className="border-b border-gray-800/60 px-2 py-1 align-top text-gray-300" {...p} />
  ),
  // Links/images stripped of behaviour, not just styling — see the security
  // note above.
  a: ({ children }: ComponentPropsWithoutRef<'a'>) => <span>{children}</span>,
  img: ({ alt }: ComponentPropsWithoutRef<'img'>) => <span>{alt ?? ''}</span>,
}

export default function ReportMarkdown({ children }: { children: string }) {
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
      {children}
    </ReactMarkdown>
  )
}

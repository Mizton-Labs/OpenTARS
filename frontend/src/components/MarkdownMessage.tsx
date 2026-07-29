/**
 * Markdown renderer for SmartSearch answers (issue-local-031).
 *
 * Kept separate from the About page's API-docs renderer: this one styles chat
 * bubbles in a ~420px drawer, so it needs much tighter spacing and type than a
 * full-width reference document, and it applies a stricter content policy.
 *
 * SECURITY — the text here is model output, and the model has just read
 * snippets from threat reports and fetched web pages that an attacker may have
 * authored. It is treated as untrusted markup:
 *
 *   - **No raw HTML.** `rehype-raw` is deliberately not installed, so
 *     react-markdown escapes any HTML in the string rather than rendering it.
 *   - **No images.** An image URL is an outbound request the moment it renders,
 *     which would leak that the answer was viewed and could encode data in the
 *     path. Rendered as their alt text instead.
 *   - **No links.** This is the domain-specific one: URLs in this product
 *     routinely *are* the malicious indicators under investigation. A clickable
 *     link in an analyst's chat window is a footgun, so anchors render as plain
 *     text. Navigation is offered separately, through the cited source chips.
 */
import type { ComponentPropsWithoutRef } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const components = {
  p: (p: ComponentPropsWithoutRef<'p'>) => <p className="mb-2 last:mb-0" {...p} />,
  ul: (p: ComponentPropsWithoutRef<'ul'>) => (
    <ul className="mb-2 list-disc list-outside space-y-0.5 pl-4 last:mb-0" {...p} />
  ),
  ol: (p: ComponentPropsWithoutRef<'ol'>) => (
    <ol className="mb-2 list-decimal list-outside space-y-0.5 pl-4 last:mb-0" {...p} />
  ),
  li: (p: ComponentPropsWithoutRef<'li'>) => <li className="marker:text-gray-600" {...p} />,
  strong: (p: ComponentPropsWithoutRef<'strong'>) => (
    <strong className="font-semibold text-gray-100" {...p} />
  ),
  em: (p: ComponentPropsWithoutRef<'em'>) => <em className="italic" {...p} />,
  code: (p: ComponentPropsWithoutRef<'code'>) => (
    <code className="rounded bg-gray-900/70 px-1 py-0.5 font-mono text-[11px] text-brand-300" {...p} />
  ),
  pre: (p: ComponentPropsWithoutRef<'pre'>) => (
    <pre
      className="mb-2 overflow-x-auto rounded border border-gray-700 bg-gray-900/70 p-2 font-mono text-[11px] text-gray-300 last:mb-0 [&>code]:bg-transparent [&>code]:p-0 [&>code]:text-gray-300"
      {...p}
    />
  ),
  blockquote: (p: ComponentPropsWithoutRef<'blockquote'>) => (
    <blockquote className="mb-2 border-l-2 border-gray-700 pl-2 text-gray-400 last:mb-0" {...p} />
  ),
  // The prompt asks for h3 at most; h1/h2 are mapped to the same size so an
  // over-eager heading cannot blow up the bubble's type scale.
  h1: (p: ComponentPropsWithoutRef<'h1'>) => (
    <p className="mt-2 mb-1 font-semibold text-gray-100 first:mt-0" {...p} />
  ),
  h2: (p: ComponentPropsWithoutRef<'h2'>) => (
    <p className="mt-2 mb-1 font-semibold text-gray-100 first:mt-0" {...p} />
  ),
  h3: (p: ComponentPropsWithoutRef<'h3'>) => (
    <p className="mt-2 mb-1 font-semibold text-gray-100 first:mt-0" {...p} />
  ),
  hr: () => <hr className="my-2 border-gray-800" />,
  table: (p: ComponentPropsWithoutRef<'table'>) => (
    <div className="mb-2 overflow-x-auto rounded border border-gray-800 last:mb-0">
      <table className="w-full text-[11px]" {...p} />
    </div>
  ),
  thead: (p: ComponentPropsWithoutRef<'thead'>) => <thead className="bg-gray-800/60" {...p} />,
  th: (p: ComponentPropsWithoutRef<'th'>) => (
    <th className="border-b border-gray-800 px-2 py-1 text-left font-semibold text-gray-300" {...p} />
  ),
  td: (p: ComponentPropsWithoutRef<'td'>) => (
    <td className="border-b border-gray-800/60 px-2 py-1 align-top" {...p} />
  ),
  // Links and images are stripped of their behaviour, not just their styling —
  // see the security note above.
  a: ({ children }: ComponentPropsWithoutRef<'a'>) => <span>{children}</span>,
  img: ({ alt }: ComponentPropsWithoutRef<'img'>) => <span>{alt ?? ''}</span>,
}

export default function MarkdownMessage({ children }: { children: string }) {
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
      {children}
    </ReactMarkdown>
  )
}

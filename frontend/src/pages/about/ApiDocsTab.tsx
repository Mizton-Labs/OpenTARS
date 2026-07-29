/**
 * About -> API Docs tab (issue-local-030).
 *
 * Two pieces:
 *   - The Threat Hunting API reference (docs/api-threat-hunting.md), fetched
 *     via GET /api/app/docs/api-threat-hunting and rendered as real HTML —
 *     no @tailwindcss/typography plugin (its default palette wouldn't follow
 *     this app's per-theme CSS-variable color system), so headings/tables/
 *     code blocks are styled directly via ReactMarkdown's `components` prop
 *     using the same gray and brand color tokens as the rest of the app.
 *   - FastAPI's own interactive Swagger UI, embedded via <iframe> pointing at
 *     swaggerUiSrc() (same-origin, so the session cookie authenticates it
 *     exactly like any other page — see backend/main.py's _DOCS_PATHS gate).
 */
import type { ComponentPropsWithoutRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { ExternalLink, FileText, Code2 } from 'lucide-react'
import { api, swaggerUiSrc } from '../../api/client'

const markdownComponents = {
  h1: (p: ComponentPropsWithoutRef<'h1'>) => (
    <h1 className="text-lg font-semibold text-gray-100 mt-6 mb-3 first:mt-0" {...p} />
  ),
  h2: (p: ComponentPropsWithoutRef<'h2'>) => (
    <h2 className="text-base font-semibold text-gray-100 mt-6 mb-2 pb-1 border-b border-gray-800" {...p} />
  ),
  h3: (p: ComponentPropsWithoutRef<'h3'>) => (
    <h3 className="text-sm font-semibold text-gray-200 mt-4 mb-1.5" {...p} />
  ),
  p: (p: ComponentPropsWithoutRef<'p'>) => <p className="text-sm text-gray-400 leading-relaxed mb-3" {...p} />,
  a: (p: ComponentPropsWithoutRef<'a'>) => (
    <a className="text-brand-400 hover:text-brand-300 hover:underline" target="_blank" rel="noopener noreferrer" {...p} />
  ),
  ul: (p: ComponentPropsWithoutRef<'ul'>) => (
    <ul className="list-disc list-outside pl-5 text-sm text-gray-400 space-y-1 mb-3" {...p} />
  ),
  ol: (p: ComponentPropsWithoutRef<'ol'>) => (
    <ol className="list-decimal list-outside pl-5 text-sm text-gray-400 space-y-1 mb-3" {...p} />
  ),
  li: (p: ComponentPropsWithoutRef<'li'>) => <li className="marker:text-gray-600" {...p} />,
  code: (p: ComponentPropsWithoutRef<'code'>) => (
    <code className="rounded bg-gray-800/70 px-1 py-0.5 text-xs font-mono text-brand-300" {...p} />
  ),
  pre: (p: ComponentPropsWithoutRef<'pre'>) => (
    <pre className="rounded-lg border border-gray-800 bg-gray-900/60 p-3 mb-3 overflow-x-auto text-xs font-mono text-gray-300 [&>code]:bg-transparent [&>code]:p-0 [&>code]:text-gray-300" {...p} />
  ),
  blockquote: (p: ComponentPropsWithoutRef<'blockquote'>) => (
    <blockquote className="border-l-2 border-brand-700/50 pl-3 text-sm text-gray-500 italic mb-3" {...p} />
  ),
  hr: () => <hr className="border-gray-800 my-5" />,
  table: (p: ComponentPropsWithoutRef<'table'>) => (
    <div className="overflow-x-auto mb-3 rounded-lg border border-gray-800">
      <table className="w-full text-xs" {...p} />
    </div>
  ),
  thead: (p: ComponentPropsWithoutRef<'thead'>) => <thead className="bg-gray-800/50" {...p} />,
  th: (p: ComponentPropsWithoutRef<'th'>) => (
    <th className="px-3 py-2 text-left font-semibold text-gray-300 border-b border-gray-800" {...p} />
  ),
  td: (p: ComponentPropsWithoutRef<'td'>) => (
    <td className="px-3 py-2 text-gray-400 border-b border-gray-800/60 align-top" {...p} />
  ),
  strong: (p: ComponentPropsWithoutRef<'strong'>) => <strong className="text-gray-200 font-semibold" {...p} />,
}

export default function ApiDocsTab() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['about-doc', 'api-threat-hunting'],
    queryFn: () => api.getDoc('api-threat-hunting'),
  })

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="flex items-center gap-2 mb-4">
          <FileText className="w-4 h-4 text-brand-400 shrink-0" />
          <h2 className="text-sm font-semibold text-gray-200">Threat Hunting API Reference</h2>
        </div>
        {isLoading && <p className="text-sm text-gray-500">Loading…</p>}
        {isError && (
          <p role="alert" className="text-sm text-red-400">
            Could not load the API documentation: {error instanceof Error ? error.message : String(error)}
          </p>
        )}
        {data && (
          <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
            {data.content}
          </ReactMarkdown>
        )}
      </div>

      <div className="card space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Code2 className="w-4 h-4 text-brand-400 shrink-0" />
            <h2 className="text-sm font-semibold text-gray-200">API Swagger</h2>
          </div>
          <a
            href={swaggerUiSrc()}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300"
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
    </div>
  )
}

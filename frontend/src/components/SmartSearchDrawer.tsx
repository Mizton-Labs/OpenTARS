/**
 * Global search / SmartSearch drawer (issue-local-031).
 *
 * A search-icon button sits flush in the top-right corner on every page —
 * search spans the whole application, so the entry point should not depend on
 * where the user happens to be. Pressing it expands a right-hand drawer that is
 * fully collapsed (zero width, nothing visible) until then.
 *
 * Two modes behind an always-visible switch:
 *   - Search — the deterministic global search. Hits are grouped by the section
 *     they were found in (hunts, threat intel, settings, docs, …) with a short
 *     context snippet, and clicking one navigates there.
 *   - Smart  — a chatbot answering from the same role-scoped results. The
 *     switch is always rendered; when no LLM provider is configured it is
 *     disabled and its tooltip names the setting that enables it.
 *
 * The assistant's reply is rendered as Markdown by MarkdownMessage, which
 * renders no raw HTML, no images and no clickable links — the answer is shaped
 * by threat reports an attacker may have authored, and in this product a URL is
 * often the malicious indicator itself. Everything here is read-only; there is
 * no action the drawer can take on the user's behalf.
 */
import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { Search, X, Sparkles, Loader2, CornerDownLeft, AlertTriangle } from 'lucide-react'
import { api, type SearchHit, type SearchResults, type SmartTurn } from '../api/client'

// Lazy: pulls in react-markdown/remark-gfm, which is only needed once an
// answer arrives. The drawer mounts on every Threat Hunting page, so a static
// import would put the whole Markdown stack in the bundle those pages load
// even for users who never open Smart mode.
const MarkdownMessage = lazy(() => import('./MarkdownMessage'))

type Mode = 'normal' | 'smart'

/** Mirrors MAX_HISTORY_TURNS in backend/search/smart.py — the server keeps this
 *  many prior turns, so sending more is wasted payload that can trip its bound. */
const MAX_HISTORY_TURNS = 6

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  sources?: SearchHit[]
  failed?: boolean
}

export default function SmartSearchDrawer() {
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState<Mode>('normal')

  // Search state
  const [term, setTerm] = useState('')
  const [debounced, setDebounced] = useState('')

  // Chat state
  const [question, setQuestion] = useState('')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [thinking, setThinking] = useState(false)

  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)
  const transcriptRef = useRef<HTMLDivElement>(null)

  const { data: status } = useQuery({
    queryKey: ['smart-search-status'],
    queryFn: api.search.status,
    staleTime: 60_000,
  })
  const smartAvailable = status?.available ?? false

  // Debounce so typing doesn't fan out a search request per keystroke.
  useEffect(() => {
    const id = setTimeout(() => setDebounced(term.trim()), 300)
    return () => clearTimeout(id)
  }, [term])

  const { data: results, isFetching } = useQuery<SearchResults>({
    queryKey: ['global-search', debounced],
    queryFn: () => api.search.query(debounced),
    enabled: open && mode === 'normal' && debounced.length > 0,
  })

  useEffect(() => {
    if (open) inputRef.current?.focus()
  }, [open, mode])

  // Close on Escape from anywhere in the drawer.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  // Keep the newest turn in view. scrollTo is not available everywhere (jsdom
  // among others), so fall back to the universally supported scrollTop.
  useEffect(() => {
    const el = transcriptRef.current
    if (!el) return
    if (typeof el.scrollTo === 'function') el.scrollTo({ top: el.scrollHeight })
    else el.scrollTop = el.scrollHeight
  }, [messages, thinking])

  function goTo(hit: SearchHit) {
    setOpen(false)
    navigate(hit.route)
  }

  async function ask() {
    const asked = question.trim()
    if (!asked || thinking) return

    // Only the text of prior turns is replayed — never sources or metadata.
    // Two things matter here:
    //   - failed bubbles hold an error string, not an answer; replaying them
    //     would feed "502 Bad Gateway: {...}" back as if the assistant said it;
    //   - the server keeps only the last few turns anyway and rejects an
    //     oversized list outright, so an unbounded transcript would start
    //     failing mid-conversation and, because each failure is appended, never
    //     recover. Trim to the same window the server keeps.
    const history: SmartTurn[] = messages
      .filter((m) => !m.failed)
      .slice(-MAX_HISTORY_TURNS)
      .map((m) => ({ role: m.role, content: m.content }))
    setMessages((prev) => [...prev, { role: 'user', content: asked }])
    setQuestion('')
    setThinking(true)
    try {
      const reply = await api.search.smart(asked, history)
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: reply.answer, sources: reply.sources },
      ])
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: e instanceof Error ? e.message : String(e),
          failed: true,
        },
      ])
    } finally {
      setThinking(false)
    }
  }

  return (
    <>
      {!open && (
        <button
          type="button"
          onClick={() => setOpen(true)}
          title="Search OpenTARS"
          aria-label="Search OpenTARS"
          // Flush into the top-right corner so it reads as application chrome
          // rather than something floating over the page. ProtectedLayout
          // reserves a matching right-hand gutter on <main>, so it can never
          // cover a page's own header controls (the Threat Hunting header, for
          // one, puts "New Package" exactly here).
          className="fixed top-0 right-0 z-30 rounded-bl-lg border-b border-l border-gray-700 bg-gray-900/95 p-2.5 text-gray-300 shadow-lg backdrop-blur hover:border-brand-600 hover:text-brand-300 transition-colors"
        >
          <Search className="w-4 h-4" />
        </button>
      )}

      <aside
        aria-label="Search"
        aria-hidden={!open}
        className={clsx(
          'fixed inset-y-0 right-0 z-40 flex flex-col overflow-hidden border-l border-gray-800 bg-gray-900 shadow-2xl transition-[width] duration-200 ease-out',
          open ? 'w-full sm:w-[420px]' : 'w-0 border-l-0',
        )}
      >
        {/* Rendered only when open so nothing is focusable while collapsed. */}
        {open && (
          <>
            <div className="flex items-center justify-between gap-2 border-b border-gray-800 px-3 py-2.5">
              <div className="flex items-center gap-2 min-w-0">
                <Search className="w-4 h-4 text-brand-400 shrink-0" />
                <h2 className="text-sm font-semibold text-gray-200 truncate">Search</h2>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close search"
                className="btn-ghost p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Mode switch — always rendered; Smart is disabled (with a tooltip
                naming the setting) when no LLM provider is configured. */}
            <div className="flex gap-1 border-b border-gray-800 px-3 py-2">
              <button
                type="button"
                onClick={() => setMode('normal')}
                className={clsx(
                  'flex-1 rounded px-2 py-1 text-xs font-medium transition-colors',
                  mode === 'normal'
                    ? 'bg-gray-800 text-gray-100'
                    : 'text-gray-500 hover:text-gray-300',
                )}
              >
                Search
              </button>
              <button
                type="button"
                disabled={!smartAvailable}
                onClick={() => setMode('smart')}
                title={
                  smartAvailable
                    ? 'Ask questions about this installation'
                    : (status?.reason ?? 'Smart Search is unavailable.')
                }
                className={clsx(
                  'flex-1 inline-flex items-center justify-center gap-1.5 rounded px-2 py-1 text-xs font-medium transition-colors',
                  !smartAvailable && 'cursor-not-allowed text-gray-600 opacity-60',
                  smartAvailable && mode === 'smart'
                    ? 'bg-gray-800 text-gray-100'
                    : smartAvailable && 'text-gray-500 hover:text-gray-300',
                )}
              >
                <Sparkles className="w-3.5 h-3.5" />
                Smart
              </button>
            </div>

            {mode === 'normal' ? (
              <NormalMode
                inputRef={inputRef}
                term={term}
                onTerm={setTerm}
                busy={isFetching}
                results={results}
                onPick={goTo}
              />
            ) : (
              <SmartMode
                inputRef={inputRef}
                question={question}
                onQuestion={setQuestion}
                messages={messages}
                thinking={thinking}
                transcriptRef={transcriptRef}
                onAsk={() => void ask()}
                onPick={goTo}
              />
            )}
          </>
        )}
      </aside>
    </>
  )
}

// ── Normal search ────────────────────────────────────────────────────────────

function NormalMode({
  inputRef,
  term,
  onTerm,
  busy,
  results,
  onPick,
}: {
  inputRef: React.RefObject<HTMLInputElement>
  term: string
  onTerm: (v: string) => void
  busy: boolean
  results: SearchResults | undefined
  onPick: (hit: SearchHit) => void
}) {
  return (
    <>
      <div className="border-b border-gray-800 px-3 py-2">
        <input
          ref={inputRef}
          className="input w-full"
          placeholder="Search hunts, threat intel, settings, docs…"
          value={term}
          onChange={(e) => onTerm(e.target.value)}
          aria-label="Search query"
        />
      </div>

      <div className="flex-1 overflow-y-auto px-3 py-2 space-y-4">
        {busy && (
          <p className="flex items-center gap-2 text-xs text-gray-500">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Searching…
          </p>
        )}

        {!busy && term.trim() === '' && (
          <p className="text-xs text-gray-600">
            Search across hunt packages, threat intel, watchers, pages, settings and
            documentation. Results show the section each match was found in.
          </p>
        )}

        {!busy && term.trim() !== '' && results && results.total === 0 && (
          <p className="text-xs text-gray-500">No matches for “{results.query}”.</p>
        )}

        {/* Gated on the live term, not just on `results`: for the 300 ms the
            debounce lags behind a cleared box, the previous term's hits would
            otherwise render underneath the "search across…" placeholder. */}
        {term.trim() !== '' &&
          results?.sections.map((section) => (
          <div key={section.section}>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-gray-500">
              {section.section}
            </p>
            <ul className="space-y-1">
              {section.hits.map((hit, i) => (
                <li key={`${hit.route}-${hit.ref ?? i}`}>
                  <button
                    type="button"
                    onClick={() => onPick(hit)}
                    className="w-full rounded border border-gray-800 bg-gray-900/60 px-2.5 py-1.5 text-left hover:border-gray-600 hover:bg-gray-800/60 transition-colors"
                  >
                    <span className="block text-xs font-medium text-gray-200">{hit.title}</span>
                    {hit.snippet && (
                      <span className="mt-0.5 block text-[11px] leading-snug text-gray-500">
                        {hit.snippet}
                      </span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </>
  )
}

// ── Smart search (chat) ──────────────────────────────────────────────────────

function SmartMode({
  inputRef,
  question,
  onQuestion,
  messages,
  thinking,
  transcriptRef,
  onAsk,
  onPick,
}: {
  inputRef: React.RefObject<HTMLInputElement>
  question: string
  onQuestion: (v: string) => void
  messages: ChatMessage[]
  thinking: boolean
  transcriptRef: React.RefObject<HTMLDivElement>
  onAsk: () => void
  onPick: (hit: SearchHit) => void
}) {
  return (
    <>
      <div ref={transcriptRef} className="flex-1 overflow-y-auto px-3 py-3 space-y-3">
        {messages.length === 0 && !thinking && (
          <div className="space-y-2">
            <p className="text-xs text-gray-500">
              Ask about this installation — your hunts, the threat intel you have ingested,
              or how a part of the product works.
            </p>
            <p className="text-[11px] text-gray-600">
              Answers come only from what you already have access to, and the assistant
              cannot change anything.
            </p>
          </div>
        )}

        {messages.map((message, i) => (
          <div
            key={i}
            className={clsx(
              'rounded-lg px-2.5 py-2 text-xs leading-relaxed',
              message.role === 'user'
                ? 'ml-6 bg-brand-900/20 border border-brand-800/40 text-gray-200'
                : 'mr-2 bg-gray-800/50 border border-gray-800 text-gray-300',
              message.failed && 'border-red-800/50 text-red-400',
            )}
          >
            {message.failed && (
              <span className="mb-1 flex items-center gap-1.5 font-medium">
                <AlertTriangle className="w-3.5 h-3.5" /> Could not answer
              </span>
            )}
            {/* The user's own question and error text are shown verbatim; only
                the assistant's answer is Markdown. MarkdownMessage renders no
                raw HTML, no images and no clickable links — see its module
                comment for why that last one matters here. */}
            {message.role === 'assistant' && !message.failed ? (
              // Falls back to the same text unformatted, so the answer is
              // readable immediately rather than blank while the chunk loads.
              <Suspense fallback={<p className="whitespace-pre-wrap">{message.content}</p>}>
                <MarkdownMessage>{message.content}</MarkdownMessage>
              </Suspense>
            ) : (
              <p className="whitespace-pre-wrap">{message.content}</p>
            )}

            {message.sources && message.sources.length > 0 && (
              <div className="mt-2 border-t border-gray-800 pt-1.5">
                <p className="mb-1 text-[10px] uppercase tracking-wide text-gray-600">Sources</p>
                <div className="flex flex-wrap gap-1">
                  {message.sources.slice(0, 8).map((hit, j) => (
                    <button
                      key={`${hit.route}-${j}`}
                      type="button"
                      onClick={() => onPick(hit)}
                      className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-400 hover:border-brand-600 hover:text-brand-300 transition-colors"
                    >
                      {hit.section}: {hit.title}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}

        {thinking && (
          <p className="flex items-center gap-2 text-xs text-gray-500">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Thinking…
          </p>
        )}
      </div>

      <div className="border-t border-gray-800 px-3 py-2">
        <div className="flex items-center gap-2">
          <input
            ref={inputRef}
            className="input flex-1"
            placeholder="Ask a question…"
            value={question}
            onChange={(e) => onQuestion(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                onAsk()
              }
            }}
            aria-label="Ask Smart Search"
          />
          <button
            type="button"
            onClick={onAsk}
            disabled={thinking || question.trim() === ''}
            className="btn-primary p-2"
            aria-label="Send question"
          >
            <CornerDownLeft className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </>
  )
}

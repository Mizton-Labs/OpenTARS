/**
 * Smart chat transcript UI (issue-local-031, extended when the Assistant
 * sidebar page was added).
 *
 * Extracted out of SmartSearchDrawer so the same chat — same Markdown
 * rendering, same sourcing rules — can be mounted in two places: the global
 * drawer (compact, opened over any page) and the full-page Assistant view
 * (Sidebar, above Account). Both call useSmartChat() (hooks/useSmartChat.ts)
 * for state and render this component for the transcript + composer; only
 * the surrounding chrome (drawer vs. page) differs.
 *
 * See MarkdownMessage's module comment for why the assistant's answer
 * renders no raw HTML, no images, and no clickable links.
 */
import { lazy, Suspense } from 'react'
import { clsx } from 'clsx'
import { Loader2, CornerDownLeft, AlertTriangle } from 'lucide-react'
import type { SearchHit } from '../api/client'
import type { ChatMessage } from '../hooks/useSmartChat'

const MarkdownMessage = lazy(() => import('./MarkdownMessage'))

export function SmartChatPanel({
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

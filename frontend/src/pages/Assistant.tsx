/**
 * Assistant page — the Smart Search chatbot as its own sidebar section,
 * above Account.
 *
 * Same chat: same request/history logic and the same role-scoped answers as
 * the Smart tab in the global search drawer (SmartSearchDrawer.tsx) — both
 * are built on useSmartChat()/<SmartChatPanel> (components/SmartChatPanel.tsx)
 * so there is exactly one implementation of "ask the assistant" to keep
 * correct. This page just gives that same content a permanent, full-height
 * home instead of a drawer someone has to remember to open.
 */
import { useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, Sparkles } from 'lucide-react'
import { SmartChatPanel } from '../components/SmartChatPanel'
import { useSmartChat } from '../hooks/useSmartChat'
import type { SearchHit } from '../api/client'

export default function Assistant() {
  const {
    status,
    statusLoading,
    smartAvailable,
    question,
    setQuestion,
    messages,
    thinking,
    transcriptRef,
    ask,
  } = useSmartChat()
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)

  function goTo(hit: SearchHit) {
    navigate(hit.route)
  }

  return (
    <div className="flex h-full flex-col p-6">
      <div className="mb-4 shrink-0">
        <h1 className="flex items-center gap-2 text-lg font-semibold text-gray-100">
          <Sparkles className="w-4.5 h-4.5 text-brand-400" />
          Assistant
        </h1>
        <p className="text-sm text-gray-500">
          Ask about this installation — your hunts, the threat intel you have ingested, or how a
          part of the product works.
        </p>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-gray-800 bg-gray-900/40">
        {statusLoading ? (
          <div className="flex flex-1 items-center justify-center p-6">
            <Loader2 className="w-5 h-5 text-gray-600 animate-spin" />
          </div>
        ) : !smartAvailable ? (
          <div className="flex flex-1 items-center justify-center p-6 text-center">
            <p className="text-sm text-gray-500">
              {status?.reason ?? 'Smart Search is unavailable.'}
            </p>
          </div>
        ) : (
          <SmartChatPanel
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
      </div>
    </div>
  )
}

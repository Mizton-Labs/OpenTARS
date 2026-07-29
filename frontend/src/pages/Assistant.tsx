/**
 * Assistant page — the Smart Search chatbot as its own sidebar section,
 * above Account.
 *
 * Same chat, same session: this page and the Smart tab in the global search
 * drawer (SmartSearchDrawer.tsx) both consume AssistantSessionProvider's
 * shared context (components/AssistantSessionProvider.tsx), so asking a
 * question here and then opening the drawer elsewhere (or vice versa)
 * continues the exact same conversation — not two independent chats that
 * happen to share code. The session top bar (New/Save/Export/Delete/Sessions,
 * components/AssistantSessionBar.tsx) is the same component the drawer
 * renders too.
 */
import { useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, Sparkles } from 'lucide-react'
import { SmartChatPanel } from '../components/SmartChatPanel'
import { useAssistantSessionContext } from '../hooks/useAssistantSessionContext'
import AssistantSessionBar from '../components/AssistantSessionBar'
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
  } = useAssistantSessionContext()
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)

  function goTo(hit: SearchHit) {
    navigate(hit.route)
  }

  return (
    <div className="flex h-full flex-col p-6">
      <div className="mb-4 shrink-0 space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h1 className="flex items-center gap-2 text-lg font-semibold text-gray-100">
              <Sparkles className="w-4.5 h-4.5 text-brand-400" />
              Assistant
            </h1>
            <p className="text-sm text-gray-500">
              Ask about this installation — your hunts, the threat intel you have ingested, or how a
              part of the product works.
            </p>
          </div>
          <AssistantSessionBar />
        </div>
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

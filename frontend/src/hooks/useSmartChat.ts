/**
 * Smart chat state (issue-local-031, extended when the Assistant sidebar page
 * was added).
 *
 * Shared between the global search drawer's Smart tab (SmartSearchDrawer.tsx)
 * and the full-page Assistant view (pages/Assistant.tsx) — both render
 * <SmartChatPanel> (components/SmartChatPanel.tsx) against this hook's state,
 * so there is exactly one implementation of "ask the assistant" and its
 * history/error handling to keep correct.
 */
import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, type AssistantChatMessage, type SmartTurn } from '../api/client'

/** Mirrors MAX_HISTORY_TURNS in backend/search/smart.py — the server keeps this
 *  many prior turns, so sending more is wasted payload that can trip its bound. */
const MAX_HISTORY_TURNS = 6

/** Same shape the session-storage API uses (client.ts) — a live transcript
 *  and a saved session's messages are the same thing at different points in
 *  their lifecycle, so there is one type for both. */
export type ChatMessage = AssistantChatMessage

export function useSmartChat() {
  const [question, setQuestion] = useState('')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [thinking, setThinking] = useState(false)
  const transcriptRef = useRef<HTMLDivElement>(null)

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['smart-search-status'],
    queryFn: api.search.status,
    staleTime: 60_000,
  })
  const smartAvailable = status?.available ?? false

  // Keep the newest turn in view. scrollTo is not available everywhere (jsdom
  // among others), so fall back to the universally supported scrollTop.
  useEffect(() => {
    const el = transcriptRef.current
    if (!el) return
    if (typeof el.scrollTo === 'function') el.scrollTo({ top: el.scrollHeight })
    else el.scrollTop = el.scrollHeight
  }, [messages, thinking])

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

  return {
    status,
    statusLoading,
    smartAvailable,
    question,
    setQuestion,
    messages,
    setMessages,
    thinking,
    transcriptRef,
    ask,
  }
}

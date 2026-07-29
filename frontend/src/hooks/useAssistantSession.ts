/**
 * Assistant session lifecycle (issue-local-032) — wraps useSmartChat's live
 * transcript with persistence: every completed turn is saved to a session
 * (auto-created on the first message, under its default timestamped name
 * unless the user has already named it), sessions can be listed/loaded/
 * renamed/deleted, and "New session" starts a fresh transcript without
 * losing the one just left.
 *
 * Meant to be consumed through ONE shared instance (AssistantSessionProvider,
 * mounted once in ProtectedLayout) so the search drawer's Smart tab and the
 * full-page Assistant view are the same conversation, not two independent
 * chats that happen to share code — see that provider's module comment for
 * the "changes view to another section ⇒ new session" rule.
 */
import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useSmartChat } from './useSmartChat'

export function useAssistantSession() {
  const chat = useSmartChat()
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null)
  const [currentSessionName, setCurrentSessionName] = useState<string | null>(null)
  const savingRef = useRef(false)
  const sessionIdRef = useRef<string | null>(null)
  sessionIdRef.current = currentSessionId

  const { data: sessions = [], refetch: refetchSessions } = useQuery({
    queryKey: ['assistant-sessions'],
    queryFn: api.search.sessions.list,
  })

  // Auto-save once a turn completes (thinking flips back to false) — never
  // mid-turn, so a session's stored transcript is always a whole exchange,
  // not a dangling question with no answer yet.
  useEffect(() => {
    if (chat.thinking || chat.messages.length === 0) return
    void persist()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chat.messages, chat.thinking])

  async function persist() {
    if (savingRef.current) return
    savingRef.current = true
    try {
      if (sessionIdRef.current) {
        await api.search.sessions.update(sessionIdRef.current, { messages: chat.messages })
      } else {
        const created = await api.search.sessions.create({ messages: chat.messages })
        setCurrentSessionId(created.id)
        setCurrentSessionName(created.name)
      }
      void refetchSessions()
    } catch {
      // Best-effort — a persistence hiccup must not interrupt the live chat.
    } finally {
      savingRef.current = false
    }
  }

  function newSession() {
    if (chat.messages.length === 0 && !currentSessionId) return
    chat.setMessages([])
    setCurrentSessionId(null)
    setCurrentSessionName(null)
  }

  async function saveSessionAs(name: string) {
    if (currentSessionId) {
      const updated = await api.search.sessions.update(currentSessionId, { name })
      setCurrentSessionName(updated.name)
    } else {
      const created = await api.search.sessions.create({ name, messages: chat.messages })
      setCurrentSessionId(created.id)
      setCurrentSessionName(created.name)
    }
    void refetchSessions()
  }

  async function loadSession(id: string) {
    const full = await api.search.sessions.get(id)
    chat.setMessages(full.messages)
    setCurrentSessionId(full.id)
    setCurrentSessionName(full.name)
  }

  async function deleteSession(id: string) {
    await api.search.sessions.delete(id)
    if (id === currentSessionId) {
      chat.setMessages([])
      setCurrentSessionId(null)
      setCurrentSessionName(null)
    }
    void refetchSessions()
  }

  return {
    ...chat,
    sessions,
    currentSessionId,
    currentSessionName,
    newSession,
    saveSessionAs,
    loadSession,
    deleteSession,
  }
}

export type AssistantSessionState = ReturnType<typeof useAssistantSession>

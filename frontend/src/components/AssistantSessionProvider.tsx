/**
 * AssistantSessionProvider (issue-local-032).
 *
 * Mounted once in ProtectedLayout so the search drawer's Smart tab and the
 * full-page Assistant view share exactly one live conversation + session
 * lifecycle (useAssistantSession) — asking a question in one and switching
 * to the other continues the same transcript, and the drawer's "Open in
 * Assistant" button is just a navigation, not a handoff of any kind.
 *
 * "A new session is open every time the user changes view to another
 * section": tracked here via the URL's top-level path segment. Navigating
 * from one section to a different one (e.g. /viewer → /threat-hunting, or
 * /assistant → /configuration) starts a fresh transcript — the conversation
 * just left is not lost, it was already persisted turn-by-turn and remains
 * in the session list. Sub-navigation WITHIN a section (e.g.
 * /threat-hunting → /threat-hunting/packages) does not reset anything.
 *
 * The context object itself lives in assistantSessionContext.ts and the
 * consuming hook in hooks/useAssistantSessionContext.ts — split out so this
 * file exports only the component (react-refresh/only-export-components).
 */
import { useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import { useAssistantSession } from '../hooks/useAssistantSession'
import { AssistantSessionContext } from './assistantSessionContext'

function topLevelSection(pathname: string): string {
  return pathname.split('/').filter(Boolean)[0] ?? ''
}

export function AssistantSessionProvider({ children }: { children: React.ReactNode }) {
  const session = useAssistantSession()
  const location = useLocation()
  const prevSectionRef = useRef<string | null>(null)
  const newSessionRef = useRef(session.newSession)
  newSessionRef.current = session.newSession

  useEffect(() => {
    const section = topLevelSection(location.pathname)
    if (prevSectionRef.current !== null && prevSectionRef.current !== section) {
      newSessionRef.current()
    }
    prevSectionRef.current = section
  }, [location.pathname])

  return (
    <AssistantSessionContext.Provider value={session}>{children}</AssistantSessionContext.Provider>
  )
}

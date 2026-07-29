import { useContext } from 'react'
import { AssistantSessionContext } from '../components/assistantSessionContext'
import type { AssistantSessionState } from './useAssistantSession'

/** Read the shared Assistant session/chat instance. Must be called under
 *  AssistantSessionProvider (mounted once in ProtectedLayout). */
export function useAssistantSessionContext(): AssistantSessionState {
  const ctx = useContext(AssistantSessionContext)
  if (!ctx) {
    throw new Error('useAssistantSessionContext must be used within AssistantSessionProvider')
  }
  return ctx
}

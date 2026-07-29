/**
 * Assistant session context object + value type (issue-local-032).
 *
 * Mirrors the theme/ context split: a non-component module so
 * AssistantSessionProvider.tsx can export ONLY <AssistantSessionProvider>
 * and useAssistantSessionContext.ts can export ONLY the hook, satisfying
 * react-refresh/only-export-components.
 */
import { createContext } from 'react'
import type { AssistantSessionState } from '../hooks/useAssistantSession'

export const AssistantSessionContext = createContext<AssistantSessionState | null>(null)

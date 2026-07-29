/**
 * Tests for AssistantSessionBar (issue-local-032) — the New/Save/Export/
 * Delete/Sessions top bar shared by the Assistant page and the drawer's
 * Smart tab. Mocks useAssistantSessionContext directly so the bar's own
 * rendering/gating logic is tested in isolation from persistence plumbing
 * (covered by assistantSession.test.tsx).
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../hooks/useAssistantSessionContext', () => ({
  useAssistantSessionContext: vi.fn(),
}))

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      search: {
        ...actual.api.search,
        sessions: {
          ...actual.api.search.sessions,
          get: vi.fn(),
          downloadMarkdownUrl: (id: string) => `/api/search/sessions/${id}/markdown`,
          downloadPdfUrl: (id: string) => `/api/search/sessions/${id}/pdf`,
        },
      },
    },
  }
})

import { useAssistantSessionContext } from '../hooks/useAssistantSessionContext'
import { api } from '../api/client'
import AssistantSessionBar from '../components/AssistantSessionBar'

const mockedUseContext = useAssistantSessionContext as unknown as ReturnType<typeof vi.fn>

function baseContext(overrides: Partial<ReturnType<typeof useAssistantSessionContext>> = {}) {
  return {
    sessions: [],
    currentSessionId: null,
    currentSessionName: null,
    newSession: vi.fn(),
    saveSessionAs: vi.fn(),
    loadSession: vi.fn(),
    deleteSession: vi.fn(),
    ...overrides,
  } as unknown as ReturnType<typeof useAssistantSessionContext>
}

beforeEach(() => vi.clearAllMocks())

describe('AssistantSessionBar — gating', () => {
  it('disables Save, Export, and Delete before any session exists', () => {
    mockedUseContext.mockReturnValue(baseContext())
    render(<AssistantSessionBar />)

    expect(screen.getByRole('button', { name: /save/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /export/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /delete/i })).toBeDisabled()
    // New session is always available.
    expect(screen.getByRole('button', { name: /new session/i })).toBeEnabled()
  })

  it('enables Save, Export, and Delete once a session exists', () => {
    mockedUseContext.mockReturnValue(
      baseContext({ currentSessionId: 's1', currentSessionName: 'My chat' }),
    )
    render(<AssistantSessionBar />)

    expect(screen.getByRole('button', { name: /save/i })).toBeEnabled()
    expect(screen.getByRole('button', { name: /export/i })).toBeEnabled()
    expect(screen.getByRole('button', { name: /delete/i })).toBeEnabled()
  })
})

describe('AssistantSessionBar — New session', () => {
  it('calls newSession() when clicked', async () => {
    const user = userEvent.setup()
    const newSession = vi.fn()
    mockedUseContext.mockReturnValue(baseContext({ newSession }))
    render(<AssistantSessionBar />)

    await user.click(screen.getByRole('button', { name: /new session/i }))

    expect(newSession).toHaveBeenCalledTimes(1)
  })
})

describe('AssistantSessionBar — Save', () => {
  it('opens a name dialog pre-filled with the current name and saves it', async () => {
    const user = userEvent.setup()
    const saveSessionAs = vi.fn().mockResolvedValue(undefined)
    mockedUseContext.mockReturnValue(
      baseContext({ currentSessionId: 's1', currentSessionName: 'Old name', saveSessionAs }),
    )
    render(<AssistantSessionBar />)

    await user.click(screen.getByRole('button', { name: /^save$/i }))
    const input = await screen.findByPlaceholderText('Session name')
    expect(input).toHaveValue('Old name')

    await user.clear(input)
    await user.type(input, 'New name')
    // Two "Save" buttons are on screen now: the top-bar one and the dialog's
    // confirm button — the dialog's is the last one in the tree.
    const saveButtons = screen.getAllByRole('button', { name: /^save$/i })
    await user.click(saveButtons[saveButtons.length - 1])

    await waitFor(() => expect(saveSessionAs).toHaveBeenCalledWith('New name'))
  })
})

describe('AssistantSessionBar — Delete', () => {
  it('confirms before deleting the current session', async () => {
    const user = userEvent.setup()
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    mockedUseContext.mockReturnValue(
      baseContext({ currentSessionId: 's1', currentSessionName: 'To delete', deleteSession }),
    )
    render(<AssistantSessionBar />)

    await user.click(screen.getByRole('button', { name: /delete/i }))
    expect(await screen.findByText(/delete session\?/i)).toBeInTheDocument()
    expect(screen.getByText(/To delete/)).toBeInTheDocument()

    // Two "Delete" buttons are on screen now: the top-bar one and the
    // ConfirmDialog's confirm button — the dialog's is the last one.
    const deleteButtons = screen.getAllByRole('button', { name: /^delete$/i })
    await user.click(deleteButtons[deleteButtons.length - 1])
    await waitFor(() => expect(deleteSession).toHaveBeenCalledWith('s1'))
  })
})

describe('AssistantSessionBar — Export', () => {
  it('offers Markdown/JSON/PDF once a session exists', async () => {
    const user = userEvent.setup()
    mockedUseContext.mockReturnValue(
      baseContext({ currentSessionId: 's1', currentSessionName: 'Export me' }),
    )
    render(<AssistantSessionBar />)

    await user.click(screen.getByRole('button', { name: /export/i }))

    expect(screen.getByRole('link', { name: /markdown/i })).toHaveAttribute(
      'href',
      '/api/search/sessions/s1/markdown',
    )
    expect(screen.getByRole('link', { name: /pdf/i })).toHaveAttribute(
      'href',
      '/api/search/sessions/s1/pdf',
    )
    expect(screen.getByRole('button', { name: /json/i })).toBeInTheDocument()
  })

  it('downloads JSON by fetching the full session and building a blob', async () => {
    const user = userEvent.setup()
    const getMock = api.search.sessions.get as unknown as ReturnType<typeof vi.fn>
    getMock.mockResolvedValue({
      id: 's1',
      name: 'Export me',
      messages: [{ role: 'user', content: 'hi' }],
      created_at: 't',
      updated_at: 't',
    })
    mockedUseContext.mockReturnValue(
      baseContext({ currentSessionId: 's1', currentSessionName: 'Export me' }),
    )
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    render(<AssistantSessionBar />)

    await user.click(screen.getByRole('button', { name: /export/i }))
    await user.click(screen.getByRole('button', { name: /json/i }))

    await waitFor(() => expect(getMock).toHaveBeenCalledWith('s1'))
    expect(clickSpy).toHaveBeenCalled()
    clickSpy.mockRestore()
  })
})

describe('AssistantSessionBar — Sessions picker', () => {
  it('lists saved sessions and loads the clicked one', async () => {
    const user = userEvent.setup()
    const loadSession = vi.fn()
    mockedUseContext.mockReturnValue(
      baseContext({
        sessions: [
          { id: 's1', name: 'First chat', created_at: 't', updated_at: 't', message_count: 4 },
          { id: 's2', name: 'Second chat', created_at: 't', updated_at: 't', message_count: 2 },
        ],
        loadSession,
      }),
    )
    render(<AssistantSessionBar />)

    await user.click(screen.getByRole('button', { name: /sessions/i }))
    expect(screen.getByText('First chat')).toBeInTheDocument()
    await user.click(screen.getByText('Second chat'))

    expect(loadSession).toHaveBeenCalledWith('s2')
  })

  it('shows an empty state with no saved sessions', async () => {
    const user = userEvent.setup()
    mockedUseContext.mockReturnValue(baseContext({ sessions: [] }))
    render(<AssistantSessionBar />)

    await user.click(screen.getByRole('button', { name: /sessions/i }))

    expect(screen.getByText(/no saved sessions yet/i)).toBeInTheDocument()
  })
})

describe('AssistantSessionBar — Open in Assistant (drawer only)', () => {
  it('is hidden when no handler is passed', () => {
    mockedUseContext.mockReturnValue(baseContext())
    render(<AssistantSessionBar />)

    expect(screen.queryByRole('button', { name: /open in assistant/i })).not.toBeInTheDocument()
  })

  it('is shown and emphasized when passed, and calls the handler', async () => {
    const user = userEvent.setup()
    const onOpen = vi.fn()
    mockedUseContext.mockReturnValue(baseContext())
    render(<AssistantSessionBar onOpenInAssistant={onOpen} />)

    const button = screen.getByRole('button', { name: /open in assistant/i })
    expect(button.className).toMatch(/bg-brand-\d+/)
    await user.click(button)

    expect(onOpen).toHaveBeenCalledTimes(1)
  })
})

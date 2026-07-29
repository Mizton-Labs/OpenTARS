/**
 * Tests for useAssistantSession (issue-local-032) — the hook wrapping
 * useSmartChat's live transcript with session persistence: auto-create on
 * the first completed turn, auto-save on every subsequent one, New Session,
 * Save-as-rename, load, and delete.
 */
import { renderHook, waitFor, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ReactNode } from 'react'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      search: {
        status: vi.fn().mockResolvedValue({ available: true, reason: null, provider: 'p1' }),
        query: vi.fn(),
        smart: vi.fn(),
        sessions: {
          list: vi.fn().mockResolvedValue([]),
          create: vi.fn(),
          get: vi.fn(),
          update: vi.fn(),
          delete: vi.fn(),
          downloadMarkdownUrl: vi.fn(),
          downloadPdfUrl: vi.fn(),
        },
      },
    },
  }
})

import { api } from '../api/client'
import { useAssistantSession } from '../hooks/useAssistantSession'

const mocked = api.search as unknown as {
  smart: ReturnType<typeof vi.fn>
  sessions: {
    list: ReturnType<typeof vi.fn>
    create: ReturnType<typeof vi.fn>
    get: ReturnType<typeof vi.fn>
    update: ReturnType<typeof vi.fn>
    delete: ReturnType<typeof vi.fn>
  }
}

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>
}

async function ask(result: { current: ReturnType<typeof useAssistantSession> }, question: string) {
  act(() => result.current.setQuestion(question))
  await act(async () => {
    await result.current.ask()
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  mocked.sessions.list.mockResolvedValue([])
})

describe('useAssistantSession — auto-create and auto-save', () => {
  it('creates a session (no explicit name) after the first completed turn', async () => {
    mocked.smart.mockResolvedValue({ answer: 'hi there', sources: [], used_context: 0 })
    mocked.sessions.create.mockResolvedValue({
      id: 's1',
      name: 'TARS-assistant-20260101-000000',
      messages: [],
      created_at: 't',
      updated_at: 't',
    })
    const { result } = renderHook(() => useAssistantSession(), { wrapper })

    await ask(result, 'hello?')

    await waitFor(() => expect(mocked.sessions.create).toHaveBeenCalledTimes(1))
    const [body] = mocked.sessions.create.mock.calls[0]
    expect(body.name).toBeUndefined()
    expect(body.messages).toEqual([
      { role: 'user', content: 'hello?' },
      { role: 'assistant', content: 'hi there', sources: [] },
    ])
    await waitFor(() => expect(result.current.currentSessionId).toBe('s1'))
  })

  it('updates the same session (not a new one) on the second turn', async () => {
    mocked.smart.mockResolvedValue({ answer: 'ok', sources: [], used_context: 0 })
    mocked.sessions.create.mockResolvedValue({
      id: 's1',
      name: 'default-name',
      messages: [],
      created_at: 't',
      updated_at: 't',
    })
    mocked.sessions.update.mockResolvedValue({
      id: 's1',
      name: 'default-name',
      messages: [],
      created_at: 't',
      updated_at: 't2',
    })
    const { result } = renderHook(() => useAssistantSession(), { wrapper })

    await ask(result, 'first')
    await waitFor(() => expect(mocked.sessions.create).toHaveBeenCalledTimes(1))

    await ask(result, 'second')
    await waitFor(() => expect(mocked.sessions.update).toHaveBeenCalledTimes(1))
    expect(mocked.sessions.create).toHaveBeenCalledTimes(1)
    expect(mocked.sessions.update.mock.calls[0][0]).toBe('s1')
  })

  it('does not persist while a turn is still in flight', async () => {
    let resolveSmart!: (v: { answer: string; sources: []; used_context: number }) => void
    mocked.smart.mockReturnValue(
      new Promise((resolve) => {
        resolveSmart = resolve
      }),
    )
    const { result } = renderHook(() => useAssistantSession(), { wrapper })

    act(() => result.current.setQuestion('slow question'))
    act(() => {
      void result.current.ask()
    })
    await waitFor(() => expect(result.current.thinking).toBe(true))
    expect(mocked.sessions.create).not.toHaveBeenCalled()

    await act(async () => {
      resolveSmart({ answer: 'done', sources: [], used_context: 0 })
      await Promise.resolve()
    })
    await waitFor(() => expect(mocked.sessions.create).toHaveBeenCalledTimes(1))
  })
})

describe('useAssistantSession — New Session', () => {
  it('clears the transcript and the current session id', async () => {
    mocked.smart.mockResolvedValue({ answer: 'hi', sources: [], used_context: 0 })
    mocked.sessions.create.mockResolvedValue({
      id: 's1',
      name: 'n',
      messages: [],
      created_at: 't',
      updated_at: 't',
    })
    const { result } = renderHook(() => useAssistantSession(), { wrapper })

    await ask(result, 'q1')
    await waitFor(() => expect(result.current.currentSessionId).toBe('s1'))

    act(() => result.current.newSession())

    expect(result.current.messages).toEqual([])
    expect(result.current.currentSessionId).toBeNull()
  })

  it('a message asked after New Session creates a DIFFERENT session', async () => {
    mocked.smart.mockResolvedValue({ answer: 'a', sources: [], used_context: 0 })
    mocked.sessions.create
      .mockResolvedValueOnce({ id: 's1', name: 'one', messages: [], created_at: 't', updated_at: 't' })
      .mockResolvedValueOnce({ id: 's2', name: 'two', messages: [], created_at: 't', updated_at: 't' })
    const { result } = renderHook(() => useAssistantSession(), { wrapper })

    await ask(result, 'q1')
    await waitFor(() => expect(result.current.currentSessionId).toBe('s1'))

    act(() => result.current.newSession())
    await ask(result, 'q2')

    await waitFor(() => expect(result.current.currentSessionId).toBe('s2'))
    expect(mocked.sessions.create).toHaveBeenCalledTimes(2)
  })
})

describe('useAssistantSession — save, load, delete', () => {
  it('saveSessionAs renames an existing session without creating a new one', async () => {
    mocked.smart.mockResolvedValue({ answer: 'a', sources: [], used_context: 0 })
    mocked.sessions.create.mockResolvedValue({
      id: 's1',
      name: 'default',
      messages: [],
      created_at: 't',
      updated_at: 't',
    })
    mocked.sessions.update.mockResolvedValue({
      id: 's1',
      name: 'My saved chat',
      messages: [],
      created_at: 't',
      updated_at: 't2',
    })
    const { result } = renderHook(() => useAssistantSession(), { wrapper })

    await ask(result, 'q1')
    await waitFor(() => expect(result.current.currentSessionId).toBe('s1'))

    await act(async () => {
      await result.current.saveSessionAs('My saved chat')
    })

    expect(mocked.sessions.create).toHaveBeenCalledTimes(1)
    expect(mocked.sessions.update).toHaveBeenCalledWith('s1', { name: 'My saved chat' })
    expect(result.current.currentSessionName).toBe('My saved chat')
  })

  it('loadSession replaces the live transcript with the saved one', async () => {
    mocked.sessions.get.mockResolvedValue({
      id: 'old-session',
      name: 'Old chat',
      messages: [
        { role: 'user', content: 'past question' },
        { role: 'assistant', content: 'past answer' },
      ],
      created_at: 't',
      updated_at: 't',
    })
    const { result } = renderHook(() => useAssistantSession(), { wrapper })

    await act(async () => {
      await result.current.loadSession('old-session')
    })

    expect(result.current.currentSessionId).toBe('old-session')
    expect(result.current.currentSessionName).toBe('Old chat')
    expect(result.current.messages).toEqual([
      { role: 'user', content: 'past question' },
      { role: 'assistant', content: 'past answer' },
    ])
  })

  it('deleting the CURRENT session also clears the live transcript', async () => {
    mocked.sessions.get.mockResolvedValue({
      id: 's1',
      name: 'n',
      messages: [{ role: 'user', content: 'x' }],
      created_at: 't',
      updated_at: 't',
    })
    mocked.sessions.delete.mockResolvedValue(undefined)
    const { result } = renderHook(() => useAssistantSession(), { wrapper })

    await act(async () => {
      await result.current.loadSession('s1')
    })
    await act(async () => {
      await result.current.deleteSession('s1')
    })

    expect(result.current.currentSessionId).toBeNull()
    expect(result.current.messages).toEqual([])
  })

  it('deleting a DIFFERENT session leaves the live transcript untouched', async () => {
    mocked.sessions.get.mockResolvedValue({
      id: 's1',
      name: 'n',
      messages: [{ role: 'user', content: 'x' }],
      created_at: 't',
      updated_at: 't',
    })
    mocked.sessions.delete.mockResolvedValue(undefined)
    const { result } = renderHook(() => useAssistantSession(), { wrapper })

    await act(async () => {
      await result.current.loadSession('s1')
    })
    await act(async () => {
      await result.current.deleteSession('some-other-session')
    })

    expect(result.current.currentSessionId).toBe('s1')
    expect(result.current.messages).toEqual([{ role: 'user', content: 'x' }])
  })
})

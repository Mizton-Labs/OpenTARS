/**
 * Tests for the Assistant page — the Smart Search chatbot as its own sidebar
 * section (issue-local-031 follow-up).
 *
 * The page is a thin shell around useSmartChat()/<SmartChatPanel>, the same
 * building blocks the drawer's Smart tab uses (see smartSearchDrawer.test.tsx
 * for the chat behaviour itself — history bounds, Markdown rendering, source
 * chips). These tests cover what is specific to the page: it renders without
 * a drawer to open first, and it explains itself when no LLM provider is
 * configured instead of just disabling a switch.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'

const navigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => navigate }
})

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      search: {
        query: vi.fn(),
        status: vi.fn(),
        smart: vi.fn(),
        // issue-local-032: AssistantSessionProvider lists/auto-saves sessions
        // alongside the chat itself.
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
import Assistant from '../pages/Assistant'
import { AssistantSessionProvider } from '../components/AssistantSessionProvider'

const mocked = api.search as unknown as {
  query: ReturnType<typeof vi.fn>
  status: ReturnType<typeof vi.fn>
  smart: ReturnType<typeof vi.fn>
  sessions: {
    list: ReturnType<typeof vi.fn>
    create: ReturnType<typeof vi.fn>
    get: ReturnType<typeof vi.fn>
    update: ReturnType<typeof vi.fn>
    delete: ReturnType<typeof vi.fn>
  }
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AssistantSessionProvider>
          <Assistant />
        </AssistantSessionProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('Assistant page', () => {
  it('renders the chat composer directly — no drawer to open first', async () => {
    mocked.status.mockResolvedValue({ available: true, reason: null, provider: 'p1' })
    renderPage()

    expect(await screen.findByLabelText('Ask Smart Search')).toBeInTheDocument()
  })

  it('shows a neutral loading state, not "unavailable", while status is still resolving', async () => {
    // A hard "unavailable" flash while the status query is merely still in
    // flight would be misleading — status is undefined during that window,
    // which is not the same thing as the server having actually said no.
    let resolveStatus!: (v: { available: boolean; reason: string | null; provider: string | null }) => void
    mocked.status.mockReturnValue(
      new Promise((resolve) => {
        resolveStatus = resolve
      }),
    )
    renderPage()

    expect(screen.queryByText(/unavailable/i)).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Ask Smart Search')).not.toBeInTheDocument()

    resolveStatus({ available: true, reason: null, provider: 'p1' })
    expect(await screen.findByLabelText('Ask Smart Search')).toBeInTheDocument()
  })

  it('explains why chat is unavailable when no LLM provider is configured', async () => {
    mocked.status.mockResolvedValue({
      available: false,
      reason:
        'No LLM provider is enabled. Enable one in Configuration → General → LLM Providers to turn on Smart Search.',
      provider: null,
    })
    renderPage()

    expect(await screen.findByText(/LLM Providers/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Ask Smart Search')).not.toBeInTheDocument()
  })

  it('sends a question and shows the answer with its sources', async () => {
    const user = userEvent.setup()
    mocked.status.mockResolvedValue({ available: true, reason: null, provider: 'p1' })
    mocked.smart.mockResolvedValue({
      answer: 'You have one hunt covering Lazarus.',
      sources: [
        {
          section: 'Threat Hunting',
          title: 'TH01 Lazarus sweep',
          route: '/threat-hunting/pkg-1',
          ref: 'pkg-1',
        },
      ],
      used_context: 1,
    })
    renderPage()

    await user.type(await screen.findByLabelText('Ask Smart Search'), 'any lazarus hunts?{Enter}')

    expect(await screen.findByText('You have one hunt covering Lazarus.')).toBeInTheDocument()
    expect(mocked.smart).toHaveBeenCalledWith('any lazarus hunts?', [])
    await user.click(screen.getByRole('button', { name: /Threat Hunting: TH01 Lazarus sweep/ }))
    expect(navigate).toHaveBeenCalledWith('/threat-hunting/pkg-1')
  })

  it('never issues a query-search request — this page is chat only', async () => {
    mocked.status.mockResolvedValue({ available: true, reason: null, provider: 'p1' })
    renderPage()

    await waitFor(() => expect(screen.getByLabelText('Ask Smart Search')).toBeInTheDocument())
    expect(mocked.query).not.toHaveBeenCalled()
  })
})

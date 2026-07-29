/**
 * Tests for AssistantSessionProvider's "new session on section change" rule
 * (issue-local-032): navigating to a DIFFERENT top-level section resets the
 * live transcript; navigating within the SAME section does not.
 */
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route, Link, Outlet } from 'react-router-dom'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      search: {
        status: vi.fn().mockResolvedValue({ available: true, reason: null, provider: 'p1' }),
        query: vi.fn(),
        smart: vi.fn().mockResolvedValue({ answer: 'answer', sources: [], used_context: 0 }),
        sessions: {
          list: vi.fn().mockResolvedValue([]),
          create: vi
            .fn()
            .mockResolvedValue({ id: 's1', name: 'n', messages: [], created_at: 't', updated_at: 't' }),
          get: vi.fn(),
          update: vi
            .fn()
            .mockResolvedValue({ id: 's1', name: 'n', messages: [], created_at: 't', updated_at: 't' }),
          delete: vi.fn(),
          downloadMarkdownUrl: vi.fn(),
          downloadPdfUrl: vi.fn(),
        },
      },
    },
  }
})

import { AssistantSessionProvider } from '../components/AssistantSessionProvider'
import { useAssistantSessionContext } from '../hooks/useAssistantSessionContext'

function Probe() {
  const { messages, question, setQuestion, ask } = useAssistantSessionContext()
  return (
    <div>
      <span data-testid="message-count">{messages.length}</span>
      <input aria-label="ask" value={question} onChange={(e) => setQuestion(e.target.value)} />
      <button onClick={() => void ask()}>ask</button>
    </div>
  )
}

function TestApp() {
  return (
    <Routes>
      <Route
        element={
          <AssistantSessionProvider>
            <nav>
              <Link to="/viewer">viewer</Link>
              <Link to="/threat-hunting/packages">packages</Link>
              <Link to="/threat-hunting">dashboard</Link>
              <Link to="/configuration">configuration</Link>
            </nav>
            <Probe />
            <Outlet />
          </AssistantSessionProvider>
        }
      >
        <Route path="/viewer" element={<div>Viewer page</div>} />
        <Route path="/threat-hunting" element={<div>TH dashboard</div>} />
        <Route path="/threat-hunting/packages" element={<div>TH packages</div>} />
        <Route path="/configuration" element={<div>Config page</div>} />
      </Route>
    </Routes>
  )
}

function renderApp(initialPath: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <TestApp />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => vi.clearAllMocks())

describe('AssistantSessionProvider — section-change reset', () => {
  it('does not reset on first mount', async () => {
    renderApp('/viewer')
    expect(screen.getByTestId('message-count')).toHaveTextContent('0')
  })

  it('resets the transcript when navigating to a DIFFERENT top-level section', async () => {
    const user = userEvent.setup()
    renderApp('/viewer')

    await user.type(screen.getByLabelText('ask'), 'question')
    await user.click(screen.getByRole('button', { name: 'ask' }))
    // Two messages (user + assistant) once the reply lands.
    await screen.findByText('2', { selector: '[data-testid="message-count"]' })

    await user.click(screen.getByRole('link', { name: 'configuration' }))

    expect(screen.getByTestId('message-count')).toHaveTextContent('0')
  })

  it('does NOT reset when navigating within the SAME top-level section', async () => {
    const user = userEvent.setup()
    renderApp('/threat-hunting/packages')

    await user.type(screen.getByLabelText('ask'), 'question')
    await user.click(screen.getByRole('button', { name: 'ask' }))
    await screen.findByText('2', { selector: '[data-testid="message-count"]' })

    // /threat-hunting/packages -> /threat-hunting share the top-level
    // segment "threat-hunting" — sub-navigation, not a section change.
    await user.click(screen.getByRole('link', { name: 'dashboard' }))

    expect(screen.getByText('TH dashboard')).toBeInTheDocument()
    expect(screen.getByTestId('message-count')).toHaveTextContent('2')
  })
})

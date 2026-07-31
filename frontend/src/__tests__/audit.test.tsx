/**
 * Tests for the Audit page — the "Audit" sidebar section (issue-local-033):
 * admin vs non-admin tab visibility, category switching, search debouncing,
 * pagination, and detail expansion.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { AuditEvent, AuditEventsResponse } from '../api/client'

let mockIsAdmin = true
vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isAdmin: mockIsAdmin,
    isResearcher: true,
    authEnabled: true,
    isAuthenticated: true,
    loading: false,
    user: { username: 'alice', role: mockIsAdmin ? 'admin' : 'threat-viewer' },
  }),
}))

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      audit: {
        ...actual.api.audit,
        listEvents: vi.fn(),
      },
    },
  }
})

import { api } from '../api/client'
import Audit from '../pages/Audit'

const mockListEvents = api.audit.listEvents as unknown as ReturnType<typeof vi.fn>

function emptyResponse(): AuditEventsResponse {
  return { events: [], total: 0 }
}

function renderAudit() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <Audit />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockIsAdmin = true
  mockListEvents.mockResolvedValue(emptyResponse())
})

describe('Audit — default tab', () => {
  it('defaults to the User tab and fetches its events', async () => {
    renderAudit()

    await waitFor(() => expect(mockListEvents).toHaveBeenCalledWith('user', expect.anything()))
  })

  it('shows an empty state with no events', async () => {
    renderAudit()

    expect(await screen.findByText(/no activity yet/i)).toBeInTheDocument()
  })
})

describe('Audit — admin tab visibility', () => {
  it('shows all four tabs to an admin', async () => {
    renderAudit()
    await screen.findByRole('button', { name: /^user$/i })

    expect(screen.getByRole('button', { name: /^application$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^user$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^agent$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^system$/i })).toBeInTheDocument()
  })

  it('hides only System from a non-admin — Application is their own everyday activity', async () => {
    mockIsAdmin = false
    renderAudit()
    await screen.findByRole('button', { name: /^user$/i })

    expect(screen.getByRole('button', { name: /^application$/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^system$/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^agent$/i })).toBeInTheDocument()
  })
})

describe('Audit — tab switching', () => {
  it('switches category and re-fetches on tab click', async () => {
    const user = userEvent.setup()
    renderAudit()
    await waitFor(() => expect(mockListEvents).toHaveBeenCalledWith('user', expect.anything()))

    await user.click(screen.getByRole('button', { name: /^agent$/i }))

    await waitFor(() => expect(mockListEvents).toHaveBeenLastCalledWith('agent', expect.anything()))
  })
})

describe('Audit — search', () => {
  it('debounces search input into the query', async () => {
    const user = userEvent.setup()
    renderAudit()
    await waitFor(() => expect(mockListEvents).toHaveBeenCalledWith('user', expect.anything()))

    await user.type(screen.getByLabelText('Search'), 'login')

    await waitFor(() =>
      expect(mockListEvents).toHaveBeenLastCalledWith('user', {
        search: 'login',
        limit: 25,
        offset: 0,
      }),
    )
  })
})

describe('Audit — rendering events', () => {
  function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
    return {
      id: 'evt-1',
      category: 'user',
      action: 'login.success',
      username: 'alice',
      role: 'admin',
      summary: "'alice' logged in",
      detail: { ip: '127.0.0.1' },
      created_at: '2026-01-01T00:00:00Z',
      ...overrides,
    }
  }

  it('renders an event row', async () => {
    mockListEvents.mockResolvedValue({ events: [makeEvent()], total: 1 })
    renderAudit()

    expect(await screen.findByText('login.success')).toBeInTheDocument()
    expect(screen.getAllByText(/alice/).length).toBeGreaterThan(0)
    expect(screen.getByText("'alice' logged in")).toBeInTheDocument()
  })

  it('expands and collapses the detail JSON', async () => {
    const user = userEvent.setup()
    mockListEvents.mockResolvedValue({ events: [makeEvent()], total: 1 })
    renderAudit()
    await screen.findByText('login.success')

    expect(screen.queryByText(/127.0.0.1/)).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /show details/i }))
    expect(screen.getByText(/127.0.0.1/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /hide details/i }))
    expect(screen.queryByText(/127.0.0.1/)).not.toBeInTheDocument()
  })

  it('renders a dash and no details toggle for an event without a username or detail', async () => {
    mockListEvents.mockResolvedValue({
      events: [makeEvent({ username: null, role: null, detail: null })],
      total: 1,
    })
    renderAudit()

    await screen.findByText('login.success')
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /show details/i })).not.toBeInTheDocument()
  })
})

describe('Audit — pagination', () => {
  it('requests the next page with the correct offset', async () => {
    const user = userEvent.setup()
    mockListEvents.mockResolvedValue({
      events: Array.from({ length: 25 }, (_, i) => ({
        id: `evt-${i}`,
        category: 'user' as const,
        action: 'a',
        username: 'alice',
        role: 'admin',
        summary: `event ${i}`,
        detail: null,
        created_at: '2026-01-01T00:00:00Z',
      })),
      total: 60,
    })
    renderAudit()
    await screen.findByText('event 0')

    await user.click(screen.getByRole('button', { name: /next page/i }))

    await waitFor(() =>
      expect(mockListEvents).toHaveBeenLastCalledWith('user', {
        search: undefined,
        limit: 25,
        offset: 25,
      }),
    )
  })
})

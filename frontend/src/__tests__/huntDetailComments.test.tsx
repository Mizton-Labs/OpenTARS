/**
 * Tests for issue-local-018's Comments tab in HuntDetail.tsx — per-run
 * free-text analyst notes (list, post, delete, role-gating).
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THuntPackage, THRunSummary, THRunComment } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      threatHunting: {
        ...actual.api.threatHunting,
        getPackage: vi.fn(),
        listEvidence: vi.fn(),
        listIocs: vi.fn(),
        listRuns: vi.fn(),
        getRunStatus: vi.fn(),
        listRunResults: vi.fn(),
        getRunReport: vi.fn(),
        listRunComments: vi.fn(),
        createRunComment: vi.fn(),
        deleteRunComment: vi.fn(),
      },
    },
  }
})

let mockIsResearcher = true
let mockIsAdmin = true
vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isResearcher: mockIsResearcher,
    isAdmin: mockIsAdmin,
    authEnabled: false,
    isAuthenticated: true,
    loading: false,
    user: null,
  }),
}))

import { api } from '../api/client'
import HuntDetail from '../pages/threat-hunting/HuntDetail'

function makePkg(overrides: Partial<THuntPackage> = {}): THuntPackage {
  return {
    id: 'pkg-1',
    name: 'Test Package',
    description: '',
    status: 'completed',
    created_by: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    evidence_count: 1,
    generation_status: 'completed',
    phases: [],
    total_elapsed_s: 1.2,
    run_created_at: '2026-01-01T00:00:00Z',
    runs: [],
    run_count: 1,
    ...overrides,
  }
}

function makeRun(overrides: Partial<THRunSummary> = {}): THRunSummary {
  return {
    id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'completed',
    llm_model: 'gpt-oss',
    research_effort: 'high',
    created_at: '2026-01-01T00:00:00Z',
    phases: [],
    ...overrides,
  } as THRunSummary
}

function makeComment(overrides: Partial<THRunComment> = {}): THRunComment {
  return {
    id: 'c1',
    hunt_package_id: 'pkg-1',
    run_id: 'run-1',
    body: 'Interesting lead here.',
    created_by: 'alice',
    created_at: '2026-01-02T10:00:00Z',
    ...overrides,
  }
}

function renderDetail() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <HuntDetail pkgId="pkg-1" onBack={() => {}} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockIsResearcher = true
  mockIsAdmin = true
  vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun()])
  vi.mocked(api.threatHunting.getRunStatus).mockRejectedValue(new Error('no status'))
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
  vi.mocked(api.threatHunting.createRunComment).mockResolvedValue(makeComment())
  vi.mocked(api.threatHunting.deleteRunComment).mockResolvedValue(undefined)
})

describe('HuntDetail Comments tab (issue-local-018)', () => {
  it('shows the Comments tab always, and switching to it lists existing comments', async () => {
    vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([makeComment()])
    renderDetail()

    fireEvent.click(await screen.findByRole('button', { name: /Comments/ }))

    expect(await screen.findByText('Interesting lead here.')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
  })

  it('shows an empty state when there are no comments', async () => {
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /Comments/ }))
    expect(await screen.findByText('No comments yet.')).toBeInTheDocument()
  })

  it('posts a new comment and clears the textarea', async () => {
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /Comments/ }))
    await screen.findByText('No comments yet.')

    const textarea = screen.getByPlaceholderText('Add a comment about this run…')
    fireEvent.change(textarea, { target: { value: 'A new note' } })
    fireEvent.click(screen.getByRole('button', { name: /Post/ }))

    await waitFor(() =>
      expect(api.threatHunting.createRunComment).toHaveBeenCalledWith('pkg-1', 'run-1', 'A new note'),
    )
  })

  it('deletes a comment when the delete icon is clicked', async () => {
    vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([makeComment()])
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /Comments/ }))
    await screen.findByText('Interesting lead here.')

    fireEvent.click(screen.getByTitle('Delete comment'))

    await waitFor(() =>
      expect(api.threatHunting.deleteRunComment).toHaveBeenCalledWith('pkg-1', 'run-1', 'c1'),
    )
  })

  it('hides the post form and delete icon for a non-researcher, non-admin viewer', async () => {
    mockIsResearcher = false
    mockIsAdmin = false
    vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([makeComment()])
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /Comments/ }))
    await screen.findByText('Interesting lead here.')

    expect(screen.queryByPlaceholderText('Add a comment about this run…')).not.toBeInTheDocument()
    expect(screen.queryByTitle('Delete comment')).not.toBeInTheDocument()
  })
})

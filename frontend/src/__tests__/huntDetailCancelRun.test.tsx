/**
 * Tests for issue-local-019's Cancel-run button in HuntDetail.tsx — only
 * shown while the active run is actually 'running', asks for confirmation,
 * and calls the cancel API on confirm.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THuntPackage, THuntPackageRun } from '../api/client'

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
        cancelRun: vi.fn(),
      },
    },
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isResearcher: true,
    isAdmin: true,
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
    status: 'draft',
    created_by: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    evidence_count: 1,
    generation_status: 'running',
    phases: [],
    total_elapsed_s: null,
    run_created_at: '2026-01-01T00:00:00Z',
    runs: [],
    run_count: 1,
    ...overrides,
  }
}

function makeRun(overrides: Partial<THuntPackageRun> = {}): THuntPackageRun {
  return {
    id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'running',
    llm_model: 'gpt-oss',
    research_effort: 'high',
    created_at: '2026-01-01T00:00:00Z',
    phases: [],
    ...overrides,
  } as THuntPackageRun
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
  vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunStatus).mockRejectedValue(new Error('no status'))
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
  vi.mocked(api.threatHunting.cancelRun).mockResolvedValue({ generation_status: 'cancelled' })
})

describe('HuntDetail Cancel run (issue-local-019)', () => {
  it('shows a Cancel button when the active run is running', async () => {
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun({ generation_status: 'running' })])
    renderDetail()
    expect(await screen.findByRole('button', { name: /Cancel/ })).toBeInTheDocument()
  })

  it('does not show a Cancel button once the run has completed', async () => {
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun({ generation_status: 'completed' })])
    renderDetail()
    await screen.findByText('Test Package')
    expect(screen.queryByRole('button', { name: /^Cancel$/ })).not.toBeInTheDocument()
  })

  it('asks for confirmation before cancelling', async () => {
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun({ generation_status: 'running' })])
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /^Cancel$/ }))

    expect(await screen.findByText(/Cancel this run\?/)).toBeInTheDocument()
    expect(api.threatHunting.cancelRun).not.toHaveBeenCalled()
  })

  it('calls cancelRun with the active run id on confirm', async () => {
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun({ id: 'run-42', generation_status: 'running' })])
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /^Cancel$/ }))
    await screen.findByText(/Cancel this run\?/)

    fireEvent.click(screen.getByRole('button', { name: 'Cancel run' }))

    await waitFor(() => expect(api.threatHunting.cancelRun).toHaveBeenCalledWith('pkg-1', 'run-42'))
  })
})

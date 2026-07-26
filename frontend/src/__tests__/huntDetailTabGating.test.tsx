/**
 * Regression test for issue-local-022 (item 5): HuntDetail.tsx's isFinished
 * gate must derive from the ACTIVE RUN's own generation_status, not the
 * package's. Root cause: start_generation() never touches pkg.status, so
 * re-running an already-'completed' package left pkg.status stuck on
 * 'completed' (stale, from the PRIOR run) for the entire duration of the
 * NEW run's pipeline — during which Execution/Threat-Intel/Report tabs
 * stayed wrongly enabled even though the active run was still mid-analysis.
 */
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClientProvider, QueryClient } from '@tanstack/react-query'
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
    // Stale from a PRIOR run — the whole point of this regression test.
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
    run_count: 2,
    ...overrides,
  }
}

function makeRun(overrides: Partial<THuntPackageRun> = {}): THuntPackageRun {
  return {
    id: 'run-2',
    hunt_package_id: 'pkg-1',
    generation_status: 'running',
    llm_model: 'gpt-oss',
    research_effort: 'high',
    created_at: '2026-01-02T00:00:00Z',
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
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunStatus).mockRejectedValue(new Error('no status'))
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
})

describe('HuntDetail tab gating uses the active run, not stale pkg.status (issue-local-022 item 5)', () => {
  it('keeps Execution/Threat-Intel/Report disabled while a NEW run is running on an already-completed package', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg({ status: 'completed' }))
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun({ generation_status: 'running' })])
    renderDetail()

    expect(await screen.findByRole('button', { name: /Execution/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /Threat Intelligence/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /^Report$/ })).toBeDisabled()
  })

  it('enables Execution/Threat-Intel/Report once the active run itself reaches approved', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg({ status: 'planning' }))
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun({ generation_status: 'approved' })])
    renderDetail()

    // Initial render happens before the runs query resolves and activeRunId
    // is set, so the tabs start out disabled — wait for the eventual
    // re-render once the active run's status is known.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Execution/ })).not.toBeDisabled()
    })
    expect(screen.getByRole('button', { name: /Threat Intelligence/ })).not.toBeDisabled()
    expect(screen.getByRole('button', { name: /^Report$/ })).not.toBeDisabled()
  })
})

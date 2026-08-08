/**
 * Regression test for issue-local-041: "When the new analysis starts,
 * center the view from where the row with phases starts." HuntDetail
 * renders a tall header + run selector + all-runs table above the tab
 * panels, so a newly-started run's phase progress (the run-selector block,
 * which contains PipelineStepper) could be scrolled off-screen with no way
 * to bring it back into view automatically.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClientProvider, QueryClient } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THuntPackage, THuntPackageRun } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getThResearchEffort: vi.fn(),
      llm: { ...actual.api.llm, listProviders: vi.fn() },
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
        startGeneration: vi.fn(),
        playbooks: { ...actual.api.threatHunting.playbooks, list: vi.fn() },
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

function makeRun(overrides: Partial<THuntPackageRun> = {}): THuntPackageRun {
  return {
    id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'completed',
    llm_model: 'gpt-oss',
    research_effort: 'high',
    created_at: '2026-01-02T00:00:00Z',
    phases: [],
    run_origin: 'manual',
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
  window.HTMLElement.prototype.scrollIntoView = vi.fn()
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunStatus).mockRejectedValue(new Error('no status'))
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
  vi.mocked(api.llm.listProviders).mockResolvedValue([])
  vi.mocked(api.threatHunting.playbooks.list).mockResolvedValue([])
  vi.mocked(api.getThResearchEffort).mockResolvedValue({ th_research_effort: 'high' })
})

describe('HuntDetail scrolls the phases row into view on a new run (issue-local-041)', () => {
  it('scrolls the run-selector/PipelineStepper block into view after starting a re-run', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun()])
    vi.mocked(api.threatHunting.startGeneration).mockResolvedValue({
      id: 'run-2',
      run_id: 'run-2',
      hunt_package_id: 'pkg-1',
      generation_status: 'running',
    } as never)
    renderDetail()

    fireEvent.click(await screen.findByRole('button', { name: /^Re-run$/ }))
    await screen.findByText(/effort: high/)
    fireEvent.click(screen.getByRole('button', { name: /^Start Re-run$/ }))

    await waitFor(() => {
      expect(window.HTMLElement.prototype.scrollIntoView).toHaveBeenCalledWith(
        expect.objectContaining({ block: 'center' }),
      )
    })
  })
})

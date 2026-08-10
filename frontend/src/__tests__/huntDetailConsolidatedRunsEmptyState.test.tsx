/**
 * Regression test for issue-local-041 (Hunt Package UI fix #3): switching to
 * the "Consolidated Runs" (or "Playbook Runs") sub-tab in RunsStatusTable
 * used to only filter the table's own rows — the panels below (Analysis,
 * Report, etc.) kept showing whichever run was already active, so an empty
 * "Consolidated Runs" sub-tab still displayed the main run's content instead
 * of a real empty state. HuntDetail now lifts the sub-tab state so switching
 * it also drives activeRunId, and renders an explicit empty-state card when
 * the selected sub-tab has zero matching runs.
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
      threatHunting: {
        ...actual.api.threatHunting,
        getPackage: vi.fn(),
        listEvidence: vi.fn(),
        listIocs: vi.fn(),
        listRuns: vi.fn(),
        getRunStatus: vi.fn(),
        getGenerationStatus: vi.fn(),
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
    id: 'run-manual',
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
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
    id: 'run-manual',
    hunt_package_id: 'pkg-1',
    generation_status: 'completed',
  } as never)
  vi.mocked(api.threatHunting.getGenerationStatus).mockResolvedValue({
    id: 'run-manual',
    hunt_package_id: 'pkg-1',
    generation_status: 'completed',
  } as never)
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
})

describe('HuntDetail Consolidated Runs empty state (issue-local-041)', () => {
  it('shows a real empty state instead of the main run content when Consolidated Runs has zero runs', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun({ run_origin: 'manual' })])
    renderDetail()

    // Wait for the manual run's content to be showing first (sanity check).
    await screen.findByRole('button', { name: /^Analysis$/ })

    fireEvent.click(await screen.findByRole('button', { name: /Consolidated Runs \(0\)/ }))

    // Both the table's own per-subtab empty row AND the new empty-state
    // banner below (replacing the ArrowTabs/AnalysisTab/ReportPanel content)
    // read "No consolidated runs yet." — assert both are present.
    await waitFor(() => {
      expect(screen.getAllByText('No consolidated runs yet.').length).toBe(2)
    })
    // The main run's Analysis/Report tab chrome must not still be rendered.
    expect(screen.queryByRole('button', { name: /^Analysis$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Report$/ })).not.toBeInTheDocument()
  })

  it('jumps activeRunId to the matching run when switching to a non-empty sub-tab', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg({ run_count: 2 }))
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([
      makeRun({ id: 'run-consolidated', run_origin: 'consolidated', created_at: '2026-01-03T00:00:00Z' }),
      makeRun({ id: 'run-manual', run_origin: 'manual', created_at: '2026-01-02T00:00:00Z' }),
    ])
    renderDetail()

    fireEvent.click(await screen.findByRole('button', { name: /Consolidated Runs \(1\)/ }))

    await waitFor(() => {
      expect(api.threatHunting.getRunStatus).toHaveBeenCalledWith('pkg-1', 'run-consolidated')
    })
  })
})

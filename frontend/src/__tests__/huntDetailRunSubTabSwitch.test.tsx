/**
 * Tests for issue-local-042 (item 21): starting a new run (manual re-run or
 * firing a Playbook) should switch the hunt package view to the matching
 * Runs/Playbook Runs/Consolidated Runs sub-tab automatically. Previously
 * the sub-tab stayed wherever it was — firing a playbook while looking at
 * "Runs" left the view showing nothing new, with no indication a playbook
 * was actually running.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClientProvider, QueryClient } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THuntPackage, THuntPackageRun, THPlaybook } from '../api/client'

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
        playbooks: { ...actual.api.threatHunting.playbooks, list: vi.fn(), run: vi.fn() },
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

function makePlaybook(overrides: Partial<THPlaybook> = {}): THPlaybook {
  return {
    id: 'pb-1',
    name: 'My Playbook',
    models: [{ provider_name: 'openai', model_name: 'gpt-oss' }],
    auto_approve_analysis: false,
    auto_run_comparison: false,
    auto_compare_preliminary: false,
    auto_compare_full: false,
    auto_create_run_from_recommendations: false,
    auto_generate_full_report: false,
    ioc_cleaning_enabled: false,
    created_at: '2026-01-01T00:00:00Z',
    created_by: null,
    updated_at: '2026-01-01T00:00:00Z',
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

function activeSubTabButton(name: RegExp) {
  return screen.getByRole('button', { name })
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

describe('HuntDetail — run sub-tab auto-switch (issue-local-042 item 21)', () => {
  it('switches to the Playbook Runs sub-tab when the re-run dialog fires a playbook', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([
      makeRun({ id: 'run-1', run_origin: 'manual' }),
    ])
    vi.mocked(api.threatHunting.playbooks.list).mockResolvedValue([makePlaybook()])
    vi.mocked(api.threatHunting.playbooks.run).mockResolvedValue({
      id: 'job-1',
      hunt_package_id: 'pkg-1',
      playbook_id: 'pb-1',
      playbook_name: 'My Playbook',
      status: 'running',
      current_step: 'firing_runs',
      run_ids: [],
    } as never)

    renderDetail()

    // Starts on the "Runs" sub-tab (the default). The sub-tab nav only
    // mounts once the package + runs queries resolve, so this must poll
    // rather than assume the first render already has it.
    await waitFor(() => expect(activeSubTabButton(/^Runs \(1\)/)).toHaveClass('bg-brand-900/30'))

    fireEvent.click(await screen.findByRole('button', { name: /^Re-run$/ }))
    await screen.findByText(/effort: high/)
    // The playbook <option> only exists once playbooks.list() resolves —
    // changing the select before that silently leaves it at "", so the
    // dialog fires a standalone run instead of the playbook.
    await screen.findByText('My Playbook (1 model)')
    const select = screen.getByDisplayValue('Configured default')
    fireEvent.change(select, { target: { value: 'playbook:pb-1' } })
    fireEvent.click(screen.getByRole('button', { name: /^Start Re-run$/ }))

    await waitFor(() => expect(api.threatHunting.playbooks.run).toHaveBeenCalledWith('pkg-1', 'pb-1'))
    await waitFor(() =>
      expect(activeSubTabButton(/^Playbook Runs \(0\)/)).toHaveClass('bg-brand-900/30'),
    )
  })

  it('switches to the Runs sub-tab when a manual run is started (even if Playbook Runs was selected)', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([
      makeRun({ id: 'run-playbook', run_origin: 'playbook' }),
      makeRun({ id: 'run-1', run_origin: 'manual' }),
    ])
    vi.mocked(api.threatHunting.startGeneration).mockResolvedValue({
      id: 'run-2',
      run_id: 'run-2',
      hunt_package_id: 'pkg-1',
      generation_status: 'running',
    } as never)

    renderDetail()

    // Same as above: wait for the sub-tab nav to actually mount before
    // clicking it, instead of assuming it's there on the first render.
    const playbookTabBtn = await waitFor(() => activeSubTabButton(/^Playbook Runs \(1\)/))
    fireEvent.click(playbookTabBtn)
    expect(activeSubTabButton(/^Playbook Runs \(1\)/)).toHaveClass('bg-brand-900/30')

    fireEvent.click(await screen.findByRole('button', { name: /^Re-run$/ }))
    await screen.findByText(/effort: high/)
    fireEvent.click(screen.getByRole('button', { name: /^Start Re-run$/ }))

    await waitFor(() => expect(api.threatHunting.startGeneration).toHaveBeenCalled())
    await waitFor(() => expect(activeSubTabButton(/^Runs \(1\)/)).toHaveClass('bg-brand-900/30'))
  })
})

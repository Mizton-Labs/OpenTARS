/**
 * Tests for issue-local-017's RunsStatusTable — the compact all-runs
 * overview (model, status, coarse workflow phases, IOC sanitized/removed
 * counts, report download links) shown below the run selector dropdown in
 * HuntDetail.tsx, and reused for the hunt-package list's Table density mode.
 */
import type { ReactElement } from 'react'
import { render as rtlRender, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      threatHunting: {
        ...actual.api.threatHunting,
        getRunReport: vi.fn(),
        setRunArchived: vi.fn(),
        hardDeleteRun: vi.fn(),
      },
      llm: {
        ...actual.api.llm,
        // issue-local-026: RunsStatusTable now resolves "Configured default"
        // via GET /llm/config — no default provider by default, so existing
        // tests keep seeing the same '—'/plain fallback behavior unless a
        // test opts in by mocking a specific resolved value.
        getConfig: vi.fn().mockResolvedValue({ enabled: false, default_provider: null, providers: [] }),
      },
    },
  }
})

import { api } from '../api/client'
import RunsStatusTable from '../pages/threat-hunting/RunsStatusTable'
import type { THuntPackageRun, THHuntReport } from '../api/client'

// issue-local-026: RunsStatusTable now fetches LLM config via react-query
// (to resolve "Configured default" to a real model name) — every render
// needs a QueryClientProvider ancestor. Shadowing `render` here keeps every
// existing call site in this file unchanged.
function render(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return rtlRender(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>)
}

function makeRun(overrides: Partial<THuntPackageRun> = {}): THuntPackageRun {
  return {
    id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'completed',
    llm_model: 'gpt-oss',
    research_effort: 'high',
    created_at: '2026-01-01T00:00:00Z',
    phases: [],
    total_elapsed_s: null,
    sanitized_ioc_count: null,
    removed_ioc_count: null,
    has_report: false,
    ...overrides,
  }
}

beforeEach(() => {
  vi.mocked(api.threatHunting.getRunReport).mockReset()
  vi.mocked(api.threatHunting.setRunArchived).mockReset().mockResolvedValue({ run_id: 'run-1', archived: true })
  vi.mocked(api.threatHunting.hardDeleteRun).mockReset().mockResolvedValue(undefined)
})

describe('RunsStatusTable', () => {
  it('renders nothing for an empty runs list', () => {
    const { container } = render(<RunsStatusTable pkgId="pkg-1" runs={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the model (and effort) as the first column', () => {
    render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ llm_model: 'Mistral-Large-3', research_effort: 'high' })]} />)
    expect(screen.getByText('Mistral-Large-3')).toBeInTheDocument()
    expect(screen.getByText('· high')).toBeInTheDocument()
  })

  it('falls back to the provider when llm_model is absent', () => {
    render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ llm_model: null, llm_provider: 'alt-provider' })]} />)
    expect(screen.getByText('alt-provider')).toBeInTheDocument()
  })

  it('shows the run status', () => {
    render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ generation_status: 'error' })]} />)
    expect(screen.getByText('error')).toBeInTheDocument()
  })

  it('marks a completed run\'s workflow phases as done', () => {
    render(
      <RunsStatusTable
        pkgId="pkg-1"
        runs={[
          makeRun({
            generation_status: 'completed',
            phases: [
              { step: 'intake_classifier', status: 'ok', elapsed_s: 1 },
              { step: 'report_render', status: 'ok', elapsed_s: 1 },
            ],
          }),
        ]}
      />,
    )
    // All 5 coarse phase labels render as chips inside the workflow track
    // (scoped to tbody to avoid matching the "Report" column header).
    const body = within(screen.getByRole('table').querySelector('tbody')!)
    for (const label of ['Evidence', 'IOC', 'Analysis', 'Execution', 'Report']) {
      expect(body.getByText(label)).toBeInTheDocument()
    }
  })

  it('flags a failed step\'s coarse phase as an error', () => {
    render(
      <RunsStatusTable
        pkgId="pkg-1"
        runs={[
          makeRun({
            generation_status: 'error',
            phases: [{ step: 'intake_classifier', status: 'error', elapsed_s: 1 }],
          }),
        ]}
      />,
    )
    const iocPhase = screen.getByText('IOC').closest('div')
    expect(iocPhase).toHaveClass('text-red-400')
  })

  // issue-local-041: every cell wraps its content EXCEPT the Workflow/phases
  // column, which must stay a single line "so the progress is seen clearly
  // from left to right" — previously exactly inverted (the phase track
  // wrapped, everything else forced a fixed-width horizontal scroll).
  it('keeps the Workflow phase track single-line while other cells wrap (issue-local-041)', () => {
    render(
      <RunsStatusTable
        pkgId="pkg-1"
        runs={[makeRun({ llm_model: 'a-very-long-model-name-that-should-wrap-in-its-cell' })]}
      />,
    )
    const table = screen.getByRole('table')
    expect(table).not.toHaveClass('min-w-[900px]')

    const modelCell = screen.getByText('a-very-long-model-name-that-should-wrap-in-its-cell').closest('td')!
    expect(modelCell).not.toHaveClass('whitespace-nowrap')

    const phaseTrack = within(screen.getByRole('table').querySelector('tbody')!).getByText('Evidence').closest('div.flex-nowrap')!
    expect(phaseTrack).toHaveClass('flex-nowrap')
    expect(phaseTrack.closest('td')).toHaveClass('whitespace-nowrap')
  })

  // issue-local-041: per-run token total (alongside Duration) + a
  // package-wide total footer summed across every run.
  it('shows the per-run token total and a package-wide total footer', () => {
    render(
      <RunsStatusTable
        pkgId="pkg-1"
        runs={[
          makeRun({ id: 'run-1', token_usage_total: { total_tokens: 100 } }),
          makeRun({ id: 'run-2', token_usage_total: { total_tokens: 250 } }),
        ]}
      />,
    )
    expect(screen.getByText('100 tok')).toBeInTheDocument()
    expect(screen.getByText('250 tok')).toBeInTheDocument()
    expect(screen.getByText(/Hunt package total: 350 tokens across 2 runs/)).toBeInTheDocument()
  })

  it('omits the package total footer when no run reported token usage', () => {
    render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun()]} />)
    expect(screen.queryByText(/Hunt package total:/)).not.toBeInTheDocument()
  })

  it('renders one row per run', () => {
    render(
      <RunsStatusTable
        pkgId="pkg-1"
        runs={[makeRun({ id: 'run-1', llm_model: 'model-a' }), makeRun({ id: 'run-2', llm_model: 'model-b' })]}
      />,
    )
    expect(screen.getByText('model-a')).toBeInTheDocument()
    expect(screen.getByText('model-b')).toBeInTheDocument()
  })

  describe('IOC sanitized/removed counts', () => {
    it('shows a dash when the run has no deep_retrohunt lead yet', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ sanitized_ioc_count: null, removed_ioc_count: null })]} />)
      // Run ID, Duration, IOCs, Report, and Created by all render a "—"
      // placeholder for this bare fixture (no run_id_display/total_elapsed_s/
      // deep_retrohunt lead/report/created_by) — assert all five are present.
      expect(screen.getAllByText('—')).toHaveLength(5)
    })

    it('shows sanitized and removed counts when available', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ sanitized_ioc_count: 12, removed_ioc_count: 3 })]} />)
      expect(screen.getByText('12 sanitized')).toBeInTheDocument()
      expect(screen.getByText('3 removed')).toBeInTheDocument()
    })

    it('shows an explicit total alongside sanitized and removed (issue-local-026)', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ sanitized_ioc_count: 12, removed_ioc_count: 3 })]} />)
      expect(screen.getByText(/15 total/)).toBeInTheDocument()
    })
  })

  describe('Created by column (issue-local-026)', () => {
    it('shows the username that triggered the run', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ created_by: 'alice' })]} />)
      expect(screen.getByText('alice')).toBeInTheDocument()
    })

    it('shows a dash when created_by is null', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ created_by: null })]} />)
      expect(screen.getAllByText('—').length).toBeGreaterThan(0)
    })
  })

  describe('Default model resolution (issue-local-026)', () => {
    it('resolves "Configured default" to the actual default provider/model', async () => {
      vi.mocked(api.llm.getConfig).mockResolvedValueOnce({
        enabled: true,
        default_provider: 'test-default-provider',
        providers: [{ name: 'test-default-provider', kind: 'anthropic', model: 'claude-sonnet-5' }],
      })
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ llm_model: null, llm_provider: null })]} />)
      await waitFor(() => {
        expect(screen.getByText('Default (claude-sonnet-5)')).toBeInTheDocument()
      })
    })

    it('falls back to a plain dash when there is no default provider configured', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ llm_model: null, llm_provider: null })]} />)
      expect(screen.getAllByText('—').length).toBeGreaterThan(0)
    })
  })

  describe('Report download links', () => {
    it('shows a dash when the run has no report', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ has_report: false })]} />)
      expect(screen.queryByTitle('Download report as Markdown')).not.toBeInTheDocument()
    })

    it('shows MD/PDF/JSON links when the run has a report', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ id: 'run-1', has_report: true })]} />)
      const md = screen.getByTitle('Download report as Markdown')
      const pdf = screen.getByTitle('Download report as PDF')
      expect(md).toHaveAttribute('href', expect.stringContaining('/packages/pkg-1/runs/run-1/report/markdown'))
      expect(pdf).toHaveAttribute('href', expect.stringContaining('/packages/pkg-1/runs/run-1/report/pdf'))
      expect(screen.getByTitle('Download report as JSON')).toBeInTheDocument()
    })

    it('clicking the JSON link fetches the report and triggers a download', async () => {
      vi.mocked(api.threatHunting.getRunReport).mockResolvedValue({
        id: 'r1',
        hunt_package_id: 'pkg-1',
        run_id: 'run-1',
        executive_summary: '',
        created_at: '2026-01-01T00:00:00Z',
        created_by: null,
        full_report: { hunt_name: 'x' } as THHuntReport['full_report'],
      })
      const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ id: 'run-1', has_report: true })]} />)

      fireEvent.click(screen.getByTitle('Download report as JSON'))

      await waitFor(() => expect(api.threatHunting.getRunReport).toHaveBeenCalledWith('pkg-1', 'run-1'))
      await waitFor(() => expect(clickSpy).toHaveBeenCalled())
      clickSpy.mockRestore()
    })
  })

  describe('Run ID column (issue-local-018)', () => {
    it('shows the run_id_display value', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ run_id_display: 'TH01-X02' })]} />)
      expect(screen.getByText('TH01-X02')).toBeInTheDocument()
    })
  })

  describe('Duration column (issue-local-018)', () => {
    it('formats seconds under a minute as "Xs"', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ total_elapsed_s: 48 })]} />)
      expect(screen.getByText('48s')).toBeInTheDocument()
    })

    it('formats seconds a minute or over as "Xm Ys"', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ total_elapsed_s: 332 })]} />)
      expect(screen.getByText('5m 32s')).toBeInTheDocument()
    })

    it('shows a dash when total_elapsed_s is null', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ total_elapsed_s: null })]} />)
      expect(screen.getAllByText('—').length).toBeGreaterThan(0)
    })
  })

  describe('onSelectRun (issue-local-018)', () => {
    it('renders Run ID and Model as plain text when onSelectRun is absent', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ run_id_display: 'TH01-X01', llm_model: 'gpt-oss' })]} />)
      expect(screen.queryByRole('button', { name: 'TH01-X01' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'gpt-oss' })).not.toBeInTheDocument()
      expect(screen.getByText('TH01-X01')).toBeInTheDocument()
      expect(screen.getByText('gpt-oss')).toBeInTheDocument()
    })

    it('renders Run ID and Model as clickable buttons when onSelectRun is provided, and calls it with the run id', () => {
      const onSelectRun = vi.fn()
      render(
        <RunsStatusTable
          pkgId="pkg-1"
          runs={[makeRun({ id: 'run-42', run_id_display: 'TH01-X01', llm_model: 'gpt-oss' })]}
          onSelectRun={onSelectRun}
        />,
      )
      fireEvent.click(screen.getByRole('button', { name: 'TH01-X01' }))
      expect(onSelectRun).toHaveBeenCalledWith('run-42')

      fireEvent.click(screen.getByRole('button', { name: 'gpt-oss' }))
      expect(onSelectRun).toHaveBeenCalledWith('run-42')
      expect(onSelectRun).toHaveBeenCalledTimes(2)
    })
  })

  describe('Archive/Delete actions (issue-local-034)', () => {
    it('shows no Actions column when neither isResearcher nor isAdmin', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun()]} />)
      expect(screen.queryByText('Actions')).not.toBeInTheDocument()
      expect(screen.queryByTitle('Archive run')).not.toBeInTheDocument()
      expect(screen.queryByTitle('Permanently delete run')).not.toBeInTheDocument()
    })

    it('shows only Archive (not Delete) for a researcher', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun()]} isResearcher />)
      expect(screen.getByTitle('Archive run')).toBeInTheDocument()
      expect(screen.queryByTitle('Permanently delete run')).not.toBeInTheDocument()
    })

    it('shows only Delete (not Archive) for an admin who is not a researcher', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun()]} isAdmin />)
      expect(screen.queryByTitle('Archive run')).not.toBeInTheDocument()
      expect(screen.getByTitle('Permanently delete run')).toBeInTheDocument()
    })

    it('clicking Archive calls setRunArchived with the toggled value', async () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ id: 'run-9', archived: false })]} isResearcher />)
      fireEvent.click(screen.getByTitle('Archive run'))
      await waitFor(() =>
        expect(api.threatHunting.setRunArchived).toHaveBeenCalledWith('pkg-1', 'run-9', true),
      )
    })

    it('shows "Unarchive run" and an Archived badge when the run is already archived', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ archived: true })]} isResearcher />)
      expect(screen.getByTitle('Unarchive run')).toBeInTheDocument()
      expect(screen.getByText('Archived')).toBeInTheDocument()
    })

    it('Delete requires confirmation before calling hardDeleteRun', async () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ id: 'run-9' })]} isAdmin />)
      fireEvent.click(screen.getByTitle('Permanently delete run'))
      expect(api.threatHunting.hardDeleteRun).not.toHaveBeenCalled()

      fireEvent.click(screen.getByRole('button', { name: 'Delete Permanently' }))
      await waitFor(() =>
        expect(api.threatHunting.hardDeleteRun).toHaveBeenCalledWith('pkg-1', 'run-9'),
      )
    })

    it('cancelling the delete confirmation never calls hardDeleteRun', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun()]} isAdmin />)
      fireEvent.click(screen.getByTitle('Permanently delete run'))
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(api.threatHunting.hardDeleteRun).not.toHaveBeenCalled()
    })
  })

  describe('Runs/Playbook Runs/Consolidated Runs sub-tabs (issue-local-040)', () => {
    const mixedRuns = [
      makeRun({ id: 'run-manual', llm_model: 'manual-model', run_origin: 'manual' }),
      makeRun({
        id: 'run-playbook',
        llm_model: 'pb-model',
        run_origin: 'playbook',
        playbook_id: 'pb-1',
        playbook_name: 'My Playbook',
      }),
      makeRun({
        id: 'run-consolidated',
        llm_model: 'consolidated-model',
        run_origin: 'consolidated',
        playbook_id: 'pb-1',
        playbook_name: 'My Playbook',
      }),
    ]

    it('defaults to the Runs sub-tab, showing only manual/undefined-origin runs', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={mixedRuns} />)
      expect(screen.getByText('manual-model')).toBeInTheDocument()
      expect(screen.queryByText('pb-model')).not.toBeInTheDocument()
      expect(screen.queryByText('consolidated-model')).not.toBeInTheDocument()
    })

    it('a run with no run_origin at all (legacy row) counts as a manual run', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ llm_model: 'legacy-model', run_origin: undefined })]} />)
      expect(screen.getByText('legacy-model')).toBeInTheDocument()
    })

    it('shows the per-tab counts', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={mixedRuns} />)
      expect(screen.getByRole('button', { name: /^Runs \(1\)$/ })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /^Playbook Runs \(1\)$/ })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /^Consolidated Runs \(1\)$/ })).toBeInTheDocument()
    })

    it('switching to Playbook Runs shows only playbook-origin runs, with the playbook name badge', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={mixedRuns} />)
      fireEvent.click(screen.getByRole('button', { name: /Playbook Runs/ }))
      expect(screen.getByText('pb-model')).toBeInTheDocument()
      expect(screen.queryByText('manual-model')).not.toBeInTheDocument()
      expect(screen.queryByText('consolidated-model')).not.toBeInTheDocument()
      expect(screen.getByText(/playbook · My Playbook/)).toBeInTheDocument()
    })

    it('switching to Consolidated Runs shows only consolidated-origin runs, labeled "consolidated"', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={mixedRuns} />)
      fireEvent.click(screen.getByRole('button', { name: /Consolidated Runs/ }))
      expect(screen.getByText('consolidated-model')).toBeInTheDocument()
      expect(screen.queryByText('manual-model')).not.toBeInTheDocument()
      expect(screen.queryByText('pb-model')).not.toBeInTheDocument()
      expect(screen.getByText(/consolidated · My Playbook/)).toBeInTheDocument()
    })

    it('shows an empty-subtab message rather than an empty table when a tab has no runs', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ run_origin: 'manual' })]} />)
      fireEvent.click(screen.getByRole('button', { name: /Playbook Runs/ }))
      expect(screen.getByText(/no playbook runs yet/i)).toBeInTheDocument()
      expect(screen.queryByRole('table')).not.toBeInTheDocument()
    })
  })
})

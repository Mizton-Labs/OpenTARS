/**
 * Tests for issue-local-017's RunsStatusTable — the compact all-runs
 * overview (model, status, coarse workflow phases, IOC sanitized/removed
 * counts, report download links) shown below the run selector dropdown in
 * HuntDetail.tsx, and reused for the hunt-package list's Table density mode.
 */
import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
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
      },
    },
  }
})

import { api } from '../api/client'
import RunsStatusTable from '../pages/threat-hunting/RunsStatusTable'
import type { THuntPackageRun, THHuntReport } from '../api/client'

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
      // Both the IOCs and Report columns render a "—" placeholder for this
      // run (no deep_retrohunt lead, no report) — assert both are present.
      expect(screen.getAllByText('—')).toHaveLength(2)
    })

    it('shows sanitized and removed counts when available', () => {
      render(<RunsStatusTable pkgId="pkg-1" runs={[makeRun({ sanitized_ioc_count: 12, removed_ioc_count: 3 })]} />)
      expect(screen.getByText('12 sanitized')).toBeInTheDocument()
      expect(screen.getByText('3 removed')).toBeInTheDocument()
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
})

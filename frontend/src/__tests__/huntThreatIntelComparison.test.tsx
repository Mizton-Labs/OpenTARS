/**
 * Tests for issue-local-020 Part F: the "Threat Intelligence" tab, the
 * "Comparison Assessment" tab, and the "Assess & Compare" button in
 * HuntDetail.tsx.
 */
import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type {
  THuntPackage,
  THRunSummary,
  THuntPackageRun,
  THThreatIntel,
  THComparisonReport,
} from '../api/client'

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
        getRunThreatIntel: vi.fn(),
        getThreatIntel: vi.fn(),
        triggerRunThreatIntel: vi.fn(),
        compareRuns: vi.fn(),
        getComparison: vi.fn(),
        downloadComparisonMarkdown: vi.fn(() => 'http://x/comparison/markdown'),
        downloadComparisonPdf: vi.fn(() => 'http://x/comparison/pdf'),
        consolidateComparison: vi.fn(),
        downloadConsolidatedMarkdown: vi.fn(() => 'http://x/consolidated/markdown'),
        downloadConsolidatedPdf: vi.fn(() => 'http://x/consolidated/pdf'),
        rerunFromRecommendation: vi.fn(),
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

function makeRun(overrides: Partial<THuntPackageRun> = {}): THRunSummary {
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

function makeThreatIntel(overrides: Partial<THThreatIntel> = {}): THThreatIntel {
  return {
    id: 'ti-1',
    hunt_package_id: 'pkg-1',
    run_id: 'run-1',
    threat_actors: [{ name: 'FIN7', confidence: 'high', rationale: 'matches TTPs' }],
    attribution: { assessment: 'FIN7', confidence: 'high', rationale: 'x' },
    malware_families: ['Carbanak'],
    campaigns: [{ name: 'RetailHeist', description: 'desc' }],
    related_vendors: [],
    correlated_iocs: [
      { ioc: 'evil.example', ioc_type: 'domain', hunt_package_id: 'pkg-2', hunt_name: 'Other Hunt' },
    ],
    summary: 'FIN7 activity correlated across hunts.',
    full_analysis: {},
    created_at: '2026-01-02T00:00:00Z',
    created_by: null,
    ...overrides,
  }
}

function makeComparison(overrides: Partial<THComparisonReport> = {}): THComparisonReport {
  return {
    id: 'cmp-1',
    hunt_package_id: 'pkg-1',
    run_id: null,
    executive_summary: 'Runs agree on the threat actor.',
    full_report: {
      hunt_name: 'Test Package',
      hunt_id: 'pkg-1',
      hunt_id_display: 'TH01',
      compared_run_ids: ['run-1', 'run-2'],
      generated_at: '2026-01-03T00:00:00Z',
      diff_table: [
        {
          run_id: 'run-1',
          run_id_display: 'TH01-X01',
          model: 'gpt-oss',
          effort: 'high',
          status: 'completed',
          hypothesis_count: 3,
          sanitized_ioc_count: 5,
          removed_ioc_count: 1,
          total_ioc_count: 6,
          technique_count: 2,
          event_count: 10,
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
      ioc_overview: [],
      summary: 'Runs largely agree on the threat actor.',
      key_differences: ['Run 2 found an additional C2 domain'],
      gaps: ['Run 1 did not check DNS logs'],
      enrichment_opportunities: ['Merge IOC sets'],
      recommended_combination: 'Combine IOC lists.',
    },
    created_at: '2026-01-03T00:00:00Z',
    created_by: null,
    ...overrides,
  }
}

function renderDetail() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter initialEntries={['/threat-hunting/pkg-1']}>
      <QueryClientProvider client={qc}>
        <HuntDetail pkgId="pkg-1" onBack={() => {}} />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun()])
  vi.mocked(api.threatHunting.getRunStatus).mockRejectedValue(new Error('no status'))
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunThreatIntel).mockRejectedValue(new Error('none'))
  vi.mocked(api.threatHunting.getThreatIntel).mockRejectedValue(new Error('none'))
  vi.mocked(api.threatHunting.getComparison).mockRejectedValue(new Error('none'))
})

describe('HuntDetail tabs (issue-local-020)', () => {
  it('shows Threat Intelligence before Report in the tab bar, and a Comparison Assessment control on the All-Runs row', async () => {
    renderDetail()
    // issue-local-021: Comparison Assessment is no longer a tab-bar button —
    // it's a control on the "All runs" row (above the tab bar), signaling
    // it's a package-level view, not a per-run tab. Wait for it as the
    // readiness signal (still gated on runs.length>0).
    const nav = await screen.findByRole('button', { name: 'Comparison Assessment' })
    expect(nav).toBeInTheDocument()

    const buttons = screen.getAllByRole('button').map((b) => b.textContent)
    const tiIdx = buttons.findIndex((t) => t === 'Threat Intelligence')
    const reportIdx = buttons.findIndex((t) => t === 'Report')
    expect(tiIdx).toBeGreaterThan(-1)
    expect(reportIdx).toBeGreaterThan(tiIdx)
  })

  it('shows Threat Intelligence/Report tabs disabled (not absent) when the active run is not finished', async () => {
    // issue-local-022 (item 5): gating now derives from the ACTIVE RUN's own
    // generation_status, not the package's — a stale-but-still-'completed'
    // pkg.status from a PRIOR run must no longer keep these tabs enabled
    // while the current run is still mid-pipeline.
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg({ status: 'planning' }))
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun({ generation_status: 'running' })])
    renderDetail()
    expect(await screen.findByRole('button', { name: 'Comparison Assessment' })).toBeInTheDocument()
    // issue-local-021: always rendered, just greyed/disabled — not absent.
    expect(await screen.findByRole('button', { name: 'Threat Intelligence' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Report' })).toBeDisabled()
  })

  it('hides both tabs and the Assess & Compare button when there are no runs', async () => {
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([])
    renderDetail()
    await screen.findByRole('heading', { name: /Test Package/ })
    expect(screen.queryByRole('button', { name: 'Comparison Assessment' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Assess & Compare/ })).not.toBeInTheDocument()
  })
})

describe('ThreatIntelTab (issue-local-020)', () => {
  it('shows an empty state when no analysis exists yet', async () => {
    renderDetail()
    // issue-local-021: the tab is always rendered but starts disabled until
    // the package finishes loading (isFinished depends on pkg) — wait for
    // it to become enabled before clicking, rather than clicking the instant
    // it appears in the DOM.
    await waitFor(() => expect(screen.getByRole('button', { name: 'Threat Intelligence' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Threat Intelligence' }))
    expect(await screen.findByText('No threat intelligence analysis yet.')).toBeInTheDocument()
  })

  it('renders threat actors, summary, and correlated IOCs when data exists', async () => {
    vi.mocked(api.threatHunting.getRunThreatIntel).mockResolvedValue(makeThreatIntel())
    renderDetail()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Threat Intelligence' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Threat Intelligence' }))

    expect(await screen.findByText('FIN7 activity correlated across hunts.')).toBeInTheDocument()
    // "FIN7" appears twice (Threat Actors card + Attribution assessment).
    expect(screen.getAllByText('FIN7').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('Carbanak')).toBeInTheDocument()
    expect(screen.getByText('evil.example')).toBeInTheDocument()
    expect(screen.getByText('Other Hunt')).toBeInTheDocument()
  })
})

describe('ComparisonAssessmentTab and Assess & Compare (issue-local-020)', () => {
  it('shows an empty state when no comparison exists yet', async () => {
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Comparison Assessment' }))
    expect(await screen.findByText('No full comparison assessment yet.')).toBeInTheDocument()
  })

  it('renders the diff table and narrative sections when a comparison exists', async () => {
    vi.mocked(api.threatHunting.getComparison).mockResolvedValue(makeComparison())
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Comparison Assessment' }))

    expect(await screen.findByText('Runs largely agree on the threat actor.')).toBeInTheDocument()
    expect(screen.getByText('TH01-X01')).toBeInTheDocument()
    expect(screen.getByText('Run 2 found an additional C2 domain')).toBeInTheDocument()
    expect(screen.getByText('Combine IOC lists.')).toBeInTheDocument()
  })

  it('clicking Comparison Assessment then Assess & Compare opens the run picker and calls compareRuns', async () => {
    // issue-local-021: Assess & Compare is now self-contained inside
    // ComparisonAssessmentTab — navigate to the tab first (no comparison
    // yet), then trigger the dialog from within it.
    vi.mocked(api.threatHunting.compareRuns).mockResolvedValue(makeComparison())
    renderDetail()

    fireEvent.click(await screen.findByRole('button', { name: 'Comparison Assessment' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Assess & Compare' }))

    // getComparison starts empty; after a successful compare it must
    // resolve with data so the invalidated query refetches real content.
    vi.mocked(api.threatHunting.getComparison).mockResolvedValue(makeComparison())
    fireEvent.click(await screen.findByRole('button', { name: 'Compare' }))

    await waitFor(() =>
      expect(api.threatHunting.compareRuns).toHaveBeenCalledWith('pkg-1', {
        run_ids: undefined,
        provider_name: undefined,
        model_name: undefined,
        phase: 'full',
      }),
    )
    expect(await screen.findByText('Runs largely agree on the threat actor.')).toBeInTheDocument()
  })

  it('issue-local-035: renders one consolidated row per unique IOC with a per-run occurrence breakdown', async () => {
    vi.mocked(api.threatHunting.getComparison).mockResolvedValue(
      makeComparison({
        full_report: {
          ...makeComparison().full_report,
          ioc_overview: [
            {
              ioc: 'evil.example.com',
              ioc_type: 'domain',
              run_count: 2,
              verdict_summary: 'kept in 1, removed in 1',
              occurrences: [
                {
                  run_id: 'run-1',
                  run_id_display: 'TH01-X01',
                  model: 'gpt-oss',
                  confidence_pct: 90,
                  verdict: 'keep',
                },
                {
                  run_id: 'run-2',
                  run_id_display: 'TH01-X02',
                  model: 'gpt-oss',
                  confidence_pct: 40,
                  verdict: 'remove',
                },
              ],
              hypotheses: ['H1'],
            },
          ],
        },
      }),
    )
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Comparison Assessment' }))

    expect(await screen.findByText('Overall IOCs (1 unique)')).toBeInTheDocument()
    expect(screen.getAllByText('evil.example.com')).toHaveLength(1)
    // TH01-X01 also appears in the diff table above — only assert the
    // second run's chip, which is unique to the IOC occurrence breakdown.
    expect(screen.getByText('TH01-X02')).toBeInTheDocument()
    expect(screen.getByText('kept in 1, removed in 1')).toBeInTheDocument()
  })

  it('issue-local-035: Preliminary and Full tabs fetch and show independent reports', async () => {
    vi.mocked(api.threatHunting.getComparison).mockImplementation(async (_pkgId, phase = 'full') =>
      phase === 'preliminary'
        ? makeComparison({
            full_report: {
              ...makeComparison().full_report,
              phase: 'preliminary',
              summary: 'Preliminary-only summary text.',
            },
          })
        : makeComparison({
            full_report: {
              ...makeComparison().full_report,
              phase: 'full',
              summary: 'Full-only summary text.',
            },
          }),
    )
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Comparison Assessment' }))

    // Full tab is the default.
    expect(await screen.findByText('Full-only summary text.')).toBeInTheDocument()
    expect(api.threatHunting.getComparison).toHaveBeenCalledWith('pkg-1', 'full')

    fireEvent.click(screen.getByRole('button', { name: 'Preliminary Analysis' }))
    expect(await screen.findByText('Preliminary-only summary text.')).toBeInTheDocument()
    expect(api.threatHunting.getComparison).toHaveBeenCalledWith('pkg-1', 'preliminary')
    expect(screen.queryByText('Full-only summary text.')).not.toBeInTheDocument()
  })

  it('issue-local-035: "Use as Consolidated Report" calls consolidateComparison and shows download links', async () => {
    vi.mocked(api.threatHunting.getComparison).mockResolvedValue(makeComparison())
    vi.mocked(api.threatHunting.consolidateComparison).mockResolvedValue(makeComparison())
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Comparison Assessment' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Use as Consolidated Report' }))

    await waitFor(() =>
      expect(api.threatHunting.consolidateComparison).toHaveBeenCalledWith('pkg-1', 'full'),
    )
    expect(await screen.findByText('Consolidated report created.')).toBeInTheDocument()
  })

  it('issue-local-035: "Re-run with All Compared Runs" calls rerunFromRecommendation with no run_ids', async () => {
    vi.mocked(api.threatHunting.getComparison).mockResolvedValue(makeComparison())
    vi.mocked(api.threatHunting.rerunFromRecommendation).mockResolvedValue({
      package: { ...makePkg(), id: 'pkg-2', name: 'pkg (recommended combination)' },
      generation: { id: 'run-new', generation_status: 'running' } as never,
    })
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Comparison Assessment' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Re-run with All Compared Runs' }))

    await waitFor(() =>
      expect(api.threatHunting.rerunFromRecommendation).toHaveBeenCalledWith('pkg-1', {
        run_ids: undefined,
        phase: 'full',
      }),
    )
  })

  it('issue-local-035: "Re-run with Selected Runs" opens a picker and submits the chosen subset', async () => {
    vi.mocked(api.threatHunting.getComparison).mockResolvedValue(makeComparison())
    vi.mocked(api.threatHunting.rerunFromRecommendation).mockResolvedValue({
      package: { ...makePkg(), id: 'pkg-2', name: 'pkg (recommended combination)' },
      generation: { id: 'run-new', generation_status: 'running' } as never,
    })
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Comparison Assessment' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Re-run with Selected Runs…' }))
    const dialogHeading = await screen.findByText('Re-run with Selected Runs')
    const dialog = dialogHeading.closest('div.space-y-4') as HTMLElement

    // makeComparison()'s compared_run_ids is ['run-1', 'run-2'] but `runs`
    // passed to HuntDetail only ever includes run-1 (makeRun()) — the picker
    // must only list runs that are both compared AND known, not crash on run-2.
    fireEvent.click(within(dialog).getByRole('button', { name: 'Re-run' }))

    await waitFor(() =>
      expect(api.threatHunting.rerunFromRecommendation).toHaveBeenCalledWith('pkg-1', {
        run_ids: ['run-1'],
        phase: 'full',
      }),
    )
  })
})

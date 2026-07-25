/**
 * Tests for issue-local-020 Part F: the "Threat Intelligence" tab, the
 * "Comparison Assessment" tab, and the "Assess & Compare" button in
 * HuntDetail.tsx.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
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
          technique_count: 2,
          event_count: 10,
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
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
  it('shows Threat Intelligence and Comparison Assessment tabs before Report, in order', async () => {
    renderDetail()
    const nav = await screen.findByRole('button', { name: 'Threat Intelligence' })
    expect(nav).toBeInTheDocument()

    const buttons = screen.getAllByRole('button').map((b) => b.textContent)
    const tiIdx = buttons.findIndex((t) => t === 'Threat Intelligence')
    const cmpIdx = buttons.findIndex((t) => t === 'Comparison Assessment')
    const reportIdx = buttons.findIndex((t) => t === 'Report')
    expect(tiIdx).toBeGreaterThan(-1)
    expect(cmpIdx).toBeGreaterThan(tiIdx)
    expect(reportIdx).toBeGreaterThan(cmpIdx)
  })

  it('shows Comparison Assessment tab even when the package is not finished, as long as a run exists', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg({ status: 'planning' }))
    renderDetail()
    expect(await screen.findByRole('button', { name: 'Comparison Assessment' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Threat Intelligence' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Report' })).not.toBeInTheDocument()
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
    fireEvent.click(await screen.findByRole('button', { name: 'Threat Intelligence' }))
    expect(await screen.findByText('No threat intelligence analysis yet.')).toBeInTheDocument()
  })

  it('renders threat actors, summary, and correlated IOCs when data exists', async () => {
    vi.mocked(api.threatHunting.getRunThreatIntel).mockResolvedValue(makeThreatIntel())
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Threat Intelligence' }))

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
    expect(await screen.findByText('No comparison assessment yet.')).toBeInTheDocument()
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

  it('clicking Assess & Compare calls compareRuns and switches to the Comparison tab', async () => {
    vi.mocked(api.threatHunting.compareRuns).mockResolvedValue(makeComparison())
    // onSuccess invalidates the ['th-comparison', pkgId] query, which
    // refetches via getComparison — must resolve for the tab to render data.
    vi.mocked(api.threatHunting.getComparison).mockResolvedValue(makeComparison())
    renderDetail()

    fireEvent.click(await screen.findByRole('button', { name: /Assess & Compare/ }))

    await waitFor(() => expect(api.threatHunting.compareRuns).toHaveBeenCalledWith('pkg-1'))
    expect(await screen.findByText('Runs largely agree on the threat actor.')).toBeInTheDocument()
  })
})

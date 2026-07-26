/**
 * Tests for issue-local-022 item 2: HypothesisLeadIocChart — the
 * Hypothesis -> Hunting Lead -> IOC relationship chart shown above the
 * Analysis tab's flat lists, plus its Deep View Threat Intel overlay.
 *
 * @xyflow/react is mocked — actual SVG/canvas rendering isn't under test
 * here, only that the component computes the right node/edge set from
 * the confirmed design decisions (coverage definition, discarded-hypothesis
 * exclusion, Deep View query gating).
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THGenerationRecord, THExtractedIOC, THThreatIntel } from '../api/client'

vi.mock('@xyflow/react', () => {
  return {
    ReactFlow: ({ nodes, edges }: { nodes: { id: string; data: { label: string } }[]; edges: { id: string; source: string; target: string }[] }) => (
      <div data-testid="react-flow-stub">
        <div data-testid="node-count">{nodes.length}</div>
        <div data-testid="edge-count">{edges.length}</div>
        {nodes.map((n) => (
          <div key={n.id} data-testid={`node-${n.id}`}>{n.data.label}</div>
        ))}
        {edges.map((e) => (
          <div key={e.id} data-testid={`edge-${e.id}`} data-source={e.source} data-target={e.target} />
        ))}
      </div>
    ),
    Background: () => null,
    Controls: () => null,
  }
})

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      threatHunting: {
        ...actual.api.threatHunting,
        getRunThreatIntel: vi.fn(),
      },
    },
  }
})

import { api } from '../api/client'
import HypothesisLeadIocChart from '../pages/threat-hunting/HypothesisLeadIocChart'

function makeIoc(overrides: Partial<THExtractedIOC> = {}): THExtractedIOC {
  return {
    id: `ioc-${Math.random()}`,
    evidence_item_id: 'ev-1',
    hunt_package_id: 'pkg-1',
    ioc: 'evil.example',
    ioc_type: 'domain',
    ioc_description: '',
    noise_score: 0.1,
    flagged_noisy: false,
    action: 'keep',
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

function makeRecord(overrides: Partial<THGenerationRecord> = {}): THGenerationRecord {
  return {
    hunt_package_id: 'pkg-1',
    generation_status: 'awaiting_approval',
    hypotheses: [],
    hunting_leads: [],
    ...overrides,
  } as THGenerationRecord
}

function makeThreatIntel(overrides: Partial<THThreatIntel> = {}): THThreatIntel {
  return {
    id: 'ti-1',
    hunt_package_id: 'pkg-1',
    run_id: 'run-1',
    threat_actors: [],
    attribution: null,
    malware_families: [],
    campaigns: [],
    related_vendors: [],
    correlated_iocs: [],
    summary: '',
    full_analysis: {},
    created_at: '2026-01-01T00:00:00Z',
    created_by: null,
    ...overrides,
  }
}

function renderChart(record: THGenerationRecord, iocs: THExtractedIOC[] = []) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <HypothesisLeadIocChart record={record} iocs={iocs} pkgId="pkg-1" runId="run-1" />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(api.threatHunting.getRunThreatIntel).mockReset()
})

describe('HypothesisLeadIocChart — coverage computation', () => {
  it('flags an IOC cited by no hypothesis as uncovered', () => {
    const record = makeRecord({
      hypotheses: [{ id: 'H1', title: 't', description: '', justification: '', relevance: 'high', ioc_basis: ['covered.example'] }],
    })
    renderChart(record, [makeIoc({ ioc: 'covered.example' }), makeIoc({ ioc: 'uncovered.example' })])
    expect(screen.getByTestId('node-ioc:uncovered.example')).toBeInTheDocument()
    expect(screen.getByTestId('node-ioc:covered.example')).toBeInTheDocument()
    expect(screen.getByText(/1 uncovered/)).toBeInTheDocument()
  })

  it('does not count a DISCARDED hypothesis toward IOC coverage', () => {
    const record = makeRecord({
      hypotheses: [
        { id: 'H1', title: 't', description: '', justification: '', relevance: 'high', ioc_basis: ['a.example'], discarded: true },
      ],
    })
    renderChart(record, [makeIoc({ ioc: 'a.example' })])
    // Cited only by a discarded hypothesis — still uncovered.
    expect(screen.getByText(/1 uncovered/)).toBeInTheDocument()
  })

  it('excludes removed (action=remove) IOCs from the coverage stat, showing them as their own category', () => {
    const record = makeRecord({
      hypotheses: [{ id: 'H1', title: 't', description: '', justification: '', relevance: 'high', ioc_basis: [] }],
    })
    renderChart(record, [makeIoc({ ioc: 'gone.example', action: 'remove' })])
    // Not counted as "uncovered" — it has its own "removed" count instead.
    expect(screen.queryByText(/uncovered/)).not.toBeInTheDocument()
    expect(screen.getByText(/1 removed/)).toBeInTheDocument()
    expect(screen.getByTestId('node-ioc:gone.example')).toHaveTextContent('removed')
  })
})

describe('HypothesisLeadIocChart — Hypothesis -> Hunting Lead fan-out', () => {
  it('draws one edge per hunting lead when a hypothesis has multiple leads', () => {
    const record = makeRecord({
      hypotheses: [{ id: 'H1', title: 't', description: '', justification: '', relevance: 'high', ioc_basis: [] }],
      hunting_leads: [
        { id: 'L1', hypothesis_id: 'H1', title: 'lead 1', description: '', priority: 'high', tasks: [] },
        { id: 'L2', hypothesis_id: 'H1', title: 'lead 2', description: '', priority: 'medium', tasks: [] },
      ],
    })
    renderChart(record)
    expect(screen.getByTestId('edge-e-hl-L1')).toBeInTheDocument()
    expect(screen.getByTestId('edge-e-hl-L2')).toBeInTheDocument()
    expect(screen.getByTestId('edge-e-hl-L1')).toHaveAttribute('data-source', 'hyp:H1')
    expect(screen.getByTestId('edge-e-hl-L2')).toHaveAttribute('data-source', 'hyp:H1')
  })

  it('renders nothing to chart when there are no hypotheses/leads/IOCs', () => {
    renderChart(makeRecord())
    expect(screen.getByText('Nothing to chart yet.')).toBeInTheDocument()
    expect(screen.queryByTestId('react-flow-stub')).not.toBeInTheDocument()
  })
})

describe('HypothesisLeadIocChart — Deep View toggle', () => {
  it('does not fetch Threat Intel while Deep View is off', () => {
    const record = makeRecord({
      hypotheses: [{ id: 'H1', title: 't', description: '', justification: '', relevance: 'high', ioc_basis: [] }],
    })
    renderChart(record)
    expect(api.threatHunting.getRunThreatIntel).not.toHaveBeenCalled()
  })

  it('fetches Threat Intel and overlays actor/malware/campaign/TTP nodes once Deep View is enabled', async () => {
    vi.mocked(api.threatHunting.getRunThreatIntel).mockResolvedValue(
      makeThreatIntel({
        threat_actors: [{ name: 'FIN7', confidence: 'high' }],
        malware_families: ['Carbanak'],
        campaigns: [{ name: 'RetailHeist' }],
      }),
    )
    const record = makeRecord({
      hypotheses: [{ id: 'H1', title: 't', description: '', justification: '', relevance: 'high', ioc_basis: [] }],
      ttp_analysis: {
        summary: '',
        techniques: [{ technique_id: 'T1059', technique_name: 'Command Interpreter', tactic: 'Execution', description: '', evidence_basis: '' }],
        detection_opportunities: [],
      },
    })
    renderChart(record)

    fireEvent.click(screen.getByText('Deep view'))

    await waitFor(() => expect(api.threatHunting.getRunThreatIntel).toHaveBeenCalledWith('pkg-1', 'run-1'))
    expect(await screen.findByText(/FIN7/)).toBeInTheDocument()
    expect(screen.getByText(/Carbanak/)).toBeInTheDocument()
    expect(screen.getByText(/RetailHeist/)).toBeInTheDocument()
    expect(screen.getByText(/T1059/)).toBeInTheDocument()
  })

  it('draws a precise edge from an IOC node to its correlated_iocs match', async () => {
    vi.mocked(api.threatHunting.getRunThreatIntel).mockResolvedValue(
      makeThreatIntel({
        correlated_iocs: [{ ioc: 'shared.example', ioc_type: 'domain', hunt_package_id: 'pkg-2', hunt_name: 'Other Hunt' }],
      }),
    )
    const record = makeRecord({
      hypotheses: [{ id: 'H1', title: 't', description: '', justification: '', relevance: 'high', ioc_basis: ['shared.example'] }],
    })
    renderChart(record, [makeIoc({ ioc: 'shared.example' })])

    fireEvent.click(screen.getByText('Deep view'))

    await screen.findByText(/Other Hunt/)
    const corrEdge = screen.getByTestId('edge-e-corr-0')
    expect(corrEdge).toHaveAttribute('data-source', 'ioc:shared.example')
  })
})

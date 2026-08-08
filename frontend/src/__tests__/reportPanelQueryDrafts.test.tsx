/**
 * Tests for issue-local-042 (item 4a): the frozen Hunt Report used to only
 * carry query_drafts_count (a number) and a bare SPL macro *name* — the
 * actual queries never appeared anywhere in the report view, unlike
 * AnalysisTab.tsx's live review, which already shows them in a code card.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THHuntReport, THFullReport } from '../api/client'

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
import ReportPanel from '../pages/threat-hunting/ReportPanel'

function makeFullReport(overrides: Partial<THFullReport> = {}): THFullReport {
  return {
    executive_summary: 'Summary.',
    hunt_name: 'Hunt',
    hunt_id: 'hunt-1',
    generated_at: '2026-01-01T00:00:00Z',
    generated_by: null,
    package_status: 'completed',
    evidence_summary: { total_items: 0, ioc_count: 0, item_types: [] },
    threat_context: null,
    hypotheses: [],
    hunting_leads: [],
    deep_retrohunt_summary: null,
    ttp_analysis: null,
    query_drafts_count: 0,
    execution_results: [],
    recommendations: [],
    ...overrides,
  }
}

function makeReport(overrides: Partial<THHuntReport> = {}): THHuntReport {
  return {
    id: 'report-1',
    hunt_package_id: 'pkg-1',
    run_id: 'run-1',
    executive_summary: 'Summary.',
    full_report: makeFullReport(),
    created_at: '2026-01-01T00:00:00Z',
    created_by: null,
    ...overrides,
  }
}

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ReportPanel pkgId="pkg-1" runId="run-1" />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(api.threatHunting.getRunReport).mockReset()
})

describe('ReportPanel — Query Drafts section (issue-local-042)', () => {
  it('does not render a Query Drafts section when there are none', async () => {
    vi.mocked(api.threatHunting.getRunReport).mockResolvedValue(makeReport())
    renderPanel()
    await screen.findByText('Summary.')
    expect(screen.queryByText(/Query Drafts/)).not.toBeInTheDocument()
  })

  it('shows each query draft in a code card once expanded', async () => {
    vi.mocked(api.threatHunting.getRunReport).mockResolvedValue(
      makeReport({
        full_report: makeFullReport({
          query_drafts_count: 1,
          query_drafts: [
            {
              id: 'q1',
              title: 'Suspicious DNS lookups',
              language: 'spl',
              description: 'Finds beacon-like DNS activity.',
              query: 'index=dns dest_ip=1.2.3.4 | stats count by src_ip',
              data_sources: [],
              lead_id: null,
            },
          ],
        }),
      }),
    )
    renderPanel()
    await screen.findByText('Summary.')

    fireEvent.click(screen.getByText('Query Drafts (1)'))

    expect(screen.getByText('Suspicious DNS lookups')).toBeInTheDocument()
    expect(screen.getByText('Finds beacon-like DNS activity.')).toBeInTheDocument()
    expect(screen.getByText('index=dns dest_ip=1.2.3.4 | stats count by src_ip')).toBeInTheDocument()
    expect(screen.getByText('spl')).toBeInTheDocument()
  })

  it('shows the retrohunt macro SPL as a code block, not just its name', async () => {
    vi.mocked(api.threatHunting.getRunReport).mockResolvedValue(
      makeReport({
        full_report: makeFullReport({
          deep_retrohunt_summary: {
            total_iocs: 5,
            noisy_iocs: 0,
            high_noise_iocs: 0,
            spl_macro_name: 'hunt_macro_1',
            search_hint: '',
            spl_draft: '`hunt_macro_1` | table _time src_ip dest_ip',
          },
        }),
      }),
    )
    renderPanel()
    await screen.findByText('Summary.')

    expect(screen.getByText('`hunt_macro_1` | table _time src_ip dest_ip')).toBeInTheDocument()
  })
})

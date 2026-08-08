/**
 * Tests for issue-local-042 (items 2, 5): a hunting-lead task's query_hint
 * is a code/query artifact extracted from the analysis, so it renders in a
 * bordered/monospace code card (matching the app's other query cards) —
 * previously plain "Hint: ..." text indistinguishable from prose.
 */
import { render, screen, fireEvent } from '@testing-library/react'
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
        getRunStatus: vi.fn(),
        listIocs: vi.fn(),
        listEvidence: vi.fn(),
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
import AnalysisTab from '../pages/threat-hunting/AnalysisTab'

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AnalysisTab pkgId="pkg-1" runId="run-1" />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(api.threatHunting.getRunStatus).mockReset()
  vi.mocked(api.threatHunting.listIocs).mockReset().mockResolvedValue([])
  vi.mocked(api.threatHunting.listEvidence).mockReset().mockResolvedValue([])
})

describe('AnalysisTab — Hunting Lead task query cards (issue-local-042)', () => {
  it('renders a task query_hint as a code card, not "Hint:" prose', async () => {
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
      hunt_package_id: 'pkg-1',
      run_id: 'run-1',
      generation_status: 'completed',
      hypotheses: [],
      hunting_leads: [
        {
          id: 'L1',
          title: 'Investigate C2 beacons',
          description: 'Check for periodic outbound connections.',
          priority: 'high',
          hypothesis_id: '',
          tasks: [
            {
              id: 'T1',
              title: 'Search proxy logs',
              description: 'Look for beacon-like intervals.',
              datasource: 'proxy',
              query_hint: 'index=proxy dest_ip=1.2.3.4 | timechart count',
            },
          ],
        },
      ],
    })

    renderTab()

    fireEvent.click(await screen.findByText('Hunting Leads (1)'))

    const queryText = await screen.findByText('index=proxy dest_ip=1.2.3.4 | timechart count')
    expect(queryText.tagName).toBe('PRE')
    expect(queryText).toHaveClass('bg-gray-950')
    // The old "Hint: <query>" prose prefix is gone.
    expect(screen.queryByText(/^Hint:/)).not.toBeInTheDocument()
  })
})

describe('AnalysisTab — hypothesis Suggested Actions bullets (issue-local-042 item 5)', () => {
  it('renders suggested actions as a real bulleted list', async () => {
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
      hunt_package_id: 'pkg-1',
      run_id: 'run-1',
      generation_status: 'completed',
      hypotheses: [
        {
          id: 'H1',
          title: 'Test hypothesis',
          description: '',
          justification: '',
          relevance: 'high',
          ioc_basis: [],
          suggested_actions: ['Isolate the host', 'Rotate credentials'],
        },
      ],
      hunting_leads: [],
    })

    renderTab()

    const item = await screen.findByText('Isolate the host')
    expect(item.tagName).toBe('LI')
    expect(item.closest('ul')).toHaveClass('list-disc')
    expect(screen.getByText('Rotate credentials').tagName).toBe('LI')
  })
})

describe('AnalysisTab — Threat Context Actor/Campaign/Confidence cards (issue-local-042 item 19)', () => {
  it('renders Actor, Campaign, and Confidence as their own stat cards', async () => {
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
      hunt_package_id: 'pkg-1',
      run_id: 'run-1',
      generation_status: 'completed',
      threat_context: {
        summary: 'A summary.',
        threat_actor: 'APT42',
        campaign_name: 'SpearSpecter',
        confidence: 'high',
      },
      hypotheses: [],
      hunting_leads: [],
    })

    renderTab()

    const actorLabel = await screen.findByText('Actor')
    const actorCard = actorLabel.closest('div')!
    expect(actorCard).toHaveClass('bg-gray-800/50')
    expect(screen.getByText('APT42')).toBeInTheDocument()

    const campaignCard = screen.getByText('Campaign').closest('div')!
    expect(campaignCard).toHaveClass('bg-gray-800/50')
    expect(screen.getByText('SpearSpecter')).toBeInTheDocument()

    const confidenceCard = screen.getByText('Confidence').closest('div')!
    expect(confidenceCard).toHaveClass('bg-gray-800/50')
    expect(screen.getByText('high')).toHaveClass('text-green-400')
  })
})

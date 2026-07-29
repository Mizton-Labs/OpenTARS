/**
 * Tests for HuntDashboard — the Threat Hunting module's default view
 * (issue-local-032). Covers rendering the aggregate stats, the search/time
 * filter driving the query, and the "View Hunt Packages" escape hatch to
 * the list that used to live at this route.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THDashboardStats } from '../api/client'

const navigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => navigate }
})

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      threatHunting: {
        ...actual.api.threatHunting,
        getDashboard: vi.fn(),
      },
    },
  }
})

import { api } from '../api/client'
import HuntDashboard from '../pages/threat-hunting/HuntDashboard'

const mockGetDashboard = api.threatHunting.getDashboard as unknown as ReturnType<typeof vi.fn>

const STATS: THDashboardStats = {
  packages_total: 7,
  packages_by_status: { draft: 2, completed: 5 },
  runs_total: 12,
  runs_by_model: { 'gpt-a': 8, 'gpt-b': 4 },
  hunts_by_model: { 'gpt-a': 5, 'gpt-b': 2 },
  evidence_total: 20,
  evidence_by_type: { file: 15, url: 5 },
  hypotheses_total: 30,
  hunting_leads_total: 18,
  queries_total: 25,
  iocs_extracted_total: 100,
  iocs_kept_total: 80,
  siem_searches_total: 10,
  siem_searches_completed: 9,
  siem_events_total: 500,
  threat_actors_total: 3,
  campaigns_total: 2,
  malware_families_total: 4,
  ttps_total: 6,
  sources_processed: 9,
}

function renderDashboard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <HuntDashboard />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockGetDashboard.mockResolvedValue(STATS)
})

describe('HuntDashboard', () => {
  it('renders the core stat cards from the fetched stats', async () => {
    renderDashboard()

    expect(await screen.findByText('7')).toBeInTheDocument() // packages_total
    expect(screen.getByText('12')).toBeInTheDocument() // runs_total
    expect(screen.getByText('20')).toBeInTheDocument() // evidence_total
    expect(screen.getByText('100')).toBeInTheDocument() // iocs_extracted_total
    expect(screen.getByText('80 kept')).toBeInTheDocument()
  })

  it('renders the Threat Intel summary tiles', async () => {
    renderDashboard()

    await screen.findByText('Threat Intel — across all hunts')
    expect(screen.getByText('3')).toBeInTheDocument() // threat_actors_total
    expect(screen.getByText('Feed Sources Processed')).toBeInTheDocument()
  })

  it('renders a bar row per model in the breakdown panels', async () => {
    renderDashboard()

    await screen.findByText('Runs by Model')
    // gpt-a/gpt-b appear in both the "Runs by Model" and "Hunt Packages by
    // Model" panels — assert at least one of each, not a single unique match.
    expect(screen.getAllByText('gpt-a').length).toBeGreaterThan(0)
    expect(screen.getAllByText('gpt-b').length).toBeGreaterThan(0)
  })

  it('debounces search input into the dashboard query', async () => {
    const user = userEvent.setup()
    renderDashboard()
    await screen.findByText('7')

    await user.type(screen.getByLabelText('Search hunt packages'), 'lazarus')

    await waitFor(() =>
      expect(mockGetDashboard).toHaveBeenLastCalledWith(
        expect.objectContaining({ search: 'lazarus' }),
      ),
    )
  })

  it('navigates to the Hunt Packages list from the header button', async () => {
    const user = userEvent.setup()
    renderDashboard()
    await screen.findByText('7')

    await user.click(screen.getByRole('button', { name: /view hunt packages/i }))

    // Absolute path, not relative — this page is mounted at the bare
    // "threat-hunting" route (a single segment), so relative '../packages'
    // resolved to the nonexistent "/packages" (a bug, now fixed).
    expect(navigate).toHaveBeenCalledWith('/threat-hunting/packages')
  })
})

describe('HuntDashboard — panel order', () => {
  it('shows the Threat Intel summary before the hunt-scoped stat cards', async () => {
    renderDashboard()
    await screen.findByText('Threat Intel — across all hunts')

    const threatIntelHeading = screen.getByText('Threat Intel — across all hunts')
    const huntPackagesLabel = screen.getByText('Hunt Packages')
    expect(
      threatIntelHeading.compareDocumentPosition(huntPackagesLabel) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
  })

  it('shows Evidence by Type and Packages by Status before the model breakdowns', async () => {
    renderDashboard()
    await screen.findByText('Runs by Model')

    const evidenceByType = screen.getByText('Evidence by Type')
    const packagesByStatus = screen.getByText('Packages by Status')
    const runsByModel = screen.getByText('Runs by Model')
    const huntsByModel = screen.getByText('Hunt Packages by Model')

    expect(
      evidenceByType.compareDocumentPosition(runsByModel) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
    expect(
      packagesByStatus.compareDocumentPosition(huntsByModel) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
  })
})

describe('HuntDashboard — links to Data Explorer', () => {
  it('navigates to the matching category when a stat card is clicked', async () => {
    const user = userEvent.setup()
    renderDashboard()
    await screen.findByText('Hunt Packages')

    await user.click(screen.getByText('Hunt Packages').closest('button')!)

    expect(navigate).toHaveBeenCalledWith('/threat-hunting/explorer?tab=hunts')
  })

  it('navigates to the threat_actors category from the Threat Intel tile', async () => {
    const user = userEvent.setup()
    renderDashboard()
    await screen.findByText('Threat Actors')

    await user.click(screen.getByText('Threat Actors').closest('button')!)

    expect(navigate).toHaveBeenCalledWith('/threat-hunting/explorer?tab=threat_actors')
  })

  it('navigates to the runs category from a breakdown panel header', async () => {
    const user = userEvent.setup()
    renderDashboard()
    await screen.findByText('Runs by Model')

    await user.click(screen.getByText('Runs by Model').closest('button')!)

    expect(navigate).toHaveBeenCalledWith('/threat-hunting/explorer?tab=runs')
  })
})

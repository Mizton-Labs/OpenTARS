/**
 * Tests for issue-local-021 Part B: the Threat Intel Tracking dashboard page
 * (ThreatIntelTracking.tsx) — Dashboard tab panels + search, Hunts tab
 * include/exclude/delete controls.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type {
  THTrackingDashboard,
  THTrackingHunt,
} from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      threatHunting: {
        ...actual.api.threatHunting,
        tracking: {
          getDashboard: vi.fn(),
          listHunts: vi.fn(),
          setHuntExcluded: vi.fn(),
          deleteHunt: vi.fn(),
        },
      },
    },
  }
})

import { api } from '../api/client'
import ThreatIntelTracking from '../pages/threat-hunting/ThreatIntelTracking'

function emptyDashboard(): THTrackingDashboard {
  return { iocs: [], cves: [], threat_actors: [], campaigns: [], malware_families: [], ttps: [] }
}

function makeDashboard(overrides: Partial<THTrackingDashboard> = {}): THTrackingDashboard {
  return { ...emptyDashboard(), ...overrides }
}

function makeHunt(overrides: Partial<THTrackingHunt> = {}): THTrackingHunt {
  return {
    id: 'pkg-1',
    name: 'Test Hunt',
    hunt_id_display: 'TH01',
    status: 'completed',
    excluded_from_correlation: false,
    ioc_count: 3,
    has_threat_intel: true,
    ...overrides,
  }
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ThreatIntelTracking />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(api.threatHunting.tracking.getDashboard).mockReset().mockResolvedValue(emptyDashboard())
  vi.mocked(api.threatHunting.tracking.listHunts).mockReset().mockResolvedValue([])
  vi.mocked(api.threatHunting.tracking.setHuntExcluded).mockReset()
  vi.mocked(api.threatHunting.tracking.deleteHunt).mockReset()
})

describe('ThreatIntelTracking — Dashboard tab', () => {
  it('shows the Dashboard tab by default with empty-state panels', async () => {
    renderPage()
    expect(await screen.findByText('IOCs (0)')).toBeInTheDocument()
    expect(screen.getByText('CVEs (0)')).toBeInTheDocument()
    expect(screen.getByText('Threat Actors (0)')).toBeInTheDocument()
    expect(screen.getByText('Campaigns (0)')).toBeInTheDocument()
    expect(screen.getByText('Malware Families (0)')).toBeInTheDocument()
    expect(screen.getByText('TTPs (0)')).toBeInTheDocument()
  })

  it('renders IOC, threat actor, and TTP data with source hunt badges', async () => {
    vi.mocked(api.threatHunting.tracking.getDashboard).mockResolvedValue(
      makeDashboard({
        iocs: [
          {
            ioc: 'evil.example',
            ioc_type: 'domain',
            hunt_count: 2,
            hunt_packages: [
              { id: 'pkg-1', name: 'Hunt A', hunt_id_display: 'TH01' },
              { id: 'pkg-2', name: 'Hunt B', hunt_id_display: 'TH02' },
            ],
          },
        ],
        threat_actors: [
          { name: 'FIN7', confidence: 'high', rationale: 'matches TTPs', sources: [{ id: 'pkg-1', name: 'Hunt A', hunt_id_display: 'TH01' }] },
        ],
        ttps: [
          { technique_id: 'T1059', technique_name: 'CLI', tactic: 'Execution', sources: [{ id: 'pkg-1', name: 'Hunt A', hunt_id_display: 'TH01' }] },
        ],
      }),
    )
    renderPage()

    expect(await screen.findByText('evil.example')).toBeInTheDocument()
    expect(screen.getByText('2 hunts')).toBeInTheDocument()
    // TH01 appears on the IOC, threat actor, and TTP panels (all three
    // fixtures share that source), TH02 only on the IOC panel.
    expect(screen.getAllByText('TH01').length).toBeGreaterThanOrEqual(3)
    expect(screen.getByText('TH02')).toBeInTheDocument()
    expect(screen.getByText('FIN7')).toBeInTheDocument()
    expect(screen.getByText('T1059')).toBeInTheDocument()
  })

  it('debounces the search input before calling getDashboard with it', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    renderPage()
    await vi.waitFor(() =>
      expect(api.threatHunting.tracking.getDashboard).toHaveBeenCalledWith(undefined),
    )

    fireEvent.change(screen.getByLabelText('Search IOCs and CVEs'), { target: { value: 'evil' } })
    expect(api.threatHunting.tracking.getDashboard).not.toHaveBeenCalledWith('evil')

    await vi.advanceTimersByTimeAsync(400)
    await vi.waitFor(() =>
      expect(api.threatHunting.tracking.getDashboard).toHaveBeenCalledWith('evil'),
    )
    vi.useRealTimers()
  })
})

describe('ThreatIntelTracking — Hunts tab', () => {
  it('lists hunts with correlation state', async () => {
    vi.mocked(api.threatHunting.tracking.listHunts).mockResolvedValue([makeHunt()])
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Hunts' }))

    expect(await screen.findByText('Test Hunt')).toBeInTheDocument()
    expect(screen.getByText('Included')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Exclude/ })).toBeInTheDocument()
  })

  it('toggles exclude/include and refetches the list', async () => {
    vi.mocked(api.threatHunting.tracking.listHunts).mockResolvedValue([makeHunt()])
    vi.mocked(api.threatHunting.tracking.setHuntExcluded).mockResolvedValue({} as never)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Hunts' }))
    await screen.findByText('Test Hunt')

    fireEvent.click(screen.getByRole('button', { name: /Exclude/ }))

    await waitFor(() =>
      expect(api.threatHunting.tracking.setHuntExcluded).toHaveBeenCalledWith('pkg-1', true),
    )
  })

  it('deletes a hunt after confirmation', async () => {
    vi.mocked(api.threatHunting.tracking.listHunts).mockResolvedValue([makeHunt()])
    vi.mocked(api.threatHunting.tracking.deleteHunt).mockResolvedValue(undefined)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Hunts' }))
    await screen.findByText('Test Hunt')

    fireEvent.click(screen.getByRole('button', { name: /Delete/ }))
    expect(await screen.findByText('Delete Hunt Package?')).toBeInTheDocument()

    // Both the row's trigger and the confirm dialog's button are named
    // "Delete" — the dialog's confirm button is the last one in DOM order.
    const deleteButtons = screen.getAllByRole('button', { name: 'Delete' })
    fireEvent.click(deleteButtons[deleteButtons.length - 1])

    await waitFor(() => expect(api.threatHunting.tracking.deleteHunt).toHaveBeenCalledWith('pkg-1'))
  })

  it('shows an empty state when there are no hunts', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Hunts' }))
    expect(await screen.findByText('No hunt packages yet.')).toBeInTheDocument()
  })
})

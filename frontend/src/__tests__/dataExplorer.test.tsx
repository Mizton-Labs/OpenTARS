/**
 * Tests for DataExplorer — the "Data Explorer" sidebar section
 * (issue-local-033): tab switching, the ?tab= deep-link from a Dashboard
 * panel, search debouncing, and per-category rendering.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ExplorerRow } from '../api/client'

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
        getExplorerRows: vi.fn(),
      },
    },
  }
})

import { api } from '../api/client'
import DataExplorer from '../pages/threat-hunting/DataExplorer'

const mockGetRows = api.threatHunting.getExplorerRows as unknown as ReturnType<typeof vi.fn>

function renderExplorer(initialPath = '/threat-hunting/explorer') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <DataExplorer />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockGetRows.mockResolvedValue([])
})

describe('DataExplorer — default tab', () => {
  it('defaults to the Hunt Packages tab and fetches its rows', async () => {
    renderExplorer()

    await waitFor(() => expect(mockGetRows).toHaveBeenCalledWith('hunts', expect.anything()))
  })

  it('shows an empty state with no rows', async () => {
    renderExplorer()

    expect(await screen.findByText(/no data yet/i)).toBeInTheDocument()
  })
})

describe('DataExplorer — ?tab= deep link', () => {
  it('selects the category named in the query string', async () => {
    renderExplorer('/threat-hunting/explorer?tab=threat_actors')

    await waitFor(() =>
      expect(mockGetRows).toHaveBeenCalledWith('threat_actors', expect.anything()),
    )
  })

  it('ignores an unknown ?tab= value and falls back to the default', async () => {
    renderExplorer('/threat-hunting/explorer?tab=not-a-real-category')

    await waitFor(() => expect(mockGetRows).toHaveBeenCalledWith('hunts', expect.anything()))
  })
})

describe('DataExplorer — tab switching', () => {
  it('switches category and re-fetches on tab click', async () => {
    const user = userEvent.setup()
    renderExplorer()
    await waitFor(() => expect(mockGetRows).toHaveBeenCalledWith('hunts', expect.anything()))

    await user.click(screen.getByRole('button', { name: /runs/i }))

    await waitFor(() => expect(mockGetRows).toHaveBeenCalledWith('runs', expect.anything()))
  })
})

describe('DataExplorer — search', () => {
  it('debounces search input into the query', async () => {
    const user = userEvent.setup()
    renderExplorer()
    await waitFor(() => expect(mockGetRows).toHaveBeenCalledWith('hunts', expect.anything()))

    await user.type(screen.getByLabelText('Search'), 'lazarus')

    await waitFor(() =>
      expect(mockGetRows).toHaveBeenLastCalledWith('hunts', { search: 'lazarus' }),
    )
  })
})

describe('DataExplorer — rendering rows', () => {
  it('renders hunt package rows with a hunt link', async () => {
    const rows: ExplorerRow[] = [
      { id: 'pkg-1', name: 'Lazarus sweep', status: 'completed', hunt_id_display: 'TH01' },
    ]
    mockGetRows.mockResolvedValue(rows)
    renderExplorer()

    expect(await screen.findByText('Lazarus sweep')).toBeInTheDocument()
    expect(screen.getByText('completed')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'TH01' })).toBeInTheDocument()
  })

  it('navigates to the hunt package when a hunt badge is clicked', async () => {
    const user = userEvent.setup()
    const rows: ExplorerRow[] = [
      { id: 'pkg-1', name: 'Lazarus sweep', status: 'completed', hunt_id_display: 'TH01' },
    ]
    mockGetRows.mockResolvedValue(rows)
    renderExplorer()
    await screen.findByText('Lazarus sweep')

    await user.click(screen.getByRole('button', { name: 'TH01' }))

    expect(navigate).toHaveBeenCalledWith('/threat-hunting/pkg-1')
  })

  it('renders threat actor rows with source badges', async () => {
    const rows: ExplorerRow[] = [
      {
        name: 'APT-Test',
        confidence: 'high',
        rationale: 'seen twice',
        sources: [{ id: 'pkg-1', name: 'Hunt A', hunt_id_display: 'TH01' }],
      },
    ]
    mockGetRows.mockResolvedValue(rows)
    renderExplorer('/threat-hunting/explorer?tab=threat_actors')

    expect(await screen.findByText('APT-Test')).toBeInTheDocument()
    expect(screen.getByText('seen twice')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'TH01' })).toBeInTheDocument()
  })

  it('renders a dash for a threat actor with no source hunts', async () => {
    const rows: ExplorerRow[] = [{ name: 'Solo actor', sources: [] }]
    mockGetRows.mockResolvedValue(rows)
    renderExplorer('/threat-hunting/explorer?tab=threat_actors')

    expect(await screen.findByText('Solo actor')).toBeInTheDocument()
    expect(screen.getAllByText('—').length).toBeGreaterThan(0)
  })
})

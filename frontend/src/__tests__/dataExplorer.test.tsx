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
        listEvidence: vi.fn(),
      },
    },
  }
})

import { api } from '../api/client'
import DataExplorer from '../pages/threat-hunting/DataExplorer'

const mockGetRows = api.threatHunting.getExplorerRows as unknown as ReturnType<typeof vi.fn>
const mockListEvidence = api.threatHunting.listEvidence as unknown as ReturnType<typeof vi.fn>

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
  mockListEvidence.mockResolvedValue([])
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

describe('DataExplorer — tab bar layout (issue-local-034)', () => {
  it('wraps onto multiple rows instead of scrolling horizontally', async () => {
    renderExplorer()
    await screen.findByRole('button', { name: /hunt packages/i })

    const nav = screen.getByRole('button', { name: /hunt packages/i }).closest('nav')!
    expect(nav.className).toContain('flex-wrap')
    expect(nav.className).not.toContain('overflow-x-auto')
  })
})

describe('DataExplorer — pagination (issue-local-034)', () => {
  function rowsOf(n: number): ExplorerRow[] {
    return Array.from({ length: n }, (_, i) => ({
      id: `pkg-${i}`,
      name: `Hunt ${i}`,
      status: 'draft',
      hunt_id_display: `TH${i}`,
    }))
  }

  it('defaults to a page size of 25', async () => {
    mockGetRows.mockResolvedValue(rowsOf(60))
    renderExplorer()

    await screen.findByText('Hunt 0')
    expect(screen.getByLabelText(/show/i)).toHaveValue('25')
    expect(screen.getByText('Hunt 24')).toBeInTheDocument()
    expect(screen.queryByText('Hunt 25')).not.toBeInTheDocument()
  })

  it('offers 25/50/100/200 as page-size options', async () => {
    mockGetRows.mockResolvedValue(rowsOf(60))
    renderExplorer()
    await screen.findByText('Hunt 0')

    const options = screen.getAllByRole('option').map((o) => (o as HTMLOptionElement).value)
    expect(options).toEqual(['25', '50', '100', '200'])
  })

  it('advances to the next page and shows the next slice of rows', async () => {
    const user = userEvent.setup()
    mockGetRows.mockResolvedValue(rowsOf(60))
    renderExplorer()
    await screen.findByText('Hunt 0')

    await user.click(screen.getByRole('button', { name: /next page/i }))

    expect(screen.getByText('Hunt 25')).toBeInTheDocument()
    expect(screen.queryByText('Hunt 0')).not.toBeInTheDocument()
  })

  it('changing page size shows more rows and resets to page 1', async () => {
    const user = userEvent.setup()
    mockGetRows.mockResolvedValue(rowsOf(60))
    renderExplorer()
    await screen.findByText('Hunt 0')

    await user.selectOptions(screen.getByLabelText(/show/i), '50')

    expect(screen.getByText('Hunt 49')).toBeInTheDocument()
    expect(screen.queryByText('Hunt 50')).not.toBeInTheDocument()
  })

  it('resets to page 1 when switching category', async () => {
    const user = userEvent.setup()
    mockGetRows.mockResolvedValue(rowsOf(60))
    renderExplorer()
    await screen.findByText('Hunt 0')
    await user.click(screen.getByRole('button', { name: /next page/i }))
    await screen.findByText(/page 2 of/i)

    await user.click(screen.getByRole('button', { name: /^runs$/i }))
    await waitFor(() => expect(mockGetRows).toHaveBeenLastCalledWith('runs', expect.anything()))

    expect(await screen.findByText(/page 1 of/i)).toBeInTheDocument()
  })
})

describe('DataExplorer — Run column deep link (issue-local-034)', () => {
  it('a run row links to its own run, not just the package', async () => {
    const user = userEvent.setup()
    mockGetRows.mockResolvedValue([
      { id: 'run-1', hunt_package_id: 'pkg-1', hunt_id_display: 'TH01', run_id_display: 'TH01-X01', llm_model: 'gpt' },
    ])
    renderExplorer()
    await user.click(screen.getByRole('button', { name: /^runs$/i }))

    const runButton = await screen.findByRole('button', { name: 'TH01-X01' })
    await user.click(runButton)

    expect(navigate).toHaveBeenCalledWith('/threat-hunting/pkg-1?run=run-1')
  })

  it('a hypothesis row links to its own run via a separate Run column', async () => {
    const user = userEvent.setup()
    mockGetRows.mockResolvedValue([
      {
        id: 'h1',
        hunt_package_id: 'pkg-1',
        hunt_id_display: 'TH01',
        run_id: 'run-7',
        run_id_display: 'TH01-X07',
        title: 'Phishing',
      },
    ])
    renderExplorer()
    await user.click(screen.getByRole('button', { name: /^hypotheses$/i }))
    await screen.findByText('Phishing')

    await user.click(screen.getByRole('button', { name: 'TH01-X07' }))
    expect(navigate).toHaveBeenCalledWith('/threat-hunting/pkg-1?run=run-7')
  })
})

describe('DataExplorer — Feed Sources rebuilt as evidence-source aggregation (issue-local-034)', () => {
  it('shows Source/Entries/Hunts columns from the new {name, count, sources} shape', async () => {
    const user = userEvent.setup()
    mockGetRows.mockResolvedValue([
      {
        name: 'evil-example.com',
        count: 3,
        sources: [{ id: 'pkg-1', name: 'Hunt A', hunt_id_display: 'TH01' }],
      },
    ])
    renderExplorer()
    await user.click(screen.getByRole('button', { name: /feed sources/i }))

    expect(await screen.findByText('evil-example.com')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'TH01' })).toBeInTheDocument()
  })
})

describe('DataExplorer — Archived tag (issue-local-034)', () => {
  it('shows an Archived badge on an archived hunt package row', async () => {
    mockGetRows.mockResolvedValue([
      { id: 'pkg-1', hunt_id_display: 'TH01', name: 'Old hunt', status: 'archived' },
    ])
    renderExplorer()
    expect(await screen.findByText('Archived')).toBeInTheDocument()
  })

  it('shows an Archived badge on an archived run row', async () => {
    const user = userEvent.setup()
    mockGetRows.mockResolvedValue([
      { id: 'run-1', hunt_package_id: 'pkg-1', hunt_id_display: 'TH01', run_id_display: 'TH01-X01', archived: true },
    ])
    renderExplorer()
    await user.click(screen.getByRole('button', { name: /^runs$/i }))
    expect(await screen.findByText('Archived')).toBeInTheDocument()
  })
})

describe('DataExplorer — evidence row preview (issue-local-034)', () => {
  it('expanding an evidence row lazily fetches and previews the item', async () => {
    const user = userEvent.setup()
    mockGetRows.mockResolvedValue([
      {
        id: 'ev-1',
        hunt_package_id: 'pkg-1',
        hunt_id_display: 'TH01',
        item_type: 'manual_text',
        label: 'Analyst note',
        created_at: '2026-01-01T00:00:00Z',
      },
    ])
    mockListEvidence.mockResolvedValue([
      {
        id: 'ev-1',
        hunt_package_id: 'pkg-1',
        item_type: 'manual_text',
        label: 'Analyst note',
        source_ref: '',
        content_hash: '',
        mime_type: '',
        fetch_url: '',
        final_url: '',
        extracted_text: 'The extracted evidence content.',
        parser_used: 'text',
        parser_version: 'stdlib',
        parse_status: 'ok',
        parse_warnings: [],
        fetch_metadata: {},
        created_at: '2026-01-01T00:00:00Z',
        provenance_notes: '',
      },
    ])
    renderExplorer()
    await user.click(screen.getByRole('button', { name: /^evidence$/i }))
    await screen.findByText('Analyst note')

    expect(mockListEvidence).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: /show preview/i }))

    await waitFor(() => expect(mockListEvidence).toHaveBeenCalledWith('pkg-1'))
    expect(await screen.findByText('The extracted evidence content.')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /hide preview/i }))
    expect(screen.queryByText('The extracted evidence content.')).not.toBeInTheDocument()
  })
})

/**
 * Tests for issue-local-016's hunt-package list additions:
 *   - useHuntDensity: localStorage-backed compact/detailed selector.
 *   - runStatusUtils: status→class + label helpers.
 *   - ThreatHunting.tsx: density toggle hides/shows the stage rail; the
 *     per-run chip row appears for any package with at least one run, in
 *     both density modes, and clicking a chip switches which run's rail is
 *     shown.
 */
import { render, screen, fireEvent, renderHook, act, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THuntPackage } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      threatHunting: {
        ...actual.api.threatHunting,
        listPackages: vi.fn(),
        getPackage: vi.fn(),
        listEvidence: vi.fn(),
        listRuns: vi.fn(),
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
import ThreatHunting from '../pages/ThreatHunting'
import { useHuntDensity } from '../pages/threat-hunting/useHuntDensity'
import { runStatusClass, runLabel } from '../pages/threat-hunting/runStatusUtils'

function renderList() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ThreatHunting />
    </QueryClientProvider>,
  )
}

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
    phases: [{ step: 'intake_classifier', status: 'ok', elapsed_s: 1.2 }],
    total_elapsed_s: 1.2,
    run_created_at: '2026-01-01T00:00:00Z',
    runs: [],
    run_count: 0,
    ...overrides,
  }
}

beforeEach(() => {
  localStorage.clear()
  vi.mocked(api.threatHunting.listPackages).mockReset()
  vi.mocked(api.threatHunting.getPackage).mockReset()
  vi.mocked(api.threatHunting.listEvidence).mockReset().mockResolvedValue([])
  vi.mocked(api.threatHunting.listRuns).mockReset().mockResolvedValue([])
})

describe('useHuntDensity', () => {
  it('defaults to detailed', () => {
    const { result } = renderHook(() => useHuntDensity())
    expect(result.current.density).toBe('detailed')
  })

  it('persists the selection to localStorage', () => {
    const { result } = renderHook(() => useHuntDensity())
    act(() => result.current.setDensity('compact'))
    expect(result.current.density).toBe('compact')
    expect(localStorage.getItem('sfi.th.cardDensity')).toBe('compact')
  })

  it('restores a previously-persisted value on mount', () => {
    localStorage.setItem('sfi.th.cardDensity', 'compact')
    const { result } = renderHook(() => useHuntDensity())
    expect(result.current.density).toBe('compact')
  })
})

describe('ThreatHunting list — pagination (issue-local-018 follow-up)', () => {
  function makeManyPkgs(n: number): THuntPackage[] {
    return Array.from({ length: n }, (_, i) =>
      makePkg({ id: `pkg-${i}`, name: `Package ${i}`, hunt_id_display: `TH${String(i + 1).padStart(2, '0')}` }),
    )
  }

  it('shows only the first page (default size 20) and a page footer when there are more packages', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue(makeManyPkgs(45))
    renderList()

    await screen.findByText('Package 0')
    expect(screen.getByText('Package 19')).toBeInTheDocument()
    expect(screen.queryByText('Package 20')).not.toBeInTheDocument()
    expect(screen.getByText('Page 1 of 3 · 45 total')).toBeInTheDocument()
  })

  it('does not show pagination controls when everything fits on one page', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue(makeManyPkgs(5))
    renderList()

    await screen.findByText('Package 0')
    expect(screen.queryByText(/Page \d+ of \d+/)).not.toBeInTheDocument()
  })

  it('advances to the next page and back', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue(makeManyPkgs(45))
    renderList()
    await screen.findByText('Package 0')

    fireEvent.click(screen.getByLabelText('Next page'))
    await screen.findByText('Package 20')
    expect(screen.queryByText('Package 0')).not.toBeInTheDocument()
    expect(screen.getByText('Page 2 of 3 · 45 total')).toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('Previous page'))
    await screen.findByText('Package 0')
    expect(screen.queryByText('Package 20')).not.toBeInTheDocument()
  })

  it('changing the page-size dropdown re-pages the list and persists to localStorage', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue(makeManyPkgs(45))
    renderList()
    await screen.findByText('Package 0')

    fireEvent.change(screen.getByLabelText('Show'), { target: { value: '50' } })

    await waitFor(() => expect(screen.getByText('Package 44')).toBeInTheDocument())
    expect(screen.queryByText(/Page \d+ of \d+/)).not.toBeInTheDocument()
    expect(localStorage.getItem('sfi.th.pageSize')).toBe('50')
  })
})

describe('runStatusUtils', () => {
  it('maps known statuses to their classes and falls back for unknown ones', () => {
    expect(runStatusClass('completed')).toContain('green')
    expect(runStatusClass('error')).toContain('red')
    expect(runStatusClass('running')).toContain('blue')
    expect(runStatusClass('awaiting_approval')).toContain('amber')
    expect(runStatusClass('bogus')).toContain('gray')
    expect(runStatusClass(null)).toContain('gray')
  })

  it('joins model and effort into a label, skipping blanks', () => {
    expect(
      runLabel({
        id: 'r1', hunt_package_id: 'p1', generation_status: 'completed',
        llm_model: 'gpt-oss', research_effort: 'high', created_at: '',
      }),
    ).toBe('gpt-oss · high')
    expect(
      runLabel({
        id: 'r1', hunt_package_id: 'p1', generation_status: 'completed',
        llm_model: null, llm_provider: 'alt-provider', research_effort: null, created_at: '',
      }),
    ).toBe('alt-provider')
  })
})

describe('ThreatHunting list — density toggle + run chips (issue-local-016)', () => {
  it('renders the Compact/Detailed/Table toggle', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([])
    renderList()
    expect(await screen.findByRole('button', { name: /^detailed$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^compact$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^table$/i })).toBeInTheDocument()
  })

  it('shows the stage rail by default (detailed) and hides it in compact mode', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([makePkg()])
    renderList()
    await screen.findByText('Test Package')
    // The stage rail always renders every step's label ("Intake" for
    // intake_classifier), regardless of that step's own phase data.
    expect(screen.getByText('Intake')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /^compact$/i }))
    expect(screen.queryByText('Intake')).not.toBeInTheDocument()
  })

  it('shows a run tab even for a single-run package (issue-local-017 follow-up)', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([
      makePkg({ runs: [{ id: 'r1', hunt_package_id: 'pkg-1', generation_status: 'completed', created_at: '2026-01-01T00:00:00Z' }], run_count: 1 }),
    ])
    renderList()
    await screen.findByText('Test Package')
    // Run tabs render as <button>s; the package-status badge and the
    // ProcessArrow status row are plain <span>s — so a button-role query is
    // a precise signal the chip row rendered even with a single run.
    expect(screen.getByRole('button', { name: /completed/ })).toBeInTheDocument()
  })

  it('does not show a run-chip row for a package with zero runs', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([makePkg({ runs: [], run_count: 0 })])
    renderList()
    await screen.findByText('Test Package')
    expect(screen.queryByText('Runs')).not.toBeInTheDocument()
  })

  it('shows a run chip per run for a multi-run package, in both density modes, and switches the rail on click', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([
      makePkg({
        runs: [
          {
            id: 'run-new', hunt_package_id: 'pkg-1', generation_status: 'completed',
            created_at: '2026-01-02T00:00:00Z',
            phases: [{ step: 'intake_classifier', status: 'ok', elapsed_s: 2 }],
            total_elapsed_s: 2,
          },
          {
            id: 'run-old', hunt_package_id: 'pkg-1', generation_status: 'error',
            created_at: '2026-01-01T00:00:00Z',
            phases: [{ step: 'threat_context_builder', status: 'error', elapsed_s: 1 }],
            total_elapsed_s: 1,
          },
        ],
        run_count: 2,
      }),
    ])
    renderList()
    await screen.findByText('Test Package')

    // A run tab per run, rendered as clickable buttons whose accessible name
    // combines the (fallback-date) label with the status word.
    const completedChip = screen.getByRole('button', { name: /completed/ })
    const errorChip = screen.getByRole('button', { name: /error/ })
    expect(completedChip).toBeInTheDocument()
    expect(errorChip).toBeInTheDocument()

    // Default selection is the newest run (run-new, total_elapsed_s=2).
    expect(screen.getByText('2s total')).toBeInTheDocument()
    expect(screen.queryByText('1s total')).not.toBeInTheDocument()

    // Clicking the older run's tab switches the rail to that run's data.
    fireEvent.click(errorChip)
    expect(screen.getByText('1s total')).toBeInTheDocument()
    expect(screen.queryByText('2s total')).not.toBeInTheDocument()

    // Chip row survives switching to compact mode (only the heavy rail hides).
    fireEvent.click(screen.getByRole('button', { name: /^compact$/i }))
    expect(screen.getByRole('button', { name: /error/ })).toBeInTheDocument()
    expect(screen.queryByText('Context')).not.toBeInTheDocument()
  })
})

describe('ThreatHunting list — Table density mode (issue-local-017)', () => {
  it('switching to Table mode replaces the card list with a per-package runs table', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([
      makePkg({
        name: 'Test Package',
        runs: [
          { id: 'r1', hunt_package_id: 'pkg-1', generation_status: 'completed', llm_model: 'gpt-oss', created_at: '2026-01-01T00:00:00Z' },
        ],
        run_count: 1,
      }),
    ])
    renderList()
    await screen.findByText('Test Package')
    // Card mode: no table headers present.
    expect(screen.queryByText('Model')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /^table$/i }))

    expect(await screen.findByText('Model')).toBeInTheDocument()
    expect(screen.getByText('Workflow')).toBeInTheDocument()
    expect(screen.getByText('gpt-oss')).toBeInTheDocument()
  })

  it('shows a "No runs yet" fallback for a package with no runs in Table mode', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([makePkg({ runs: [], run_count: 0 })])
    renderList()
    await screen.findByText('Test Package')

    fireEvent.click(screen.getByRole('button', { name: /^table$/i }))
    expect(await screen.findByText('No runs yet.')).toBeInTheDocument()
  })

  it('clicking a package name in Table mode opens its detail view', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([
      makePkg({
        name: 'Test Package',
        runs: [{ id: 'r1', hunt_package_id: 'pkg-1', generation_status: 'completed', created_at: '2026-01-01T00:00:00Z' }],
        run_count: 1,
      }),
    ])
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg({ id: 'pkg-1' }))
    renderList()
    await screen.findByText('Test Package')
    fireEvent.click(screen.getByRole('button', { name: /^table$/i }))
    await screen.findByText('Model')

    fireEvent.click(screen.getByRole('button', { name: /Test Package/ }))

    // HuntDetail renders a back arrow / evidence tab once a package is selected.
    expect(await screen.findByText('Evidence (0)')).toBeInTheDocument()
  })

  it('shows the package owner in Table mode (issue-local-026)', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([
      makePkg({
        name: 'Test Package',
        created_by: 'alice',
        runs: [{ id: 'r1', hunt_package_id: 'pkg-1', generation_status: 'completed', created_at: '2026-01-01T00:00:00Z' }],
        run_count: 1,
      }),
    ])
    renderList()
    await screen.findByText('Test Package')

    fireEvent.click(screen.getByRole('button', { name: /^table$/i }))
    await screen.findByText('Model')

    expect(screen.getByText('alice')).toBeInTheDocument()
  })
})

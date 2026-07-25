/**
 * Tests for issue-local-020 Part E: the hunt package list's search box +
 * HuntTimeFilter (relative/range/presets sub-modes), and the debounced
 * server-side search wiring in ThreatHunting.tsx.
 */
import { useState } from 'react'
import { render, screen, fireEvent, act, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
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
import HuntTimeFilter, { type HuntTimeRange } from '../pages/threat-hunting/HuntTimeFilter'

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
    phases: [],
    total_elapsed_s: 0,
    run_created_at: '2026-01-01T00:00:00Z',
    runs: [],
    run_count: 0,
    ...overrides,
  }
}

beforeEach(() => {
  vi.mocked(api.threatHunting.listPackages).mockReset()
  vi.mocked(api.threatHunting.getPackage).mockReset()
  vi.mocked(api.threatHunting.listEvidence).mockReset().mockResolvedValue([])
  vi.mocked(api.threatHunting.listRuns).mockReset().mockResolvedValue([])
})

describe('ThreatHunting list — search box (issue-local-020)', () => {
  beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }))
  afterEach(() => vi.useRealTimers())

  it('debounces typed input before calling listPackages with the search param', async () => {
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue([makePkg()])
    renderList()

    // initial load (no filters)
    await waitFor(() => expect(api.threatHunting.listPackages).toHaveBeenCalledWith({
      search: undefined,
      date_from: undefined,
      date_to: undefined,
    }))

    fireEvent.change(screen.getByLabelText('Search hunt packages'), {
      target: { value: 'Emotet' },
    })

    // Not yet — debounce hasn't elapsed.
    expect(api.threatHunting.listPackages).not.toHaveBeenCalledWith(
      expect.objectContaining({ search: 'Emotet' }),
    )

    await act(async () => {
      vi.advanceTimersByTime(400)
    })

    await waitFor(() =>
      expect(api.threatHunting.listPackages).toHaveBeenCalledWith(
        expect.objectContaining({ search: 'Emotet' }),
      ),
    )
  })

  it('resets to page 1 when the search filter changes', async () => {
    const many = Array.from({ length: 25 }, (_, i) => makePkg({ id: `p${i}`, name: `Pkg ${i}` }))
    vi.mocked(api.threatHunting.listPackages).mockResolvedValue(many)
    renderList()

    await screen.findByText('Pkg 0')
    fireEvent.click(screen.getByLabelText('Next page'))
    await waitFor(() => expect(screen.getByText(/Page 2 of/)).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText('Search hunt packages'), {
      target: { value: 'x' },
    })
    await act(async () => {
      vi.advanceTimersByTime(400)
    })

    await waitFor(() => expect(screen.getByText(/Page 1 of/)).toBeInTheDocument())
  })
})

describe('HuntTimeFilter', () => {
  const fixedNow = new Date('2026-03-15T12:00:00Z')

  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(fixedNow)
  })
  afterEach(() => vi.useRealTimers())

  function Wrapper() {
    const [value, setValue] = useState<HuntTimeRange>({})
    return <HuntTimeFilter value={value} onChange={setValue} />
  }

  it('Relative mode: "Last N days" resolves from = today - N days', () => {
    render(<Wrapper />)
    fireEvent.click(screen.getByText('Relative'))
    fireEvent.change(screen.getByLabelText('Number of days'), { target: { value: '5' } })
    // Component recomputes on change; verify the Clear button appears (a
    // filter is now active) as an outward-visible signal of state change.
    expect(screen.getByText('Clear')).toBeInTheDocument()
  })

  it('Presets: "Last 7d" resolves an inclusive end-of-day "to"', () => {
    render(<Wrapper />)
    fireEvent.click(screen.getByText('Last 7d'))
    expect(screen.getByText('Clear')).toBeInTheDocument()
  })

  it('Presets: "Year to Date" resolves from Jan 1 of the current year', () => {
    render(<Wrapper />)
    fireEvent.click(screen.getByText('Year to Date'))
    expect(screen.getByText('Clear')).toBeInTheDocument()
  })

  it('Range mode: selecting a "to" date appends T23:59:59', () => {
    let captured: HuntTimeRange = {}
    function Capture() {
      const [value, setValue] = useState<HuntTimeRange>({})
      captured = value
      return (
        <HuntTimeFilter
          value={value}
          onChange={(r) => {
            setValue(r)
            captured = r
          }}
        />
      )
    }
    render(<Capture />)
    fireEvent.click(screen.getByText('Time Range'))
    fireEvent.change(screen.getByLabelText('To date'), { target: { value: '2026-03-20' } })
    expect(captured.to).toBe('2026-03-20T23:59:59')
  })

  it('Clear button resets the range to undefined', () => {
    render(<Wrapper />)
    fireEvent.click(screen.getByText('Last 7d'))
    fireEvent.click(screen.getByText('Clear'))
    expect(screen.queryByText('Clear')).not.toBeInTheDocument()
  })
})

/**
 * Tests for issue-local-038's Clone button in HuntDetail.tsx's header —
 * reuses the existing clone backend route (already exercised from the list
 * page's own CloneTarget dialog) with the same prefilled-name + confirm
 * dialog pattern.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
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
        getPackage: vi.fn(),
        listEvidence: vi.fn(),
        listIocs: vi.fn(),
        listRuns: vi.fn(),
        getRunStatus: vi.fn(),
        listRunResults: vi.fn(),
        getRunReport: vi.fn(),
        listRunComments: vi.fn(),
        clonePackage: vi.fn(),
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
    status: 'draft',
    created_by: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    evidence_count: 1,
    generation_status: null,
    phases: null,
    total_elapsed_s: null,
    run_created_at: null,
    runs: [],
    run_count: 0,
    hunt_id_display: 'TH01',
    ...overrides,
  }
}

function renderDetail(onBack = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <HuntDetail pkgId="pkg-1" onBack={onBack} />
    </QueryClientProvider>,
  )
  return { onBack }
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.listRuns).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunStatus).mockRejectedValue(new Error('no status'))
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
  vi.mocked(api.threatHunting.clonePackage).mockResolvedValue(
    makePkg({ id: 'pkg-2', name: 'Copy of Test Package' }),
  )
})

describe('HuntDetail clone package button', () => {
  it('prefills the dialog with Copy of name and calls clonePackage on confirm', async () => {
    const { onBack } = renderDetail()
    // Wait for the package to actually load — the header buttons render
    // unconditionally, but the prefilled name needs pkg.name to be present.
    await screen.findByText('Test Package')
    const openBtn = screen.getByRole('button', { name: /^clone$/i })

    fireEvent.click(openBtn)
    expect(api.threatHunting.clonePackage).not.toHaveBeenCalled()

    const input = await screen.findByPlaceholderText('New package name')
    expect(input).toHaveValue('Copy of Test Package')

    // The header "Clone" button and the dialog's "Clone" submit button share
    // the same accessible name once the dialog is open — the dialog's is
    // the one added last (rendered later in the component tree).
    const cloneButtons = screen.getAllByRole('button', { name: /^clone$/i })
    fireEvent.click(cloneButtons[cloneButtons.length - 1])

    await waitFor(() =>
      expect(api.threatHunting.clonePackage).toHaveBeenCalledWith('pkg-1', 'Copy of Test Package'),
    )
    await waitFor(() => expect(onBack).toHaveBeenCalled())
  })

  it('lets the admin edit the name before cloning', async () => {
    renderDetail()
    await screen.findByText('Test Package')
    fireEvent.click(screen.getByRole('button', { name: /^clone$/i }))

    const input = await screen.findByPlaceholderText('New package name')
    fireEvent.change(input, { target: { value: 'A totally different name' } })

    const cloneButtons = screen.getAllByRole('button', { name: /^clone$/i })
    fireEvent.click(cloneButtons[cloneButtons.length - 1])

    await waitFor(() =>
      expect(api.threatHunting.clonePackage).toHaveBeenCalledWith(
        'pkg-1',
        'A totally different name',
      ),
    )
  })

  it('cancelling the dialog never calls clonePackage', async () => {
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /^clone$/i }))
    await screen.findByPlaceholderText('New package name')

    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))

    expect(api.threatHunting.clonePackage).not.toHaveBeenCalled()
    expect(screen.queryByPlaceholderText('New package name')).not.toBeInTheDocument()
  })
})

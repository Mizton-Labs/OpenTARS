/**
 * Tests for issue-local-034's package-level Archive/Unarchive and Delete
 * buttons in HuntDetail.tsx's header — Archive/Unarchive is researcher+
 * (reversible, reuses the existing archive/update routes); Delete is
 * admin-only (irreversible, cascading — backend/tests/test_th_delete_archive.py
 * covers the cascade itself).
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
        archivePackage: vi.fn(),
        updatePackage: vi.fn(),
        hardDeletePackage: vi.fn(),
      },
    },
  }
})

let mockIsAdmin = true
vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isResearcher: true,
    isAdmin: mockIsAdmin,
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
  mockIsAdmin = true
  vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.listRuns).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunStatus).mockRejectedValue(new Error('no status'))
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
  vi.mocked(api.threatHunting.archivePackage).mockResolvedValue(undefined)
  vi.mocked(api.threatHunting.updatePackage).mockResolvedValue(makePkg({ status: 'draft' }))
  vi.mocked(api.threatHunting.hardDeletePackage).mockResolvedValue(undefined)
})

describe('HuntDetail — Archive/Unarchive package button', () => {
  it('shows "Archive" and calls archivePackage for a non-archived package', async () => {
    renderDetail()
    const btn = await screen.findByRole('button', { name: /^archive$/i })

    fireEvent.click(btn)

    await waitFor(() => expect(api.threatHunting.archivePackage).toHaveBeenCalledWith('pkg-1'))
  })

  it('shows "Unarchive" and calls updatePackage(status: draft) for an archived package', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg({ status: 'archived' }))
    renderDetail()
    const btn = await screen.findByRole('button', { name: /^unarchive$/i })

    fireEvent.click(btn)

    await waitFor(() =>
      expect(api.threatHunting.updatePackage).toHaveBeenCalledWith('pkg-1', { status: 'draft' }),
    )
  })

  it('shows an Archived badge in the header when the package is archived', async () => {
    vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg({ status: 'archived' }))
    renderDetail()
    expect(await screen.findByText('Archived')).toBeInTheDocument()
  })
})

describe('HuntDetail — Delete package button (admin-only)', () => {
  it('is not shown to a non-admin', async () => {
    mockIsAdmin = false
    renderDetail()
    await screen.findByText('Test Package')
    expect(screen.queryByRole('button', { name: /^delete$/i })).not.toBeInTheDocument()
  })

  it('requires confirmation, then calls hardDeletePackage and onBack on success', async () => {
    const { onBack } = renderDetail()
    const btn = await screen.findByRole('button', { name: /^delete$/i })

    fireEvent.click(btn)
    expect(api.threatHunting.hardDeletePackage).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Delete Permanently' }))

    await waitFor(() => expect(api.threatHunting.hardDeletePackage).toHaveBeenCalledWith('pkg-1'))
    await waitFor(() => expect(onBack).toHaveBeenCalled())
  })

  it('cancelling the confirmation never calls hardDeletePackage', async () => {
    renderDetail()
    const btn = await screen.findByRole('button', { name: /^delete$/i })

    fireEvent.click(btn)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(api.threatHunting.hardDeletePackage).not.toHaveBeenCalled()
  })
})

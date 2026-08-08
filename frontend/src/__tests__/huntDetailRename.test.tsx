/**
 * Tests for the Rename button (issue-local-042, item 1+2) — added to
 * HuntDetail.tsx's action-button row (now on its own row below the title,
 * per item 2). Reuses the existing PUT /packages/{id} route via
 * api.threatHunting.updatePackage — no new backend endpoint.
 */
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
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
        updatePackage: vi.fn(),
      },
    },
  }
})

function mockAuth(overrides: { isResearcher?: boolean } = {}) {
  vi.doMock('../auth/useAuth', () => ({
    useAuth: () => ({
      isResearcher: overrides.isResearcher ?? true,
      isAdmin: true,
      authEnabled: false,
      isAuthenticated: true,
      loading: false,
      user: null,
    }),
  }))
}

function makePkg(overrides: Partial<THuntPackage> = {}): THuntPackage {
  return {
    id: 'pkg-1',
    name: 'Original Name',
    description: '',
    status: 'draft',
    created_by: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    evidence_count: 0,
    generation_status: null,
    phases: [],
    total_elapsed_s: null,
    run_created_at: null,
    runs: [],
    run_count: 0,
    ...overrides,
  }
}

async function renderDetail() {
  mockAuth()
  const { api } = await import('../api/client')
  const HuntDetail = (await import('../pages/threat-hunting/HuntDetail')).default
  vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.listRuns).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunStatus).mockRejectedValue(new Error('no status'))
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
  vi.mocked(api.threatHunting.updatePackage).mockResolvedValue(makePkg({ name: 'New Name' }))

  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <HuntDetail pkgId="pkg-1" onBack={() => {}} />
    </QueryClientProvider>,
  )
  return { api }
}

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
})

describe('Rename hunt package (issue-local-042)', () => {
  it('opens a dialog pre-filled with the current name', async () => {
    await renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /Rename/ }))
    expect(screen.getByDisplayValue('Original Name')).toBeInTheDocument()
  })

  it('disables Rename until the name actually changes', async () => {
    await renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /Rename/ }))
    const dialog = screen.getByText('Rename Hunt Package').closest('div') as HTMLElement
    expect(within(dialog).getByRole('button', { name: 'Rename' })).toBeDisabled()
  })

  it('calls updatePackage with the new name and closes on success', async () => {
    const { api } = await renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: /Rename/ }))
    const dialog = screen.getByText('Rename Hunt Package').closest('div') as HTMLElement
    const input = screen.getByDisplayValue('Original Name')
    fireEvent.change(input, { target: { value: 'New Name' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Rename' }))

    await waitFor(() =>
      expect(api.threatHunting.updatePackage).toHaveBeenCalledWith('pkg-1', { name: 'New Name' }),
    )
    await waitFor(() => expect(screen.queryByDisplayValue('New Name')).not.toBeInTheDocument())
  })
})

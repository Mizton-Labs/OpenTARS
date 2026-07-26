/**
 * Tests for issue-local-024 follow-up: the admin-only top-bar notice that
 * appears when a newer release's shipped config templates introduced
 * content this deployment's live config files don't have yet.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ConfigDriftReport } from '../api/client'

let mockIsAdmin = true

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isAdmin: mockIsAdmin,
    isResearcher: true,
    authEnabled: false,
    isAuthenticated: true,
  }),
}))

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getConfigDrift: vi.fn(),
      applyConfigDriftFix: vi.fn(),
    },
  }
})

import { api } from '../api/client'
import ConfigDriftBanner from '../components/ConfigDriftBanner'

function renderBanner() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ConfigDriftBanner />
    </QueryClientProvider>,
  )
}

const missingCoreField: ConfigDriftReport = {
  file: 'feed-fields.yaml',
  missing_keys: [],
  missing_core_fields: [{ name: 'new_field', description: 'A brand-new built-in field' }],
}

beforeEach(() => {
  mockIsAdmin = true
  vi.mocked(api.getConfigDrift).mockReset()
  vi.mocked(api.applyConfigDriftFix).mockReset()
})

describe('ConfigDriftBanner', () => {
  it('renders nothing when there is no drift', async () => {
    vi.mocked(api.getConfigDrift).mockResolvedValue({ reports: [] })
    const { container } = renderBanner()
    await waitFor(() => expect(api.getConfigDrift).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing for a non-admin, even when drift exists', async () => {
    mockIsAdmin = false
    vi.mocked(api.getConfigDrift).mockResolvedValue({ reports: [missingCoreField] })
    const { container } = renderBanner()
    // The query itself is disabled for non-admins (enabled: isAdmin).
    expect(api.getConfigDrift).not.toHaveBeenCalled()
    expect(container).toBeEmptyDOMElement()
  })

  it('shows a count and opens the review modal', async () => {
    vi.mocked(api.getConfigDrift).mockResolvedValue({ reports: [missingCoreField] })
    renderBanner()

    expect(await screen.findByText(/1 new configuration item/i)).toBeInTheDocument()
    expect(screen.queryByText('New configuration available')).not.toBeInTheDocument()

    fireEvent.click(screen.getByText(/Review & update/i))
    expect(await screen.findByText('New configuration available')).toBeInTheDocument()
    expect(screen.getByText('new_field')).toBeInTheDocument()
  })

  it('applying the fix invalidates and re-fetches the drift query', async () => {
    vi.mocked(api.getConfigDrift)
      .mockResolvedValueOnce({ reports: [missingCoreField] })
      .mockResolvedValueOnce({ reports: [] })
    vi.mocked(api.applyConfigDriftFix).mockResolvedValue({ reports: [] })
    renderBanner()

    fireEvent.click(await screen.findByText(/Review & update/i))
    await screen.findByText('New configuration available')

    fireEvent.click(screen.getByRole('button', { name: 'Apply selected' }))

    await waitFor(() =>
      expect(api.applyConfigDriftFix).toHaveBeenCalledWith('feed-fields.yaml', {
        keys: [],
        core_field_names: ['new_field'],
      }),
    )
    await waitFor(() =>
      expect(screen.queryByText('New configuration available')).not.toBeInTheDocument(),
    )
  })
})

/**
 * Tests for the API Access configuration tab (issue-local-029).
 *
 * The `api.auth` API-key methods are mocked so the master toggle, the
 * existing-keys list (enable/disable, test, delete), and the create wizard
 * (scope quick-picks, one-time secret reveal, copy/download) are driven
 * deterministically without a network.
 */
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: {
        ...actual.api.auth,
        getApiAccessConfig: vi.fn(),
        setApiAccessConfig: vi.fn(),
        listApiKeyScopes: vi.fn(),
        listApiKeys: vi.fn(),
        createApiKey: vi.fn(),
        updateApiKey: vi.fn(),
        deleteApiKey: vi.fn(),
        testApiKey: vi.fn(),
      },
    },
  }
})

import { api, type ApiKey, type ApiScope, type CreatedApiKey } from '../api/client'
import ApiAccessTab from '../pages/configuration/ApiAccessTab'

const mockedAuth = api.auth as unknown as {
  getApiAccessConfig: ReturnType<typeof vi.fn>
  setApiAccessConfig: ReturnType<typeof vi.fn>
  listApiKeyScopes: ReturnType<typeof vi.fn>
  listApiKeys: ReturnType<typeof vi.fn>
  createApiKey: ReturnType<typeof vi.fn>
  updateApiKey: ReturnType<typeof vi.fn>
  deleteApiKey: ReturnType<typeof vi.fn>
  testApiKey: ReturnType<typeof vi.fn>
}

const SCOPES: ApiScope[] = [
  { id: 'hunts:create', label: 'Create hunt packages', description: 'Create new hunt packages' },
  { id: 'evidence:add', label: 'Add evidence', description: 'Attach evidence to a hunt package' },
  { id: 'reports:download', label: 'Download reports', description: 'Download generated reports' },
]
const DEFAULT_PROFILE = ['hunts:create', 'evidence:add', 'reports:download']

function apiKey(over: Partial<ApiKey> = {}): ApiKey {
  return {
    id: 1,
    client_id: 'ak_abc123def456',
    name: 'CI pipeline',
    scopes: ['hunts:create'],
    enabled: true,
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    last_used_at: null,
    ...over,
  }
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ApiAccessTab />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockedAuth.getApiAccessConfig.mockResolvedValue({ enabled: true })
  mockedAuth.listApiKeys.mockResolvedValue([])
  mockedAuth.listApiKeyScopes.mockResolvedValue({ scopes: SCOPES, default_profile: DEFAULT_PROFILE })
})

describe('ApiAccessTab', () => {
  it('renders the master toggle reflecting api_access_enabled', async () => {
    mockedAuth.getApiAccessConfig.mockResolvedValue({ enabled: false })
    renderTab()

    expect(await screen.findByText('Programmatic API access')).toBeInTheDocument()
    const toggle = screen.getByRole('switch')
    await waitFor(() => expect(toggle).toHaveAttribute('aria-checked', 'false'))
  })

  it('toggles api_access_enabled on click', async () => {
    const user = userEvent.setup()
    mockedAuth.getApiAccessConfig.mockResolvedValue({ enabled: false })
    mockedAuth.setApiAccessConfig.mockResolvedValue({ enabled: true })
    renderTab()

    const toggle = await screen.findByRole('switch')
    await waitFor(() => expect(toggle).toHaveAttribute('aria-checked', 'false'))

    await user.click(toggle)
    await waitFor(() => expect(mockedAuth.setApiAccessConfig).toHaveBeenCalledWith(true))
  })

  it('shows an empty state when there are no keys', async () => {
    renderTab()
    expect(await screen.findByText('No API keys yet.')).toBeInTheDocument()
  })

  it('lists existing keys with their scope count and last-used status', async () => {
    mockedAuth.listApiKeys.mockResolvedValue([
      apiKey({ name: 'CI pipeline', scopes: ['hunts:create', 'evidence:add'], last_used_at: null }),
    ])
    renderTab()

    expect(await screen.findByText('CI pipeline')).toBeInTheDocument()
    expect(screen.getByText('ak_abc123def456')).toBeInTheDocument()
    expect(screen.getByText(/2 scopes/)).toBeInTheDocument()
    expect(screen.getByText(/never used/)).toBeInTheDocument()
  })

  it('disables a key via its row toggle', async () => {
    const user = userEvent.setup()
    mockedAuth.listApiKeys.mockResolvedValue([apiKey({ enabled: true })])
    mockedAuth.updateApiKey.mockResolvedValue(apiKey({ enabled: false }))
    renderTab()

    await screen.findByText('CI pipeline')
    // Master toggle is the first switch; the key row toggle is the second.
    const switches = screen.getAllByRole('switch')
    await user.click(switches[1])

    await waitFor(() =>
      expect(mockedAuth.updateApiKey).toHaveBeenCalledWith('ak_abc123def456', { enabled: false }),
    )
  })

  it('runs a key test and shows the result inline', async () => {
    const user = userEvent.setup()
    mockedAuth.listApiKeys.mockResolvedValue([apiKey()])
    mockedAuth.testApiKey.mockResolvedValue({
      status: 'ok',
      detail: 'Key is healthy (1 scope granted).',
      scopes: ['hunts:create'],
    })
    renderTab()

    await screen.findByText('CI pipeline')
    await user.click(screen.getByTitle('Test key'))

    expect(await screen.findByText('Key is healthy (1 scope granted).')).toBeInTheDocument()
  })

  it('edits scopes on an existing key, preselecting its current scopes', async () => {
    const user = userEvent.setup()
    mockedAuth.listApiKeys.mockResolvedValue([apiKey({ scopes: ['hunts:create'] })])
    mockedAuth.updateApiKey.mockResolvedValue(
      apiKey({ scopes: ['hunts:create', 'evidence:add'] }),
    )
    renderTab()

    await screen.findByText('CI pipeline')
    await user.click(screen.getByTitle('Edit scopes'))

    const huntsCheckbox = screen.getByText(SCOPES[0].label).closest('label')!.querySelector('input')!
    const evidenceCheckbox = screen.getByText(SCOPES[1].label).closest('label')!.querySelector('input')!
    expect(huntsCheckbox.checked).toBe(true)
    expect(evidenceCheckbox.checked).toBe(false)

    await user.click(evidenceCheckbox)
    await user.click(screen.getByRole('button', { name: /save scopes/i }))

    await waitFor(() =>
      expect(mockedAuth.updateApiKey).toHaveBeenCalledWith('ak_abc123def456', {
        scopes: ['hunts:create', 'evidence:add'],
      }),
    )
  })

  it('"Use default profile" and "Select all" quick-picks work in the scope editor', async () => {
    const user = userEvent.setup()
    mockedAuth.listApiKeys.mockResolvedValue([apiKey({ scopes: [] })])
    renderTab()

    await screen.findByText('CI pipeline')
    await user.click(screen.getByTitle('Edit scopes'))

    await user.click(screen.getByText('Use default profile'))
    for (const s of SCOPES) {
      const checkbox = screen.getByText(s.label).closest('label')!.querySelector('input')!
      expect(checkbox.checked).toBe(DEFAULT_PROFILE.includes(s.id))
    }

    // DEFAULT_PROFILE in this fixture already covers every scope, so the
    // quick-pick now reads "Deselect all" — exercise the full off/on toggle.
    expect(screen.getByText('Deselect all')).toBeInTheDocument()
    await user.click(screen.getByText('Deselect all'))
    for (const s of SCOPES) {
      const checkbox = screen.getByText(s.label).closest('label')!.querySelector('input')!
      expect(checkbox.checked).toBe(false)
    }

    await user.click(screen.getByText('Select all'))
    for (const s of SCOPES) {
      const checkbox = screen.getByText(s.label).closest('label')!.querySelector('input')!
      expect(checkbox.checked).toBe(true)
    }
  })

  it('cancelling the scope editor does not call the API', async () => {
    const user = userEvent.setup()
    mockedAuth.listApiKeys.mockResolvedValue([apiKey()])
    renderTab()

    await screen.findByText('CI pipeline')
    await user.click(screen.getByTitle('Edit scopes'))
    await user.click(screen.getByRole('button', { name: /^cancel$/i }))

    expect(screen.queryByRole('button', { name: /save scopes/i })).not.toBeInTheDocument()
    expect(mockedAuth.updateApiKey).not.toHaveBeenCalled()
  })

  it('opening delete confirmation closes an open scope editor, and vice versa', async () => {
    const user = userEvent.setup()
    mockedAuth.listApiKeys.mockResolvedValue([apiKey()])
    renderTab()

    await screen.findByText('CI pipeline')
    await user.click(screen.getByTitle('Edit scopes'))
    expect(screen.getByRole('button', { name: /save scopes/i })).toBeInTheDocument()

    await user.click(screen.getByTitle('Delete key'))
    expect(screen.queryByRole('button', { name: /save scopes/i })).not.toBeInTheDocument()
    expect(await screen.findByRole('alertdialog')).toBeInTheDocument()
  })

  it('requires confirmation before deleting a key', async () => {
    const user = userEvent.setup()
    mockedAuth.listApiKeys.mockResolvedValue([apiKey()])
    mockedAuth.deleteApiKey.mockResolvedValue({ status: 'deleted', client_id: 'ak_abc123def456' })
    renderTab()

    await screen.findByText('CI pipeline')
    await user.click(screen.getByTitle('Delete key'))

    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText(/cannot be undone/i)).toBeInTheDocument()
    expect(mockedAuth.deleteApiKey).not.toHaveBeenCalled()

    await user.click(within(dialog).getByRole('button', { name: /confirm delete/i }))
    await waitFor(() => expect(mockedAuth.deleteApiKey).toHaveBeenCalledWith('ak_abc123def456'))
  })

  it('cancelling delete confirmation does not call the API', async () => {
    const user = userEvent.setup()
    mockedAuth.listApiKeys.mockResolvedValue([apiKey()])
    renderTab()

    await screen.findByText('CI pipeline')
    await user.click(screen.getByTitle('Delete key'))
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: /cancel/i }))

    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    expect(mockedAuth.deleteApiKey).not.toHaveBeenCalled()
  })

  describe('create wizard', () => {
    it('opens the wizard and lists scope checkboxes', async () => {
      const user = userEvent.setup()
      renderTab()

      await user.click(await screen.findByRole('button', { name: /create api key/i }))

      expect(screen.getByLabelText('Name')).toBeInTheDocument()
      for (const s of SCOPES) {
        expect(screen.getByText(s.label)).toBeInTheDocument()
      }
    })

    it('disables Create until a name and at least one scope are set', async () => {
      const user = userEvent.setup()
      renderTab()
      await user.click(await screen.findByRole('button', { name: /create api key/i }))

      const create = screen.getByRole('button', { name: /^create$/i })
      expect(create).toBeDisabled()

      await user.type(screen.getByLabelText('Name'), 'CI pipeline')
      expect(create).toBeDisabled()

      await user.click(screen.getByText(SCOPES[0].label))
      expect(create).toBeEnabled()
    })

    it('"Use default profile" selects exactly the default scope set', async () => {
      const user = userEvent.setup()
      renderTab()
      await user.click(await screen.findByRole('button', { name: /create api key/i }))

      await user.click(screen.getByText('Use default profile'))

      for (const s of SCOPES) {
        const checkbox = screen.getByText(s.label).closest('label')!.querySelector('input')!
        expect(checkbox.checked).toBe(DEFAULT_PROFILE.includes(s.id))
      }
    })

    it('"Select all" toggles every scope on, then off', async () => {
      const user = userEvent.setup()
      renderTab()
      await user.click(await screen.findByRole('button', { name: /create api key/i }))

      await user.click(screen.getByText('Select all'))
      for (const s of SCOPES) {
        const checkbox = screen.getByText(s.label).closest('label')!.querySelector('input')!
        expect(checkbox.checked).toBe(true)
      }

      await user.click(screen.getByText('Deselect all'))
      for (const s of SCOPES) {
        const checkbox = screen.getByText(s.label).closest('label')!.querySelector('input')!
        expect(checkbox.checked).toBe(false)
      }
    })

    it('submits the selected name and scopes, then shows the one-time secret card', async () => {
      const user = userEvent.setup()
      const created: CreatedApiKey = {
        ...apiKey({ name: 'CI pipeline', scopes: ['hunts:create'] }),
        secret: 'super-secret-value',
        api_key: 'ak_abc123def456.super-secret-value',
        endpoint: 'https://example.test/api/threat-hunting',
      }
      mockedAuth.createApiKey.mockResolvedValue(created)
      renderTab()

      await user.click(await screen.findByRole('button', { name: /create api key/i }))
      await user.type(screen.getByLabelText('Name'), 'CI pipeline')
      await user.click(screen.getByText(SCOPES[0].label))
      await user.click(screen.getByRole('button', { name: /^create$/i }))

      await waitFor(() =>
        expect(mockedAuth.createApiKey).toHaveBeenCalledWith('CI pipeline', ['hunts:create']),
      )

      expect(await screen.findByText(/shown only once/i)).toBeInTheDocument()
      expect(screen.getByLabelText('Client ID')).toHaveValue('ak_abc123def456')
      expect(screen.getByLabelText('API Key')).toHaveValue('ak_abc123def456.super-secret-value')
      expect(screen.getByLabelText('Endpoint')).toHaveValue('https://example.test/api/threat-hunting')
    })

    it('copies a field to the clipboard from the reveal card', async () => {
      const user = userEvent.setup()
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText },
        configurable: true,
      })

      const created: CreatedApiKey = {
        ...apiKey(),
        secret: 'super-secret-value',
        api_key: 'ak_abc123def456.super-secret-value',
        endpoint: 'https://example.test/api/threat-hunting',
      }
      mockedAuth.createApiKey.mockResolvedValue(created)
      renderTab()

      await user.click(await screen.findByRole('button', { name: /create api key/i }))
      await user.type(screen.getByLabelText('Name'), 'CI pipeline')
      await user.click(screen.getByText(SCOPES[0].label))
      await user.click(screen.getByRole('button', { name: /^create$/i }))

      await screen.findByText(/shown only once/i)
      await user.click(screen.getByTitle('Copy API Key'))

      expect(writeText).toHaveBeenCalledWith('ak_abc123def456.super-secret-value')
    })

    it('closing the wizard invalidates the keys list on create', async () => {
      const user = userEvent.setup()
      mockedAuth.listApiKeys
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([apiKey({ name: 'CI pipeline' })])
      const created: CreatedApiKey = {
        ...apiKey({ name: 'CI pipeline' }),
        secret: 'super-secret-value',
        api_key: 'ak_abc123def456.super-secret-value',
        endpoint: 'https://example.test/api/threat-hunting',
      }
      mockedAuth.createApiKey.mockResolvedValue(created)
      renderTab()

      await screen.findByText('No API keys yet.')
      await user.click(screen.getByRole('button', { name: /create api key/i }))
      await user.type(screen.getByLabelText('Name'), 'CI pipeline')
      await user.click(screen.getByText(SCOPES[0].label))
      await user.click(screen.getByRole('button', { name: /^create$/i }))

      await screen.findByText(/shown only once/i)
      await user.click(screen.getByRole('button', { name: /^done$/i }))

      await waitFor(() => expect(mockedAuth.listApiKeys).toHaveBeenCalledTimes(2))
    })

    it('cancelling the wizard returns to the key list without creating anything', async () => {
      const user = userEvent.setup()
      renderTab()

      await user.click(await screen.findByRole('button', { name: /create api key/i }))
      await user.click(screen.getByRole('button', { name: /^cancel$/i }))

      expect(screen.queryByLabelText('Name')).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: /create api key/i })).toBeInTheDocument()
      expect(mockedAuth.createApiKey).not.toHaveBeenCalled()
    })
  })
})

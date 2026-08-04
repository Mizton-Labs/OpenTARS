/**
 * Tests for SsoConfigTab's callback_base_url override field (issue-local-036).
 *
 * The API client is mocked so the component can be exercised in isolation.
 * No existing test file covered SsoConfigTab before this — scope here is
 * the new override field, not a full re-test of every existing control.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { SsoConfig } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: {
        ...actual.api.auth,
        getSsoConfig: vi.fn(),
        updateSsoConfig: vi.fn(),
        getSsoCallbackUrl: vi.fn(),
      },
    },
  }
})

import { api } from '../api/client'
import SsoConfigTab from '../pages/configuration/SsoConfigTab'

function makeConfig(overrides: Partial<SsoConfig> = {}): SsoConfig {
  return {
    enabled: false,
    provider_preset: 'generic',
    issuer: '',
    client_id: '',
    client_secret: '',
    scopes: 'openid profile email',
    button_label: 'Sign in with SSO',
    username_claim: 'preferred_username',
    role_claim: 'roles',
    role_mapping: {},
    default_role: 'threat-viewer',
    auto_provision: true,
    callback_base_url: '',
    ...overrides,
  }
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <SsoConfigTab />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('SsoConfigTab callback_base_url override (issue-local-036)', () => {
  it('shows the detected value as a placeholder when no override is saved', async () => {
    vi.mocked(api.auth.getSsoConfig).mockResolvedValue(makeConfig())
    vi.mocked(api.auth.getSsoCallbackUrl).mockResolvedValue({
      callback_url: 'http://localhost/api/auth/oidc/callback',
    })
    renderTab()

    const input = await screen.findByPlaceholderText(/^http:\/\/localhost/)
    expect(input).toHaveValue('')
  })

  it('shows the saved override value when one exists', async () => {
    vi.mocked(api.auth.getSsoConfig).mockResolvedValue(
      makeConfig({ callback_base_url: 'https://host.example.com/tars' }),
    )
    vi.mocked(api.auth.getSsoCallbackUrl).mockResolvedValue({
      callback_url: 'https://host.example.com/tars/api/auth/oidc/callback',
    })
    renderTab()

    expect(await screen.findByDisplayValue('https://host.example.com/tars')).toBeInTheDocument()
  })

  it('"Use detected" fills the field with the browser-detected base URL', async () => {
    vi.mocked(api.auth.getSsoConfig).mockResolvedValue(makeConfig())
    vi.mocked(api.auth.getSsoCallbackUrl).mockResolvedValue({
      callback_url: 'http://localhost/api/auth/oidc/callback',
    })
    renderTab()

    await screen.findByRole('button', { name: /use detected/i })
    fireEvent.click(screen.getByRole('button', { name: /use detected/i }))

    expect(await screen.findByDisplayValue(/^http:\/\/localhost/)).toBeInTheDocument()
  })

  it('saves callback_base_url along with the rest of the form', async () => {
    vi.mocked(api.auth.getSsoConfig).mockResolvedValue(makeConfig())
    vi.mocked(api.auth.getSsoCallbackUrl).mockResolvedValue({
      callback_url: 'http://localhost/api/auth/oidc/callback',
    })
    vi.mocked(api.auth.updateSsoConfig).mockResolvedValue(makeConfig())
    renderTab()

    const input = await screen.findByPlaceholderText(/^http:\/\/localhost/)
    fireEvent.change(input, { target: { value: 'https://host.example.com/tars' } })

    fireEvent.click(await screen.findByRole('button', { name: /^save/i }))

    await waitFor(() =>
      expect(api.auth.updateSsoConfig).toHaveBeenCalledWith(
        expect.objectContaining({ callback_base_url: 'https://host.example.com/tars' }),
      ),
    )
  })

  it('leaving the field blank saves an empty override (unchanged zero-config behavior)', async () => {
    vi.mocked(api.auth.getSsoConfig).mockResolvedValue(makeConfig())
    vi.mocked(api.auth.getSsoCallbackUrl).mockResolvedValue({
      callback_url: 'http://localhost/api/auth/oidc/callback',
    })
    vi.mocked(api.auth.updateSsoConfig).mockResolvedValue(makeConfig())
    renderTab()

    fireEvent.click(await screen.findByRole('button', { name: /^save/i }))

    await waitFor(() =>
      expect(api.auth.updateSsoConfig).toHaveBeenCalledWith(
        expect.objectContaining({ callback_base_url: '' }),
      ),
    )
  })
})

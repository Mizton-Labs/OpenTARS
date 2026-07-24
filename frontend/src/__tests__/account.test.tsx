/**
 * Account page tests (prompts-046).
 *
 * The Account page replaces the former Configuration > Account tab. It shows
 * the signed-in identity and embeds the shared ChangePasswordCard in self mode.
 * The API client and useAuth hook are mocked so the page is exercised in
 * isolation.
 */
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { AuthUser } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      auth: { changePassword: vi.fn(), setOwnTheme: vi.fn() },
      getDefaultTheme: vi.fn().mockResolvedValue({ theme: 'classic' }),
    },
  }
})

vi.mock('../auth/useAuth', () => ({ useAuth: vi.fn() }))

import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import Account from '../pages/Account'
import { ThemeProvider } from '../theme/ThemeProvider'

const selfUser: AuthUser = { id: 7, username: 'reader', role: 'threat-viewer', enabled: true }

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(useAuth).mockReturnValue({
    loading: false,
    authEnabled: true,
    user: selfUser,
    isAuthenticated: true,
    isAdmin: false,
    isResearcher: false,
    isViewer: true,
    passwordPolicy: { min_length: 8, required_classes: 3, max_bytes: 72 },
    ssoEnabled: false,
    ssoButtonLabel: 'Sign in with SSO',
    login: vi.fn(),
    logout: vi.fn(),
    refresh: vi.fn(),
  })
})

function renderAccount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ThemeProvider>
        <Account />
      </ThemeProvider>
    </QueryClientProvider>,
  )
}

describe('Account page', () => {
  it('shows the signed-in username and role', () => {
    renderAccount()
    expect(screen.getByText('reader')).toBeInTheDocument()
    expect(screen.getByText('threat-viewer')).toBeInTheDocument()
  })

  it('blocks submission when the new password reuses the current one', () => {
    renderAccount()
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'Adminpass1' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Adminpass1' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'Adminpass1' } })
    expect(screen.getByText(/must differ from the current password/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /change password/i })).toBeDisabled()
  })

  it('blocks submission when the new password fails the policy', () => {
    renderAccount()
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'Adminpass1' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'lowercase12' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'lowercase12' } })
    expect(screen.getByText(/must include at least 3 of/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /change password/i })).toBeDisabled()
  })

  it('submits a valid self change-password and confirms success', async () => {
    vi.mocked(api.auth.changePassword).mockResolvedValue({ status: 'password_changed' })
    renderAccount()
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'Adminpass1' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Newpass123' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'Newpass123' } })
    fireEvent.click(screen.getByRole('button', { name: /change password/i }))

    await waitFor(() => {
      expect(api.auth.changePassword).toHaveBeenCalledWith('Adminpass1', 'Newpass123')
    })
    expect(await screen.findByText('Password changed.')).toBeInTheDocument()
  })
})

describe('Account page theme selector (issue-local-016)', () => {
  it('shows Classic, Energy, Light, and "use instance default" options', async () => {
    renderAccount()
    expect(await screen.findByText('Classic')).toBeInTheDocument()
    expect(screen.getByText('Energy')).toBeInTheDocument()
    expect(screen.getByText('Light')).toBeInTheDocument()
    expect(screen.getByText(/use instance default/i)).toBeInTheDocument()
  })

  it('selecting Light calls setOwnTheme and marks it active (issue-local-017)', async () => {
    vi.mocked(api.auth.setOwnTheme).mockResolvedValue({
      id: 7, username: 'reader', role: 'threat-viewer', enabled: true, theme: 'light',
    })
    renderAccount()
    fireEvent.click(await screen.findByText('Light'))

    await waitFor(() => expect(api.auth.setOwnTheme).toHaveBeenCalledWith('light'))
    const lightButton = screen.getByText('Light').closest('button')
    await waitFor(() => expect(lightButton).toHaveTextContent('Active'))
  })

  it('defaults to "use instance default" as active when the user has no override', async () => {
    renderAccount()
    const defaultOption = (await screen.findByText(/use instance default/i)).closest('button')
    expect(defaultOption).toHaveTextContent('Active')
  })

  it('selecting Energy calls setOwnTheme and marks it active', async () => {
    vi.mocked(api.auth.setOwnTheme).mockResolvedValue({
      id: 7, username: 'reader', role: 'threat-viewer', enabled: true, theme: 'energy',
    })
    renderAccount()
    fireEvent.click(await screen.findByText('Energy'))

    await waitFor(() => expect(api.auth.setOwnTheme).toHaveBeenCalledWith('energy'))
    const energyButton = screen.getByText('Energy').closest('button')
    await waitFor(() => expect(energyButton).toHaveTextContent('Active'))
  })
})

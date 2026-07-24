/**
 * Tests for the auth-gated Configuration tabs (prompts-045):
 * AccountTab (self-service password change) and UserManagementTab (admin).
 *
 * The API client and useAuth hook are both mocked so the components can be
 * exercised in isolation without an AuthProvider or real network.
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
      auth: {
        changePassword: vi.fn(),
        listUsers: vi.fn(),
        createUser: vi.fn(),
        setUserRole: vi.fn(),
        setUserEnabled: vi.fn(),
        resetUserPassword: vi.fn(),
        deleteUser: vi.fn(),
      },
    },
  }
})

vi.mock('../auth/useAuth', () => ({ useAuth: vi.fn() }))

import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import UserManagementTab from '../pages/configuration/UserManagementTab'

const selfAdmin: AuthUser = { id: 1, username: 'admin', role: 'admin', enabled: true }

function mockAuth(user: AuthUser) {
  vi.mocked(useAuth).mockReturnValue({
    loading: false,
    authEnabled: true,
    user,
    isAuthenticated: true,
    isAdmin: user.role === 'admin',
    isResearcher: user.role === 'admin' || user.role === 'threat-researcher',
    isViewer: true,
    passwordPolicy: { min_length: 8, required_classes: 3, max_bytes: 72 },
    ssoEnabled: false,
    ssoButtonLabel: 'Sign in with SSO',
    login: vi.fn(),
    logout: vi.fn(),
    refresh: vi.fn(),
  })
}

function renderWithClient(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>)
}

beforeEach(() => {
  vi.clearAllMocks()
  mockAuth(selfAdmin)
})

describe('UserManagementTab (prompts-045)', () => {
  const users: AuthUser[] = [
    selfAdmin,
    { id: 2, username: 'analyst', role: 'threat-viewer', enabled: true },
  ]

  it('lists users and marks the current user', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue(users)
    renderWithClient(<UserManagementTab />)
    await screen.findByRole('button', { name: /add user/i })
    expect(screen.getByText('analyst')).toBeInTheDocument()
    expect(screen.getByText('(you)')).toBeInTheDocument()
  })

  it('disables the delete button for the current user', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue(users)
    renderWithClient(<UserManagementTab />)
    await screen.findByRole('button', { name: /add user/i })
    const deleteButtons = screen.getAllByTitle(/delete/i)
    // First row is self → its delete control is disabled.
    expect(deleteButtons[0]).toBeDisabled()
    expect(deleteButtons[1]).not.toBeDisabled()
  })

  it('deletes another user after an inline confirmation (prompts-049)', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue(users)
    vi.mocked(api.auth.deleteUser).mockResolvedValue({ status: 'deleted', id: 2 })
    renderWithClient(<UserManagementTab />)
    await screen.findByText('analyst')

    // First click only arms the confirm panel — the API is NOT called yet.
    fireEvent.click(screen.getAllByTitle('Delete user')[0])
    expect(await screen.findByTestId('delete-confirm-2')).toBeInTheDocument()
    expect(api.auth.deleteUser).not.toHaveBeenCalled()

    // Confirm fires the delete.
    fireEvent.click(screen.getByTestId('delete-confirm-yes-2'))
    await waitFor(() => expect(api.auth.deleteUser).toHaveBeenCalledWith(2))
  })

  it('cancels an armed delete without calling the API (prompts-049)', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue(users)
    renderWithClient(<UserManagementTab />)
    await screen.findByText('analyst')

    fireEvent.click(screen.getAllByTitle('Delete user')[0])
    expect(await screen.findByTestId('delete-confirm-2')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))

    await waitFor(() =>
      expect(screen.queryByTestId('delete-confirm-2')).not.toBeInTheDocument(),
    )
    expect(api.auth.deleteUser).not.toHaveBeenCalled()
  })

  it('creates a new user (with confirm + policy, prompts-046)', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue([selfAdmin])
    vi.mocked(api.auth.createUser).mockResolvedValue({
      id: 3, username: 'newbie', role: 'threat-viewer', enabled: true,
    })
    renderWithClient(<UserManagementTab />)
    await screen.findByRole('button', { name: /add user/i })

    fireEvent.click(screen.getByRole('button', { name: /add user/i }))
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newbie' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Secret123' } })
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'Secret123' } })
    fireEvent.click(screen.getByRole('button', { name: /^create$/i }))

    await waitFor(() => {
      expect(api.auth.createUser).toHaveBeenCalledWith({
        username: 'newbie', password: 'Secret123', role: 'threat-viewer',
      })
    })
  })

  it('creates a feed-sender account via the role dropdown (prompts-054)', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue([selfAdmin])
    vi.mocked(api.auth.createUser).mockResolvedValue({
      id: 4, username: 'bot', role: 'feed-sender', enabled: true,
    })
    renderWithClient(<UserManagementTab />)
    fireEvent.click(await screen.findByRole('button', { name: /add user/i }))
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'bot' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Secret123' } })
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'Secret123' } })
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'feed-sender' } })
    fireEvent.click(screen.getByRole('button', { name: /^create$/i }))

    await waitFor(() => {
      expect(api.auth.createUser).toHaveBeenCalledWith({
        username: 'bot', password: 'Secret123', role: 'feed-sender',
      })
    })
  })

  it('blocks create when the password fails the policy (prompts-046)', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue([selfAdmin])
    renderWithClient(<UserManagementTab />)
    fireEvent.click(await screen.findByRole('button', { name: /add user/i }))
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newbie' } })
    // Only lowercase + digits → 2 of 4 classes, policy requires 3.
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'lowercase12' } })
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'lowercase12' } })
    expect(screen.getByText(/must include at least 3 of/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^create$/i })).toBeDisabled()
  })

  it('blocks create when the confirmation does not match (prompts-046)', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue([selfAdmin])
    renderWithClient(<UserManagementTab />)
    fireEvent.click(await screen.findByRole('button', { name: /add user/i }))
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newbie' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Secret123' } })
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'Secret124' } })
    expect(screen.getByText(/do not match/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^create$/i })).toBeDisabled()
  })

  it('surfaces a backend rejection (e.g. last-admin guard)', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue([selfAdmin, { id: 2, username: 'bob', role: 'admin', enabled: true }])
    vi.mocked(api.auth.deleteUser).mockRejectedValue(new Error('400 Bad Request: Cannot delete the last admin'))
    renderWithClient(<UserManagementTab />)
    await screen.findByText('bob')
    fireEvent.click(screen.getAllByTitle('Delete user')[0])
    fireEvent.click(await screen.findByTestId('delete-confirm-yes-2'))
    expect(await screen.findByRole('alert')).toHaveTextContent(/last admin/i)
  })

  it('generates a random password on explicit confirm and shows it read-only (issue-local-016)', async () => {
    vi.mocked(api.auth.listUsers).mockResolvedValue(users)
    vi.mocked(api.auth.resetUserPassword).mockResolvedValue({
      status: 'password_reset',
      username: 'analyst',
      generated_password: 'r4nd0m-gener4ted-p4ssw0rd',
    })
    renderWithClient(<UserManagementTab />)
    await screen.findByText('analyst')

    fireEvent.click(screen.getAllByTitle('Reset password')[1])
    // First click into the modal must NOT call the API yet — requires an
    // explicit "Generate new password" click inside it.
    expect(await screen.findByRole('button', { name: /generate new password/i })).toBeInTheDocument()
    expect(api.auth.resetUserPassword).not.toHaveBeenCalled()
    // No editable password fields — nothing left for the admin to type.
    expect(screen.queryByLabelText(/new password/i)).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /generate new password/i }))
    await waitFor(() => expect(api.auth.resetUserPassword).toHaveBeenCalledWith(2))

    const field = await screen.findByLabelText('Generated password')
    expect(field).toHaveValue('r4nd0m-gener4ted-p4ssw0rd')
    expect(field).toHaveAttribute('readonly')
    expect(screen.getByTitle('Copy to clipboard')).toBeInTheDocument()
  })
})

// ── Configuration.tsx — User Management moved to General group ──────────────

describe('Configuration tab groups (issue-local-016)', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('shows User Management under General, not Threat Intel', async () => {
    const userEventModule = await import('@testing-library/user-event')
    const user = userEventModule.default.setup()

    vi.doMock('../auth/useAuth', () => ({
      useAuth: () => ({
        authEnabled: true,
        isAdmin: true,
        isResearcher: true,
        isViewer: true,
        isAuthenticated: true,
        loading: false,
        user: selfAdmin,
      }),
    }))

    vi.doMock('../api/client', async () => {
      const original = await vi.importActual<typeof import('../api/client')>('../api/client')
      return {
        ...original,
        api: {
          ...original.api,
          getAppTitle: vi.fn().mockResolvedValue({ app_title: '' }),
          getAppBasePrefix: vi.fn().mockResolvedValue({ app_base_prefix: '' }),
          getLogoInfo: vi.fn().mockResolvedValue({ has_logo: false }),
          getDefaultTheme: vi.fn().mockResolvedValue({ theme: 'classic' }),
          setDefaultTheme: vi.fn().mockResolvedValue({ theme: 'energy' }),
          auth: { ...original.api.auth, listUsers: vi.fn().mockResolvedValue([selfAdmin]) },
        },
      }
    })

    const { default: Configuration } = await import('../pages/Configuration')
    const { QueryClient, QueryClientProvider } = await import('@tanstack/react-query')
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}>{<Configuration />}</QueryClientProvider>)

    // Default landing group is Threat Intel — User Management must not be there.
    expect(screen.queryByRole('button', { name: /user management/i })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /^general$/i }))
    expect(await screen.findByRole('button', { name: /user management/i })).toBeInTheDocument()
  })

  it('renders the Default Theme picker under General > Application and saves a selection', async () => {
    const userEventModule = await import('@testing-library/user-event')
    const user = userEventModule.default.setup()

    vi.doMock('../auth/useAuth', () => ({
      useAuth: () => ({
        authEnabled: true,
        isAdmin: true,
        isResearcher: true,
        isViewer: true,
        isAuthenticated: true,
        loading: false,
        user: selfAdmin,
      }),
    }))

    const setDefaultTheme = vi.fn().mockResolvedValue({ theme: 'energy' })
    vi.doMock('../api/client', async () => {
      const original = await vi.importActual<typeof import('../api/client')>('../api/client')
      return {
        ...original,
        api: {
          ...original.api,
          getAppTitle: vi.fn().mockResolvedValue({ app_title: '' }),
          getAppBasePrefix: vi.fn().mockResolvedValue({ app_base_prefix: '' }),
          getLogoInfo: vi.fn().mockResolvedValue({ has_logo: false }),
          getDefaultTheme: vi.fn().mockResolvedValue({ theme: 'classic' }),
          setDefaultTheme,
          auth: { ...original.api.auth, listUsers: vi.fn().mockResolvedValue([selfAdmin]) },
        },
      }
    })

    const { default: Configuration } = await import('../pages/Configuration')
    const { QueryClient, QueryClientProvider } = await import('@tanstack/react-query')
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}>{<Configuration />}</QueryClientProvider>)

    await user.click(screen.getByRole('button', { name: /^general$/i }))
    expect(await screen.findByText('Default Theme')).toBeInTheDocument()
    expect(screen.getByText('Classic')).toBeInTheDocument()
    expect(screen.getByText('Energy')).toBeInTheDocument()
    expect(screen.getByText('Light')).toBeInTheDocument()

    await user.click(screen.getByText('Energy'))
    await waitFor(() => expect(setDefaultTheme).toHaveBeenCalledWith('energy'))
  })

  it('shows Global Field Defaults under Threat Intel, not General', async () => {
    const userEventModule = await import('@testing-library/user-event')
    const user = userEventModule.default.setup()

    vi.doMock('../auth/useAuth', () => ({
      useAuth: () => ({
        authEnabled: false,
        isAdmin: true,
        isResearcher: true,
        isViewer: true,
        isAuthenticated: true,
        loading: false,
        user: null,
      }),
    }))

    vi.doMock('../api/client', async () => {
      const original = await vi.importActual<typeof import('../api/client')>('../api/client')
      return {
        ...original,
        api: {
          ...original.api,
          getAppTitle: vi.fn().mockResolvedValue({ app_title: '' }),
          getAppBasePrefix: vi.fn().mockResolvedValue({ app_base_prefix: '' }),
          getLogoInfo: vi.fn().mockResolvedValue({ has_logo: false }),
          getDefaultTheme: vi.fn().mockResolvedValue({ theme: 'classic' }),
        },
      }
    })

    const { default: Configuration } = await import('../pages/Configuration')
    const { QueryClient, QueryClientProvider } = await import('@tanstack/react-query')
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}>{<Configuration />}</QueryClientProvider>)

    // Default landing group is Threat Intel — the tab should already be there.
    expect(await screen.findByRole('button', { name: /global field defaults/i })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /^general$/i }))
    expect(screen.queryByRole('button', { name: /global field defaults/i })).not.toBeInTheDocument()
  })
})

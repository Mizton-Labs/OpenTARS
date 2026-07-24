/**
 * ThemeProvider / useTheme tests (issue-local-016).
 *
 * useAuth and the api client are mocked so ThemeProvider can be exercised in
 * isolation, mirroring the mocking style used for AuthProvider/UserManagementTab
 * tests elsewhere in this directory.
 */
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { AuthUser } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getDefaultTheme: vi.fn(),
      auth: {
        ...actual.api.auth,
        setOwnTheme: vi.fn(),
      },
    },
  }
})

vi.mock('../auth/useAuth', () => ({ useAuth: vi.fn() }))

import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { ThemeProvider } from '../theme/ThemeProvider'
import { useTheme } from '../theme/useTheme'

function mockUser(user: AuthUser | null) {
  vi.mocked(useAuth).mockReturnValue({
    loading: false,
    authEnabled: true,
    user,
    isAuthenticated: user !== null,
    isAdmin: user?.role === 'admin',
    isResearcher: true,
    isViewer: true,
    passwordPolicy: { min_length: 8, required_classes: 3, max_bytes: 72 },
    ssoEnabled: false,
    ssoButtonLabel: 'Sign in with SSO',
    login: vi.fn(),
    logout: vi.fn(),
    refresh: vi.fn(),
  })
}

function Probe() {
  const { theme, userOverride, instanceDefault, setTheme } = useTheme()
  return (
    <div>
      <span data-testid="theme">{theme}</span>
      <span data-testid="override">{userOverride ?? 'null'}</span>
      <span data-testid="default">{instanceDefault}</span>
      <button onClick={() => { setTheme('energy').catch(() => {}) }}>set energy</button>
      <button onClick={() => { setTheme(null).catch(() => {}) }}>clear</button>
    </div>
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  document.documentElement.removeAttribute('data-theme')
})

describe('ThemeProvider (issue-local-016)', () => {
  it('falls back to the instance default when the user has no override', async () => {
    vi.mocked(api.getDefaultTheme).mockResolvedValue({ theme: 'energy' })
    mockUser({ id: 1, username: 'bob', role: 'threat-viewer', enabled: true, theme: null })

    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )

    await waitFor(() => expect(screen.getByTestId('default')).toHaveTextContent('energy'))
    expect(screen.getByTestId('override')).toHaveTextContent('null')
    expect(screen.getByTestId('theme')).toHaveTextContent('energy')
    expect(document.documentElement.getAttribute('data-theme')).toBe('energy')
  })

  it("prefers the user's personal override over the instance default", async () => {
    vi.mocked(api.getDefaultTheme).mockResolvedValue({ theme: 'classic' })
    mockUser({ id: 1, username: 'bob', role: 'threat-viewer', enabled: true, theme: 'energy' })

    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )

    await waitFor(() => expect(screen.getByTestId('theme')).toHaveTextContent('energy'))
    expect(screen.getByTestId('override')).toHaveTextContent('energy')
    expect(document.documentElement.getAttribute('data-theme')).toBe('energy')
  })

  it('defaults to classic for a logged-out visitor with no configured default', async () => {
    vi.mocked(api.getDefaultTheme).mockRejectedValue(new Error('network'))
    mockUser(null)

    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )

    await waitFor(() => expect(screen.getByTestId('theme')).toHaveTextContent('classic'))
  })

  it('optimistically applies setTheme and persists via the API', async () => {
    vi.mocked(api.getDefaultTheme).mockResolvedValue({ theme: 'classic' })
    vi.mocked(api.auth.setOwnTheme).mockResolvedValue({
      id: 1, username: 'bob', role: 'threat-viewer', enabled: true, theme: 'energy',
    })
    mockUser({ id: 1, username: 'bob', role: 'threat-viewer', enabled: true, theme: null })

    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('theme')).toHaveTextContent('classic'))

    await act(async () => {
      fireEvent.click(screen.getByText('set energy'))
    })

    expect(api.auth.setOwnTheme).toHaveBeenCalledWith('energy')
    expect(screen.getByTestId('theme')).toHaveTextContent('energy')
    expect(document.documentElement.getAttribute('data-theme')).toBe('energy')
  })

  it('rolls back the optimistic update when the API call fails', async () => {
    vi.mocked(api.getDefaultTheme).mockResolvedValue({ theme: 'classic' })
    vi.mocked(api.auth.setOwnTheme).mockRejectedValue(new Error('boom'))
    mockUser({ id: 1, username: 'bob', role: 'threat-viewer', enabled: true, theme: null })

    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('theme')).toHaveTextContent('classic'))

    await act(async () => {
      fireEvent.click(screen.getByText('set energy'))
    })

    await waitFor(() => expect(screen.getByTestId('theme')).toHaveTextContent('classic'))
    expect(screen.getByTestId('override')).toHaveTextContent('null')
  })

  it('clearing the override (setTheme(null)) falls back to the instance default', async () => {
    vi.mocked(api.getDefaultTheme).mockResolvedValue({ theme: 'classic' })
    vi.mocked(api.auth.setOwnTheme).mockResolvedValue({
      id: 1, username: 'bob', role: 'threat-viewer', enabled: true, theme: null,
    })
    mockUser({ id: 1, username: 'bob', role: 'threat-viewer', enabled: true, theme: 'energy' })

    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('theme')).toHaveTextContent('energy'))

    await act(async () => {
      fireEvent.click(screen.getByText('clear'))
    })

    expect(api.auth.setOwnTheme).toHaveBeenCalledWith(null)
    expect(screen.getByTestId('theme')).toHaveTextContent('classic')
  })
})

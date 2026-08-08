/**
 * Tests for issue-local-038's first-login onboarding wizard gate:
 *   - ProtectedLayout shows OnboardingWizard when user.onboarded === false,
 *     after the must_change_password gate (which takes priority).
 *   - The wizard defaults to the current theme/density, lets the admin pick
 *     a different one, and "Get Started" persists both + marks onboarding
 *     complete, then clears the gate via refresh().
 */
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, beforeEach, vi } from 'vitest'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      auth: {
        status: vi.fn(),
        me: vi.fn(),
        login: vi.fn(),
        logout: vi.fn(),
        changePassword: vi.fn(),
        setOwnTheme: vi.fn().mockResolvedValue({}),
        completeOwnOnboarding: vi.fn(),
      },
      getDefaultTheme: vi.fn().mockResolvedValue({ theme: 'classic' }),
      getLogoInfo: vi.fn().mockResolvedValue({ has_logo: false }),
      search: {
        status: vi.fn().mockResolvedValue({ available: false, reason: null, provider: null }),
        query: vi.fn().mockResolvedValue({ query: '', total: 0, sections: [] }),
        smart: vi.fn(),
        sessions: {
          list: vi.fn().mockResolvedValue([]),
          create: vi.fn(),
          get: vi.fn(),
          update: vi.fn(),
          delete: vi.fn(),
          downloadMarkdownUrl: vi.fn(),
          downloadPdfUrl: vi.fn(),
        },
      },
    },
  }
})

import { api, type AuthUser } from '../api/client'
import { AuthProvider } from '../auth/AuthContext'
import { ThemeProvider } from '../theme/ThemeProvider'
import ProtectedLayout from '../components/ProtectedLayout'

const adminUser: AuthUser = {
  id: 1, username: 'admin', role: 'admin', enabled: true, onboarded: false,
}

function renderApp(initialPath = '/viewer') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AuthProvider>
          <ThemeProvider>
            <Routes>
              <Route path="login" element={<div>LOGIN PAGE</div>} />
              <Route element={<ProtectedLayout />}>
                <Route index element={<Navigate to="viewer" replace />} />
                <Route path="viewer" element={<div>VIEWER PAGE</div>} />
              </Route>
            </Routes>
          </ThemeProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.getDefaultTheme).mockResolvedValue({ theme: 'classic' })
  vi.mocked(api.getLogoInfo).mockResolvedValue({ has_logo: false })
  localStorage.clear()
})

describe('Onboarding wizard gate (issue-local-038)', () => {
  it('shows the wizard instead of the shell when onboarded is false', async () => {
    vi.mocked(api.auth.status).mockResolvedValue({ auth_enabled: true })
    vi.mocked(api.auth.me).mockResolvedValue({ user: adminUser })

    renderApp()

    expect(await screen.findByRole('heading', { name: /welcome to opentars/i })).toBeInTheDocument()
    expect(screen.queryByText('VIEWER PAGE')).not.toBeInTheDocument()
  })

  it('does not show the wizard when onboarded is true', async () => {
    vi.mocked(api.auth.status).mockResolvedValue({ auth_enabled: true })
    vi.mocked(api.auth.me).mockResolvedValue({ user: { ...adminUser, onboarded: true } })

    renderApp()

    expect(await screen.findByText('VIEWER PAGE')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /welcome to opentars/i })).not.toBeInTheDocument()
  })

  it('does not show the wizard when onboarded is absent (pre-existing/undefined)', async () => {
    vi.mocked(api.auth.status).mockResolvedValue({ auth_enabled: true })
    const { onboarded: _onboarded, ...withoutOnboarded } = adminUser
    vi.mocked(api.auth.me).mockResolvedValue({ user: withoutOnboarded })

    renderApp()

    expect(await screen.findByText('VIEWER PAGE')).toBeInTheDocument()
  })

  it('the must-change-password gate takes priority over the onboarding wizard', async () => {
    vi.mocked(api.auth.status).mockResolvedValue({ auth_enabled: true })
    vi.mocked(api.auth.me).mockResolvedValue({
      user: { ...adminUser, must_change_password: true, onboarded: false },
    })

    renderApp()

    expect(await screen.findByRole('heading', { name: /set a new password/i })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /welcome to opentars/i })).not.toBeInTheDocument()
  })

  it('"Get Started" completes onboarding and reveals the shell', async () => {
    vi.mocked(api.auth.status).mockResolvedValue({ auth_enabled: true })
    vi.mocked(api.auth.me)
      .mockResolvedValueOnce({ user: adminUser })
      .mockResolvedValueOnce({ user: { ...adminUser, onboarded: true } })
    vi.mocked(api.auth.completeOwnOnboarding).mockResolvedValue({ ...adminUser, onboarded: true })

    renderApp()

    await screen.findByRole('heading', { name: /welcome to opentars/i })
    fireEvent.click(screen.getByRole('button', { name: /get started/i }))

    await waitFor(() => expect(api.auth.completeOwnOnboarding).toHaveBeenCalled())
    expect(await screen.findByText('VIEWER PAGE')).toBeInTheDocument()
  })

  it('picking a different theme calls setOwnTheme with the new selection on finish', async () => {
    vi.mocked(api.auth.status).mockResolvedValue({ auth_enabled: true })
    vi.mocked(api.auth.me)
      .mockResolvedValueOnce({ user: adminUser })
      .mockResolvedValueOnce({ user: { ...adminUser, onboarded: true, theme: 'ocean' } })
    vi.mocked(api.auth.completeOwnOnboarding).mockResolvedValue({ ...adminUser, onboarded: true })

    renderApp()

    await screen.findByRole('heading', { name: /welcome to opentars/i })
    fireEvent.click(screen.getByRole('button', { name: /ocean/i }))
    fireEvent.click(screen.getByRole('button', { name: /get started/i }))

    await waitFor(() => expect(api.auth.setOwnTheme).toHaveBeenCalledWith('ocean'))
  })

  it('states clearly that the wizard is shown because this is the first sign-in (issue-local-041)', async () => {
    vi.mocked(api.auth.status).mockResolvedValue({ auth_enabled: true })
    vi.mocked(api.auth.me).mockResolvedValue({ user: adminUser })

    renderApp()

    await screen.findByRole('heading', { name: /welcome to opentars/i })
    expect(screen.getByText(/first sign-in/i)).toBeInTheDocument()
  })

  it('shows a real demo runs table in the preview, not just color swatches (issue-local-041)', async () => {
    vi.mocked(api.auth.status).mockResolvedValue({ auth_enabled: true })
    vi.mocked(api.auth.me).mockResolvedValue({ user: adminUser })

    renderApp()

    await screen.findByRole('heading', { name: /welcome to opentars/i })
    expect(screen.getByRole('table')).toBeInTheDocument()
    expect(screen.getByText('Run ID')).toBeInTheDocument()
    expect(screen.getByText('TH01-X03')).toBeInTheDocument()
    expect(screen.getAllByText('completed').length).toBeGreaterThan(0)
  })

  it('picking a different view density writes it to localStorage on finish', async () => {
    vi.mocked(api.auth.status).mockResolvedValue({ auth_enabled: true })
    vi.mocked(api.auth.me)
      .mockResolvedValueOnce({ user: adminUser })
      .mockResolvedValueOnce({ user: { ...adminUser, onboarded: true } })
    vi.mocked(api.auth.completeOwnOnboarding).mockResolvedValue({ ...adminUser, onboarded: true })

    renderApp()

    await screen.findByRole('heading', { name: /welcome to opentars/i })
    // The density button's accessible name is the label + description
    // concatenated ("Simple One line per hunt package…") — match the prefix.
    fireEvent.click(screen.getByRole('button', { name: /^simple\b/i }))
    fireEvent.click(screen.getByRole('button', { name: /get started/i }))

    await waitFor(() => expect(localStorage.getItem('sfi.th.cardDensity')).toBe('simple'))
  })
})

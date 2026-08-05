/**
 * Tests for UserManagementTab's Organization support (issue-local-037).
 *
 * The `api.auth` methods and `useAuth` are mocked so the org dropdown/
 * checkbox on Create User, the per-row "change organization" control, and
 * the post-action username notice are exercised without a network.
 */
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { AuthUser, Organization } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: {
        ...actual.api.auth,
        listUsers: vi.fn(),
        listOrganizations: vi.fn(),
        createUser: vi.fn(),
        setUserOrganization: vi.fn(),
        setUserRole: vi.fn(),
        setUserEnabled: vi.fn(),
        deleteUser: vi.fn(),
        resetUserPassword: vi.fn(),
        setUserOnboarded: vi.fn(),
      },
    },
  }
})

vi.mock('../auth/useAuth', () => ({ useAuth: vi.fn() }))

import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import UserManagementTab from '../pages/configuration/UserManagementTab'

const mockedAuth = api.auth as unknown as {
  listUsers: ReturnType<typeof vi.fn>
  listOrganizations: ReturnType<typeof vi.fn>
  createUser: ReturnType<typeof vi.fn>
  setUserOrganization: ReturnType<typeof vi.fn>
  setUserRole: ReturnType<typeof vi.fn>
  setUserEnabled: ReturnType<typeof vi.fn>
  deleteUser: ReturnType<typeof vi.fn>
  resetUserPassword: ReturnType<typeof vi.fn>
  setUserOnboarded: ReturnType<typeof vi.fn>
}

const selfUser: AuthUser = { id: 1, username: 'admin', role: 'admin', enabled: true, org_id: null }

const acme: Organization = { id: 1, name: 'Acme', email_domain: 'acme.com', user_count: 1 }

function user(over: Partial<AuthUser> = {}): AuthUser {
  return { id: 2, username: 'alice', role: 'threat-viewer', enabled: true, org_id: null, ...over }
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <UserManagementTab />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(useAuth).mockReturnValue({
    loading: false,
    authEnabled: true,
    user: selfUser,
    isAuthenticated: true,
    isAdmin: true,
    isResearcher: false,
    isViewer: false,
    passwordPolicy: { min_length: 8, required_classes: 3, max_bytes: 72 },
    ssoEnabled: false,
    ssoButtonLabel: 'Sign in with SSO',
    login: vi.fn(),
    logout: vi.fn(),
    refresh: vi.fn(),
  })
  mockedAuth.listUsers.mockResolvedValue([selfUser])
  mockedAuth.listOrganizations.mockResolvedValue([acme])
})

describe('UserManagementTab organizations', () => {
  it('shows "Local user" for a user with no org_id', async () => {
    mockedAuth.listUsers.mockResolvedValue([user({ org_id: null })])
    renderTab()
    const select = await screen.findByLabelText('Organization for alice')
    const row = select.closest('.flex.items-center') as HTMLElement
    expect(within(row).getByText(/Active · Local user/)).toBeInTheDocument()
  })

  it('resolves org_id to the organization name in the row', async () => {
    mockedAuth.listUsers.mockResolvedValue([user({ org_id: acme.id })])
    renderTab()
    const select = await screen.findByLabelText('Organization for alice')
    const row = select.closest('.flex.items-center') as HTMLElement
    expect(within(row).getByText(/Active · Acme/)).toBeInTheDocument()
  })

  it('create form: selecting an org reveals the email-username checkbox and previews the full email', async () => {
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /add user/i }))

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'bob' } })
    fireEvent.change(screen.getByLabelText('Organization'), { target: { value: String(acme.id) } })

    expect(await screen.findByLabelText(/use full email as username/i)).toBeChecked()
    expect(screen.getByText('bob@acme.com')).toBeInTheDocument()
  })

  it('create form: unchecking the email-username checkbox previews the bare local-part', async () => {
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /add user/i }))

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'bob' } })
    fireEvent.change(screen.getByLabelText('Organization'), { target: { value: String(acme.id) } })
    fireEvent.click(await screen.findByLabelText(/use full email as username/i))

    expect(screen.getByText('bob')).toBeInTheDocument()
    expect(screen.queryByText('bob@acme.com')).not.toBeInTheDocument()
  })

  it('create form: no org selected submits org_id null and shows the created username notice', async () => {
    mockedAuth.createUser.mockResolvedValue({
      ...user({ username: 'carol', org_id: null }),
      generated_password: 'generated-pw-1',
    })
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /add user/i }))

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'carol' } })
    fireEvent.click(screen.getByRole('button', { name: /^create/i }))

    await waitFor(() =>
      expect(mockedAuth.createUser).toHaveBeenCalledWith(
        expect.objectContaining({ username: 'carol', org_id: null, use_email_username: true }),
      ),
    )
    expect(await screen.findByText(/User "carol" created\./)).toBeInTheDocument()
  })

  it('create form: org selected submits the chosen org_id and use_email_username flag', async () => {
    mockedAuth.createUser.mockResolvedValue({
      ...user({ username: 'bob@acme.com', org_id: acme.id }),
      generated_password: 'generated-pw-2',
    })
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /add user/i }))

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'bob' } })
    fireEvent.change(screen.getByLabelText('Organization'), { target: { value: String(acme.id) } })
    fireEvent.click(screen.getByRole('button', { name: /^create/i }))

    await waitFor(() =>
      expect(mockedAuth.createUser).toHaveBeenCalledWith(
        expect.objectContaining({ username: 'bob', org_id: acme.id, use_email_username: true }),
      ),
    )
    expect(await screen.findByText(/User "bob@acme.com" created\./)).toBeInTheDocument()
  })

  it('changing a row\'s organization stages it behind Save, then calls setUserOrganization and shows the updated-username notice', async () => {
    mockedAuth.listUsers.mockResolvedValue([user({ id: 2, username: 'alice', org_id: null })])
    mockedAuth.setUserOrganization.mockResolvedValue(
      user({ id: 2, username: 'alice@acme.com', org_id: acme.id }),
    )
    renderTab()

    const orgSelect = await screen.findByLabelText('Organization for alice')
    fireEvent.change(orgSelect, { target: { value: String(acme.id) } })

    // issue-local-038: staged — not applied until the row's Save button is clicked.
    expect(mockedAuth.setUserOrganization).not.toHaveBeenCalled()
    fireEvent.click(await screen.findByRole('button', { name: /^save$/i }))

    await waitFor(() =>
      expect(mockedAuth.setUserOrganization).toHaveBeenCalledWith(2, {
        org_id: acme.id,
        use_email_username: true,
      }),
    )
    expect(await screen.findByText(/Username is now "alice@acme.com"\./)).toBeInTheDocument()
  })

  it('changing a row back to "Local user" passes org_id null', async () => {
    mockedAuth.listUsers.mockResolvedValue([user({ id: 2, username: 'alice@acme.com', org_id: acme.id })])
    mockedAuth.setUserOrganization.mockResolvedValue(user({ id: 2, username: 'alice', org_id: null }))
    renderTab()

    const orgSelect = await screen.findByLabelText('Organization for alice@acme.com')
    fireEvent.change(orgSelect, { target: { value: '' } })
    fireEvent.click(await screen.findByRole('button', { name: /^save$/i }))

    await waitFor(() =>
      expect(mockedAuth.setUserOrganization).toHaveBeenCalledWith(2, {
        org_id: null,
        use_email_username: true,
      }),
    )
  })
})

describe('UserManagementTab first-login wizard trigger (issue-local-038)', () => {
  it('clicking "First-login wizard" resets the onboarded flag and shows a notice', async () => {
    mockedAuth.listUsers.mockResolvedValue([user({ id: 2, username: 'alice' })])
    mockedAuth.setUserOnboarded.mockResolvedValue(user({ id: 2, username: 'alice', onboarded: false }))
    renderTab()

    const btn = await screen.findByRole('button', { name: /first-login wizard/i })
    fireEvent.click(btn)

    await waitFor(() => expect(mockedAuth.setUserOnboarded).toHaveBeenCalledWith(2, false))
    expect(
      await screen.findByText(/First-login wizard will show for "alice" on their next login\./),
    ).toBeInTheDocument()
  })
})

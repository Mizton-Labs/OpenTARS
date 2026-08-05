/**
 * Tests for OrgManagementTab (issue-local-037) — admin-only Add/List/Edit/
 * Delete organizations. The `api.auth` org methods are mocked so create,
 * inline edit, and the armed-delete-confirm (including the 409 "users
 * assigned" rejection) are exercised without a network.
 */
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { Organization } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      auth: {
        ...actual.api.auth,
        listOrganizations: vi.fn(),
        createOrganization: vi.fn(),
        updateOrganization: vi.fn(),
        deleteOrganization: vi.fn(),
      },
    },
  }
})

import { api } from '../api/client'
import OrgManagementTab from '../pages/configuration/OrgManagementTab'

const mockedAuth = api.auth as unknown as {
  listOrganizations: ReturnType<typeof vi.fn>
  createOrganization: ReturnType<typeof vi.fn>
  updateOrganization: ReturnType<typeof vi.fn>
  deleteOrganization: ReturnType<typeof vi.fn>
}

const acme: Organization = { id: 1, name: 'Acme', email_domain: 'acme.com', user_count: 0 }
const globex: Organization = { id: 2, name: 'Globex', email_domain: 'globex.com', user_count: 3 }

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <OrgManagementTab />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockedAuth.listOrganizations.mockResolvedValue([])
})

describe('OrgManagementTab', () => {
  it('shows an empty state when no organizations are configured', async () => {
    renderTab()
    expect(await screen.findByText(/no organizations configured/i)).toBeInTheDocument()
  })

  it('lists organizations with name, domain, and user count', async () => {
    mockedAuth.listOrganizations.mockResolvedValue([acme, globex])
    renderTab()
    expect(await screen.findByText('Acme')).toBeInTheDocument()
    expect(screen.getByText('acme.com')).toBeInTheDocument()
    expect(screen.getByText('0 users')).toBeInTheDocument()
    expect(screen.getByText('Globex')).toBeInTheDocument()
    expect(screen.getByText('3 users')).toBeInTheDocument()
  })

  it('creates a new organization via the Add Organization form', async () => {
    mockedAuth.createOrganization.mockResolvedValue(acme)
    renderTab()

    fireEvent.click(await screen.findByRole('button', { name: /add organization/i }))
    fireEvent.change(screen.getByLabelText('Org name'), { target: { value: 'Acme' } })
    fireEvent.change(screen.getByLabelText('Email domain'), { target: { value: 'acme.com' } })
    fireEvent.click(screen.getByRole('button', { name: /^create/i }))

    await waitFor(() =>
      expect(mockedAuth.createOrganization).toHaveBeenCalledWith({
        name: 'Acme',
        email_domain: 'acme.com',
      }),
    )
  })

  it('the Create button is disabled until both fields are filled', async () => {
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /add organization/i }))
    expect(screen.getByRole('button', { name: /^create/i })).toBeDisabled()

    fireEvent.change(screen.getByLabelText('Org name'), { target: { value: 'Acme' } })
    expect(screen.getByRole('button', { name: /^create/i })).toBeDisabled()

    fireEvent.change(screen.getByLabelText('Email domain'), { target: { value: 'acme.com' } })
    expect(screen.getByRole('button', { name: /^create/i })).toBeEnabled()
  })

  it('edits an existing organization inline', async () => {
    mockedAuth.listOrganizations.mockResolvedValue([acme])
    mockedAuth.updateOrganization.mockResolvedValue({ ...acme, name: 'Acme Corp' })
    renderTab()

    fireEvent.click(await screen.findByTitle('Edit organization'))
    const nameInput = screen.getByDisplayValue('Acme')
    fireEvent.change(nameInput, { target: { value: 'Acme Corp' } })
    fireEvent.click(screen.getByRole('button', { name: /^save/i }))

    await waitFor(() =>
      expect(mockedAuth.updateOrganization).toHaveBeenCalledWith(acme.id, {
        name: 'Acme Corp',
        email_domain: 'acme.com',
      }),
    )
  })

  it('deletes an organization after arming the confirm panel', async () => {
    mockedAuth.listOrganizations.mockResolvedValue([acme])
    mockedAuth.deleteOrganization.mockResolvedValue({ status: 'deleted', id: acme.id })
    renderTab()

    fireEvent.click(await screen.findByTitle('Delete organization'))
    fireEvent.click(await screen.findByTestId(`org-delete-confirm-yes-${acme.id}`))

    await waitFor(() => expect(mockedAuth.deleteOrganization).toHaveBeenCalledWith(acme.id))
  })

  it('surfaces a 409 error when deleting an organization with assigned users', async () => {
    mockedAuth.listOrganizations.mockResolvedValue([globex])
    mockedAuth.deleteOrganization.mockRejectedValue(
      new Error('Cannot delete: 3 user(s) are assigned to this organization'),
    )
    renderTab()

    fireEvent.click(await screen.findByTitle(/cannot delete/i))
    fireEvent.click(await screen.findByTestId(`org-delete-confirm-yes-${globex.id}`))

    expect(await screen.findByRole('alert')).toHaveTextContent(/3 user\(s\) are assigned/)
  })

  it('duplicate name/domain create shows the backend 409 error', async () => {
    mockedAuth.createOrganization.mockRejectedValue(
      new Error('Organization name or email domain already exists'),
    )
    renderTab()

    fireEvent.click(await screen.findByRole('button', { name: /add organization/i }))
    fireEvent.change(screen.getByLabelText('Org name'), { target: { value: 'Acme' } })
    fireEvent.change(screen.getByLabelText('Email domain'), { target: { value: 'acme.com' } })
    fireEvent.click(screen.getByRole('button', { name: /^create/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/already exists/)
  })
})

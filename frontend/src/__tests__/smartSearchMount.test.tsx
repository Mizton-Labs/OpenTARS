/**
 * The search drawer is offered *while the Threat Hunting module is open*
 * (issue-local-031), so this checks where ProtectedLayout actually mounts it —
 * the drawer's own behaviour is covered in smartSearchDrawer.test.tsx.
 */
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    loading: false,
    authEnabled: false,
    user: null,
    isAdmin: true,
    isResearcher: true,
    isViewer: true,
    refresh: vi.fn(),
    logout: vi.fn(),
  }),
}))

// The shell renders the sidebar and drift banner, neither of which is under
// test here; stub the endpoints they reach for so nothing hits the network.
vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getAppTitle: vi.fn().mockResolvedValue({ app_title: '' }),
      getLogoInfo: vi.fn().mockResolvedValue({ has_logo: false }),
      getConfigDrift: vi.fn().mockResolvedValue({ reports: [] }),
      search: {
        status: vi.fn().mockResolvedValue({ available: false, reason: 'off', provider: null }),
        query: vi.fn().mockResolvedValue({ query: '', total: 0, sections: [] }),
        smart: vi.fn(),
      },
    },
  }
})

import ProtectedLayout from '../components/ProtectedLayout'

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route element={<ProtectedLayout />}>
            <Route path="*" element={<div>page</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const searchButton = () => screen.queryByRole('button', { name: /search opentars/i })

beforeEach(() => vi.clearAllMocks())

describe('search drawer mounting', () => {
  it.each([
    '/threat-hunting',
    '/threat-hunting/new',
    '/threat-hunting/tracking',
    '/threat-hunting/some-package-id',
  ])('is offered on %s', (path) => {
    renderAt(path)
    expect(searchButton()).toBeInTheDocument()
  })

  it.each(['/home', '/viewer', '/configuration', '/about', '/account'])(
    'is not offered on %s',
    (path) => {
      renderAt(path)
      expect(searchButton()).not.toBeInTheDocument()
    },
  )

  it('is still offered under a reverse-proxy base prefix', () => {
    // The router basename is stripped before matching, but a defensive check:
    // a path that merely *contains* the segment must still resolve.
    renderAt('/feeds/threat-hunting')
    expect(searchButton()).toBeInTheDocument()
  })

  it('does not match a route that merely starts with the same letters', () => {
    renderAt('/threat-hunting-archive')
    expect(searchButton()).not.toBeInTheDocument()
  })
})

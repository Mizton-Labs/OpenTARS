/**
 * Where ProtectedLayout mounts the search drawer (issue-local-031).
 *
 * Search spans the whole application, so its entry point is global rather than
 * scoped to one module — and the shell reserves a right-hand gutter for it so
 * the button can never sit on top of a page's own header controls. The
 * drawer's own behaviour is covered in smartSearchDrawer.test.tsx.
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
    '/home',
    '/viewer',
    '/threat-hunting',
    '/threat-hunting/new',
    '/threat-hunting/tracking',
    '/threat-hunting/some-package-id',
    '/configuration',
    '/normalizer',
    '/watchers',
    '/assistant',
    '/account',
    '/about',
    '/feeds/threat-hunting',
  ])('is available on %s', (path) => {
    renderAt(path)
    expect(searchButton()).toBeInTheDocument()
  })

  it('sits flush in the top-right corner', () => {
    renderAt('/home')
    const cls = searchButton()!.className
    expect(cls).toContain('fixed')
    expect(cls).toContain('top-0')
    expect(cls).toContain('right-0')
  })

  it('is emphasised as a primary action, not another grey icon', () => {
    // It is the only entry point to search and sits in a corner people do not
    // habitually look at, so a plain grey button is too easy to miss.
    renderAt('/home')
    const cls = searchButton()!.className
    expect(cls).toMatch(/bg-brand-\d+/)
    expect(cls).not.toMatch(/bg-gray-\d+/)
  })

  it('reserves a right-hand gutter so it cannot cover page header controls', () => {
    // Threat Hunting puts "New Package" at the top right of its own header;
    // without this gutter the floating button would land on top of it.
    const { container } = renderAt('/threat-hunting')
    const main = container.querySelector('main')
    expect(main?.className).toMatch(/\bpr-\d+\b/)
  })
})

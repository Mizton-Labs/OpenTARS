/**
 * Sidebar section-title emphasis tests (issue-local-018, Part 6).
 *
 * The module sections (Threat Intel, Threat Hunting) should read as
 * emphasized subsection headers — brighter/bolder than the plain Home
 * section label — so the app's two product modules are visually set apart
 * from Home and the utility items in the sidebar.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../auth/useAuth', () => ({ useAuth: vi.fn() }))
vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getLogoInfo: vi.fn().mockResolvedValue({ has_logo: false }),
      getAppTitle: vi.fn().mockResolvedValue({ app_title: 'OpenTARS' }),
    },
  }
})

import { useAuth } from '../auth/useAuth'
import Sidebar from '../components/Sidebar'

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({
    authEnabled: false,
    isAdmin: true,
    isResearcher: true,
    user: null,
    logout: vi.fn(),
  } as unknown as ReturnType<typeof useAuth>)
})

function renderSidebar() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Sidebar section title emphasis', () => {
  it('gives module section labels (Threat Intel, Threat Hunting) a brand-emphasized style', () => {
    renderSidebar()
    expect(screen.getByText('Threat Intel', { selector: 'span' })).toHaveClass('text-brand-400', 'font-semibold')
    expect(screen.getByText('Threat Hunting', { selector: 'span' })).toHaveClass('text-brand-400', 'font-semibold')
  })

  it('keeps the Home section label in the plain muted style', () => {
    renderSidebar()
    expect(screen.getByText('Home', { selector: 'span' })).toHaveClass('text-gray-500', 'font-medium')
  })
})

describe('Sidebar Threat Intel Tracking nav item (issue-local-021)', () => {
  it('links to the nested threat-hunting/tracking route', () => {
    renderSidebar()
    const link = screen.getByText('Threat Intel Tracking').closest('a')
    expect(link).toHaveAttribute('href', '/threat-hunting/tracking')
  })

  it('sits under the Threat Hunting section, alongside the base Threat Hunting item', () => {
    renderSidebar()
    expect(screen.getByText('Threat Hunting', { selector: 'span' })).toBeInTheDocument()
    expect(screen.getByText('Threat Intel Tracking')).toBeInTheDocument()
  })
})

describe('Sidebar Hunt Playbooks nav item — researcherOnly gating (issue-local-041)', () => {
  it('shows for a researcher, below Data Explorer', () => {
    vi.mocked(useAuth).mockReturnValue({
      authEnabled: true,
      isAdmin: false,
      isResearcher: true,
      user: { username: 'researcher1', role: 'threat-researcher' },
      logout: vi.fn(),
    } as unknown as ReturnType<typeof useAuth>)
    renderSidebar()
    const link = screen.getByText('Hunt Playbooks').closest('a')
    expect(link).toHaveAttribute('href', '/threat-hunting/playbooks')
  })

  it('shows for an admin', () => {
    vi.mocked(useAuth).mockReturnValue({
      authEnabled: true,
      isAdmin: true,
      isResearcher: false,
      user: { username: 'admin1', role: 'admin' },
      logout: vi.fn(),
    } as unknown as ReturnType<typeof useAuth>)
    renderSidebar()
    expect(screen.getByText('Hunt Playbooks')).toBeInTheDocument()
  })

  it('is hidden for a plain viewer', () => {
    vi.mocked(useAuth).mockReturnValue({
      authEnabled: true,
      isAdmin: false,
      isResearcher: false,
      user: { username: 'viewer1', role: 'threat-viewer' },
      logout: vi.fn(),
    } as unknown as ReturnType<typeof useAuth>)
    renderSidebar()
    expect(screen.queryByText('Hunt Playbooks')).not.toBeInTheDocument()
  })
})

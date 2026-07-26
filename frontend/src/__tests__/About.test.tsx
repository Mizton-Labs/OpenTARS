/**
 * About page tests (prompts-051).
 *
 * Verifies the rebrand display name, the Credits row (Code Dev Team), and the
 * License card that points to the LICENSE and THIRD-PARTY-NOTICES.md files.
 * The API client is mocked so the page renders in isolation; the health query
 * is irrelevant to the assertions below.
 */
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi } from 'vitest'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: { health: vi.fn().mockResolvedValue({ status: 'ok', version: '0.1.0' }) },
  }
})

import About from '../pages/About'

function renderAbout() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <About />
    </QueryClientProvider>,
  )
}

describe('About page (prompts-051)', () => {
  it('shows the OpenTARS brand name', () => {
    renderAbout()
    expect(screen.getByText('OpenTARS')).toBeInTheDocument()
  })

  it('credits the code dev team with a repo link and author list', () => {
    renderAbout()
    expect(screen.getByText('Code Dev Team')).toBeInTheDocument()
    // The link shows the repository slug as visible text and links to the repo.
    const repo = screen.getByRole('link', { name: /Mizton-Labs\/Mizton-ThreatBox/ })
    expect(repo).toHaveAttribute('href', 'https://github.com/Mizton-Labs/Mizton-ThreatBox')
    expect(repo).toHaveTextContent('Mizton-Labs/Mizton-ThreatBox')
    // The primary author @jusafing is always listed first.
    const authorLink = screen.getByRole('link', { name: '@jusafing' })
    expect(authorLink).toHaveAttribute('href', 'https://github.com/jusafing')
    // "HoneyMex Lab" plain text is no longer rendered (replaced by author list).
    expect(screen.queryByText('HoneyMex Lab')).toBeNull()
  })

  it('shows the License card referencing the license files', () => {
    renderAbout()
    expect(screen.getByRole('heading', { name: 'License' })).toBeInTheDocument()
    expect(screen.getByText(/Apache License 2.0/)).toBeInTheDocument()
    expect(screen.getByText('LICENSE')).toBeInTheDocument()
    expect(screen.getByText('THIRD-PARTY-NOTICES.md')).toBeInTheDocument()
  })

  it('shows the git branch alongside the git commit (issue-local-016)', () => {
    renderAbout()
    expect(screen.getByText('Git Commit')).toBeInTheDocument()
    expect(screen.getByText('Git Branch')).toBeInTheDocument()
    // vitest runs with the same vite.config.ts `define` as a real build, so
    // __GIT_BRANCH__/__GIT_COMMIT_DATE__ both fall back to their 'unknown'
    // default (no GIT_BRANCH/GIT_COMMIT_DATE env vars set for the test
    // runner) — assert both fallbacks render, not a blank/undefined value.
    expect(screen.getAllByText('unknown')).toHaveLength(2)
  })

  it('shows the commit date alongside the commit', () => {
    renderAbout()
    expect(screen.getByText('Commit Date')).toBeInTheDocument()
  })
})

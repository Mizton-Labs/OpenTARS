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
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      health: vi.fn().mockResolvedValue({ status: 'ok', version: '0.1.0' }),
      getDoc: vi.fn().mockResolvedValue({ doc_id: 'api-threat-hunting', content: '# API Reference\n\nSome docs.' }),
    },
  }
})

import About from '../pages/About'

function renderAbout() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  // About reads ?tab= to deep-link a tab (issue-local-031), so it needs a
  // router context — it always has one in the app.
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <About />
      </MemoryRouter>
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
    const repo = screen.getByRole('link', { name: /Mizton-Labs\/OpenTARS/ })
    expect(repo).toHaveAttribute('href', 'https://github.com/Mizton-Labs/OpenTARS')
    expect(repo).toHaveTextContent('Mizton-Labs/OpenTARS')
    // The primary author @jusafing is always listed first.
    const authorLink = screen.getByRole('link', { name: '@jusafing' })
    expect(authorLink).toHaveAttribute('href', 'https://github.com/jusafing')
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

describe('About page tabs (issue-local-030)', () => {
  it('defaults to the General tab', () => {
    renderAbout()
    expect(screen.getByRole('button', { name: 'General' })).toHaveClass('tab-active')
    expect(screen.getByRole('button', { name: 'API Docs' })).toHaveClass('tab-inactive')
    expect(screen.getByRole('button', { name: 'API Swagger' })).toHaveClass('tab-inactive')
    // General-tab-only content is visible by default.
    expect(screen.getByText('Code Dev Team')).toBeInTheDocument()
  })

  it('offers General, API Docs and API Swagger as separate tabs', () => {
    renderAbout()
    for (const label of ['General', 'API Docs', 'API Swagger']) {
      expect(screen.getByRole('button', { name: label })).toBeInTheDocument()
    }
  })

  it('switches to the API Docs tab and hides General content', async () => {
    const userEventModule = await import('@testing-library/user-event')
    const user = userEventModule.default.setup()
    renderAbout()

    await user.click(screen.getByRole('button', { name: 'API Docs' }))

    expect(screen.getByRole('button', { name: 'API Docs' })).toHaveClass('tab-active')
    expect(screen.queryByText('Code Dev Team')).not.toBeInTheDocument()
  })

  it('switches to the API Swagger tab and hides General content', async () => {
    const userEventModule = await import('@testing-library/user-event')
    const user = userEventModule.default.setup()
    renderAbout()

    await user.click(screen.getByRole('button', { name: 'API Swagger' }))

    expect(screen.getByRole('button', { name: 'API Swagger' })).toHaveClass('tab-active')
    expect(screen.queryByText('Code Dev Team')).not.toBeInTheDocument()
    // Lazily loaded, so the iframe itself appears once the chunk resolves.
    expect(await screen.findByTitle('OpenTARS API Swagger UI')).toBeInTheDocument()
  })
})

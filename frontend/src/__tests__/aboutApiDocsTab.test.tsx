/**
 * Tests for the About page's API Docs tab (issue-local-030).
 *
 * The API client's `getDoc` is mocked so the Markdown render and loading/
 * error states are driven deterministically without a network. `swaggerUiSrc`
 * is exercised for real (no network call itself — it just builds a relative
 * URL string) to confirm the iframe points at the right location.
 */
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getDoc: vi.fn(),
    },
  }
})

import { api } from '../api/client'
import ApiDocsTab from '../pages/about/ApiDocsTab'

const mockedGetDoc = api.getDoc as unknown as ReturnType<typeof vi.fn>

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ApiDocsTab />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('ApiDocsTab', () => {
  it('shows a loading state before the doc resolves', () => {
    mockedGetDoc.mockReturnValue(new Promise(() => {})) // never resolves
    renderTab()
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('renders the fetched Markdown as real HTML', async () => {
    mockedGetDoc.mockResolvedValue({
      doc_id: 'api-threat-hunting',
      content: '# Threat Hunting API Reference\n\nSome **bold** intro text.\n\n## Authentication\n\nDetails here.',
    })
    renderTab()

    expect(await screen.findByRole('heading', { name: 'Threat Hunting API Reference', level: 1 })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Authentication', level: 2 })).toBeInTheDocument()
    const bold = screen.getByText('bold')
    expect(bold.tagName).toBe('STRONG')
  })

  it('renders a Markdown table with styled cells', async () => {
    mockedGetDoc.mockResolvedValue({
      doc_id: 'api-threat-hunting',
      content: '| Method | Path |\n|---|---|\n| GET | /packages |',
    })
    renderTab()

    expect(await screen.findByRole('columnheader', { name: 'Method' })).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: 'GET' })).toBeInTheDocument()
  })

  it('shows an error message if the doc fetch fails', async () => {
    mockedGetDoc.mockRejectedValue(new Error('boom'))
    renderTab()

    expect(await screen.findByRole('alert')).toHaveTextContent('boom')
  })

  it('embeds the Swagger UI iframe pointing at the docs route', async () => {
    mockedGetDoc.mockResolvedValue({ doc_id: 'api-threat-hunting', content: '# Ref' })
    renderTab()

    await screen.findByRole('heading', { name: 'Ref', level: 1 })
    const iframe = screen.getByTitle('OpenTARS API Swagger UI')
    expect(iframe.tagName).toBe('IFRAME')
    expect(iframe).toHaveAttribute('src', 'docs')

    const openLink = screen.getByRole('link', { name: /open in a new tab/i })
    expect(openLink).toHaveAttribute('href', 'docs')
    expect(openLink).toHaveAttribute('target', '_blank')
  })

  it('waits for content before rendering the Swagger card is not required — both sections render independently', async () => {
    // The Swagger card (static content, no fetch) should be present even
    // while the Markdown doc query is still pending.
    mockedGetDoc.mockReturnValue(new Promise(() => {}))
    renderTab()
    expect(screen.getByRole('heading', { name: 'API Swagger' })).toBeInTheDocument()
  })
})

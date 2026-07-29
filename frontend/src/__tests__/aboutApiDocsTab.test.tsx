/**
 * Tests for the About page's API Docs tab (issue-local-030).
 *
 * The API client's `getDoc` is mocked so the Markdown render, the derived
 * table of contents, and the loading/error states are driven deterministically
 * without a network.
 */
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
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
import { splitSections } from '../pages/about/docSections'

const mockedGetDoc = api.getDoc as unknown as ReturnType<typeof vi.fn>

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ApiDocsTab />
    </QueryClientProvider>,
  )
}

const DOC = [
  '# Threat Hunting API Reference',
  '',
  'Intro paragraph.',
  '',
  '## Authentication',
  '',
  'How auth works.',
  '',
  '## Hunt Packages',
  '',
  '| Method | Path |',
  '|---|---|',
  '| GET | /packages |',
  '',
  '## Threat Intel Tracking (issue-local-021)',
  '',
  'Cross-hunt aggregation.',
].join('\n')

beforeEach(() => {
  vi.clearAllMocks()
})

describe('splitSections', () => {
  it('splits on ## headings and keeps the intro separate', () => {
    const { intro, sections } = splitSections(DOC)
    expect(intro).toContain('# Threat Hunting API Reference')
    expect(intro).toContain('Intro paragraph.')
    expect(sections.map((s) => s.title)).toEqual([
      'Authentication',
      'Hunt Packages',
      'Threat Intel Tracking',
    ])
  })

  it('strips internal issue references from displayed titles', () => {
    const { sections } = splitSections(DOC)
    expect(sections[2].title).toBe('Threat Intel Tracking')
    expect(sections[2].title).not.toContain('issue-local')
  })

  it('derives stable anchor ids from the titles', () => {
    const { sections } = splitSections(DOC)
    expect(sections.map((s) => s.id)).toEqual([
      'authentication',
      'hunt-packages',
      'threat-intel-tracking',
    ])
  })

  it('keeps each section body with its heading', () => {
    const { sections } = splitSections(DOC)
    expect(sections[0].body).toBe('How auth works.')
    expect(sections[1].body).toContain('| GET | /packages |')
  })

  it('ignores ## lines inside fenced code blocks', () => {
    const md = ['## Real', '', '```bash', '## not a heading', '```', '', '## Also real'].join('\n')
    const { sections } = splitSections(md)
    expect(sections.map((s) => s.title)).toEqual(['Real', 'Also real'])
    expect(sections[0].body).toContain('## not a heading')
  })

  it('de-duplicates ids when two topics share a name', () => {
    const { sections } = splitSections('## Reports\n\na\n\n## Reports\n\nb')
    expect(sections.map((s) => s.id)).toEqual(['reports', 'reports-2'])
  })

  it('handles a document with no ## headings at all', () => {
    const { intro, sections } = splitSections('# Only a title\n\nBody.')
    expect(sections).toEqual([])
    expect(intro).toContain('Only a title')
  })
})

describe('ApiDocsTab', () => {
  it('shows a loading state before the doc resolves', () => {
    mockedGetDoc.mockReturnValue(new Promise(() => {}))
    renderTab()
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('renders a table of contents listing every topic', async () => {
    mockedGetDoc.mockResolvedValue({ doc_id: 'api-threat-hunting', content: DOC })
    renderTab()

    const toc = await screen.findByRole('navigation', { name: /table of contents/i })
    for (const title of ['Authentication', 'Hunt Packages', 'Threat Intel Tracking']) {
      expect(within(toc).getByRole('button', { name: new RegExp(title) })).toBeInTheDocument()
    }
  })

  it('renders one card per topic, each with an anchor id', async () => {
    mockedGetDoc.mockResolvedValue({ doc_id: 'api-threat-hunting', content: DOC })
    const { container } = renderTab()

    await screen.findByRole('navigation', { name: /table of contents/i })
    for (const id of ['authentication', 'hunt-packages', 'threat-intel-tracking']) {
      expect(container.querySelector(`section#${id}`)).not.toBeNull()
    }
  })

  it('scrolls to the matching section when a contents entry is clicked', async () => {
    const user = userEvent.setup()
    mockedGetDoc.mockResolvedValue({ doc_id: 'api-threat-hunting', content: DOC })
    const { container } = renderTab()

    const toc = await screen.findByRole('navigation', { name: /table of contents/i })
    const target = container.querySelector('section#hunt-packages') as HTMLElement
    const scrollIntoView = vi.fn()
    target.scrollIntoView = scrollIntoView

    await user.click(within(toc).getByRole('button', { name: /Hunt Packages/ }))

    expect(scrollIntoView).toHaveBeenCalled()
  })

  it('renders the section content as real HTML, not raw Markdown', async () => {
    mockedGetDoc.mockResolvedValue({ doc_id: 'api-threat-hunting', content: DOC })
    renderTab()

    await screen.findByRole('navigation', { name: /table of contents/i })
    expect(screen.getByRole('columnheader', { name: 'Method' })).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: 'GET' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Threat Hunting API Reference', level: 1 })).toBeInTheDocument()
  })

  it('shows an error message if the doc fetch fails', async () => {
    mockedGetDoc.mockRejectedValue(new Error('boom'))
    renderTab()

    expect(await screen.findByRole('alert')).toHaveTextContent('boom')
  })

  it('does not render the Swagger UI — that lives in its own sibling tab', async () => {
    mockedGetDoc.mockResolvedValue({ doc_id: 'api-threat-hunting', content: DOC })
    renderTab()

    await screen.findByRole('navigation', { name: /table of contents/i })
    expect(screen.queryByTitle('OpenTARS API Swagger UI')).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'API Swagger' })).not.toBeInTheDocument()
  })
})

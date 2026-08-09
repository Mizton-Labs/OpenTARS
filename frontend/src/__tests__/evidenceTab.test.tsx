/**
 * Tests for issue-local-023: EvidenceTab — the two-pane Evidence tab
 * (sidebar list + content viewer) that replaced the old flat metadata-only
 * card list. Covers sidebar selection, PDF/plaintext/binary content
 * rendering, delete + auto-reselection, and researcher-only controls.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THEvidenceItem } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      threatHunting: {
        ...actual.api.threatHunting,
        listEvidence: vi.fn(),
        deleteEvidence: vi.fn(),
        updateEvidence: vi.fn(),
      },
    },
  }
})

import { api } from '../api/client'
import EvidenceTab from '../pages/threat-hunting/EvidenceTab'

function makeItem(overrides: Partial<THEvidenceItem> = {}): THEvidenceItem {
  return {
    id: `ev-${Math.random()}`,
    hunt_package_id: 'pkg-1',
    item_type: 'file',
    label: 'notes.txt',
    source_ref: 'notes.txt',
    content_hash: '',
    mime_type: 'text/plain',
    fetch_url: '',
    final_url: '',
    extracted_text: 'Hello from the file.',
    parser_used: 'text_extractor',
    parser_version: '1',
    parse_status: 'ok',
    parse_warnings: [],
    fetch_metadata: {},
    created_at: '2026-01-01T00:00:00Z',
    provenance_notes: '',
    ...overrides,
  }
}

function renderTab(isResearcher = true, hasRuns = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <EvidenceTab pkgId="pkg-1" isResearcher={isResearcher} hasRuns={hasRuns} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(api.threatHunting.listEvidence).mockReset()
  vi.mocked(api.threatHunting.deleteEvidence).mockReset()
  vi.mocked(api.threatHunting.updateEvidence).mockReset()
})

describe('EvidenceTab — empty state', () => {
  it('shows an empty state (with an Add Item button) when there are no evidence items', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
    renderTab()
    expect(await screen.findByText('No evidence items yet.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /add item/i })).toBeInTheDocument()
  })

  it('hides the Add Item button for a non-researcher', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
    renderTab(false)
    await screen.findByText('No evidence items yet.')
    expect(screen.queryByRole('button', { name: /add item/i })).not.toBeInTheDocument()
  })
})

describe('EvidenceTab — run not started yet (issue-local-040, item 23)', () => {
  it('still shows the evidence list + Add Item, with a "not retrieved yet" content notice', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([makeItem({ label: 'notes.txt' })])
    const onGoToAnalysis = vi.fn()
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <EvidenceTab pkgId="pkg-1" isResearcher={true} hasRuns={false} onGoToAnalysis={onGoToAnalysis} />
      </QueryClientProvider>,
    )

    // The list itself is still visible, not replaced by the notice.
    expect(await screen.findByText('notes.txt')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /add item/i })).toBeInTheDocument()

    expect(screen.getByText(/not retrieved yet/i)).toBeInTheDocument()
    const button = screen.getByRole('button', { name: /go to analysis/i })
    fireEvent.click(button)
    expect(onGoToAnalysis).toHaveBeenCalledTimes(1)
  })

  it('does not show the notice once a run exists, even mid-analysis', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([makeItem()])
    renderTab(true, true)
    expect(await screen.findByText('Hello from the file.')).toBeInTheDocument()
    expect(screen.queryByText(/not retrieved yet/i)).not.toBeInTheDocument()
  })
})

describe('EvidenceTab — rename flow (issue-local-042 item 23)', () => {
  it('renames an item via the pencil icon, calling updateEvidence and refreshing the list', async () => {
    vi.mocked(api.threatHunting.listEvidence)
      .mockResolvedValueOnce([makeItem({ id: 'a', label: 'first.txt' })])
      .mockResolvedValueOnce([makeItem({ id: 'a', label: 'renamed.txt' })])
    vi.mocked(api.threatHunting.updateEvidence).mockResolvedValue(makeItem({ id: 'a', label: 'renamed.txt' }))

    renderTab()
    await screen.findByText('first.txt')

    fireEvent.click(screen.getByTitle('Rename'))
    const input = screen.getByDisplayValue('first.txt')
    fireEvent.change(input, { target: { value: 'renamed.txt' } })
    fireEvent.click(screen.getByTitle('Save'))

    await waitFor(() =>
      expect(api.threatHunting.updateEvidence).toHaveBeenCalledWith('pkg-1', 'a', { label: 'renamed.txt' }),
    )
    // "renamed.txt" now appears in both the sidebar row and the content
    // pane header once the list refetches — assert at least one shows it.
    expect((await screen.findAllByText('renamed.txt')).length).toBeGreaterThan(0)
  })

  it('hides rename buttons for a non-researcher', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([makeItem({ id: 'a', label: 'first.txt' })])
    renderTab(false)
    await screen.findByText('first.txt')
    expect(screen.queryByTitle('Rename')).not.toBeInTheDocument()
  })
})

describe('EvidenceTab — sidebar selection + content rendering', () => {
  it('auto-selects the first item and renders its extracted_text', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([
      makeItem({ id: 'a', label: 'first.txt', extracted_text: 'First content.' }),
      makeItem({ id: 'b', label: 'second.txt', extracted_text: 'Second content.' }),
    ])
    renderTab()
    expect(await screen.findByText('First content.')).toBeInTheDocument()
    expect(screen.queryByText('Second content.')).not.toBeInTheDocument()
  })

  it('switches the content card when a different sidebar item is clicked', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([
      makeItem({ id: 'a', label: 'first.txt', extracted_text: 'First content.' }),
      makeItem({ id: 'b', label: 'second.txt', extracted_text: 'Second content.' }),
    ])
    renderTab()
    await screen.findByText('First content.')

    fireEvent.click(screen.getByText('second.txt'))

    expect(await screen.findByText('Second content.')).toBeInTheDocument()
    expect(screen.queryByText('First content.')).not.toBeInTheDocument()
  })

  it('renders a PDF item as an iframe pointed at the PDF preview URL', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([
      makeItem({ id: 'pdf-1', label: 'report.pdf', mime_type: 'application/pdf', extracted_text: 'Extracted PDF markdown.' }),
    ])
    renderTab()

    const iframe = await screen.findByTitle('report.pdf')
    expect(iframe.tagName).toBe('IFRAME')
    expect(iframe).toHaveAttribute('src', api.threatHunting.getEvidencePdfUrl('pkg-1', 'pdf-1'))
    // PDF gets the native iframe, not the plaintext extracted_text block —
    // even though extracted_text is also present for this item.
    expect(screen.queryByText('Extracted PDF markdown.')).not.toBeInTheDocument()
  })

  it('shows a "not processed" placeholder for a binary file with no extracted_text', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([
      makeItem({
        id: 'bin-1',
        label: 'archive.zip',
        mime_type: 'application/zip',
        extracted_text: '',
      }),
    ])
    renderTab()
    expect(await screen.findByText('Preview not available for this file type.')).toBeInTheDocument()
  })

  it('shows a pending indicator instead of content while parse_status is pending', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([
      makeItem({ id: 'p-1', parse_status: 'pending', extracted_text: '' }),
    ])
    renderTab()
    expect(await screen.findByText(/Pending — fetched during analysis/)).toBeInTheDocument()
  })

  it('offers a Download link for a file-type item', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([
      makeItem({ id: 'f-1', item_type: 'file', label: 'first.txt' }),
    ])
    renderTab()
    expect(await screen.findByRole('link', { name: /Download/ })).toBeInTheDocument()
  })

  it('does not offer a Download link for a URL-type item (no blob to download)', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([
      makeItem({ id: 'u-1', item_type: 'url', label: 'example.com', source_ref: 'https://example.com' }),
    ])
    renderTab()
    // "example.com" (the label) appears in both the sidebar and the content
    // header — wait on the source_ref URL text instead, unique to the
    // content card.
    await screen.findByText('https://example.com')
    expect(screen.queryByRole('link', { name: /Download/ })).not.toBeInTheDocument()
  })
})

describe('EvidenceTab — delete flow', () => {
  it('hides delete buttons for a non-researcher', async () => {
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([makeItem({ id: 'a', label: 'first.txt' })])
    renderTab(false)
    await screen.findByText('first.txt')
    expect(screen.queryByTitle('Remove')).not.toBeInTheDocument()
  })

  it('asks for confirmation, then deletes and lets the list re-select another item', async () => {
    vi.mocked(api.threatHunting.listEvidence)
      .mockResolvedValueOnce([
        makeItem({ id: 'a', label: 'first.txt', extracted_text: 'First content.' }),
        makeItem({ id: 'b', label: 'second.txt', extracted_text: 'Second content.' }),
      ])
      .mockResolvedValueOnce([makeItem({ id: 'b', label: 'second.txt', extracted_text: 'Second content.' })])
    vi.mocked(api.threatHunting.deleteEvidence).mockResolvedValue(undefined)

    renderTab()
    await screen.findByText('First content.')

    // Two sidebar items, each with its own Remove button — click the one
    // for "first.txt" (the currently-selected item).
    fireEvent.click(screen.getAllByTitle('Remove')[0])
    expect(await screen.findByText('Delete Evidence Item?')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(api.threatHunting.deleteEvidence).toHaveBeenCalledWith('pkg-1', 'a'))
    // Selection falls through to the remaining item once the list refetches.
    expect(await screen.findByText('Second content.')).toBeInTheDocument()
  })
})

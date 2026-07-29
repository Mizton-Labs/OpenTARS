/**
 * Tests for the global search / SmartSearch drawer (issue-local-031).
 *
 * The API client is mocked so the collapsed/expanded behaviour, the
 * always-visible Normal/Smart switch, grouped results, and the chat flow are
 * driven deterministically without a network.
 */
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'

const navigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => navigate }
})

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      search: { query: vi.fn(), status: vi.fn(), smart: vi.fn() },
    },
  }
})

import { api } from '../api/client'
import SmartSearchDrawer from '../components/SmartSearchDrawer'

const mocked = api.search as unknown as {
  query: ReturnType<typeof vi.fn>
  status: ReturnType<typeof vi.fn>
  smart: ReturnType<typeof vi.fn>
}

const RESULTS = {
  query: 'lazarus',
  total: 2,
  sections: [
    {
      section: 'Threat Hunting',
      hits: [
        {
          section: 'Threat Hunting',
          title: 'TH01 Lazarus sweep',
          snippet: 'Hunting Lazarus C2 domains',
          route: '/threat-hunting/pkg-1',
          ref: 'pkg-1',
        },
      ],
    },
    {
      section: 'Docs',
      hits: [
        {
          section: 'Docs',
          title: 'API reference — Authentication',
          snippet: 'Session cookie or scoped API key',
          route: '/about',
          ref: 'doc:api',
        },
      ],
    },
  ],
}

function renderDrawer() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SmartSearchDrawer />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const openButton = () => screen.getByRole('button', { name: /search opentars/i })
const smartTab = () => screen.getByRole('button', { name: /smart/i })

beforeEach(() => {
  vi.clearAllMocks()
  mocked.status.mockResolvedValue({ available: true, reason: null, provider: 'p1' })
  mocked.query.mockResolvedValue(RESULTS)
})

describe('SmartSearchDrawer', () => {
  it('starts fully collapsed — only the search button is visible', () => {
    renderDrawer()
    expect(openButton()).toBeInTheDocument()
    // Nothing inside the drawer is rendered (so nothing is focusable) until opened.
    expect(screen.queryByLabelText('Search query')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Search')).toHaveAttribute('aria-hidden', 'true')
  })

  it('expands when the search button is pressed', async () => {
    const user = userEvent.setup()
    renderDrawer()
    await user.click(openButton())

    expect(await screen.findByLabelText('Search query')).toBeInTheDocument()
    expect(screen.getByLabelText('Search')).toHaveAttribute('aria-hidden', 'false')
  })

  it('closes again from the close button', async () => {
    const user = userEvent.setup()
    renderDrawer()
    await user.click(openButton())
    await user.click(screen.getByRole('button', { name: /close search/i }))

    expect(screen.queryByLabelText('Search query')).not.toBeInTheDocument()
  })

  it('groups results by the section they were found in', async () => {
    const user = userEvent.setup()
    renderDrawer()
    await user.click(openButton())
    await user.type(screen.getByLabelText('Search query'), 'lazarus')

    expect(await screen.findByText('Threat Hunting')).toBeInTheDocument()
    expect(screen.getByText('Docs')).toBeInTheDocument()
    expect(screen.getByText('TH01 Lazarus sweep')).toBeInTheDocument()
    expect(screen.getByText('Hunting Lazarus C2 domains')).toBeInTheDocument()
  })

  it('navigates to a hit and closes the drawer', async () => {
    const user = userEvent.setup()
    renderDrawer()
    await user.click(openButton())
    await user.type(screen.getByLabelText('Search query'), 'lazarus')

    await user.click(await screen.findByRole('button', { name: /TH01 Lazarus sweep/ }))

    expect(navigate).toHaveBeenCalledWith('/threat-hunting/pkg-1')
    expect(screen.queryByLabelText('Search query')).not.toBeInTheDocument()
  })

  it('reports when nothing matched', async () => {
    const user = userEvent.setup()
    mocked.query.mockResolvedValue({ query: 'zzz', total: 0, sections: [] })
    renderDrawer()
    await user.click(openButton())
    await user.type(screen.getByLabelText('Search query'), 'zzz')

    expect(await screen.findByText(/no matches for/i)).toBeInTheDocument()
  })
})

describe('SmartSearchDrawer — Smart switch availability', () => {
  it('shows the Smart switch disabled with a tooltip naming the setting', async () => {
    const user = userEvent.setup()
    mocked.status.mockResolvedValue({
      available: false,
      reason:
        'No LLM provider is enabled. Enable one in Configuration → General → LLM Providers to turn on Smart Search.',
      provider: null,
    })
    renderDrawer()
    await user.click(openButton())

    await waitFor(() => expect(smartTab()).toBeDisabled())
    // The switch is still rendered — it is only greyed out.
    expect(smartTab()).toBeInTheDocument()
    expect(smartTab()).toHaveAttribute('title', expect.stringContaining('LLM Providers'))
  })

  it('leaves the Smart switch enabled when a provider is configured', async () => {
    const user = userEvent.setup()
    renderDrawer()
    await user.click(openButton())

    await waitFor(() => expect(smartTab()).toBeEnabled())
  })
})

describe('SmartSearchDrawer — chat', () => {
  it('sends a question and shows the answer with its sources', async () => {
    const user = userEvent.setup()
    mocked.smart.mockResolvedValue({
      answer: 'You have one hunt covering Lazarus.',
      sources: RESULTS.sections[0].hits,
      used_context: 1,
    })
    renderDrawer()
    await user.click(openButton())
    await waitFor(() => expect(smartTab()).toBeEnabled())
    await user.click(smartTab())

    await user.type(screen.getByLabelText('Ask Smart Search'), 'any lazarus hunts?{Enter}')

    expect(await screen.findByText('You have one hunt covering Lazarus.')).toBeInTheDocument()
    expect(mocked.smart).toHaveBeenCalledWith('any lazarus hunts?', [])
    // Sources are offered as navigable chips.
    expect(
      screen.getByRole('button', { name: /Threat Hunting: TH01 Lazarus sweep/ }),
    ).toBeInTheDocument()
  })

  it('replays prior turns as history on the next question', async () => {
    const user = userEvent.setup()
    mocked.smart.mockResolvedValue({ answer: 'first answer', sources: [], used_context: 0 })
    renderDrawer()
    await user.click(openButton())
    await waitFor(() => expect(smartTab()).toBeEnabled())
    await user.click(smartTab())

    const box = screen.getByLabelText('Ask Smart Search')
    await user.type(box, 'one{Enter}')
    await screen.findByText('first answer')
    await user.type(box, 'two{Enter}')

    await waitFor(() =>
      expect(mocked.smart).toHaveBeenLastCalledWith('two', [
        { role: 'user', content: 'one' },
        { role: 'assistant', content: 'first answer' },
      ]),
    )
  })

  it('renders the answer as text, never as markup', async () => {
    const user = userEvent.setup()
    const hostile = '<img src=x onerror="alert(1)">'
    mocked.smart.mockResolvedValue({ answer: hostile, sources: [], used_context: 0 })
    renderDrawer()
    await user.click(openButton())
    await waitFor(() => expect(smartTab()).toBeEnabled())
    await user.click(smartTab())
    await user.type(screen.getByLabelText('Ask Smart Search'), 'x{Enter}')

    // Present as literal text; no element was created from it.
    const node = await screen.findByText(hostile)
    expect(node).toBeInTheDocument()
    expect(node.querySelector('img')).toBeNull()
  })

  it('surfaces a failure without breaking the transcript', async () => {
    const user = userEvent.setup()
    mocked.smart.mockRejectedValue(new Error('503: provider unavailable'))
    renderDrawer()
    await user.click(openButton())
    await waitFor(() => expect(smartTab()).toBeEnabled())
    await user.click(smartTab())
    await user.type(screen.getByLabelText('Ask Smart Search'), 'x{Enter}')

    expect(await screen.findByText(/could not answer/i)).toBeInTheDocument()
    expect(screen.getByText(/provider unavailable/)).toBeInTheDocument()
  })

  it('explains that answers are scoped and read-only before any question', async () => {
    const user = userEvent.setup()
    renderDrawer()
    await user.click(openButton())
    await waitFor(() => expect(smartTab()).toBeEnabled())
    await user.click(smartTab())

    const transcript = screen.getByText(/cannot change anything/i)
    expect(transcript).toBeInTheDocument()
    expect(within(transcript).queryByRole('button')).toBeNull()
  })
})

describe('SmartSearchDrawer — chat history bounds', () => {
  async function openChat(user: ReturnType<typeof userEvent.setup>) {
    renderDrawer()
    await user.click(openButton())
    await waitFor(() => expect(smartTab()).toBeEnabled())
    await user.click(smartTab())
    return screen.getByLabelText('Ask Smart Search')
  }

  it('never sends more turns than the server keeps', async () => {
    const user = userEvent.setup()
    mocked.smart.mockImplementation(async () => ({
      answer: 'ok',
      sources: [],
      used_context: 0,
    }))
    const box = await openChat(user)

    // Long conversation: an unbounded transcript would eventually be rejected
    // outright, and because each failure is appended the chat never recovered.
    for (let i = 0; i < 10; i++) {
      await user.type(box, `q${i}{Enter}`)
      await waitFor(() => expect(mocked.smart).toHaveBeenCalledTimes(i + 1))
    }

    for (const call of mocked.smart.mock.calls) {
      expect(call[1].length).toBeLessThanOrEqual(6)
    }
  })

  it('does not replay failed turns as if the assistant had said them', async () => {
    const user = userEvent.setup()
    mocked.smart.mockRejectedValueOnce(new Error('502 Bad Gateway: upstream died'))
    mocked.smart.mockResolvedValueOnce({ answer: 'recovered', sources: [], used_context: 0 })
    const box = await openChat(user)

    await user.type(box, 'first{Enter}')
    await screen.findByText(/could not answer/i)
    await user.type(box, 'second{Enter}')

    await waitFor(() => expect(mocked.smart).toHaveBeenCalledTimes(2))
    const history = mocked.smart.mock.calls[1][1] as { role: string; content: string }[]
    expect(history.some((t) => t.content.includes('502 Bad Gateway'))).toBe(false)
    expect(history).toEqual([{ role: 'user', content: 'first' }])
  })

  it('recovers after a failure instead of dying permanently', async () => {
    const user = userEvent.setup()
    mocked.smart.mockRejectedValueOnce(new Error('boom'))
    mocked.smart.mockResolvedValueOnce({ answer: 'back again', sources: [], used_context: 0 })
    const box = await openChat(user)

    await user.type(box, 'one{Enter}')
    await screen.findByText(/could not answer/i)
    await user.type(box, 'two{Enter}')

    expect(await screen.findByText('back again')).toBeInTheDocument()
  })
})

describe('SmartSearchDrawer — stale results', () => {
  it('clears results as soon as the box is emptied', async () => {
    const user = userEvent.setup()
    renderDrawer()
    await user.click(openButton())
    const box = screen.getByLabelText('Search query')

    await user.type(box, 'lazarus')
    expect(await screen.findByText('TH01 Lazarus sweep')).toBeInTheDocument()

    await user.clear(box)
    // The debounce lags ~300ms; the previous term's hits must not linger
    // underneath the placeholder in the meantime.
    expect(screen.queryByText('TH01 Lazarus sweep')).not.toBeInTheDocument()
  })
})

describe('SmartSearchDrawer — Markdown answers', () => {
  async function ask(answer: string) {
    const user = userEvent.setup()
    mocked.smart.mockResolvedValue({ answer, sources: [], used_context: 0 })
    renderDrawer()
    await user.click(openButton())
    await waitFor(() => expect(smartTab()).toBeEnabled())
    await user.click(smartTab())
    await user.type(screen.getByLabelText('Ask Smart Search'), 'q{Enter}')
    return user
  }

  it('renders formatting rather than printing the markup', async () => {
    await ask('You have **two** hunts:\n\n- TH01\n- TH02\n\nRun `generate` to start.')

    const bold = await screen.findByText('two')
    expect(bold.tagName).toBe('STRONG')
    expect(screen.getAllByRole('listitem')).toHaveLength(2)
    expect(screen.getByText('generate').tagName).toBe('CODE')
    // The source markup itself must not be visible.
    expect(screen.queryByText(/\*\*two\*\*/)).not.toBeInTheDocument()
  })

  it('renders GFM tables', async () => {
    await ask('| Hunt | Status |\n|---|---|\n| TH01 | completed |')

    expect(await screen.findByRole('columnheader', { name: 'Hunt' })).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: 'completed' })).toBeInTheDocument()
  })

  it('renders fenced code blocks', async () => {
    await ask('Try:\n\n```\nindex=main sourcetype=dns\n```')

    const code = await screen.findByText(/index=main sourcetype=dns/)
    expect(code.closest('pre')).not.toBeNull()
  })

  it('never renders a clickable link, even when the model emits one', async () => {
    // URLs here are frequently the malicious indicator under investigation, so
    // an anchor in an analyst's chat window is a footgun.
    await ask('The indicator was [evil-host.example](http://evil-host.example/payload).')

    expect(await screen.findByText('evil-host.example')).toBeInTheDocument()
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })

  it('never renders an image, so nothing is fetched from the answer', async () => {
    // An image URL is an outbound request the moment it renders, which would
    // both confirm the answer was read and let the path carry data out.
    await ask('![tracker](http://attacker.example/pixel.png)')

    expect(await screen.findByText('tracker')).toBeInTheDocument()
    expect(document.querySelectorAll('img')).toHaveLength(0)
  })

  it('escapes raw HTML instead of rendering it', async () => {
    const hostile = '<img src=x onerror="alert(1)"><b>bold</b>'
    await ask(hostile)

    expect(await screen.findByText(hostile)).toBeInTheDocument()
    expect(document.querySelectorAll('img')).toHaveLength(0)
  })

  it('shows the user question and error text verbatim, not as Markdown', async () => {
    const user = userEvent.setup()
    mocked.smart.mockRejectedValue(new Error('failed: **not bold**'))
    renderDrawer()
    await user.click(openButton())
    await waitFor(() => expect(smartTab()).toBeEnabled())
    await user.click(smartTab())
    await user.type(screen.getByLabelText('Ask Smart Search'), '**my question**{Enter}')

    // Both are shown literally — only the assistant's answer is Markdown.
    expect(await screen.findByText('**my question**')).toBeInTheDocument()
    expect(screen.getByText(/failed: \*\*not bold\*\*/)).toBeInTheDocument()
  })
})

/**
 * Tests for the AssistantSettingsCard control (issue-local-039) in the
 * Application configuration tab — lets an admin pin the Smart Assistant to
 * a specific configured LLM provider and adjust its retrieved-hit context
 * budget.
 */
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import type { LLMConfig, LLMProviderSummary, AssistantSettings } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getAssistantSettings: vi.fn(),
      setAssistantSettings: vi.fn(),
      llm: {
        ...actual.api.llm,
        getConfig: vi.fn(),
        listProviders: vi.fn(),
      },
    },
  }
})

import { api } from '../api/client'
import { AssistantSettingsCard } from '../pages/Configuration'

function renderWithClient() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AssistantSettingsCard />
    </QueryClientProvider>,
  )
}

const defaultSettings: AssistantSettings = {
  assistant_provider: null,
  assistant_context_hits: 24,
}

const llmConfig: LLMConfig = {
  enabled: true,
  default_provider: 'primary',
  providers: [],
}

const providers: LLMProviderSummary[] = [
  { name: 'primary', kind: 'openai', model: 'gpt-4o', has_api_key: true, skip_tls_verify: false },
  { name: 'secondary', kind: 'anthropic', model: 'claude', has_api_key: true, skip_tls_verify: false },
]

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.llm.getConfig).mockResolvedValue(llmConfig)
  vi.mocked(api.llm.listProviders).mockResolvedValue(providers)
})

describe('AssistantSettingsCard (issue-local-039)', () => {
  it('shows "Use default" with the configured default provider name when unset', async () => {
    vi.mocked(api.getAssistantSettings).mockResolvedValue(defaultSettings)
    renderWithClient()

    await waitFor(() => expect(api.getAssistantSettings).toHaveBeenCalled())
    const select = (await screen.findByDisplayValue(/use default \(primary\)/i)) as HTMLSelectElement
    expect(select.value).toBe('')
  })

  it('lists every configured provider as a selectable option', async () => {
    vi.mocked(api.getAssistantSettings).mockResolvedValue(defaultSettings)
    renderWithClient()

    expect(await screen.findByRole('option', { name: /secondary/i })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: /^primary \(/i })).toBeInTheDocument()
  })

  it('pre-fills the context budget input from the loaded setting', async () => {
    vi.mocked(api.getAssistantSettings).mockResolvedValue({
      assistant_provider: 'secondary',
      assistant_context_hits: 40,
    })
    renderWithClient()

    const input = (await screen.findByDisplayValue('40')) as HTMLInputElement
    expect(input).toBeInTheDocument()
  })

  it('saves a chosen provider and context budget', async () => {
    vi.mocked(api.getAssistantSettings).mockResolvedValue(defaultSettings)
    vi.mocked(api.setAssistantSettings).mockResolvedValue({
      assistant_provider: 'secondary',
      assistant_context_hits: 50,
    })
    renderWithClient()

    // Wait for both the context-budget value and the provider catalog to have
    // loaded before interacting — otherwise the number input is still empty
    // and the Save button stays disabled regardless of the provider change.
    const numberInput = await screen.findByDisplayValue('24')
    const select = await screen.findByRole('option', { name: /secondary/i }).then(
      opt => opt.closest('select') as HTMLSelectElement,
    )
    fireEvent.change(select, { target: { value: 'secondary' } })
    fireEvent.change(numberInput, { target: { value: '50' } })

    fireEvent.click(screen.getByRole('button', { name: /save/i }))

    await waitFor(() =>
      expect(api.setAssistantSettings).toHaveBeenCalledWith({
        assistant_provider: 'secondary',
        assistant_context_hits: 50,
      }),
    )
  })

  it('disables Save and shows an error for an out-of-range context budget', async () => {
    vi.mocked(api.getAssistantSettings).mockResolvedValue(defaultSettings)
    renderWithClient()

    const numberInput = await screen.findByDisplayValue('24')
    fireEvent.change(numberInput, { target: { value: '5000' } })

    expect(screen.getByRole('button', { name: /save/i })).toBeDisabled()
    expect(screen.getByText(/must be an integer between/i)).toBeInTheDocument()
    expect(api.setAssistantSettings).not.toHaveBeenCalled()
  })

  it('disables Save when nothing has changed from the loaded values', async () => {
    vi.mocked(api.getAssistantSettings).mockResolvedValue(defaultSettings)
    renderWithClient()

    await screen.findByDisplayValue('24')
    expect(screen.getByRole('button', { name: /save/i })).toBeDisabled()
  })

  it('surfaces a save error from the backend (e.g. an unknown provider)', async () => {
    vi.mocked(api.getAssistantSettings).mockResolvedValue(defaultSettings)
    vi.mocked(api.setAssistantSettings).mockRejectedValue(new Error('Unknown LLM provider'))
    renderWithClient()

    await screen.findByDisplayValue('24')
    const option = await screen.findByRole('option', { name: /secondary/i })
    fireEvent.change(option.closest('select') as HTMLSelectElement, { target: { value: 'secondary' } })
    fireEvent.click(screen.getByRole('button', { name: /save/i }))

    expect(await screen.findByText(/unknown llm provider/i)).toBeInTheDocument()
  })
})

/**
 * Tests for HuntPlaybooksTab (issue-local-040) — the Configuration →
 * Threat Hunting → "Hunt Playbooks" tab: list of playbook cards with
 * create/edit/clone/delete, mirroring SiemConnectorsTab's established
 * card-list + inline form pattern.
 */
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THPlaybook, LLMProviderSummary } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      llm: {
        ...actual.api.llm,
        listProviders: vi.fn(),
      },
      threatHunting: {
        ...actual.api.threatHunting,
        playbooks: {
          list: vi.fn(),
          create: vi.fn(),
          update: vi.fn(),
          delete: vi.fn(),
          clone: vi.fn(),
        },
      },
    },
  }
})

import { api } from '../api/client'
import HuntPlaybooksTab from '../pages/configuration/HuntPlaybooksTab'

// issue-local-042: checkboxes became Toggle (role="switch") buttons with no
// associated <label>, so tests locate the switch via its row's descriptive
// text instead of getByLabelText — same "find text, scope to its row"
// pattern apiAccessTab.test.tsx/userManagementOrg.test.tsx already use for
// their own multi-checkbox lists (there via closest('label')).
function switchNear(text: string | RegExp): HTMLElement {
  return screen.getByText(text).closest('div')!.querySelector('[role="switch"]') as HTMLElement
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <HuntPlaybooksTab />
    </QueryClientProvider>,
  )
}

const providers: LLMProviderSummary[] = [
  {
    name: 'openai-prod',
    kind: 'openai',
    model: 'gpt-4o',
    has_api_key: true,
    skip_tls_verify: false,
    available_models: ['gpt-4o', 'gpt-4o-mini'],
  },
]

function makePlaybook(overrides: Partial<THPlaybook> = {}): THPlaybook {
  return {
    id: 'pb-1',
    name: 'My Playbook',
    models: [{ provider_name: 'openai-prod', model_name: 'gpt-4o' }],
    auto_approve_analysis: false,
    auto_run_comparison: false,
    auto_compare_preliminary: false,
    auto_compare_full: false,
    auto_create_run_from_recommendations: false,
    auto_generate_full_report: false,
    created_at: '2026-01-01T00:00:00Z',
    created_by: null,
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

beforeEach(() => {
  vi.mocked(api.llm.listProviders).mockReset().mockResolvedValue(providers)
  vi.mocked(api.threatHunting.playbooks.list).mockReset().mockResolvedValue([])
  vi.mocked(api.threatHunting.playbooks.create).mockReset()
  vi.mocked(api.threatHunting.playbooks.update).mockReset()
  vi.mocked(api.threatHunting.playbooks.delete).mockReset()
  vi.mocked(api.threatHunting.playbooks.clone).mockReset()
})

describe('HuntPlaybooksTab — list', () => {
  it('shows an empty state when there are no playbooks', async () => {
    renderTab()
    expect(await screen.findByText('No Hunt Playbooks configured.')).toBeInTheDocument()
  })

  it('renders a card per playbook with its model count and automation summary', async () => {
    vi.mocked(api.threatHunting.playbooks.list).mockResolvedValue([
      makePlaybook({ auto_approve_analysis: true, auto_compare_preliminary: true }),
    ])
    renderTab()
    expect(await screen.findByText('My Playbook')).toBeInTheDocument()
    expect(screen.getByText('1 model')).toBeInTheDocument()
    expect(screen.getByText(/auto-approve analysis/)).toBeInTheDocument()
    expect(screen.getByText(/auto preliminary compare/)).toBeInTheDocument()
  })

  it('shows a plain automation summary when no toggles are on', async () => {
    vi.mocked(api.threatHunting.playbooks.list).mockResolvedValue([makePlaybook()])
    renderTab()
    expect(await screen.findByText('No automation beyond firing the runs')).toBeInTheDocument()
  })
})

describe('HuntPlaybooksTab — create', () => {
  it('disables Save until a name and at least one model are chosen', async () => {
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /new playbook/i }))

    await screen.findByText(/openai-prod · gpt-4o-mini/)
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()

    fireEvent.change(screen.getByPlaceholderText(/multi-model triage/i), {
      target: { value: 'PB1' },
    })
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()

    fireEvent.click(switchNear(/openai-prod · gpt-4o-mini/))
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
  })

  it('submits the chosen name, models, and toggles to create()', async () => {
    vi.mocked(api.threatHunting.playbooks.create).mockResolvedValue(makePlaybook())
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /new playbook/i }))

    fireEvent.change(await screen.findByPlaceholderText(/multi-model triage/i), {
      target: { value: 'PB1' },
    })
    fireEvent.click(switchNear(/openai-prod · gpt-4o-mini/))
    fireEvent.click(switchNear(/automatically approve the analysis phase/i))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(api.threatHunting.playbooks.create).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'PB1',
          models: [{ provider_name: 'openai-prod', model_name: 'gpt-4o-mini' }],
          auto_approve_analysis: true,
        }),
      ),
    )
  })

  it('lets a per-model effort be picked, and submits it on the model entry', async () => {
    vi.mocked(api.threatHunting.playbooks.create).mockResolvedValue(makePlaybook())
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /new playbook/i }))

    fireEvent.change(await screen.findByPlaceholderText(/multi-model triage/i), {
      target: { value: 'PB1' },
    })
    fireEvent.click(switchNear(/openai-prod · gpt-4o-mini/))
    fireEvent.click(screen.getByRole('button', { name: 'high' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(api.threatHunting.playbooks.create).toHaveBeenCalledWith(
        expect.objectContaining({
          models: [{ provider_name: 'openai-prod', model_name: 'gpt-4o-mini', effort: 'high' }],
        }),
      ),
    )
  })

  it('reveals the preliminary/full sub-toggles only once auto_run_comparison is on, and hides them again when turned off', async () => {
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /new playbook/i }))

    expect(screen.queryByText('Preliminary Analysis')).not.toBeInTheDocument()

    fireEvent.click(switchNear(/automatically run comparison assessment/i))
    expect(screen.getByText('Preliminary Analysis')).toBeInTheDocument()
    expect(screen.getByText('Full Assessment')).toBeInTheDocument()

    fireEvent.click(switchNear(/automatically run comparison assessment/i))
    expect(screen.queryByText('Preliminary Analysis')).not.toBeInTheDocument()
  })

  it('the recommendation-run toggle is disabled until Preliminary Analysis is checked', async () => {
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /new playbook/i }))
    fireEvent.click(switchNear(/automatically run comparison assessment/i))

    const recToggle = switchNear(/automatically create a new run from the preliminary analysis recommendations/i)
    expect(recToggle).toHaveAttribute('disabled')

    fireEvent.click(switchNear('Preliminary Analysis'))
    expect(recToggle).not.toHaveAttribute('disabled')
  })

  it('cancel discards the form without calling create()', async () => {
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /new playbook/i }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(api.threatHunting.playbooks.create).not.toHaveBeenCalled()
  })
})

describe('HuntPlaybooksTab — edit/clone/delete', () => {
  it('edit pre-fills the form and update() sends only what changed plus existing fields', async () => {
    vi.mocked(api.threatHunting.playbooks.list).mockResolvedValue([makePlaybook()])
    vi.mocked(api.threatHunting.playbooks.update).mockResolvedValue(makePlaybook({ name: 'Renamed' }))
    renderTab()

    fireEvent.click(await screen.findByTitle('Edit'))
    const nameInput = screen.getByDisplayValue('My Playbook')
    fireEvent.change(nameInput, { target: { value: 'Renamed' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(api.threatHunting.playbooks.update).toHaveBeenCalledWith(
        'pb-1',
        expect.objectContaining({ name: 'Renamed' }),
      ),
    )
  })

  it('clone prompts for a name and calls clone() with it', async () => {
    vi.mocked(api.threatHunting.playbooks.list).mockResolvedValue([makePlaybook()])
    vi.mocked(api.threatHunting.playbooks.clone).mockResolvedValue(makePlaybook({ id: 'pb-2', name: 'Cloned' }))
    const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('Cloned')
    renderTab()

    fireEvent.click(await screen.findByTitle('Clone'))

    await waitFor(() =>
      expect(api.threatHunting.playbooks.clone).toHaveBeenCalledWith('pb-1', 'Cloned'),
    )
    promptSpy.mockRestore()
  })

  it('clone does nothing when the prompt is cancelled', async () => {
    vi.mocked(api.threatHunting.playbooks.list).mockResolvedValue([makePlaybook()])
    const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue(null)
    renderTab()

    fireEvent.click(await screen.findByTitle('Clone'))
    expect(api.threatHunting.playbooks.clone).not.toHaveBeenCalled()
    promptSpy.mockRestore()
  })

  it('delete requires confirmation before calling delete()', async () => {
    vi.mocked(api.threatHunting.playbooks.list).mockResolvedValue([makePlaybook()])
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    renderTab()

    fireEvent.click(await screen.findByTitle('Delete'))
    await waitFor(() => expect(api.threatHunting.playbooks.delete).toHaveBeenCalledWith('pb-1'))
    confirmSpy.mockRestore()
  })

  it('cancelling the delete confirmation never calls delete()', async () => {
    vi.mocked(api.threatHunting.playbooks.list).mockResolvedValue([makePlaybook()])
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false)
    renderTab()

    fireEvent.click(await screen.findByTitle('Delete'))
    expect(api.threatHunting.playbooks.delete).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })
})

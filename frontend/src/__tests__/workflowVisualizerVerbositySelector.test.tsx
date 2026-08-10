/**
 * Tests for issue-local-044: a logging-level (verbosity) selector rendered
 * above WorkflowVisualizer's diagram. The configured agent_workflow_
 * verbosity setting only picks the view's DEFAULT tier — this selector
 * lets the user switch to any of Info/Detailed/Verbose/Debug for the
 * current session without touching the saved config (same "default, then
 * local override" pattern already used for showSubtasks/trackWorkflow).
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THGenerationRecord } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getAgentVerbosity: vi.fn(),
      getAgentVisualization: vi.fn().mockResolvedValue({ agent_workflow_visualization: 'timeline' }),
      getAgentShowSubtasks: vi.fn().mockResolvedValue({ agent_workflow_show_subtasks: false }),
    },
  }
})

import { api } from '../api/client'
import WorkflowVisualizer from '../pages/threat-hunting/WorkflowVisualizer'

function makeGenRecord(overrides: Partial<THGenerationRecord> = {}): THGenerationRecord {
  return {
    id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'running',
    current_step: 'ttp_analyst',
    completed_steps: ['hypothesis_generator'],
    step_logs: [],
    ...overrides,
  } as THGenerationRecord
}

function renderViz(genRecord: THGenerationRecord, props: { compact?: boolean } = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <WorkflowVisualizer genRecord={genRecord} {...props} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('WorkflowVisualizer verbosity selector (issue-local-044)', () => {
  it('opens on the configured default tier, with that tier highlighted', async () => {
    vi.mocked(api.getAgentVerbosity).mockResolvedValue({ agent_workflow_verbosity: 'detailed' })
    renderViz(makeGenRecord())

    const detailedBtn = await screen.findByRole('button', { name: 'Detailed' })
    await waitFor(() => expect(detailedBtn).toHaveClass('bg-brand-900/40'))
    expect(screen.getByRole('button', { name: 'Info' })).not.toHaveClass('bg-brand-900/40')
  })

  it('switching to a higher tier changes the rendered view without persisting anything', async () => {
    vi.mocked(api.getAgentVerbosity).mockResolvedValue({ agent_workflow_verbosity: 'info' })
    renderViz(makeGenRecord())

    // Info tier: compact checklist, no Pipeline Log console.
    await screen.findByRole('button', { name: 'Info' })
    expect(screen.queryByText(/Pipeline Log/)).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Verbose' }))

    // Verbose tier shows the full console.
    await waitFor(() => expect(screen.getByText(/Pipeline Log/)).toBeInTheDocument())
  })

  it('switching tiers back down to Info returns to the compact checklist', async () => {
    vi.mocked(api.getAgentVerbosity).mockResolvedValue({ agent_workflow_verbosity: 'debug' })
    renderViz(makeGenRecord())

    await waitFor(() => expect(screen.getByText(/Pipeline Log/)).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Info' }))

    await waitFor(() => expect(screen.queryByText(/Pipeline Log/)).not.toBeInTheDocument())
  })

  it('is not shown in compact mode', async () => {
    vi.mocked(api.getAgentVerbosity).mockResolvedValue({ agent_workflow_verbosity: 'info' })
    renderViz(makeGenRecord(), { compact: true })

    await screen.findByText('Hypothesis Generator')
    expect(screen.queryByRole('button', { name: 'Info' })).not.toBeInTheDocument()
    expect(screen.queryByText('View')).not.toBeInTheDocument()
  })

  it('is shown even at the Info default (so the user can switch up)', async () => {
    vi.mocked(api.getAgentVerbosity).mockResolvedValue({ agent_workflow_verbosity: 'info' })
    renderViz(makeGenRecord())

    expect(await screen.findByRole('button', { name: 'Detailed' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Verbose' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Debug' })).toBeInTheDocument()
  })
})

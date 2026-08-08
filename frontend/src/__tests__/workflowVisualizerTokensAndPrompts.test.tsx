/**
 * Tests for issue-local-041's debug-console additions to
 * WorkflowVisualizer.tsx's TimelineVisualizer: per-step token chips, a
 * run-level token total, and a 'debug'-only prompt inspector.
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

function renderViz(genRecord: THGenerationRecord) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <WorkflowVisualizer genRecord={genRecord} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('WorkflowVisualizer token totals (issue-local-041)', () => {
  it('shows the run total and per-step token chip at "detailed" verbosity (not gated to debug)', async () => {
    vi.mocked(api.getAgentVerbosity).mockResolvedValue({ agent_workflow_verbosity: 'detailed' })
    renderViz(
      makeGenRecord({
        step_logs: [
          {
            step: 'hypothesis_generator',
            status: 'ok',
            elapsed_s: 1,
            tokens: { input_tokens: 100, output_tokens: 20, cache_read_tokens: null, cache_creation_tokens: null, total_tokens: 120 },
          },
        ],
      }),
    )

    await waitFor(() => expect(screen.getByText(/Run total: 120 tokens/)).toBeInTheDocument())
    expect(screen.getByText('120 tok')).toBeInTheDocument()
  })

  it('does not show a run total when no step reported usage', async () => {
    vi.mocked(api.getAgentVerbosity).mockResolvedValue({ agent_workflow_verbosity: 'detailed' })
    renderViz(makeGenRecord({ step_logs: [{ step: 'hypothesis_generator', status: 'ok', elapsed_s: 1 }] }))

    await screen.findByText('Hypothesis Generator')
    expect(screen.queryByText(/Run total:/)).not.toBeInTheDocument()
  })
})

describe('WorkflowVisualizer prompt inspector (issue-local-041)', () => {
  it('shows the Prompts toggle only at debug verbosity when a step has prompts', async () => {
    vi.mocked(api.getAgentVerbosity).mockResolvedValue({ agent_workflow_verbosity: 'debug' })
    renderViz(
      makeGenRecord({
        step_logs: [
          {
            step: 'hypothesis_generator',
            status: 'ok',
            elapsed_s: 1,
            prompts: [
              { type: 'system', content: 'You are an analyst.' },
              { type: 'user', content: 'Task: generate hypotheses' },
              { type: 'agent', content: '[{"id": "H1"}]' },
            ],
          },
        ],
      }),
    )

    const toggle = await screen.findByRole('button', { name: /Prompts/ })
    expect(screen.queryByText('You are an analyst.')).not.toBeInTheDocument()

    fireEvent.click(toggle)
    expect(await screen.findByText('You are an analyst.')).toBeInTheDocument()
    expect(screen.getByText('Task: generate hypotheses')).toBeInTheDocument()
    expect(screen.getByText('system')).toBeInTheDocument()
    expect(screen.getByText('user')).toBeInTheDocument()
    expect(screen.getByText('agent')).toBeInTheDocument()

    // Toggling again collapses it.
    fireEvent.click(toggle)
    expect(screen.queryByText('You are an analyst.')).not.toBeInTheDocument()
  })

  it('does not show the Prompts toggle below debug verbosity even if prompts exist', async () => {
    vi.mocked(api.getAgentVerbosity).mockResolvedValue({ agent_workflow_verbosity: 'verbose' })
    renderViz(
      makeGenRecord({
        step_logs: [
          {
            step: 'hypothesis_generator',
            status: 'ok',
            elapsed_s: 1,
            prompts: [{ type: 'system', content: 'should not be reachable' }],
          },
        ],
      }),
    )

    await screen.findByText('Hypothesis Generator')
    expect(screen.queryByRole('button', { name: /Prompts/ })).not.toBeInTheDocument()
  })
})

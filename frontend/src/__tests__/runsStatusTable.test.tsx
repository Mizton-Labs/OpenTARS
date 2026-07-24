/**
 * Tests for issue-local-017's RunsStatusTable — the compact all-runs
 * overview (model, status, coarse workflow phases) shown below the run
 * selector dropdown in HuntDetail.tsx.
 */
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import RunsStatusTable from '../pages/threat-hunting/RunsStatusTable'
import type { THuntPackageRun } from '../api/client'

function makeRun(overrides: Partial<THuntPackageRun> = {}): THuntPackageRun {
  return {
    id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'completed',
    llm_model: 'gpt-oss',
    research_effort: 'high',
    created_at: '2026-01-01T00:00:00Z',
    phases: [],
    total_elapsed_s: null,
    ...overrides,
  }
}

describe('RunsStatusTable', () => {
  it('renders nothing for an empty runs list', () => {
    const { container } = render(<RunsStatusTable runs={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the model (and effort) as the first column', () => {
    render(<RunsStatusTable runs={[makeRun({ llm_model: 'Mistral-Large-3', research_effort: 'high' })]} />)
    expect(screen.getByText('Mistral-Large-3')).toBeInTheDocument()
    expect(screen.getByText('· high')).toBeInTheDocument()
  })

  it('falls back to the provider when llm_model is absent', () => {
    render(<RunsStatusTable runs={[makeRun({ llm_model: null, llm_provider: 'alt-provider' })]} />)
    expect(screen.getByText('alt-provider')).toBeInTheDocument()
  })

  it('shows the run status', () => {
    render(<RunsStatusTable runs={[makeRun({ generation_status: 'error' })]} />)
    expect(screen.getByText('error')).toBeInTheDocument()
  })

  it('marks a completed run\'s workflow phases as done', () => {
    render(
      <RunsStatusTable
        runs={[
          makeRun({
            generation_status: 'completed',
            phases: [
              { step: 'intake_classifier', status: 'ok', elapsed_s: 1 },
              { step: 'report_render', status: 'ok', elapsed_s: 1 },
            ],
          }),
        ]}
      />,
    )
    // All 5 coarse phase labels render.
    for (const label of ['Evidence', 'IOC', 'Analysis', 'Execution', 'Report']) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })

  it('flags a failed step\'s coarse phase as an error', () => {
    render(
      <RunsStatusTable
        runs={[
          makeRun({
            generation_status: 'error',
            phases: [{ step: 'intake_classifier', status: 'error', elapsed_s: 1 }],
          }),
        ]}
      />,
    )
    const iocPhase = screen.getByText('IOC').closest('div')
    expect(iocPhase).toHaveClass('text-red-400')
  })

  it('renders one row per run', () => {
    render(
      <RunsStatusTable
        runs={[makeRun({ id: 'run-1', llm_model: 'model-a' }), makeRun({ id: 'run-2', llm_model: 'model-b' })]}
      />,
    )
    expect(screen.getByText('model-a')).toBeInTheDocument()
    expect(screen.getByText('model-b')).toBeInTheDocument()
  })
})

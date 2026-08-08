/**
 * Tests for ReactFlowVisualizer's "Track workflow" behavior (issue-local-018
 * follow-up): when enabled, the chart re-centers on the currently active
 * node every time it changes, instead of staying at its initial fit.
 *
 * @xyflow/react is mocked — its actual rendering (SVG/canvas layout) isn't
 * under test here, only that this component wires onInit/fitView calls
 * correctly given the trackWorkflow prop and genRecord.current_step.
 */
import { render } from '@testing-library/react'
import { useEffect, useRef } from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THGenerationRecord } from '../api/client'

const fitViewMock = vi.fn()

vi.mock('@xyflow/react', () => {
  return {
    // Real ReactFlow's onInit fires exactly once, on mount — mimic that
    // with a ref guard rather than calling it on every render.
    ReactFlow: ({ onInit, children }: { onInit?: (instance: unknown) => void; children?: React.ReactNode }) => {
      const initialized = useRef(false)
      useEffect(() => {
        if (initialized.current) return
        initialized.current = true
        onInit?.({ fitView: fitViewMock })
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, [])
      return <div data-testid="react-flow-stub">{children}</div>
    },
    Background: () => null,
    Controls: () => null,
    // issue-local-042 follow-up: FitViewOnReady (rendered as a child of
    // <ReactFlow>) now owns the initial scoped fitView call, via these two
    // hooks instead of onInit directly — jsdom never actually measures node
    // dimensions, so "initialized" is mocked true immediately (no real
    // measurement to wait for in this test's stubbed rendering anyway).
    useNodesInitialized: () => true,
    useReactFlow: () => ({ fitView: fitViewMock }),
  }
})

import ReactFlowVisualizer from '../pages/threat-hunting/ReactFlowVisualizer'

function makeGenRecord(overrides: Partial<THGenerationRecord> = {}): THGenerationRecord {
  return {
    id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'running',
    current_step: 'intake_classifier',
    completed_steps: [],
    step_logs: [],
    ...overrides,
  } as THGenerationRecord
}

beforeEach(() => {
  fitViewMock.mockClear()
})

describe('ReactFlowVisualizer — trackWorkflow (issue-local-018 follow-up)', () => {
  it('fits view to Evidence + intake_classifier once on mount regardless of trackWorkflow', () => {
    render(<ReactFlowVisualizer genRecord={makeGenRecord()} trackWorkflow={false} />)
    expect(fitViewMock).toHaveBeenCalledTimes(1)
    expect(fitViewMock).toHaveBeenCalledWith(
      expect.objectContaining({ nodes: [{ id: 'intake_classifier' }] }),
    )
  })

  it('does not re-fit when the active step changes and trackWorkflow is off', () => {
    const { rerender } = render(<ReactFlowVisualizer genRecord={makeGenRecord()} trackWorkflow={false} />)
    fitViewMock.mockClear()
    rerender(
      <ReactFlowVisualizer
        genRecord={makeGenRecord({ current_step: 'hypothesis_generator' })}
        trackWorkflow={false}
      />,
    )
    expect(fitViewMock).not.toHaveBeenCalled()
  })

  it('re-fits on the newly active node whenever it changes while trackWorkflow is on', () => {
    const { rerender } = render(<ReactFlowVisualizer genRecord={makeGenRecord()} trackWorkflow={true} />)
    fitViewMock.mockClear()
    rerender(
      <ReactFlowVisualizer
        genRecord={makeGenRecord({ current_step: 'hypothesis_generator' })}
        trackWorkflow={true}
      />,
    )
    expect(fitViewMock).toHaveBeenCalledWith(
      expect.objectContaining({ nodes: [{ id: 'hypothesis_generator' }] }),
    )
  })

  it('re-fits immediately when trackWorkflow is toggled on for an already-active step', () => {
    const { rerender } = render(<ReactFlowVisualizer genRecord={makeGenRecord()} trackWorkflow={false} />)
    fitViewMock.mockClear()
    rerender(<ReactFlowVisualizer genRecord={makeGenRecord()} trackWorkflow={true} />)
    expect(fitViewMock).toHaveBeenCalledWith(
      expect.objectContaining({ nodes: [{ id: 'intake_classifier' }] }),
    )
  })

  // issue-local-041: regression for the "Track workflow" checkbox reading
  // checked but doing nothing after switching tabs and back. AnalysisTab
  // unmounts/remounts this component's whole subtree on tab switch — a
  // fresh mount with trackWorkflow ALREADY true (its default) and an
  // already-active step must fit-view on that step without requiring the
  // user to uncheck/recheck the box.
  it('fits view to the already-active step on a fresh mount with trackWorkflow already on', () => {
    render(
      <ReactFlowVisualizer
        genRecord={makeGenRecord({ current_step: 'hypothesis_generator' })}
        trackWorkflow={true}
      />,
    )
    expect(fitViewMock).toHaveBeenCalledWith(
      expect.objectContaining({ nodes: [{ id: 'hypothesis_generator' }] }),
    )
  })
})

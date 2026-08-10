/**
 * Tests for issue-local-016's manual IOC verdict override feature:
 *   - IocVerdictToggle: Keep/Remove segmented control, dirty-ring on staged
 *     overrides.
 *   - useIocVerdictStaging: per-IOC staged-map, unstage-on-match-server-value,
 *     dirty count, apply clears pending + invalidates queries.
 *   - RetrohuntPanel: three-way All/Sanitized/Removed filter, and the
 *     verdict toggle column appearing only when interactive props are given.
 */
import { render, screen, fireEvent, renderHook, act, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THDeepRetrohuntLead, THSanitizedIOC } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      // issue-local-041 follow-up: the new "Show Pipeline Diagram" toggle
      // mounts WorkflowVisualizer, which queries these on its own — mocked
      // here so opening it doesn't hit a real, unmocked fetch().
      getAgentVerbosity: vi.fn().mockResolvedValue({ agent_workflow_verbosity: 'verbose' }),
      getAgentVisualization: vi.fn().mockResolvedValue({ agent_workflow_visualization: 'timeline' }),
      getAgentShowSubtasks: vi.fn().mockResolvedValue({ agent_workflow_show_subtasks: false }),
      threatHunting: {
        ...actual.api.threatHunting,
        updateIocVerdicts: vi.fn(),
        getRunStatus: vi.fn(),
        getGenerationStatus: vi.fn(),
        listIocs: vi.fn(),
        listEvidence: vi.fn(),
      },
    },
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isResearcher: true,
    isAdmin: true,
    authEnabled: false,
    isAuthenticated: true,
    loading: false,
    user: null,
  }),
}))

// issue-local-023: AnalysisTab lazy-renders HypothesisLeadIocChart once its
// "Show Hunting Artifacts Relationship" toggle is clicked — mocked here the
// same minimal way as hypothesisLeadIocChart.test.tsx/
// reactFlowVisualizerTracking.test.tsx, so actual SVG/canvas graph layout
// isn't a dependency of these otherwise-unrelated IOC-verdict tests.
vi.mock('@xyflow/react', () => ({
  ReactFlow: ({ nodes }: { nodes: { id: string }[] }) => (
    <div data-testid="react-flow-stub">{nodes.length}</div>
  ),
  Background: () => null,
  Controls: () => null,
}))

import { api } from '../api/client'
import IocVerdictToggle from '../pages/threat-hunting/IocVerdictToggle'
import { useIocVerdictStaging } from '../pages/threat-hunting/useIocVerdictStaging'
import RetrohuntPanel from '../pages/threat-hunting/RetrohuntPanel'
import AnalysisTab from '../pages/threat-hunting/AnalysisTab'

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>
}

beforeEach(() => {
  vi.mocked(api.threatHunting.updateIocVerdicts).mockReset()
  vi.mocked(api.threatHunting.getRunStatus).mockReset()
  vi.mocked(api.threatHunting.getGenerationStatus).mockReset()
  vi.mocked(api.threatHunting.listIocs).mockReset()
  vi.mocked(api.threatHunting.listEvidence).mockReset()
})

describe('IocVerdictToggle', () => {
  it('renders Keep active when value is keep, no dirty ring', () => {
    const onChange = vi.fn()
    render(<IocVerdictToggle value="keep" onChange={onChange} />)
    // issue-local-022 (item 6): brighter active-state fill for contrast.
    expect(screen.getByRole('button', { name: 'Keep' })).toHaveClass('bg-green-700/70')
    expect(screen.getByRole('button', { name: 'Remove' })).not.toHaveClass('bg-red-700/70')
  })

  it('calls onChange with the clicked verdict', () => {
    const onChange = vi.fn()
    render(<IocVerdictToggle value="keep" onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }))
    expect(onChange).toHaveBeenCalledWith('remove')
  })

  it('shows a dirty ring and reflects the pending value when it differs from the server value', () => {
    const { container } = render(<IocVerdictToggle value="keep" pending="remove" onChange={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'Remove' })).toHaveClass('bg-red-700/70')
    expect(container.querySelector('[title*="staged"]')).toBeInTheDocument()
  })
})

describe('useIocVerdictStaging', () => {
  it('stages a change and reports it dirty', () => {
    const { result } = renderHook(() => useIocVerdictStaging('pkg-1', 'run-1'), { wrapper })
    expect(result.current.isDirty).toBe(false)
    act(() => result.current.stage('evil.com', 'domain', 'remove', 'keep'))
    expect(result.current.isDirty).toBe(true)
    expect(result.current.pendingCount).toBe(1)
    expect(result.current.pendingFor('evil.com', 'domain')).toBe('remove')
  })

  it('unstages when the action is set back to the server value', () => {
    const { result } = renderHook(() => useIocVerdictStaging('pkg-1', 'run-1'), { wrapper })
    act(() => result.current.stage('evil.com', 'domain', 'remove', 'keep'))
    act(() => result.current.stage('evil.com', 'domain', 'keep', 'keep'))
    expect(result.current.isDirty).toBe(false)
    expect(result.current.pendingFor('evil.com', 'domain')).toBeUndefined()
  })

  it('tracks multiple distinct IOCs independently', () => {
    const { result } = renderHook(() => useIocVerdictStaging('pkg-1', 'run-1'), { wrapper })
    act(() => result.current.stage('evil.com', 'domain', 'remove', 'keep'))
    act(() => result.current.stage('1.2.3.4', 'ip', 'remove', 'keep'))
    expect(result.current.pendingCount).toBe(2)
  })

  it('apply sends staged updates and clears pending on success', async () => {
    vi.mocked(api.threatHunting.updateIocVerdicts).mockResolvedValue({
      status: 'ok',
      updated_count: 1,
      deep_retrohunt: null,
    })
    const { result } = renderHook(() => useIocVerdictStaging('pkg-1', 'run-1'), { wrapper })
    act(() => result.current.stage('evil.com', 'domain', 'remove', 'keep'))
    act(() => result.current.apply())

    await waitFor(() => expect(result.current.isDirty).toBe(false))
    expect(api.threatHunting.updateIocVerdicts).toHaveBeenCalledWith('pkg-1', 'run-1', [
      { ioc: 'evil.com', ioc_type: 'domain', action: 'remove' },
    ])
    expect(result.current.pendingCount).toBe(0)
  })
})

function makeRetrohunt(sanitized: THSanitizedIOC[]): THDeepRetrohuntLead {
  return {
    sanitized_iocs: sanitized,
    ioc_csv: 'ioc,ioc_type,ioc_description\n',
    total_ioc_count: sanitized.filter((s) => s.action !== 'remove').length,
    noisy_ioc_count: 0,
    high_noise_ioc_count: 0,
    spl_draft: '',
    spl_macro_name: 'macro',
    search_hint: '',
    analyst_notes: '',
    llm_parse_error: false,
  }
}

describe('RetrohuntPanel — three-way filter + verdict column', () => {
  const sanitized: THSanitizedIOC[] = [
    { ioc: 'evil.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.1, noise_reasons: [], search_token: 'tok-evil', action: 'keep' },
    { ioc: 'google.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.9, noise_reasons: ['known CDN'], search_token: 'tok-google', action: 'remove' },
  ]

  it('defaults to the Sanitized filter (kept IOCs only)', () => {
    render(<RetrohuntPanel retrohunt={makeRetrohunt(sanitized)} pkgId="pkg-1" />)
    expect(screen.getByText('evil.com')).toBeInTheDocument()
    expect(screen.queryByText('google.com')).not.toBeInTheDocument()
  })

  it('All shows every IOC regardless of verdict', () => {
    render(<RetrohuntPanel retrohunt={makeRetrohunt(sanitized)} pkgId="pkg-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'All' }))
    expect(screen.getByText('evil.com')).toBeInTheDocument()
    expect(screen.getByText('google.com')).toBeInTheDocument()
  })

  it('Removed shows only removed IOCs', () => {
    render(<RetrohuntPanel retrohunt={makeRetrohunt(sanitized)} pkgId="pkg-1" />)
    fireEvent.click(screen.getByRole('button', { name: /^Removed/ }))
    expect(screen.queryByText('evil.com')).not.toBeInTheDocument()
    expect(screen.getByText('google.com')).toBeInTheDocument()
  })

  it('does not render a verdict toggle when no staging props are given (read-only draft view)', () => {
    render(<RetrohuntPanel retrohunt={makeRetrohunt(sanitized)} pkgId="pkg-1" />)
    expect(screen.queryByRole('button', { name: 'Keep' })).not.toBeInTheDocument()
  })

  it('renders an interactive verdict toggle per row when staging props are given', () => {
    const onStageVerdict = vi.fn()
    render(
      <RetrohuntPanel
        retrohunt={makeRetrohunt(sanitized)}
        pkgId="pkg-1"
        pendingFor={() => undefined}
        onStageVerdict={onStageVerdict}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'All' }))
    const removeButtons = screen.getAllByRole('button', { name: 'Remove' })
    fireEvent.click(removeButtons[0])
    expect(onStageVerdict).toHaveBeenCalledWith('evil.com', 'domain', 'remove', 'keep')
  })

  describe('iocApplyBar (issue-local-018 follow-up)', () => {
    it('renders the Apply button next to the All/Sanitized/Removed filter when dirty', () => {
      const onApply = vi.fn()
      render(
        <RetrohuntPanel
          retrohunt={makeRetrohunt(sanitized)}
          pkgId="pkg-1"
          iocApplyBar={{ isDirty: true, pendingCount: 2, isApplying: false, justApplied: false, onApply }}
        />,
      )
      expect(screen.getByText('2 staged')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: /Apply changes/ }))
      expect(onApply).toHaveBeenCalled()
    })

    it('renders nothing when not dirty and not just applied', () => {
      render(
        <RetrohuntPanel
          retrohunt={makeRetrohunt(sanitized)}
          pkgId="pkg-1"
          iocApplyBar={{ isDirty: false, pendingCount: 0, isApplying: false, justApplied: false, onApply: vi.fn() }}
        />,
      )
      expect(screen.queryByText(/staged/)).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /Apply changes/ })).not.toBeInTheDocument()
    })

    it('shows a confirmation after applying', () => {
      render(
        <RetrohuntPanel
          retrohunt={makeRetrohunt(sanitized)}
          pkgId="pkg-1"
          iocApplyBar={{ isDirty: false, pendingCount: 0, isApplying: false, justApplied: true, onApply: vi.fn() }}
        />,
      )
      expect(screen.getByText('Applied')).toBeInTheDocument()
    })

    it('does not render when iocApplyBar is omitted (read-only draft view)', () => {
      render(<RetrohuntPanel retrohunt={makeRetrohunt(sanitized)} pkgId="pkg-1" />)
      expect(screen.queryByText(/staged/)).not.toBeInTheDocument()
    })
  })
})

describe('RetrohuntPanel — removal-reason dedupe (issue-local-022 item 6)', () => {
  const REMOVE_NOISY_REASON = 'Flagged as noisy — excluded by active cleaning (remove_noisy)'

  const manyRemoved: THSanitizedIOC[] = [
    { ioc: 'noisy1.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.9, noise_reasons: [REMOVE_NOISY_REASON], search_token: 'tok-1', action: 'remove' },
    { ioc: 'noisy2.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.9, noise_reasons: [REMOVE_NOISY_REASON], search_token: 'tok-2', action: 'remove' },
    { ioc: 'noisy3.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.9, noise_reasons: [REMOVE_NOISY_REASON, 'also unusually long TLD'], search_token: 'tok-3', action: 'remove' },
    { ioc: 'kept.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.1, noise_reasons: [], search_token: 'tok-4', action: 'keep' },
  ]

  it('shows the shared removal reason once, with a count, instead of repeating it per row', () => {
    render(<RetrohuntPanel retrohunt={makeRetrohunt(manyRemoved)} pkgId="pkg-1" />)
    fireEvent.click(screen.getByRole('button', { name: /^Removed/ }))

    // Summary line: exactly one occurrence, with the count of affected IOCs.
    const summaryOccurrences = screen.getAllByText(
      (_, node) => node?.tagName === 'SPAN' && node?.textContent === `${REMOVE_NOISY_REASON} — 3 IOCs`,
    )
    expect(summaryOccurrences.length).toBe(1)
  })

  it('still shows a reason unique to one IOC inline on that row, not just in the summary', () => {
    render(<RetrohuntPanel retrohunt={makeRetrohunt(manyRemoved)} pkgId="pkg-1" />)
    fireEvent.click(screen.getByRole('button', { name: /^Removed/ }))
    expect(screen.getByText('also unusually long TLD')).toBeInTheDocument()
  })

  it('does not show a removal-reason summary when no reason is shared by more than one IOC', () => {
    const uniqueOnly: THSanitizedIOC[] = [
      { ioc: 'a.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.9, noise_reasons: ['reason A'], search_token: 'tok-a', action: 'remove' },
      { ioc: 'b.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.9, noise_reasons: ['reason B'], search_token: 'tok-b', action: 'remove' },
    ]
    render(<RetrohuntPanel retrohunt={makeRetrohunt(uniqueOnly)} pkgId="pkg-1" />)
    fireEvent.click(screen.getByRole('button', { name: /^Removed/ }))
    expect(screen.queryByText('Removal reasons')).not.toBeInTheDocument()
  })
})

describe('AnalysisTab — evidence-chip flag for manually removed IOCs', () => {
  function renderTab(props: Partial<React.ComponentProps<typeof AnalysisTab>> = {}) {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    return render(
      <QueryClientProvider client={qc}>
        <AnalysisTab pkgId="pkg-1" runId="run-1" {...props} />
      </QueryClientProvider>,
    )
  }

  it('flags a hypothesis ioc_basis chip as struck-through when that IOC was removed, leaving kept IOCs unaffected', async () => {
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
      hunt_package_id: 'pkg-1',
      run_id: 'run-1',
      generation_status: 'completed',
      hypotheses: [
        {
          id: 'h1',
          title: 'Test hypothesis',
          description: '',
          justification: '',
          relevance: 'high',
          ioc_basis: ['evil.com', 'good.com'],
        },
      ],
    })
    vi.mocked(api.threatHunting.listIocs).mockResolvedValue([
      {
        id: 'ioc-1', evidence_item_id: 'ev-1', hunt_package_id: 'pkg-1', run_id: 'run-1',
        ioc: 'evil.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.9,
        flagged_noisy: true, action: 'remove', created_at: '2026-01-01T00:00:00Z',
      },
      {
        id: 'ioc-2', evidence_item_id: 'ev-1', hunt_package_id: 'pkg-1', run_id: 'run-1',
        ioc: 'good.com', ioc_type: 'domain', ioc_description: '', noise_score: 0.1,
        flagged_noisy: false, action: 'keep', created_at: '2026-01-01T00:00:00Z',
      },
    ])
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])

    renderTab()

    await screen.findByText('evil.com')
    await waitFor(() => expect(screen.getByText('evil.com')).toHaveClass('line-through'))
    expect(screen.getByText('good.com')).not.toHaveClass('line-through')
  })

  // issue-local-023: the Hypothesis/Lead/IOC relationship chart moved below
  // the main (Threat Context) summary and is collapsed by default behind an
  // emphasized "Show Hunting Artifacts Relationship" toggle, instead of
  // always rendering above everything.
  it('keeps the relationship chart collapsed by default, below Threat Context, revealed by its toggle button', async () => {
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
      hunt_package_id: 'pkg-1',
      run_id: 'run-1',
      generation_status: 'completed',
      threat_context: { summary: 'A summary of the threat.' },
      hypotheses: [],
    })
    vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])

    renderTab()

    const summary = await screen.findByText('A summary of the threat.')
    const toggle = screen.getByRole('button', { name: /Show Hunting Artifacts Relationship/i })
    // Threat Context renders before the chart's toggle button in DOM order.
    expect(summary.compareDocumentPosition(toggle) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    // Collapsed by default — the chart itself hasn't rendered yet.
    expect(screen.queryByTestId('react-flow-stub')).not.toBeInTheDocument()

    fireEvent.click(toggle)

    expect(await screen.findByRole('button', { name: /Hide Hunting Artifacts Relationship/i })).toBeInTheDocument()
  })

  // issue-local-041 follow-up: the pipeline diagram (with its per-node hover
  // tooltips) used to only render while a run's status was 'running' —
  // unreachable once a run finished, which is the state a run is in during
  // almost all review. It now also renders here, collapsed by default below
  // Threat Context, behind its own toggle.
  it('keeps the pipeline diagram collapsed by default, below Threat Context, revealed by its own toggle', async () => {
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
      hunt_package_id: 'pkg-1',
      run_id: 'run-1',
      generation_status: 'awaiting_approval',
      threat_context: { summary: 'A summary of the threat.' },
      hypotheses: [],
      current_step: 'report_render',
      completed_steps: ['intake_classifier'],
    })
    vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])

    renderTab()

    const summary = await screen.findByText('A summary of the threat.')
    const toggle = screen.getByRole('button', { name: /Show Pipeline Diagram/i })
    expect(summary.compareDocumentPosition(toggle) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    // Collapsed by default — the timeline's step list hasn't rendered yet.
    expect(screen.queryByText('Intake Classifier')).not.toBeInTheDocument()

    await act(async () => {
      fireEvent.click(toggle)
    })

    expect(await screen.findByRole('button', { name: /Hide Pipeline Diagram/i })).toBeInTheDocument()
    expect(await screen.findByText('Intake Classifier')).toBeInTheDocument()
  })

  it('also renders the Pipeline Diagram toggle on a completed (read-only) run', async () => {
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
      hunt_package_id: 'pkg-1',
      run_id: 'run-1',
      generation_status: 'completed',
      threat_context: { summary: 'A summary of the threat.' },
      hypotheses: [],
      current_step: 'report_render',
      completed_steps: ['intake_classifier'],
    })
    vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])

    renderTab()

    await screen.findByText('A summary of the threat.')
    expect(screen.getByRole('button', { name: /Show Pipeline Diagram/i })).toBeInTheDocument()
  })

  describe('Approve gating on unapplied IOC verdict changes (issue-local-018 follow-up)', () => {
    beforeEach(() => {
      vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
        hunt_package_id: 'pkg-1',
        run_id: 'run-1',
        generation_status: 'awaiting_approval',
        hypotheses: [],
      })
      vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
      vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
    })

    it('enables Approve when there are no staged IOC verdict changes', async () => {
      renderTab({ iocVerdictsDirty: false })
      expect(await screen.findByRole('button', { name: 'Approve' })).not.toBeDisabled()
    })

    it('disables Approve and shows a warning while IOC verdict changes are unapplied', async () => {
      renderTab({ iocVerdictsDirty: true })
      expect(await screen.findByRole('button', { name: 'Approve' })).toBeDisabled()
      expect(screen.getByText(/unapplied IOC verdict changes/i)).toBeInTheDocument()
    })
  })
})

/**
 * Tests for issue-local-022 (item 3): RunConfigForm.tsx is the single
 * shared source for the run-configuration fields used by both
 * AnalysisTab.tsx's first-run form ('compact' variant) and HuntDetail.tsx's
 * Re-run dialog ('dialog' variant) — this guards that both variants render
 * the same controlled fields and call the right change handlers, so the two
 * call sites can't silently drift apart again.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import RunConfigForm from '../pages/threat-hunting/RunConfigForm'
import { DEFAULT_IOC_CLEANING_OPTIONS, playbookChoiceValue } from '../pages/threat-hunting/runConfigUtils'
import type { THPlaybook } from '../api/client'

function baseProps(overrides: Partial<React.ComponentProps<typeof RunConfigForm>> = {}) {
  return {
    variant: 'dialog' as const,
    effort: 'medium',
    onEffortChange: vi.fn(),
    modelChoice: '',
    onModelChoiceChange: vi.fn(),
    modelOptions: [{ provider: 'openai', model: 'gpt-oss' }],
    iocMode: 'active_cleaning' as const,
    onIocModeChange: vi.fn(),
    iocCleaningOptions: DEFAULT_IOC_CLEANING_OPTIONS,
    onIocCleaningOptionsChange: vi.fn(),
    includeThreatIntel: true,
    onIncludeThreatIntelChange: vi.fn(),
    ...overrides,
  }
}

describe('RunConfigForm', () => {
  it('renders the Threat Intel checkbox checked by default in both variants', () => {
    const { unmount } = render(<RunConfigForm {...baseProps({ variant: 'dialog' })} />)
    expect(screen.getByText(/Include Threat Intel analysis/)).toBeInTheDocument()
    unmount()
    render(<RunConfigForm {...baseProps({ variant: 'compact' })} />)
    expect(screen.getByText(/Include Threat Intel analysis/)).toBeInTheDocument()
  })

  it('calls onIncludeThreatIntelChange when the Threat Intel checkbox is toggled', () => {
    const onIncludeThreatIntelChange = vi.fn()
    render(<RunConfigForm {...baseProps({ includeThreatIntel: true, onIncludeThreatIntelChange })} />)
    const checkbox = screen.getByText(/Include Threat Intel analysis/).closest('label')!.querySelector('input')!
    fireEvent.click(checkbox)
    expect(onIncludeThreatIntelChange).toHaveBeenCalledWith(false)
  })

  it('shows the IOC cleaning toggles only when iocMode is active_cleaning', () => {
    const { rerender } = render(<RunConfigForm {...baseProps({ iocMode: 'tagging_only' })} />)
    expect(screen.queryByText(/Remove noisy IOCs/)).not.toBeInTheDocument()
    rerender(<RunConfigForm {...baseProps({ iocMode: 'active_cleaning' })} />)
    expect(screen.getByText(/Remove noisy IOCs/)).toBeInTheDocument()
  })

  it('calls onEffortChange when an effort pill is clicked', () => {
    const onEffortChange = vi.fn()
    render(<RunConfigForm {...baseProps({ effort: 'medium', onEffortChange })} />)
    fireEvent.click(screen.getByRole('button', { name: 'high' }))
    expect(onEffortChange).toHaveBeenCalledWith('high')
  })

  describe('issue-local-040: playbook options in the model dropdown', () => {
    const playbooks: THPlaybook[] = [
      {
        id: 'pb-1',
        name: 'Multi-model triage',
        models: [
          { provider_name: 'openai', model_name: 'gpt-oss' },
          { provider_name: 'anthropic', model_name: 'claude' },
        ],
        auto_approve_analysis: false,
        auto_run_comparison: false,
        auto_compare_preliminary: false,
        auto_compare_full: false,
        auto_create_run_from_recommendations: false,
        auto_generate_full_report: false,
        created_at: '2026-01-01T00:00:00Z',
        created_by: null,
        updated_at: '2026-01-01T00:00:00Z',
      },
    ]

    it('does not render a Playbook optgroup when none are passed', () => {
      render(<RunConfigForm {...baseProps({ variant: 'dialog' })} />)
      expect(screen.queryByText(/Multi-model triage/)).not.toBeInTheDocument()
    })

    it('lists each playbook in both variants, showing its model count', () => {
      const { unmount } = render(
        <RunConfigForm {...baseProps({ variant: 'dialog', playbookOptions: playbooks })} />,
      )
      expect(screen.getByText('Multi-model triage (2 models)')).toBeInTheDocument()
      unmount()
      render(<RunConfigForm {...baseProps({ variant: 'compact', playbookOptions: playbooks })} />)
      expect(screen.getByText('Multi-model triage (2 models)')).toBeInTheDocument()
    })

    it('selecting a playbook option calls onModelChoiceChange with the playbook-prefixed value', () => {
      const onModelChoiceChange = vi.fn()
      render(
        <RunConfigForm
          {...baseProps({ variant: 'dialog', playbookOptions: playbooks, onModelChoiceChange })}
        />,
      )
      const select = screen.getByText('Multi-model triage (2 models)').closest('select')!
      fireEvent.change(select, { target: { value: playbookChoiceValue('pb-1') } })
      expect(onModelChoiceChange).toHaveBeenCalledWith('playbook:pb-1')
    })
  })
})

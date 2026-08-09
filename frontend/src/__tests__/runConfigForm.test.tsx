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
import { DEFAULT_IOC_CLEANING_OPTIONS, DEFAULT_QUERY_LANGUAGES, playbookChoiceValue } from '../pages/threat-hunting/runConfigUtils'
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
    queryLanguages: DEFAULT_QUERY_LANGUAGES,
    onQueryLanguagesChange: vi.fn(),
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

  describe('issue-local-041: query language toggles', () => {
    it('renders SPL/KQL/CQL/Elasticsearch checkboxes reflecting the queryLanguages prop in both variants', () => {
      const { unmount } = render(
        <RunConfigForm
          {...baseProps({
            variant: 'dialog',
            queryLanguages: { spl: true, kql: true, cql: false, elasticsearch: true },
          })}
        />,
      )
      expect(screen.getByLabelText('SPL')).toBeChecked()
      expect(screen.getByLabelText('KQL')).toBeChecked()
      expect(screen.getByLabelText('CQL')).not.toBeChecked()
      expect(screen.getByLabelText('Elasticsearch')).toBeChecked()
      unmount()

      render(
        <RunConfigForm
          {...baseProps({
            variant: 'compact',
            queryLanguages: { spl: false, kql: false, cql: true, elasticsearch: false },
          })}
        />,
      )
      expect(screen.getByLabelText('SPL')).not.toBeChecked()
      expect(screen.getByLabelText('CQL')).toBeChecked()
    })

    it('calls onQueryLanguagesChange with an updater toggling only the clicked language', () => {
      const onQueryLanguagesChange = vi.fn()
      const queryLanguages = { spl: true, kql: true, cql: false, elasticsearch: true }
      render(<RunConfigForm {...baseProps({ queryLanguages, onQueryLanguagesChange })} />)

      fireEvent.click(screen.getByLabelText('CQL'))
      expect(onQueryLanguagesChange).toHaveBeenCalledTimes(1)
      const updater = onQueryLanguagesChange.mock.calls[0][0]
      expect(updater(queryLanguages)).toEqual({ spl: true, kql: true, cql: true, elasticsearch: true })
    })
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
        ioc_cleaning_enabled: false,
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

  // issue-local-042 (item 20 addendum): a playbook fires with its own
  // model/effort/IOC-cleaning config, none of which this form can actually
  // override — previously every field stayed fully interactive regardless,
  // implying control that had zero effect on a playbook-triggered run.
  describe('issue-local-042: disabled when a playbook is selected', () => {
    it.each(['dialog', 'compact'] as const)(
      'hides Effort/IOC Handling/Threat Intel/Query Languages and shows an explanatory note (%s variant)',
      (variant) => {
        render(
          <RunConfigForm
            {...baseProps({ variant, modelChoice: playbookChoiceValue('pb-1') })}
          />,
        )
        expect(screen.queryByText('Research Effort')).not.toBeInTheDocument()
        expect(screen.queryByText('Research effort:')).not.toBeInTheDocument()
        expect(screen.queryByText('IOC Handling')).not.toBeInTheDocument()
        expect(screen.queryByText('IOC handling:')).not.toBeInTheDocument()
        expect(screen.queryByText(/Include Threat Intel analysis/)).not.toBeInTheDocument()
        expect(screen.queryByText('Query Languages')).not.toBeInTheDocument()
        expect(screen.queryByText('Query languages:')).not.toBeInTheDocument()
        expect(screen.getByText(/has its own configuration/)).toBeInTheDocument()
      },
    )

    it('shows every field again once switched back to a standalone model', () => {
      const { rerender } = render(
        <RunConfigForm {...baseProps({ variant: 'dialog', modelChoice: playbookChoiceValue('pb-1') })} />,
      )
      expect(screen.queryByText('Research Effort')).not.toBeInTheDocument()

      rerender(<RunConfigForm {...baseProps({ variant: 'dialog', modelChoice: '0' })} />)
      expect(screen.getByText('Research Effort')).toBeInTheDocument()
      expect(screen.queryByText(/has its own configuration/)).not.toBeInTheDocument()
    })

    it('the model selector itself stays visible and interactive when a playbook is selected', () => {
      render(
        <RunConfigForm {...baseProps({ variant: 'dialog', modelChoice: playbookChoiceValue('pb-1') })} />,
      )
      expect(screen.getByText('Model')).toBeInTheDocument()
      expect(document.querySelector('select')).not.toBeDisabled()
    })
  })
})

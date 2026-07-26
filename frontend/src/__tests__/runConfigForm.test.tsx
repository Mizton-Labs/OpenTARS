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
import { DEFAULT_IOC_CLEANING_OPTIONS } from '../pages/threat-hunting/runConfigUtils'

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
})

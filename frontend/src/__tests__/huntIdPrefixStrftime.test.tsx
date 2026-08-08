/**
 * Regression test for issue-local-038: the HuntID Prefix input used to force
 * every keystroke to uppercase (`.toUpperCase()`), which silently corrupts
 * case-sensitive strftime directives — e.g. a typed "%m" (month) becomes
 * "%M" (minutes). The input must now preserve exactly what the admin types.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    api: {
      ...actual.api,
      getThResearchEffort: vi.fn().mockResolvedValue({ th_research_effort: 'medium' }),
      setThResearchEffort: vi.fn(),
      getThReportFormats: vi.fn().mockResolvedValue({ th_report_formats: { pdf: true, markdown: true } }),
      setThReportFormats: vi.fn(),
      getHuntIdPrefix: vi.fn().mockResolvedValue({ hunt_id_prefix: 'TH' }),
      setHuntIdPrefix: vi.fn().mockResolvedValue({ hunt_id_prefix: 'TH-%Y%m%d' }),
      getThQueryLanguages: vi.fn().mockResolvedValue({
        th_query_languages: { spl: true, kql: true, cql: false, elasticsearch: true },
      }),
      setThQueryLanguages: vi.fn(),
    },
  }
})

import { api } from '../api/client'
import ThreatHuntingSettingsTab from '../pages/configuration/ThreatHuntingSettingsTab'

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ThreatHuntingSettingsTab />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.getHuntIdPrefix).mockResolvedValue({ hunt_id_prefix: 'TH' })
})

describe('ThreatHuntingSettingsTab HuntID prefix (issue-local-038)', () => {
  it('preserves mixed-case strftime directives instead of forcing uppercase', async () => {
    renderTab()
    const input = await screen.findByDisplayValue('TH')

    fireEvent.change(input, { target: { value: 'TH-%Y%m%d' } })

    // Case must survive verbatim — %m (month) must NOT become %M (minutes).
    expect(input).toHaveValue('TH-%Y%m%d')
  })

  it('saves the exact typed prefix, case preserved', async () => {
    renderTab()
    const input = await screen.findByDisplayValue('TH')
    fireEvent.change(input, { target: { value: 'TH-%Y%m%d' } })

    fireEvent.click(screen.getByRole('button', { name: /save/i }))

    await waitFor(() => expect(api.setHuntIdPrefix).toHaveBeenCalledWith('TH-%Y%m%d'))
  })

  it('accepts a longer template (up to the new 24-char max)', async () => {
    renderTab()
    const input = await screen.findByDisplayValue('TH')
    expect(input).toHaveAttribute('maxLength', '24')
  })
})

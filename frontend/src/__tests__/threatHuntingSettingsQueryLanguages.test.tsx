/**
 * Tests for issue-local-041: the "Default Query Languages" card in
 * Configuration → Threat Hunting → Threat Hunting Packages — SPL/KQL/CQL/
 * Elasticsearch toggles controlling query_drafting_agent's default output.
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
      setHuntIdPrefix: vi.fn(),
      getThQueryLanguages: vi.fn(),
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
  vi.mocked(api.getThQueryLanguages).mockResolvedValue({
    th_query_languages: { spl: true, kql: true, cql: false, elasticsearch: true },
  })
})

describe('ThreatHuntingSettingsTab Default Query Languages (issue-local-041)', () => {
  it('renders the configured toggles (CQL off, others on)', async () => {
    renderTab()
    await screen.findByText('Default Query Languages')

    const cqlToggle = screen.getByText('CQL').closest('button')!
    const splToggle = screen.getByText('SPL').closest('button')!
    expect(cqlToggle).toHaveClass('border-gray-700')
    expect(splToggle).toHaveClass('border-brand-500')
  })

  it('toggling CQL on and saving persists all four languages', async () => {
    renderTab()
    await screen.findByText('Default Query Languages')

    fireEvent.click(screen.getByText('CQL').closest('button')!)
    fireEvent.click(screen.getByRole('button', { name: /save/i }))

    await waitFor(() =>
      expect(api.setThQueryLanguages).toHaveBeenCalledWith({
        spl: true,
        kql: true,
        cql: true,
        elasticsearch: true,
      }),
    )
  })

  it('warns when every language is disabled', async () => {
    renderTab()
    await screen.findByText('Default Query Languages')

    for (const label of ['SPL', 'KQL', 'Elasticsearch']) {
      fireEvent.click(screen.getByText(label).closest('button')!)
    }

    expect(
      screen.getByText(/At least one query language should be enabled/),
    ).toBeInTheDocument()
  })
})

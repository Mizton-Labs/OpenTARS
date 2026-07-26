/**
 * Focused tests for ConfigDriftModal's selection/apply behavior
 * (issue-local-024 follow-up) — the banner-level suite in
 * configDriftBanner.test.tsx covers the end-to-end open/apply flow; this
 * file exercises per-item checkbox selection in detail.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ConfigDriftReport } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      applyConfigDriftFix: vi.fn(),
    },
  }
})

import { api } from '../api/client'
import ConfigDriftModal from '../components/ConfigDriftModal'

function renderModal(reports: ConfigDriftReport[], onClose = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return {
    onClose,
    ...render(
      <QueryClientProvider client={qc}>
        <ConfigDriftModal reports={reports} onClose={onClose} />
      </QueryClientProvider>,
    ),
  }
}

beforeEach(() => {
  vi.mocked(api.applyConfigDriftFix).mockReset()
})

const twoFieldsReport: ConfigDriftReport = {
  file: 'feed-fields.yaml',
  missing_keys: [],
  missing_core_fields: [
    { name: 'field_a', description: 'First new field' },
    { name: 'field_b', description: 'Second new field' },
  ],
}

const mixedReport: ConfigDriftReport = {
  file: 'application.yaml',
  missing_keys: ['new_toggle'],
  missing_core_fields: [],
}

describe('ConfigDriftModal', () => {
  it('starts with every item selected', () => {
    renderModal([twoFieldsReport])
    const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[]
    expect(checkboxes).toHaveLength(2)
    expect(checkboxes.every(cb => cb.checked)).toBe(true)
    expect(screen.getByText('2 of 2 selected')).toBeInTheDocument()
  })

  it('unchecking an item excludes it from the apply payload', async () => {
    vi.mocked(api.applyConfigDriftFix).mockResolvedValue({ reports: [] })
    renderModal([twoFieldsReport])

    fireEvent.click(screen.getByText('field_b').closest('label')!.querySelector('input')!)
    expect(screen.getByText('1 of 2 selected')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Apply selected' }))

    await waitFor(() =>
      expect(api.applyConfigDriftFix).toHaveBeenCalledWith('feed-fields.yaml', {
        keys: [],
        core_field_names: ['field_a'],
      }),
    )
  })

  it('Apply is disabled once every item is unchecked', () => {
    renderModal([twoFieldsReport])
    const checkboxes = screen.getAllByRole('checkbox')
    checkboxes.forEach(cb => fireEvent.click(cb))
    expect(screen.getByRole('button', { name: 'Apply selected' })).toBeDisabled()
  })

  it('handles a mix of missing_keys and missing_core_fields across files independently', async () => {
    vi.mocked(api.applyConfigDriftFix).mockResolvedValue({ reports: [] })
    renderModal([twoFieldsReport, mixedReport])

    expect(screen.getByText('new_toggle')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Apply selected' }))

    await waitFor(() => expect(api.applyConfigDriftFix).toHaveBeenCalledTimes(2))
    expect(api.applyConfigDriftFix).toHaveBeenCalledWith('feed-fields.yaml', {
      keys: [],
      core_field_names: ['field_a', 'field_b'],
    })
    expect(api.applyConfigDriftFix).toHaveBeenCalledWith('application.yaml', {
      keys: ['new_toggle'],
      core_field_names: [],
    })
  })

  it('shows an inline error and does not close on apply failure', async () => {
    vi.mocked(api.applyConfigDriftFix).mockRejectedValue(new Error('Server exploded'))
    const { onClose } = renderModal([mixedReport])

    fireEvent.click(screen.getByRole('button', { name: 'Apply selected' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Server exploded')
    expect(onClose).not.toHaveBeenCalled()
  })

  it('Cancel closes without applying anything', () => {
    const { onClose } = renderModal([mixedReport])
    fireEvent.click(screen.getByText('Cancel'))
    expect(onClose).toHaveBeenCalled()
    expect(api.applyConfigDriftFix).not.toHaveBeenCalled()
  })
})

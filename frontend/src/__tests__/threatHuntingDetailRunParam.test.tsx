/**
 * Tests for ThreatHuntingDetail's `?run=` query-param deep link
 * (issue-local-034) — Data Explorer's Run column links to
 * `/threat-hunting/{pkgId}?run={runId}` to open a SPECIFIC run rather than
 * always landing on the package's newest run. HuntDetail.tsx already has an
 * `initialRunId` prop (used by the package list's Table density mode); the
 * gap was that the routed page never read it from the URL.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'

vi.mock('../pages/threat-hunting/HuntDetail', () => ({
  default: ({ pkgId, initialRunId }: { pkgId: string; initialRunId?: string }) => (
    <div>
      <span data-testid="pkg-id">{pkgId}</span>
      <span data-testid="initial-run-id">{initialRunId ?? '(none)'}</span>
    </div>
  ),
}))

import ThreatHuntingDetail from '../pages/threat-hunting/ThreatHuntingDetail'

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/threat-hunting/:id" element={<ThreatHuntingDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('ThreatHuntingDetail — ?run= deep link', () => {
  it('passes the run query param through as initialRunId', () => {
    renderAt('/threat-hunting/pkg-1?run=run-42')
    expect(screen.getByTestId('pkg-id')).toHaveTextContent('pkg-1')
    expect(screen.getByTestId('initial-run-id')).toHaveTextContent('run-42')
  })

  it('leaves initialRunId undefined when no run param is present', () => {
    renderAt('/threat-hunting/pkg-1')
    expect(screen.getByTestId('initial-run-id')).toHaveTextContent('(none)')
  })
})

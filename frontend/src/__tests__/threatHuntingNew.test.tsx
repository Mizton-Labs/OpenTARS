/**
 * Test for issue-local-042 (item 6): after the wizard finishes, the user
 * should land on the hunt package's default (Evidence) tab, not jump
 * straight to Analysis — reverses issue-local-040's choice, since Evidence
 * already lists what was just added and links onward to Analysis itself.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'

const navigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => navigate }
})

vi.mock('../pages/threat-hunting/HuntPackageWizard', () => ({
  default: ({ onCreated }: { onCreated: (id: string) => void }) => (
    <button onClick={() => onCreated('pkg-123')}>fire onCreated</button>
  ),
}))

import ThreatHuntingNew from '../pages/threat-hunting/ThreatHuntingNew'

describe('ThreatHuntingNew — post-wizard navigation (issue-local-042)', () => {
  it('navigates to the plain package URL (Evidence tab default), not ?tab=analysis', () => {
    render(<ThreatHuntingNew />)
    fireEvent.click(screen.getByText('fire onCreated'))
    expect(navigate).toHaveBeenCalledWith('../pkg-123', { relative: 'path' })
  })
})

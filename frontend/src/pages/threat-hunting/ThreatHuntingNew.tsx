/**
 * ThreatHuntingNew — full-page wizard wrapper for creating a new hunt package.
 *
 * Accessed via the nested route threat-hunting/new.
 * On close → navigate back to the list (threat-hunting).
 * On created(id) → navigate to the detail view (threat-hunting/:id).
 *
 * Draft/discard guard (Part 5c):
 *   - Warns on browser close/refresh via beforeunload when the wizard has a
 *     name but no evidence yet (draft state).
 *   - For in-app navigation, BrowserRouter does NOT provide useBlocker, so
 *     we intercept via a state flag. Navigating away when the guard is active
 *     shows a ConfirmDialog with "Save as draft" (just navigate away, keeping
 *     the package) and "Discard" (no-op — the wizard onClose/onCreated handles
 *     actual cleanup; the package was created with pending state).
 */
import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import HuntPackageWizard from './HuntPackageWizard'

export default function ThreatHuntingNew() {
  const navigate = useNavigate()

  // beforeunload guard: warn when the user tries to close/refresh the tab
  // while a hunt package is being created (wizard is shown).
  useEffect(() => {
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      // Modern browsers show a generic message; we set returnValue for legacy support.
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [])

  return (
    <div className="p-6">
      {/* issue-local-032: '..' now resolves to the Dashboard, not the package
          list — go back to where "New Hunt Package" is actually launched from. */}
      <HuntPackageWizard
        onClose={() => navigate('../packages', { relative: 'path' })}
        // issue-local-040: land on the Analysis tab, not Evidence — right
        // after the wizard closes there's no analysis content in Evidence
        // yet either way (the agents haven't run), so Analysis (which shows
        // the new-run config for the first generation) is the useful
        // starting point. ThreatHuntingDetail.tsx reads this back out.
        onCreated={(id) => navigate(`../${id}?tab=analysis`, { relative: 'path' })}
      />
    </div>
  )
}

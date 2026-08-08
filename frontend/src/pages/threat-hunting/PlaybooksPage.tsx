/**
 * PlaybooksPage — "Hunt Playbooks" sidebar entry, below Data Explorer
 * (issue-local-041).
 *
 * Was a Configuration → Threat Hunting tab (admin-only, issue-local-040);
 * moved to its own sidebar-reachable page, gated to threat-researcher and
 * admin (not threat-viewer) — see RequireResearcher in App.tsx. The actual
 * CRUD UI (HuntPlaybooksTab) is unchanged, just re-hosted under a page
 * header matching the other Threat Hunting sidebar pages (DataExplorer.tsx,
 * ThreatIntelTracking.tsx).
 */
import { ListChecks } from 'lucide-react'
import HuntPlaybooksTab from '../configuration/HuntPlaybooksTab'

export default function PlaybooksPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
          <ListChecks className="w-5 h-5 text-brand-400" />
          Hunt Playbooks
        </h1>
        <p className="text-sm text-gray-500">
          Named, reusable multi-model automation configs — fire N concurrent generation runs (one
          per enabled model) with optional auto-approve, auto-compare, and auto-consolidate. You
          can edit or delete your own playbooks; admins can manage any playbook.
        </p>
      </div>
      <HuntPlaybooksTab />
    </div>
  )
}

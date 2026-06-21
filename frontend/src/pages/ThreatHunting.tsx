import { useAuth } from '../auth/useAuth'

export default function ThreatHunting() {
  const { isResearcher } = useAuth()
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-gray-100">Threat Hunting</h1>
        <p className="text-sm text-gray-500">
          Agentic Threat Hunting Operations Framework.
        </p>
      </div>
      <div className="card space-y-3">
        <p className="text-sm text-gray-400">
          The Threat Hunting module is under construction. Phase 2 will introduce the
          manual Hunt Package wizard for creating investigation packages from files,
          URLs, watcher feeds, and manual notes.
        </p>
        {isResearcher && (
          <button className="btn-primary text-sm" disabled>
            New Hunt Package (coming soon)
          </button>
        )}
      </div>
    </div>
  )
}

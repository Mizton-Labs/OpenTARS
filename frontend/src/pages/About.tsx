import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { GitCommit, GitBranch, Calendar, Tag, Activity, Users, Github, Scale } from 'lucide-react'
import BrandLogo from '../components/BrandLogo'

declare const __APP_VERSION__: string
declare const __GIT_COMMIT__: string
declare const __GIT_BRANCH__: string
declare const __GIT_COMMIT_DATE__: string

export default function About() {
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
  })

  return (
    <div className="p-6 max-w-lg space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-gray-100">About</h1>
        <p className="text-sm text-gray-500">OpenTARS — version information.</p>
      </div>

      <div className="card space-y-5">
        {/* App identity */}
        <div className="flex items-center gap-3">
          <BrandLogo size={40} />
          <div>
            <p className="text-base font-semibold text-gray-100">OpenTARS</p>
            <p className="text-xs text-gray-500">Threat Agentic Research System</p>
          </div>
        </div>

        <div className="border-t border-gray-800" />

        {/* Version details */}
        <dl className="space-y-3">
          <div className="flex items-center gap-3">
            <Tag className="w-4 h-4 text-brand-400 shrink-0" />
            <dt className="text-sm text-gray-400 w-32">Version</dt>
            <dd className="text-sm font-mono text-gray-200">{__APP_VERSION__}</dd>
          </div>

          <div className="flex items-center gap-3">
            <GitCommit className="w-4 h-4 text-brand-400 shrink-0" />
            <dt className="text-sm text-gray-400 w-32">Git Commit</dt>
            <dd className="text-sm font-mono text-gray-200 truncate" title={__GIT_COMMIT__}>
              {__GIT_COMMIT__ === 'dev' ? 'dev (not built from git)' : __GIT_COMMIT__.slice(0, 12)}
            </dd>
          </div>

          {/* Commit date alongside the commit itself, so it's obvious how
              stale a running deployment is without cross-referencing git log. */}
          <div className="flex items-center gap-3">
            <Calendar className="w-4 h-4 text-brand-400 shrink-0" />
            <dt className="text-sm text-gray-400 w-32">Commit Date</dt>
            <dd className="text-sm font-mono text-gray-200 truncate" title={__GIT_COMMIT_DATE__}>
              {__GIT_COMMIT_DATE__ === 'unknown' ? 'unknown' : new Date(__GIT_COMMIT_DATE__).toLocaleString()}
            </dd>
          </div>

          {/* issue-local-016: explicit build branch alongside the commit, so
              the exact version deployed is always unambiguous (e.g. a feature
              branch build vs. main). */}
          <div className="flex items-center gap-3">
            <GitBranch className="w-4 h-4 text-brand-400 shrink-0" />
            <dt className="text-sm text-gray-400 w-32">Git Branch</dt>
            <dd className="text-sm font-mono text-gray-200 truncate" title={__GIT_BRANCH__}>
              {__GIT_BRANCH__}
            </dd>
          </div>

          <div className="flex items-center gap-3">
            <Activity className="w-4 h-4 text-brand-400 shrink-0" />
            <dt className="text-sm text-gray-400 w-32">Backend</dt>
            <dd className="text-sm">
              {health ? (
                <span className="badge bg-green-900/50 text-green-400 border border-green-800/50">
                  Online · v{health.version}
                </span>
              ) : (
                <span className="badge bg-red-900/50 text-red-400 border border-red-800/50">
                  Offline
                </span>
              )}
            </dd>
          </div>

          <div className="flex items-start gap-3">
            <Users className="w-4 h-4 text-brand-400 shrink-0 mt-0.5" />
            <dt className="text-sm text-gray-400 w-32 shrink-0">Code Dev Team</dt>
            <dd className="text-sm text-gray-200 space-y-1.5">
              {/* Repository link */}
              <a
                href="https://github.com/Mizton-Labs/Mizton-ThreatBox"
                target="_blank"
                rel="noopener noreferrer"
                title="OpenTARS on GitHub"
                className="inline-flex items-center gap-1.5 text-brand-400 hover:text-brand-300"
              >
                <Github className="w-4 h-4 shrink-0" />
                <span>Mizton-Labs/Mizton-ThreatBox</span>
              </a>
              {/* Authors — @jusafing always first; add future collaborators below */}
              <ul className="space-y-0.5 pl-0.5">
                {([
                  'jusafing',
                ] as const).map((username) => (
                  <li key={username} className="flex items-center gap-1 text-xs text-gray-400">
                    <span className="text-gray-600">•</span>
                    <a
                      href={`https://github.com/${username}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:text-gray-200 transition-colors"
                    >
                      @{username}
                    </a>
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        </dl>

        <div className="border-t border-gray-800" />

        <p className="text-xs text-gray-600 leading-relaxed">
          OpenTARS (Threat Agentic Research System) is a standalone, local Threat Intelligence and
          Threat Hunting platform. It listens for, pulls, and normalises threat intel from multiple
          sources, runs LLM-driven agentic threat-hunting workflows, stores data in SQLite, and
          exposes this web interface for viewing, hunting, and configuration.
        </p>
      </div>

      <div className="card space-y-3">
        <div className="flex items-center gap-3">
          <Scale className="w-4 h-4 text-brand-400 shrink-0" />
          <h2 className="text-sm font-semibold text-gray-200">License</h2>
        </div>
        <p className="text-xs text-gray-500 leading-relaxed">
          OpenTARS is released under the Apache License 2.0. The full
          terms are in the <span className="font-mono text-gray-400">LICENSE</span>{' '}
          file at the project root.
        </p>
        <p className="text-xs text-gray-500 leading-relaxed">
          This product includes third-party open-source software. Each component
          remains under its own license; see{' '}
          <span className="font-mono text-gray-400">THIRD-PARTY-NOTICES.md</span>{' '}
          for the list of bundled dependencies and their licenses.
        </p>
      </div>
    </div>
  )
}

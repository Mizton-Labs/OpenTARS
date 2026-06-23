/**
 * Home — landing page presenting the two main modules.
 *
 * Part 6: shows Threat Intel Feeds and Threat Hunting cards.
 */

import { useNavigate } from 'react-router-dom'
import { Radar, Crosshair } from 'lucide-react'

export default function Home() {
  const navigate = useNavigate()

  return (
    <div className="p-8 flex flex-col items-center">
      <div className="text-center mb-8">
        <h1 className="text-2xl font-bold text-gray-100">Mizton-ThreatBox</h1>
        <p className="text-sm text-gray-400 mt-2">Choose a module to get started</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-2xl mx-auto mt-8 w-full">
        {/* Threat Intel Feeds card */}
        <div
          className="card hover:border-brand-600/50 hover:bg-gray-800/40 cursor-pointer transition-all p-8 flex flex-col items-center text-center gap-4"
          onClick={() => navigate('../viewer', { relative: 'path' })}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') navigate('../viewer', { relative: 'path' }) }}
        >
          <div className="rounded-full bg-teal-900/40 border border-teal-700/40 p-3">
            <Radar className="w-16 h-16 text-teal-400" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-gray-100">Threat Intelligence Feeds</h2>
            <p className="text-sm text-gray-400 mt-2">
              Ingest, normalize and analyze threat intelligence from RSS feeds, APIs, local
              uploads and live watchers.
            </p>
          </div>
        </div>

        {/* Threat Hunting card */}
        <div
          className="card hover:border-brand-600/50 hover:bg-gray-800/40 cursor-pointer transition-all p-8 flex flex-col items-center text-center gap-4"
          onClick={() => navigate('../threat-hunting', { relative: 'path' })}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') navigate('../threat-hunting', { relative: 'path' }) }}
        >
          <div className="rounded-full bg-brand-900/40 border border-brand-700/40 p-3">
            <Crosshair className="w-16 h-16 text-brand-400" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-gray-100">Threat Hunting</h2>
            <p className="text-sm text-gray-400 mt-2">
              Run LLM-powered threat hunts: upload evidence, generate hypotheses, execute SIEM
              queries, and produce structured reports.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

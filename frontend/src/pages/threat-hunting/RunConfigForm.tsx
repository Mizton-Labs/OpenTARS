/**
 * RunConfigForm — shared run-configuration UI (model, research effort, IOC
 * handling mode + cleaning toggles, Threat Intel inclusion) used by both
 * AnalysisTab.tsx's first-run form and HuntDetail.tsx's Re-run dialog.
 *
 * issue-local-022 (item 3): these two forms used to be independently
 * duplicated pieces of state/JSX that drifted apart — e.g. the Re-run
 * dialog gained an `include_threat_intel` checkbox and an `active_cleaning`
 * default that the first-run form never got. This component is the single
 * source of truth for the fields themselves; each call site still owns its
 * own React state (they submit to different mutations) and is fully
 * controlled via props, so behavior/defaults can't silently diverge again.
 */

import { clsx } from 'clsx'
import type { THPlaybook, THQueryLanguages } from '../../api/client'
import {
  EFFORT_OPTIONS,
  playbookChoiceValue,
  type IocCleaningOptions,
  type ModelOption,
} from './runConfigUtils'

const CLEANING_TOGGLES = [
  ['remove_noisy', 'Noisy', 'Remove noisy IOCs'],
  ['remove_legit_domains', 'Legit domains', 'Remove known legit domains'],
  ['remove_cdn_ranges', 'CDN ranges', 'Remove known CDN ranges'],
  ['remove_legit_services', 'Legit services', 'Remove known legit services'],
] as const

// issue-local-041: SPL/KQL/CQL/ElasticSearch — same keys as
// th_query_languages (the global default) and run_config.query_languages
// (the per-run override this form edits).
const QUERY_LANGUAGE_TOGGLES: { key: keyof THQueryLanguages; label: string }[] = [
  { key: 'spl', label: 'SPL' },
  { key: 'kql', label: 'KQL' },
  { key: 'cql', label: 'CQL' },
  { key: 'elasticsearch', label: 'Elasticsearch' },
]

export default function RunConfigForm({
  variant,
  effort,
  onEffortChange,
  modelChoice,
  onModelChoiceChange,
  modelOptions,
  playbookOptions = [],
  iocMode,
  onIocModeChange,
  iocCleaningOptions,
  onIocCleaningOptionsChange,
  includeThreatIntel,
  onIncludeThreatIntelChange,
  queryLanguages,
  onQueryLanguagesChange,
}: {
  /** 'dialog' = vertical labeled layout (Re-run dialog); 'compact' = centered
   *  pill layout (first-run form). */
  variant: 'dialog' | 'compact'
  effort: string
  onEffortChange: (effort: string) => void
  modelChoice: string
  onModelChoiceChange: (choice: string) => void
  modelOptions: ModelOption[]
  /** issue-local-040: Hunt Playbooks offered alongside standalone models in
   *  the same selector, grouped under their own optgroup so the type
   *  ("standalone model" vs "playbook") is clear at a glance. */
  playbookOptions?: THPlaybook[]
  iocMode: 'tagging_only' | 'active_cleaning'
  onIocModeChange: (mode: 'tagging_only' | 'active_cleaning') => void
  iocCleaningOptions: IocCleaningOptions
  onIocCleaningOptionsChange: (updater: (prev: IocCleaningOptions) => IocCleaningOptions) => void
  includeThreatIntel: boolean
  onIncludeThreatIntelChange: (include: boolean) => void
  /** issue-local-041: which SIEM query languages this run should draft —
   *  seeded from the configured global default (th_query_languages) by the
   *  call site, editable here as a per-run override. */
  queryLanguages: THQueryLanguages
  onQueryLanguagesChange: (updater: (prev: THQueryLanguages) => THQueryLanguages) => void
}) {
  if (variant === 'compact') {
    return (
      <div className="space-y-3">
        <div className="flex items-center gap-2 justify-center text-sm">
          <span className="text-gray-500">Research effort:</span>
          {EFFORT_OPTIONS.map((e) => (
            <button
              key={e}
              onClick={() => onEffortChange(e)}
              className={clsx(
                'px-2.5 py-1 rounded text-sm border transition-colors capitalize',
                effort === e
                  ? 'border-brand-500 bg-brand-900/20 text-brand-300'
                  : 'border-gray-700 text-gray-500 hover:border-gray-500',
              )}
            >
              {e}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 justify-center text-sm">
          <label htmlFor="th-model-select" className="text-gray-500 shrink-0">Model:</label>
          <select
            id="th-model-select"
            className="input text-sm max-w-xs"
            value={modelChoice}
            onChange={(e) => onModelChoiceChange(e.target.value)}
          >
            <option value="">Configured default</option>
            {modelOptions.length > 0 && (
              <optgroup label="Standalone model">
                {modelOptions.map((o, i) => (
                  <option key={`${o.provider}\x00${o.model}`} value={String(i)}>
                    {o.provider} · {o.model}
                  </option>
                ))}
              </optgroup>
            )}
            {playbookOptions.length > 0 && (
              <optgroup label="Playbook">
                {playbookOptions.map((p) => (
                  <option key={p.id} value={playbookChoiceValue(p.id)}>
                    {p.name} ({p.models.length} model{p.models.length === 1 ? '' : 's'})
                  </option>
                ))}
              </optgroup>
            )}
          </select>
        </div>
        <div className="flex flex-col items-center gap-1.5 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-gray-500">IOC handling:</span>
            {(['tagging_only', 'active_cleaning'] as const).map((m) => (
              <button
                key={m}
                className={clsx(
                  'px-2.5 py-1 rounded text-sm border transition-colors',
                  iocMode === m
                    ? 'border-brand-500 bg-brand-900/20 text-brand-300'
                    : 'border-gray-700 text-gray-500 hover:border-gray-500',
                )}
                onClick={() => onIocModeChange(m)}
              >
                {m === 'tagging_only' ? 'Tagging only' : 'Active cleaning'}
              </button>
            ))}
          </div>
          {iocMode === 'active_cleaning' && (
            <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 pt-1">
              {CLEANING_TOGGLES.map(([key, shortLabel]) => (
                <label key={key} className="flex items-center gap-1 text-[12px] text-gray-400">
                  <input
                    type="checkbox"
                    checked={iocCleaningOptions[key]}
                    onChange={(e) =>
                      onIocCleaningOptionsChange((prev) => ({ ...prev, [key]: e.target.checked }))
                    }
                    className="accent-brand-500"
                  />
                  {shortLabel}
                </label>
              ))}
            </div>
          )}
        </div>
        <label className="flex items-center gap-2 justify-center text-[12px] text-gray-400">
          <input
            type="checkbox"
            checked={includeThreatIntel}
            onChange={(e) => onIncludeThreatIntelChange(e.target.checked)}
            className="accent-brand-500"
          />
          Include Threat Intel analysis (preliminary + post-execution)
        </label>
        <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-[12px]">
          <span className="text-gray-500">Query languages:</span>
          {QUERY_LANGUAGE_TOGGLES.map(({ key, label }) => (
            <label key={key} className="flex items-center gap-1 text-gray-400">
              <input
                type="checkbox"
                checked={queryLanguages[key]}
                onChange={(e) => {
                  const checked = e.target.checked
                  onQueryLanguagesChange((prev) => ({ ...prev, [key]: checked }))
                }}
                className="accent-brand-500"
              />
              {label}
            </label>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Model selector */}
      <div className="space-y-1.5">
        <label className="block text-sm text-gray-400">Model</label>
        <div className="relative">
          <select
            className="input w-full text-sm pr-7 appearance-none"
            value={modelChoice}
            onChange={(e) => onModelChoiceChange(e.target.value)}
          >
            <option value="">Configured default</option>
            {modelOptions.length > 0 && (
              <optgroup label="Standalone model">
                {modelOptions.map((opt, i) => (
                  <option key={`${opt.provider}:${opt.model}`} value={String(i)}>
                    {opt.provider} · {opt.model}
                  </option>
                ))}
              </optgroup>
            )}
            {playbookOptions.length > 0 && (
              <optgroup label="Playbook">
                {playbookOptions.map((p) => (
                  <option key={p.id} value={playbookChoiceValue(p.id)}>
                    {p.name} ({p.models.length} model{p.models.length === 1 ? '' : 's'})
                  </option>
                ))}
              </optgroup>
            )}
          </select>
        </div>
      </div>

      {/* Effort pills */}
      <div className="space-y-1.5">
        <label className="block text-sm text-gray-400">Research Effort</label>
        <div className="flex gap-2">
          {EFFORT_OPTIONS.map((e) => (
            <button
              key={e}
              className={clsx(
                'flex-1 py-1.5 text-sm rounded border transition-colors',
                effort === e
                  ? 'bg-brand-900/40 text-brand-300 border-brand-700/60'
                  : 'bg-gray-800/50 text-gray-500 border-gray-700/40 hover:text-gray-300',
              )}
              onClick={() => onEffortChange(e)}
            >
              {e}
            </button>
          ))}
        </div>
      </div>

      {/* IOC handling mode */}
      <div className="space-y-1.5">
        <label className="block text-sm text-gray-400">IOC Handling</label>
        <div className="flex gap-2">
          {(['tagging_only', 'active_cleaning'] as const).map((m) => (
            <button
              key={m}
              className={clsx(
                'flex-1 py-1.5 text-[12px] rounded border transition-colors',
                iocMode === m
                  ? 'bg-brand-900/40 text-brand-300 border-brand-700/60'
                  : 'bg-gray-800/50 text-gray-500 border-gray-700/40 hover:text-gray-300',
              )}
              onClick={() => onIocModeChange(m)}
            >
              {m === 'tagging_only' ? 'Tagging only' : 'Active cleaning'}
            </button>
          ))}
        </div>
        {iocMode === 'active_cleaning' && (
          <div className="space-y-1 pt-1">
            {CLEANING_TOGGLES.map(([key, , longLabel]) => (
              <label key={key} className="flex items-center gap-2 text-[12px] text-gray-400">
                <input
                  type="checkbox"
                  checked={iocCleaningOptions[key]}
                  onChange={(e) =>
                    onIocCleaningOptionsChange((prev) => ({ ...prev, [key]: e.target.checked }))
                  }
                  className="accent-brand-500"
                />
                {longLabel}
              </label>
            ))}
          </div>
        )}
      </div>

      {/* Threat Intel inclusion */}
      <label className="flex items-center gap-2 text-[12px] text-gray-400">
        <input
          type="checkbox"
          checked={includeThreatIntel}
          onChange={(e) => onIncludeThreatIntelChange(e.target.checked)}
          className="accent-brand-500"
        />
        Include Threat Intel analysis (preliminary + post-execution)
      </label>

      {/* Query languages (issue-local-041) */}
      <div className="space-y-1.5">
        <label className="block text-sm text-gray-400">Query Languages</label>
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {QUERY_LANGUAGE_TOGGLES.map(({ key, label }) => (
            <label key={key} className="flex items-center gap-2 text-[12px] text-gray-400">
              <input
                type="checkbox"
                checked={queryLanguages[key]}
                onChange={(e) => {
                  const checked = e.target.checked
                  onQueryLanguagesChange((prev) => ({ ...prev, [key]: checked }))
                }}
                className="accent-brand-500"
              />
              {label}
            </label>
          ))}
        </div>
      </div>
    </div>
  )
}

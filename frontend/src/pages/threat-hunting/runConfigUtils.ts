/**
 * Shared constants/helpers for RunConfigForm.tsx, split into their own
 * (non-component) module — a .tsx file that exports both a component and
 * plain values trips the react-refresh/only-export-components lint rule.
 */

import { type LLMProviderSummary } from '../../api/client'

export interface IocCleaningOptions {
  remove_noisy: boolean
  remove_legit_domains: boolean
  remove_cdn_ranges: boolean
  remove_legit_services: boolean
}

// issue-local-021: active_cleaning + all four toggles on is the default for
// new runs (was tagging_only / remove_legit_services off).
export const DEFAULT_IOC_MODE: 'tagging_only' | 'active_cleaning' = 'active_cleaning'
export const DEFAULT_IOC_CLEANING_OPTIONS: IocCleaningOptions = {
  remove_noisy: true,
  remove_legit_domains: true,
  remove_cdn_ranges: true,
  remove_legit_services: true,
}
// issue-local-022 (item 3): Threat Intel analysis defaults to included for
// every run-starting UI, not just the Re-run dialog.
export const DEFAULT_INCLUDE_THREAT_INTEL = true

export const EFFORT_OPTIONS = ['low', 'medium', 'high'] as const

export interface ModelOption {
  provider: string
  model: string
}

export function modelOptionsFromProviders(providers: LLMProviderSummary[]): ModelOption[] {
  const opts: ModelOption[] = []
  const seen = new Set<string>()
  for (const p of providers) {
    for (const m of p.available_models ?? []) {
      const key = `${p.name}\x00${m}`
      if (seen.has(key)) continue
      seen.add(key)
      opts.push({ provider: p.name, model: m })
    }
  }
  return opts
}

export function buildRunConfig(
  iocMode: 'tagging_only' | 'active_cleaning',
  iocCleaningOptions: IocCleaningOptions,
  includeThreatIntel: boolean,
): {
  ioc_mode: 'tagging_only' | 'active_cleaning'
  ioc_cleaning_options: IocCleaningOptions | undefined
  include_threat_intel: boolean
} {
  return {
    ioc_mode: iocMode,
    ioc_cleaning_options: iocMode === 'active_cleaning' ? iocCleaningOptions : undefined,
    include_threat_intel: includeThreatIntel,
  }
}

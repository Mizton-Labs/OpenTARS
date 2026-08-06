/**
 * First-login onboarding wizard (issue-local-038).
 *
 * Shown once per user, gated by AuthUser.onboarded — same architectural
 * pattern as ProtectedLayout's forced-password-change gate (backend-driven,
 * not localStorage, so it survives across devices) rather than a one-off
 * localStorage dismiss flag. An admin can force it to show again for a
 * given user via User Management's "Trigger first-login wizard" action
 * (PUT /api/auth/users/{id}/onboarding).
 *
 * Lets the user pick a theme (persisted via useTheme(), same as the Account
 * page's theme picker) and a Threat Hunting list view density (persisted to
 * the same localStorage key useHuntDensity() already uses elsewhere — no
 * backend field for this half, deliberately: it's a display preference, not
 * an account setting). A preview card reflects the live selection. "Get
 * Started" applies both and marks onboarding complete.
 */
import { useState } from 'react'
import { Sparkles } from 'lucide-react'
import { api } from '../api/client'
import { useTheme } from '../theme/useTheme'
import type { ThemeName } from '../theme/context'
import { useHuntDensity, type HuntDensity } from '../pages/threat-hunting/useHuntDensity'

const THEME_OPTIONS: { id: ThemeName; label: string; colors: string[] }[] = [
  { id: 'classic', label: 'Classic', colors: ['#030712', '#111827', '#2f58f0', '#dc2626'] },
  { id: 'energy', label: 'Energy', colors: ['#0a0a0a', '#121212', '#eab308', '#7f1d1d'] },
  { id: 'light', label: 'Light', colors: ['#fafbfd', '#e3e6e9', '#2f58f0', '#dc2626'] },
  { id: 'ocean', label: 'Ocean', colors: ['#02080b', '#08161c', '#0ea5e9', '#dc2626'] },
  { id: 'redhunter', label: 'RedHunter', colors: ['#080808', '#141414', '#f43f5e', '#dc2626'] },
]

const DENSITY_OPTIONS: { id: HuntDensity; label: string; description: string }[] = [
  { id: 'simple', label: 'Simple', description: 'One line per hunt package — just the run count.' },
  { id: 'compact', label: 'Compact', description: 'Status, evidence count, and per-run chips.' },
  { id: 'detailed', label: 'Detailed', description: 'Compact, plus the full pipeline stage rail.' },
  { id: 'table', label: 'Table', description: 'A dense, sortable table — scan many packages at once.' },
]

export default function OnboardingWizard({ onDone }: { onDone: () => void }) {
  const { theme: currentTheme, setTheme } = useTheme()
  const { density: currentDensity, setDensity } = useHuntDensity()
  const [selectedTheme, setSelectedTheme] = useState<ThemeName>(currentTheme)
  const [selectedDensity, setSelectedDensity] = useState<HuntDensity>(currentDensity)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const selectedThemeInfo = THEME_OPTIONS.find((t) => t.id === selectedTheme) ?? THEME_OPTIONS[0]
  const selectedDensityInfo =
    DENSITY_OPTIONS.find((d) => d.id === selectedDensity) ?? DENSITY_OPTIONS[3]

  async function handleFinish() {
    setSaving(true)
    setError(null)
    try {
      if (selectedTheme !== currentTheme) await setTheme(selectedTheme)
      if (selectedDensity !== currentDensity) setDensity(selectedDensity)
      await api.auth.completeOwnOnboarding()
      onDone()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-950 p-4">
      <div className="w-full max-w-lg space-y-5 rounded-lg border border-gray-800 bg-gray-900 p-6">
        <div className="flex items-start gap-3">
          <div className="rounded-full bg-brand-900/40 border border-brand-700/40 p-2 shrink-0">
            <Sparkles className="w-5 h-5 text-brand-400" />
          </div>
          <div className="space-y-1">
            <h1 className="text-lg font-semibold text-gray-100">Welcome to OpenTARS</h1>
            <p className="text-xs text-gray-400">
              Pick a theme and how you'd like Hunt Packages to display. You can always change
              these later in Configuration and Account.
            </p>
          </div>
        </div>

        <div className="space-y-2">
          <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">Theme</p>
          <div className="grid grid-cols-5 gap-2">
            {THEME_OPTIONS.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setSelectedTheme(t.id)}
                className={`rounded-lg border p-2 text-left transition-colors ${
                  selectedTheme === t.id
                    ? 'border-brand-500 bg-brand-900/10'
                    : 'border-gray-700 hover:border-gray-600'
                }`}
              >
                <div className="flex gap-1 mb-1.5">
                  {t.colors.map((c, i) => (
                    <span
                      key={i}
                      className="w-3 h-3 rounded-sm border border-gray-700/40"
                      style={{ backgroundColor: c }}
                    />
                  ))}
                </div>
                <span className="text-[11px] text-gray-300">{t.label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-2">
          <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
            Hunt Package View
          </p>
          <div className="space-y-1.5">
            {DENSITY_OPTIONS.map((d) => (
              <button
                key={d.id}
                type="button"
                onClick={() => setSelectedDensity(d.id)}
                className={`w-full text-left rounded-lg border px-3 py-2 transition-colors ${
                  selectedDensity === d.id
                    ? 'border-brand-500 bg-brand-900/10'
                    : 'border-gray-700 hover:border-gray-600'
                }`}
              >
                <span className="text-sm text-gray-200">{d.label}</span>
                <span className="text-xs text-gray-500 block">{d.description}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Preview card — swatch + description, live-updating (issue-local-038) */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-3 space-y-1.5">
          <p className="text-[11px] text-gray-500 uppercase tracking-wider font-semibold">
            Preview
          </p>
          <div className="flex gap-1">
            {selectedThemeInfo.colors.map((c, i) => (
              <span key={i} className="w-4 h-4 rounded border border-gray-700/40" style={{ backgroundColor: c }} />
            ))}
          </div>
          <p className="text-xs text-gray-300">
            <span className="font-medium">{selectedThemeInfo.label}</span> theme ·{' '}
            <span className="font-medium">{selectedDensityInfo.label}</span> view
          </p>
          <p className="text-xs text-gray-500">{selectedDensityInfo.description}</p>
        </div>

        {error && <p role="alert" className="text-xs text-red-400">{error}</p>}

        <div className="flex justify-end">
          <button
            type="button"
            className="btn-primary"
            disabled={saving}
            onClick={() => void handleFinish()}
          >
            {saving ? 'Saving…' : 'Get Started'}
          </button>
        </div>
      </div>
    </div>
  )
}

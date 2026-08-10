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

// issue-local-041: full palette per theme for the live demo-table preview
// below — page/card/border/text/accent, mirroring frontend/src/index.css's
// current `--color-*` custom properties (and the per-theme `.card`
// background overrides). Same "duplicated literal, not read from the CSS
// variables" trade-off THEME_OPTIONS.colors above already accepts — kept in
// sync by hand when index.css's ramps change.
interface DemoPalette {
  page: string
  card: string
  cardBorder: string
  headerBg: string
  textPrimary: string
  textMuted: string
  textFaint: string
  accent: string
  accentBg: string
}

const DEMO_PALETTES: Record<ThemeName, DemoPalette> = {
  classic: {
    page: '#030712', card: '#111827', cardBorder: '#1f2937', headerBg: '#1f2937',
    textPrimary: '#f3f4f6', textMuted: '#a8b0b8', textFaint: '#5c626e',
    accent: '#2f58f0', accentBg: 'rgba(47, 88, 240, 0.18)',
  },
  energy: {
    page: '#0a0a0a', card: '#181818', cardBorder: '#2e2e2e', headerBg: '#1c1c1c',
    textPrimary: '#ececec', textMuted: '#a8a8a8', textFaint: '#606060',
    accent: '#facc15', accentBg: 'rgba(250, 204, 21, 0.18)',
  },
  light: {
    page: '#fafbfd', card: '#e3e6e9', cardBorder: '#cbd5e1', headerBg: '#dbdee1',
    textPrimary: '#111827', textMuted: '#5a606b', textFaint: '#474d56',
    accent: '#2f58f0', accentBg: 'rgba(47, 88, 240, 0.12)',
  },
  ocean: {
    page: '#02080b', card: '#08161c', cardBorder: '#1e3d45', headerBg: '#11262d',
    textPrimary: '#dbeef1', textMuted: '#5f96a0', textFaint: '#44747a',
    accent: '#0ea5e9', accentBg: 'rgba(14, 165, 233, 0.18)',
  },
  redhunter: {
    page: '#181818', card: '#282828', cardBorder: '#404040', headerBg: '#2e2e2e',
    textPrimary: '#e8e8e8', textMuted: '#969696', textFaint: '#5a5a5a',
    accent: '#f43f5e', accentBg: 'rgba(244, 63, 94, 0.18)',
  },
}

// issue-local-041: a short, static sample of what RunsStatusTable.tsx's
// runs table looks like — purely illustrative, not real data.
const DEMO_RUNS: { id: string; model: string; status: string; statusColor: 'green' | 'blue' | 'red'; created: string }[] = [
  { id: 'TH01-X03', model: 'gpt-4o · high', status: 'completed', statusColor: 'green', created: '2 hours ago' },
  { id: 'TH01-X02', model: 'claude · medium', status: 'running', statusColor: 'blue', created: '5 min ago' },
  { id: 'TH01-X01', model: 'gpt-oss · high', status: 'completed', statusColor: 'green', created: '1 day ago' },
]

const DEMO_STATUS_COLOR: Record<'green' | 'blue' | 'red', string> = {
  green: '#4ade80',
  blue: '#60a5fa',
  red: '#f87171',
}

function DemoRunsTable({ palette }: { palette: DemoPalette }) {
  return (
    <div
      className="rounded-lg border overflow-hidden"
      style={{ backgroundColor: palette.card, borderColor: palette.cardBorder }}
    >
      <table className="w-full text-left">
        <thead>
          <tr style={{ backgroundColor: palette.headerBg }}>
            {['Run ID', 'Model', 'Status', 'Created'].map((h) => (
              <th
                key={h}
                className="px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wider"
                style={{ color: palette.textFaint }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {DEMO_RUNS.map((run) => (
            <tr key={run.id} style={{ borderTop: `1px solid ${palette.cardBorder}` }}>
              <td className="px-2.5 py-1.5 text-[11px] font-mono" style={{ color: palette.textPrimary }}>
                {run.id}
              </td>
              <td className="px-2.5 py-1.5 text-[11px] font-mono" style={{ color: palette.textMuted }}>
                {run.model}
              </td>
              <td className="px-2.5 py-1.5">
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded"
                  style={{ color: DEMO_STATUS_COLOR[run.statusColor], backgroundColor: palette.accentBg }}
                >
                  {run.status}
                </span>
              </td>
              <td className="px-2.5 py-1.5 text-[10px]" style={{ color: palette.textFaint }}>
                {run.created}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

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
  const selectedPalette = DEMO_PALETTES[selectedTheme]

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
            {/* issue-local-041: explicit "why am I seeing this" — the wizard
                is gated by AuthUser.onboarded and only ever shows once
                (or when an admin re-triggers it), which wasn't stated
                anywhere on the screen itself. */}
            <p className="text-[11px] text-brand-400 font-medium uppercase tracking-wide">
              Shown because this is your first sign-in
            </p>
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

        {/* issue-local-041: real demo table preview (a short version of the
            Hunt Package runs table), live-styled with the selected theme's
            actual palette — not just abstract swatches, so the user sees a
            real table before committing to a theme. */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-3 space-y-2">
          <p className="text-[11px] text-gray-500 uppercase tracking-wider font-semibold">
            Preview
          </p>
          <div className="rounded-lg p-3" style={{ backgroundColor: selectedPalette.page }}>
            <DemoRunsTable palette={selectedPalette} />
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

/**
 * Account page (prompts-046).
 *
 * Self-service for the signed-in user: shows identity (username + role), a
 * change-password form, and (issue-local-016) a personal theme override. The
 * change-password form lives in the shared ChangePasswordCard component; the
 * theme picker uses useTheme() (frontend/src/theme/).
 *
 * Only meaningful when auth enforcement is enabled; App.tsx wraps this route in
 * RequireAuthEnabled, which redirects to /viewer when auth is disabled.
 */
import { useState } from 'react'
import { clsx } from 'clsx'
import ChangePasswordCard from '../components/ChangePasswordCard'
import { useAuth } from '../auth/useAuth'
import { useTheme } from '../theme/useTheme'

// Same swatch colors as the General Config default-theme picker (Configuration.tsx) —
// hardcoded hex so each option shows its own theme's real colors regardless of
// which theme is currently active on the page rendering this picker.
const THEME_SWATCHES: Record<'classic' | 'energy', string[]> = {
  classic: ['#030712', '#111827', '#2f58f0', '#dc2626'],
  energy: ['#0a0a0a', '#161512', '#eab308', '#7f1d1d'],
}

function ThemePreferenceSection() {
  const { userOverride, instanceDefault, setTheme } = useTheme()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSelect(next: 'classic' | 'energy' | null) {
    setPending(true)
    setError(null)
    try {
      await setTheme(next)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setPending(false)
    }
  }

  const options: { id: 'classic' | 'energy' | null; label: string; colors?: string[] }[] = [
    { id: 'classic', label: 'Classic', colors: THEME_SWATCHES.classic },
    { id: 'energy', label: 'Energy', colors: THEME_SWATCHES.energy },
    {
      id: null,
      label: `Use instance default (${instanceDefault === 'energy' ? 'Energy' : 'Classic'})`,
    },
  ]

  return (
    <div className="space-y-2">
      <p className="text-sm font-medium text-gray-300">Theme</p>
      <div className="space-y-1.5">
        {options.map((opt) => {
          const active = opt.id === userOverride
          return (
            <button
              key={opt.id ?? 'default'}
              type="button"
              disabled={pending}
              onClick={() => void handleSelect(opt.id)}
              className={clsx(
                'w-full flex items-center justify-between rounded-lg border px-3 py-2 text-left transition-colors',
                active
                  ? 'border-brand-500 bg-brand-900/10'
                  : 'border-gray-700 hover:border-gray-600',
                pending && 'opacity-60',
              )}
            >
              <span className="text-sm text-gray-200">{opt.label}</span>
              <div className="flex items-center gap-2">
                {opt.colors && (
                  <div className="flex gap-1">
                    {opt.colors.map((c, i) => (
                      <span key={i} className="w-3.5 h-3.5 rounded" style={{ backgroundColor: c }} />
                    ))}
                  </div>
                )}
                {active && <span className="text-[10px] text-brand-400">Active</span>}
              </div>
            </button>
          )
        })}
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  )
}

export default function Account() {
  const { user } = useAuth()

  return (
    <div className="p-6 max-w-md space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-gray-100">Account</h1>
        <p className="text-sm text-gray-500">Your sign-in identity, password, and theme.</p>
      </div>

      <div className="card space-y-5">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <p className="label">Username</p>
            <p className="text-sm text-gray-200 font-mono">{user?.username ?? '—'}</p>
          </div>
          <div>
            <p className="label">Role</p>
            <p className="text-sm text-gray-200 capitalize">{user?.role ?? '—'}</p>
          </div>
        </div>

        <div className="border-t border-gray-800 pt-4">
          <ThemePreferenceSection />
        </div>

        <div className="border-t border-gray-800 pt-4">
          <ChangePasswordCard heading="Change password" />
        </div>
      </div>
    </div>
  )
}

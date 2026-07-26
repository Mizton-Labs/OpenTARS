/**
 * IocVerdictToggle (issue-local-016) — a Keep/Remove segmented control for
 * one IOC row, used in both the extracted_iocs table (HuntDetail's IOCs
 * tab) and the Sanitized IOCs table (RetrohuntPanel). Purely a controlled
 * display+callback component — staging/dirty-tracking lives in
 * useIocVerdictStaging, one level up.
 */
import { clsx } from 'clsx'

export type IocVerdict = 'keep' | 'remove'

export default function IocVerdictToggle({
  value,
  pending,
  onChange,
}: {
  /** The server-confirmed verdict. */
  value: IocVerdict
  /** A staged-but-not-yet-applied override, if any — drives both the
   *  effective selection shown and a "dirty" highlight ring. */
  pending?: IocVerdict
  onChange: (next: IocVerdict) => void
}) {
  const effective = pending ?? value
  const dirty = pending !== undefined && pending !== value

  return (
    <div
      className={clsx(
        'inline-flex items-center rounded overflow-hidden border text-[11px]',
        dirty ? 'border-brand-500 ring-1 ring-brand-500/60' : 'border-gray-700',
      )}
      title={dirty ? 'Change staged — click Apply changes to save' : undefined}
    >
      {/* issue-local-022 (item 6): brighter fill + a border matching the fill
          color on the active state — the previous bg-*-900/40 + *-300 text
          combination was too close in luminance against the dark theme to
          read at a glance. */}
      <button
        type="button"
        className={clsx(
          'px-1.5 py-0.5 transition-colors font-medium',
          effective === 'keep'
            ? 'bg-green-700/70 text-green-100 border-r border-green-500/60'
            : 'bg-transparent text-gray-400 hover:text-gray-200',
        )}
        onClick={() => onChange('keep')}
      >
        Keep
      </button>
      <button
        type="button"
        className={clsx(
          'px-1.5 py-0.5 transition-colors font-medium',
          effective === 'remove'
            ? 'bg-red-700/70 text-red-100 border-l border-red-500/60'
            : 'bg-transparent text-gray-400 hover:text-gray-200',
        )}
        onClick={() => onChange('remove')}
      >
        Remove
      </button>
    </div>
  )
}

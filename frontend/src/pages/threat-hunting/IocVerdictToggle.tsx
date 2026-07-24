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
      <button
        type="button"
        className={clsx(
          'px-1.5 py-0.5 transition-colors',
          effective === 'keep'
            ? 'bg-green-900/40 text-green-300'
            : 'bg-transparent text-gray-500 hover:text-gray-300',
        )}
        onClick={() => onChange('keep')}
      >
        Keep
      </button>
      <button
        type="button"
        className={clsx(
          'px-1.5 py-0.5 transition-colors',
          effective === 'remove'
            ? 'bg-red-900/40 text-red-300'
            : 'bg-transparent text-gray-500 hover:text-gray-300',
        )}
        onClick={() => onChange('remove')}
      >
        Remove
      </button>
    </div>
  )
}

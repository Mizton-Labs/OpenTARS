/**
 * useIocVerdictStaging (issue-local-016) — manual per-IOC keep/remove
 * verdict overrides, staged locally until the analyst clicks "Apply
 * changes". Mirrors AgentsConfigTab.tsx's `toolsEnabled: Record<string,
 * boolean>` + single dirty-gated Save button pattern — the closest existing
 * precedent in this codebase for a per-item staged-map + batch-save UI.
 *
 * Instantiated once in HuntDetail.tsx (the parent of both the IOCs tab and
 * the Analysis tab's embedded RetrohuntPanel), so a change staged while
 * viewing one tab is still pending when the analyst switches to the other.
 * Scoped to a single run — changes apply to the current run only.
 */
import { useCallback, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { IocVerdict } from './IocVerdictToggle'

function iocKey(ioc: string, iocType: string): string {
  return `${ioc}::${iocType}`
}

export function useIocVerdictStaging(pkgId: string, runId: string | undefined) {
  const qc = useQueryClient()
  const [pending, setPending] = useState<Map<string, { ioc: string; ioc_type: string; action: IocVerdict }>>(
    new Map(),
  )
  // issue-local-018 follow-up: brief "Applied" confirmation shown wherever
  // the Apply button lives, cleared automatically so it doesn't linger.
  const [justApplied, setJustApplied] = useState(false)
  const justAppliedTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const stage = useCallback((ioc: string, iocType: string, action: IocVerdict, serverValue: IocVerdict) => {
    setPending((prev) => {
      const next = new Map(prev)
      const key = iocKey(ioc, iocType)
      if (action === serverValue) {
        // Back to the server-confirmed value — nothing left to stage for this IOC.
        next.delete(key)
      } else {
        next.set(key, { ioc, ioc_type: iocType, action })
      }
      return next
    })
  }, [])

  const pendingFor = useCallback(
    (ioc: string, iocType: string): IocVerdict | undefined => pending.get(iocKey(ioc, iocType))?.action,
    [pending],
  )

  const applyMut = useMutation({
    mutationFn: () => {
      if (!runId) return Promise.reject(new Error('No active run'))
      return api.threatHunting.updateIocVerdicts(pkgId, runId, [...pending.values()])
    },
    onSuccess: () => {
      setPending(new Map())
      qc.invalidateQueries({ queryKey: ['th-iocs', pkgId, runId] })
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId, runId] })
      setJustApplied(true)
      if (justAppliedTimer.current) clearTimeout(justAppliedTimer.current)
      justAppliedTimer.current = setTimeout(() => setJustApplied(false), 2500)
    },
  })

  return {
    stage,
    pendingFor,
    isDirty: pending.size > 0,
    pendingCount: pending.size,
    apply: () => applyMut.mutate(),
    isApplying: applyMut.isPending,
    applyError: applyMut.error,
    justApplied,
  }
}

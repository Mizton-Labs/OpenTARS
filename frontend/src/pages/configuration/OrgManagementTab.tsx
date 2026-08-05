/**
 * Org Management tab (issue-local-037) — admin only.
 *
 * Add/list/edit/delete Organizations (name + email domain). Organizations
 * populate the dropdown on User Management's Create/Change-Organization
 * controls; deleting one that still has users assigned is rejected by the
 * backend (409) rather than silently orphaning those users.
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, Plus, X, Check, Pencil } from 'lucide-react'
import { api, type OrganizationPayload } from '../../api/client'
import { ORGS_KEY } from './UserManagementTab'

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

const EMPTY_DRAFT: OrganizationPayload = { name: '', email_domain: '' }

export default function OrgManagementTab() {
  const qc = useQueryClient()
  const [actionError, setActionError] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState<OrganizationPayload>(EMPTY_DRAFT)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [editDraft, setEditDraft] = useState<OrganizationPayload>(EMPTY_DRAFT)
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null)

  const { data: organizations = [], isLoading } = useQuery({
    queryKey: ORGS_KEY,
    queryFn: api.auth.listOrganizations,
  })

  const invalidate = () => qc.invalidateQueries({ queryKey: ORGS_KEY })

  const createMut = useMutation({
    mutationFn: (payload: OrganizationPayload) => api.auth.createOrganization(payload),
    onSuccess: () => {
      setActionError(null)
      setAdding(false)
      setDraft(EMPTY_DRAFT)
      invalidate()
    },
    onError: (e) => setActionError(errorMessage(e)),
  })
  const updateMut = useMutation({
    mutationFn: ({ id, payload }: { id: number; payload: OrganizationPayload }) =>
      api.auth.updateOrganization(id, payload),
    onSuccess: () => {
      setActionError(null)
      setEditingId(null)
      invalidate()
    },
    onError: (e) => setActionError(errorMessage(e)),
  })
  const deleteMut = useMutation({
    mutationFn: (id: number) => api.auth.deleteOrganization(id),
    onSuccess: () => { setActionError(null); setConfirmDeleteId(null); invalidate() },
    onError: (e) => { setConfirmDeleteId(null); setActionError(errorMessage(e)) },
  })

  if (isLoading) return <div className="text-sm text-gray-500">Loading…</div>

  return (
    <div className="card space-y-5">
      <div>
        <h3 className="text-sm font-semibold text-gray-200">Org Management</h3>
        <p className="text-xs text-gray-500 mt-1">
          Organizations users can be assigned to in User Management. Each has a name and an email
          domain, used to build a user's full-email username (<span className="font-mono">local-part@domain</span>).
          An organization with users assigned cannot be deleted.
        </p>
      </div>

      {actionError !== null && (
        <p role="alert" className="text-xs text-red-400">{actionError}</p>
      )}

      {organizations.length === 0 && !adding && (
        <p className="text-xs text-gray-600 px-1 py-1">No organizations configured.</p>
      )}

      <div className="space-y-2">
        {organizations.map((o) => {
          const armed = confirmDeleteId === o.id
          return (
            <div key={o.id} className="rounded-lg border border-gray-700 bg-gray-800/50">
              {editingId === o.id ? (
                <div className="p-3 space-y-3">
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="label">Org name</label>
                      <input
                        className="input"
                        value={editDraft.name}
                        onChange={(e) => setEditDraft((d) => ({ ...d, name: e.target.value }))}
                      />
                    </div>
                    <div>
                      <label className="label">Email domain</label>
                      <input
                        className="input font-mono"
                        placeholder="acme.com"
                        value={editDraft.email_domain}
                        onChange={(e) =>
                          setEditDraft((d) => ({ ...d, email_domain: e.target.value }))
                        }
                      />
                    </div>
                  </div>
                  <div className="flex justify-end gap-2">
                    <button className="btn-ghost" onClick={() => setEditingId(null)}>
                      <X className="w-3.5 h-3.5" /> Cancel
                    </button>
                    <button
                      className="btn-primary"
                      disabled={
                        !editDraft.name.trim() || !editDraft.email_domain.trim() || updateMut.isPending
                      }
                      onClick={() => updateMut.mutate({ id: o.id, payload: editDraft })}
                    >
                      <Check className="w-3.5 h-3.5" />
                      {updateMut.isPending ? 'Saving…' : 'Save'}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-3 px-3 py-2.5">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-200 truncate">{o.name}</p>
                    <p className="text-xs text-gray-500 font-mono">{o.email_domain}</p>
                  </div>
                  <span className="text-xs text-gray-500 shrink-0">
                    {o.user_count} user{o.user_count === 1 ? '' : 's'}
                  </span>
                  <button
                    className="btn-ghost p-1"
                    title="Edit organization"
                    onClick={() => {
                      setActionError(null)
                      setEditingId(o.id)
                      setEditDraft({ name: o.name, email_domain: o.email_domain })
                    }}
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </button>
                  <button
                    className="btn-ghost p-1 text-red-400 hover:text-red-300 disabled:opacity-40"
                    title={o.user_count > 0 ? 'Cannot delete — users assigned' : 'Delete organization'}
                    disabled={deleteMut.isPending}
                    onClick={() => { setActionError(null); setConfirmDeleteId(o.id) }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}

              {armed && (
                <div
                  className="border-t border-red-500/40 bg-red-500/5 rounded-b-lg px-3 py-2.5 space-y-2"
                  data-testid={`org-delete-confirm-${o.id}`}
                  role="alertdialog"
                  aria-label={`Confirm delete ${o.name}`}
                >
                  <p className="text-xs text-gray-200">
                    Delete organization "<span className="font-mono">{o.name}</span>"? This cannot
                    be undone.
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      className="btn-danger flex items-center gap-1.5"
                      onClick={() => deleteMut.mutate(o.id)}
                      disabled={deleteMut.isPending}
                      data-testid={`org-delete-confirm-yes-${o.id}`}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      {deleteMut.isPending ? 'Deleting…' : 'Confirm delete'}
                    </button>
                    <button
                      className="btn-secondary"
                      onClick={() => setConfirmDeleteId(null)}
                      disabled={deleteMut.isPending}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {adding ? (
        <div className="rounded-lg border border-brand-700/40 bg-brand-900/10 p-3 space-y-3">
          <p className="text-sm font-medium text-gray-300">New organization</p>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label htmlFor="new-org-name" className="label">Org name</label>
              <input
                id="new-org-name"
                className="input"
                placeholder="Acme Corp"
                value={draft.name}
                onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
              />
            </div>
            <div>
              <label htmlFor="new-org-domain" className="label">Email domain</label>
              <input
                id="new-org-domain"
                className="input font-mono"
                placeholder="acme.com"
                value={draft.email_domain}
                onChange={(e) => setDraft((d) => ({ ...d, email_domain: e.target.value }))}
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button className="btn-ghost" onClick={() => { setAdding(false); setDraft(EMPTY_DRAFT) }}>
              <X className="w-3.5 h-3.5" /> Cancel
            </button>
            <button
              className="btn-primary"
              disabled={!draft.name.trim() || !draft.email_domain.trim() || createMut.isPending}
              onClick={() => createMut.mutate(draft)}
            >
              <Plus className="w-3.5 h-3.5" />
              {createMut.isPending ? 'Creating…' : 'Create'}
            </button>
          </div>
        </div>
      ) : (
        <button className="btn-secondary w-full justify-center" onClick={() => setAdding(true)}>
          <Plus className="w-3.5 h-3.5" /> Add Organization
        </button>
      )}
    </div>
  )
}

/**
 * User Management tab (prompts-045) — admin only.
 *
 * Lists users and provides create / enable-disable / role-change / reset-
 * password / delete actions, each backed by the /api/auth/users endpoints.
 *
 * The backend enforces the real invariants (cannot demote/disable/delete the
 * last admin; cannot act on your own role/enabled/account). This UI mirrors
 * the self-action guards by disabling those controls for the current user and
 * surfaces any backend rejection inline rather than trying to re-implement the
 * last-admin accounting client-side.
 *
 * Configuration only mounts this tab when authEnabled && isAdmin.
 */
import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient, type UseMutationResult } from '@tanstack/react-query'
import { Trash2, KeyRound, Plus, X, Copy, Check, AlertTriangle, Save, Sparkles } from 'lucide-react'
import { api, type AuthUser, type Organization, type UserRole } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import Toggle from '../../components/Toggle'

const USERS_KEY = ['auth-users'] as const
// issue-local-037: shared with OrgManagementTab so both tabs invalidate the
// same cache entry after any org add/edit/delete.
export const ORGS_KEY = ['auth-organizations'] as const
const USERNAME_RE = /^[A-Za-z0-9._-]{1,40}$/

/** "Local user" (no org) resolves to this label; otherwise the org's name. */
function orgLabel(orgId: number | null | undefined, organizations: Organization[]): string {
  if (orgId == null) return 'Local user'
  return organizations.find((o) => o.id === orgId)?.name ?? 'Local user'
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

export default function UserManagementTab() {
  const qc = useQueryClient()
  const { user: self } = useAuth()
  const [actionError, setActionError] = useState<string | null>(null)
  // issue-local-037: after any add/change, always surface the actual
  // generated/updated username — the org+checkbox combination makes it easy
  // to guess wrong otherwise.
  const [notice, setNotice] = useState<string | null>(null)
  const [resetFor, setResetFor] = useState<AuthUser | null>(null)
  // issue-local-038: one-time reveal of a newly-created user's generated
  // password — same shape/urgency as ResetPasswordModal's reveal.
  const [createdReveal, setCreatedReveal] = useState<{ username: string; password: string } | null>(
    null,
  )
  // prompts-049: armed inline delete confirmation (mirrors the provider-delete
  // pattern) — the trash button arms it; the actual delete only fires from the
  // confirm panel.
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null)

  const { data: users = [], isLoading } = useQuery({
    queryKey: USERS_KEY,
    queryFn: api.auth.listUsers,
  })
  const { data: organizations = [] } = useQuery({
    queryKey: ORGS_KEY,
    queryFn: api.auth.listOrganizations,
  })

  const invalidate = () => qc.invalidateQueries({ queryKey: USERS_KEY })

  const roleMut = useMutation({
    mutationFn: ({ id, role }: { id: number; role: UserRole }) => api.auth.setUserRole(id, role),
    onSuccess: () => { setActionError(null); invalidate() },
    onError: (e) => setActionError(errorMessage(e)),
  })
  const enabledMut = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) =>
      api.auth.setUserEnabled(id, enabled),
    onSuccess: () => { setActionError(null); invalidate() },
    onError: (e) => setActionError(errorMessage(e)),
  })
  const deleteMut = useMutation({
    mutationFn: (id: number) => api.auth.deleteUser(id),
    onSuccess: () => { setActionError(null); setConfirmDeleteId(null); invalidate() },
    onError: (e) => { setConfirmDeleteId(null); setActionError(errorMessage(e)) },
  })
  // issue-local-037: change (or clear) a user's organization. Defaults to
  // the same "use full email as username" behavior as create — the org
  // change flow has no separate checkbox, so it always builds the email-
  // shaped username when moving INTO an org (clearing org_id always drops
  // back to the bare local-part regardless, per build_username).
  const orgMut = useMutation({
    mutationFn: ({ id, org_id }: { id: number; org_id: number | null }) =>
      api.auth.setUserOrganization(id, { org_id, use_email_username: true }),
    onSuccess: (updated) => {
      setActionError(null)
      setNotice(`Username is now "${updated.username}".`)
      invalidate()
    },
    onError: (e) => setActionError(errorMessage(e)),
  })
  // issue-local-038: admin-triggered — resets a user's onboarded flag so
  // the first-login wizard shows again on their next login.
  const onboardMut = useMutation({
    mutationFn: (id: number) => api.auth.setUserOnboarded(id, false),
    onSuccess: (updated) => {
      setActionError(null)
      setNotice(`First-login wizard will show for "${updated.username}" on their next login.`)
      invalidate()
    },
    onError: (e) => setActionError(errorMessage(e)),
  })

  if (isLoading) return <div className="text-sm text-gray-500">Loading…</div>

  return (
    <div className="card space-y-5">
      <div>
        <h3 className="text-sm font-semibold text-gray-200">User Management</h3>
        <p className="text-xs text-gray-500 mt-1">
          Create accounts and manage roles. <span className="text-gray-300">Admin</span> users have
          full access; <span className="text-gray-300">Normal</span> users have read-only (viewer)
          access; <span className="text-gray-300">Sender</span> accounts can only push feeds to the
          listener endpoint. You cannot change your own role, disable, or delete your own account.
        </p>
      </div>

      {actionError !== null && (
        <p role="alert" className="text-xs text-red-400">{actionError}</p>
      )}
      {notice !== null && (
        <p className="text-xs text-green-400">{notice}</p>
      )}

      <div className="space-y-2">
        {users.map((u) => (
          <UserRow
            key={u.id}
            user={u}
            organizations={organizations}
            isSelf={self?.id === u.id}
            armed={confirmDeleteId === u.id}
            roleMut={roleMut}
            orgMut={orgMut}
            enabledMut={enabledMut}
            deleteMut={deleteMut}
            onboardMut={onboardMut}
            onArmDelete={() => { setActionError(null); setConfirmDeleteId(u.id) }}
            onCancelDelete={() => setConfirmDeleteId(null)}
            onResetPassword={() => { setActionError(null); setResetFor(u) }}
            onSaveError={setActionError}
          />
        ))}
      </div>

      <CreateUserForm
        organizations={organizations}
        onCreated={(username, generatedPassword) => {
          invalidate()
          setNotice(`User "${username}" created.`)
          setCreatedReveal({ username, password: generatedPassword })
        }}
        onError={setActionError}
      />

      {resetFor !== null && (
        <ResetPasswordModal
          user={resetFor}
          onClose={() => setResetFor(null)}
        />
      )}

      {createdReveal !== null && (
        <CreatedUserPasswordModal
          username={createdReveal.username}
          password={createdReveal.password}
          onClose={() => setCreatedReveal(null)}
        />
      )}
    </div>
  )
}

// ── User row (issue-local-038: staged Role/Organization + explicit Save) ────
//
// Role and Organization are staged locally and only applied on an explicit
// Save click — a "Save" button appears in the row once either is dirty
// (mirrors the "Save Callback URL" pattern already used in SSO config,
// issue-local-036). The Enabled toggle stays instant, unlike Role/Org — an
// admin disabling a compromised account should not be delayed by a confirm
// step.

function UserRow({
  user: u,
  organizations,
  isSelf,
  armed,
  roleMut,
  orgMut,
  enabledMut,
  deleteMut,
  onboardMut,
  onArmDelete,
  onCancelDelete,
  onResetPassword,
  onSaveError,
}: {
  user: AuthUser
  organizations: Organization[]
  isSelf: boolean
  armed: boolean
  roleMut: UseMutationResult<AuthUser, unknown, { id: number; role: UserRole }>
  orgMut: UseMutationResult<AuthUser, unknown, { id: number; org_id: number | null }>
  enabledMut: UseMutationResult<AuthUser, unknown, { id: number; enabled: boolean }>
  deleteMut: UseMutationResult<{ status: string; id: number }, unknown, number>
  onboardMut: UseMutationResult<AuthUser, unknown, number>
  onArmDelete: () => void
  onCancelDelete: () => void
  onResetPassword: () => void
  onSaveError: (msg: string | null) => void
}) {
  const [draftRole, setDraftRole] = useState<UserRole>(u.role)
  const [draftOrgId, setDraftOrgId] = useState<number | ''>(u.org_id ?? '')

  // Re-sync the draft whenever the persisted value actually changes (a
  // successful save, or a refetch picking up someone else's change) — NOT
  // on every render, so mid-edit keystrokes/selections survive unrelated
  // re-renders of this row.
  useEffect(() => {
    setDraftRole(u.role)
  }, [u.role])
  useEffect(() => {
    setDraftOrgId(u.org_id ?? '')
  }, [u.org_id])

  const roleDirty = draftRole !== u.role
  const orgDirty = draftOrgId !== (u.org_id ?? '')
  const dirty = roleDirty || orgDirty
  const saving = roleMut.isPending || orgMut.isPending

  function handleSave() {
    onSaveError(null)
    if (roleDirty) roleMut.mutate({ id: u.id, role: draftRole })
    if (orgDirty) orgMut.mutate({ id: u.id, org_id: draftOrgId === '' ? null : draftOrgId })
  }

  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800/50">
      <div className="flex items-center gap-3 px-3 py-2.5">
        <div className="flex-1 min-w-0">
          <p className="text-sm font-mono font-medium text-gray-200 truncate">
            {u.username}
            {isSelf && <span className="ml-2 text-[10px] text-gray-500">(you)</span>}
          </p>
          <p className="text-xs text-gray-500">
            {u.enabled ? 'Active' : 'Disabled'} · {orgLabel(u.org_id, organizations)}
          </p>
        </div>

        {/* Organization selector — staged, applied on Save */}
        <select
          className="input w-32 text-xs"
          aria-label={`Organization for ${u.username}`}
          value={draftOrgId}
          disabled={saving}
          onChange={(e) => setDraftOrgId(e.target.value === '' ? '' : Number(e.target.value))}
        >
          <option value="">Local user</option>
          {organizations.map((o) => (
            <option key={o.id} value={o.id}>{o.name}</option>
          ))}
        </select>

        {/* Role selector — staged, applied on Save */}
        <select
          className="input w-28 text-xs"
          value={draftRole}
          disabled={isSelf || saving}
          onChange={(e) => setDraftRole(e.target.value as UserRole)}
        >
          <option value="admin">admin</option>
          <option value="threat-researcher">threat-researcher</option>
          <option value="threat-viewer">threat-viewer</option>
          <option value="feed-sender">feed-sender</option>
        </select>

        {/* Save — only appears once Role and/or Organization is dirty */}
        {dirty && (
          <button
            className="btn-primary p-1.5 text-xs flex items-center gap-1"
            title="Save role/organization changes"
            disabled={saving}
            onClick={handleSave}
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? 'Saving…' : 'Save'}
          </button>
        )}

        {/* Enabled toggle — instant, not staged (see comment above) */}
        <div className="flex items-center gap-1.5">
          <Toggle
            checked={u.enabled}
            disabled={isSelf || enabledMut.isPending}
            onChange={(enabled) => enabledMut.mutate({ id: u.id, enabled })}
          />
        </div>

        {/* issue-local-038: explicit text label added — was icon-only. */}
        <button
          className="btn-ghost p-1 flex items-center gap-1 text-xs whitespace-nowrap"
          title="Reset password"
          onClick={onResetPassword}
        >
          <KeyRound className="w-3.5 h-3.5" />
          Reset password
        </button>
        {/* issue-local-038: admin-triggered — forces the first-login wizard
            to show again for this user on their next login. */}
        <button
          className="btn-ghost p-1 flex items-center gap-1 text-xs whitespace-nowrap"
          title="Trigger first-login wizard on next login"
          disabled={onboardMut.isPending}
          onClick={() => onboardMut.mutate(u.id)}
        >
          <Sparkles className="w-3.5 h-3.5" />
          First-login wizard
        </button>
        <button
          className="btn-ghost p-1 text-red-400 hover:text-red-300 disabled:opacity-40"
          title={isSelf ? 'You cannot delete your own account' : 'Delete user'}
          disabled={isSelf || deleteMut.isPending}
          onClick={onArmDelete}
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      {armed && (
        <div
          className="border-t border-red-500/40 bg-red-500/5 rounded-b-lg px-3 py-2.5 space-y-2"
          data-testid={`delete-confirm-${u.id}`}
          role="alertdialog"
          aria-label={`Confirm delete ${u.username}`}
        >
          <p className="text-xs text-gray-200">
            Delete user "<span className="font-mono">{u.username}</span>"? This cannot be
            undone.
          </p>
          <div className="flex items-center gap-2">
            <button
              className="btn-danger flex items-center gap-1.5"
              onClick={() => deleteMut.mutate(u.id)}
              disabled={deleteMut.isPending}
              data-testid={`delete-confirm-yes-${u.id}`}
            >
              <Trash2 className="w-3.5 h-3.5" />
              {deleteMut.isPending ? 'Deleting…' : 'Confirm delete'}
            </button>
            <button
              className="btn-secondary"
              onClick={onCancelDelete}
              disabled={deleteMut.isPending}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Create user ───────────────────────────────────────────────────────────────

function CreateUserForm({
  organizations,
  onCreated,
  onError,
}: {
  organizations: Organization[]
  // issue-local-038: carries the one-time generated password up, so the
  // parent can show the reveal modal (same one-time-reveal UX as
  // ResetPasswordModal — the password is never retrievable again).
  onCreated: (username: string, generatedPassword: string) => void
  onError: (msg: string | null) => void
}) {
  const [open, setOpen] = useState(false)
  const [username, setUsername] = useState('')
  const [role, setRole] = useState<UserRole>('threat-viewer')
  const [orgId, setOrgId] = useState<number | ''>('')
  // issue-local-037: enabled by default — the whole point of the checkbox
  // is opting OUT of the email-shaped username, not into it.
  const [useEmailUsername, setUseEmailUsername] = useState(true)

  const mutation = useMutation({
    mutationFn: () =>
      api.auth.createUser({
        username,
        role,
        org_id: orgId === '' ? null : orgId,
        use_email_username: useEmailUsername,
      }),
    onSuccess: (created) => {
      onError(null)
      setUsername('')
      setRole('threat-viewer')
      setOrgId('')
      setUseEmailUsername(true)
      setOpen(false)
      onCreated(created.username, created.generated_password)
    },
    onError: (e) => onError(errorMessage(e)),
  })

  function reset() {
    setOpen(false)
    setUsername('')
    setOrgId('')
    setUseEmailUsername(true)
    onError(null)
  }

  if (!open) {
    return (
      <button className="btn-secondary w-full justify-center" onClick={() => setOpen(true)}>
        <Plus className="w-3.5 h-3.5" /> Add User
      </button>
    )
  }

  const usernameValid = USERNAME_RE.test(username)
  const canSubmit = usernameValid && !mutation.isPending

  const selectedOrg = orgId === '' ? null : organizations.find((o) => o.id === orgId) ?? null
  const previewUsername =
    usernameValid && selectedOrg !== null && useEmailUsername
      ? `${username}@${selectedOrg.email_domain}`
      : username

  return (
    <div className="rounded-lg border border-brand-700/40 bg-brand-900/10 p-3 space-y-3">
      <p className="text-sm font-medium text-gray-300">New user</p>
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label htmlFor="new-username" className="label">Username</label>
          <input
            id="new-username"
            className="input font-mono"
            placeholder="analyst"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="new-user-role" className="label">Role</label>
          <select
            id="new-user-role"
            className="input"
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
          >
            <option value="threat-viewer">threat-viewer</option>
            <option value="threat-researcher">threat-researcher</option>
            <option value="admin">admin</option>
            <option value="feed-sender">feed-sender</option>
          </select>
        </div>
      </div>
      <div>
        <label htmlFor="new-user-org" className="label">Organization</label>
        <select
          id="new-user-org"
          className="input"
          value={orgId}
          onChange={(e) => setOrgId(e.target.value === '' ? '' : Number(e.target.value))}
        >
          <option value="">Local user (no organization)</option>
          {organizations.map((o) => (
            <option key={o.id} value={o.id}>{o.name} ({o.email_domain})</option>
          ))}
        </select>
      </div>
      {selectedOrg !== null && (
        <label htmlFor="new-user-use-email" className="flex items-center gap-2 text-xs text-gray-300">
          <input
            id="new-user-use-email"
            type="checkbox"
            checked={useEmailUsername}
            onChange={(e) => setUseEmailUsername(e.target.checked)}
          />
          Use full email as username ({selectedOrg.email_domain})
        </label>
      )}
      {usernameValid && (
        <p className="text-xs text-gray-500">
          Username will be <span className="font-mono text-gray-300">{previewUsername}</span>.
        </p>
      )}
      {/* issue-local-038: no password fields — the backend always generates
          one, shown once after creation (same as Reset Password). */}
      <p className="text-xs text-gray-500">
        A random password is generated automatically and shown once after creation. The new
        user will be required to set their own password on first login.
      </p>
      {username !== '' && !usernameValid && (
        <p className="text-xs text-red-400">
          Username must be 1–40 chars of letters, digits, &apos;.&apos;, &apos;_&apos; or &apos;-&apos;.
        </p>
      )}
      <div className="flex justify-end gap-2">
        <button className="btn-ghost" onClick={reset}>
          <X className="w-3.5 h-3.5" /> Cancel
        </button>
        <button className="btn-primary" disabled={!canSubmit} onClick={() => mutation.mutate()}>
          <Plus className="w-3.5 h-3.5" />
          {mutation.isPending ? 'Creating…' : 'Create'}
        </button>
      </div>
    </div>
  )
}

// ── Created-user password reveal (issue-local-038) ──────────────────────────
//
// Create User no longer takes a password at all — the backend always
// generates one. This is the one-time reveal for it, same read-only +
// copy-to-clipboard shape as ResetPasswordModal's reveal step below, just
// without the "Generate" confirmation step (creation already happened).

function CreatedUserPasswordModal({
  username,
  password,
  onClose,
}: {
  username: string
  password: string
  onClose: () => void
}) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    await navigator.clipboard.writeText(password)
    setCopied(true)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="card w-full max-w-sm space-y-4">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-semibold text-gray-200">
            User created — <span className="font-mono">{username}</span>
          </h4>
          <button className="btn-ghost p-1" onClick={onClose}>
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="rounded-lg border border-amber-700/40 bg-amber-900/10 p-2.5 flex gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
          <p className="text-xs text-amber-300">
            Shown only once — copy it now and share it with{' '}
            <span className="font-mono">{username}</span> through a secure channel. It cannot be
            retrieved again, and they must set a new password on their first login.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            readOnly
            aria-label="Generated password"
            className="input font-mono flex-1"
            value={password}
            onFocus={(e) => e.currentTarget.select()}
          />
          <button className="btn-secondary p-2" title="Copy to clipboard" onClick={handleCopy}>
            {copied ? (
              <Check className="w-3.5 h-3.5 text-green-400" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
        <div className="flex justify-end">
          <button className="btn-primary text-xs" onClick={onClose}>Done</button>
        </div>
      </div>
    </div>
  )
}

// ── Reset password (issue-local-016) ────────────────────────────────────────
//
// The admin no longer types a new password — the backend generates one and
// returns it once. Two-step: an explicit "Generate new password" click
// (armed-confirmation pattern, matching delete above — a reset immediately
// invalidates the account's password and evicts all sessions, so a stray
// click on the row shouldn't trigger it), then a one-time read-only reveal
// with a copy-to-clipboard affordance.

function ResetPasswordModal({
  user,
  onClose,
}: {
  user: AuthUser
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [copied, setCopied] = useState(false)

  const mutation = useMutation({
    mutationFn: () => api.auth.resetUserPassword(user.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: USERS_KEY }) },
  })

  async function handleCopy() {
    if (mutation.data === undefined) return
    await navigator.clipboard.writeText(mutation.data.generated_password)
    setCopied(true)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="card w-full max-w-sm space-y-4">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-semibold text-gray-200">
            Reset password — <span className="font-mono">{user.username}</span>
          </h4>
          <button className="btn-ghost p-1" onClick={onClose}>
            <X className="w-4 h-4" />
          </button>
        </div>

        {mutation.data === undefined ? (
          <>
            <p className="text-xs text-gray-400">
              This generates a brand-new random password for this account and immediately signs
              them out everywhere. They will be required to set their own password on next login.
            </p>
            {mutation.isError && (
              <p role="alert" className="text-xs text-red-400">{errorMessage(mutation.error)}</p>
            )}
            <div className="flex justify-end gap-2">
              <button className="btn-ghost text-xs" onClick={onClose}>Cancel</button>
              <button
                className="btn-primary"
                disabled={mutation.isPending}
                onClick={() => mutation.mutate()}
              >
                <KeyRound className="w-3.5 h-3.5" />
                {mutation.isPending ? 'Generating…' : 'Generate new password'}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="rounded-lg border border-amber-700/40 bg-amber-900/10 p-2.5 flex gap-2">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
              <p className="text-xs text-amber-300">
                Shown only once — copy it now and share it with{' '}
                <span className="font-mono">{user.username}</span> through a secure channel. It
                cannot be retrieved again, and they must set a new password on their next login.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <input
                readOnly
                aria-label="Generated password"
                className="input font-mono flex-1"
                value={mutation.data.generated_password}
                onFocus={(e) => e.currentTarget.select()}
              />
              <button className="btn-secondary p-2" title="Copy to clipboard" onClick={handleCopy}>
                {copied ? (
                  <Check className="w-3.5 h-3.5 text-green-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
            <div className="flex justify-end">
              <button className="btn-primary text-xs" onClick={onClose}>Done</button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

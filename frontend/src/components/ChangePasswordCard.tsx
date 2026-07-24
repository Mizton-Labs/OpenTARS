/**
 * Self change-password form (prompts-046).
 *
 * The signed-in user changing their OWN password. Requires the current
 * password, and enforces new != current client-side (the backend enforces it
 * authoritatively). Calls api.auth.changePassword. Enforces the active
 * password policy (length + character classes) via validatePassword, fetched
 * from the auth context (GET /api/auth/status).
 *
 * issue-local-016: the admin-reset flow used to be a second mode of this same
 * component (mode="admin", no current-password field, admin typed the new
 * password) — that flow no longer collects admin input at all (the backend
 * generates a random password), so it's a distinct one-time-reveal UI now,
 * not a variant of this form. See UserManagementTab's AdminResetPasswordPanel.
 */
import { useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { describePasswordPolicy, validatePassword } from '../utils/passwordPolicy'

interface ChangePasswordCardProps {
  /** Optional label shown above the form. */
  heading?: string
  /** Called after a successful change. */
  onSuccess?: () => void
}

export default function ChangePasswordCard({
  heading,
  onSuccess,
}: ChangePasswordCardProps) {
  const { passwordPolicy } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [done, setDone] = useState(false)

  const mutation = useMutation({
    mutationFn: () => api.auth.changePassword(current, next),
    onSuccess: () => {
      setDone(true)
      setCurrent('')
      setNext('')
      setConfirm('')
      onSuccess?.()
    },
  })

  const policyError = next !== '' ? validatePassword(next, passwordPolicy) : null

  let clientError: string | null = policyError
  if (clientError === null && confirm !== '' && next !== confirm) {
    clientError = 'New password and confirmation do not match.'
  } else if (clientError === null && next !== '' && next === current) {
    clientError = 'New password must differ from the current password.'
  }

  const canSubmit =
    next !== '' &&
    confirm !== '' &&
    current !== '' &&
    clientError === null &&
    !mutation.isPending

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!canSubmit) return
    setDone(false)
    mutation.mutate()
  }

  function resetFeedback() {
    setDone(false)
    mutation.reset()
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      {heading !== undefined && (
        <p className="text-sm font-medium text-gray-300">{heading}</p>
      )}

      <div>
        <label htmlFor="current-password" className="label">
          Current password
        </label>
        <input
          id="current-password"
          type="password"
          autoComplete="current-password"
          className="input"
          value={current}
          onChange={(e) => {
            setCurrent(e.target.value)
            resetFeedback()
          }}
        />
      </div>

      <div>
        <label htmlFor="new-password" className="label">
          New password
        </label>
        <input
          id="new-password"
          type="password"
          autoComplete="new-password"
          className="input"
          value={next}
          onChange={(e) => {
            setNext(e.target.value)
            resetFeedback()
          }}
        />
        <p className="text-xs text-gray-500 mt-1">
          {describePasswordPolicy(passwordPolicy)}
        </p>
      </div>

      <div>
        <label htmlFor="confirm-password" className="label">
          Confirm new password
        </label>
        <input
          id="confirm-password"
          type="password"
          autoComplete="new-password"
          className="input"
          value={confirm}
          onChange={(e) => {
            setConfirm(e.target.value)
            resetFeedback()
          }}
        />
      </div>

      {clientError !== null && <p className="text-xs text-red-400">{clientError}</p>}
      {mutation.isError && (
        <p role="alert" className="text-xs text-red-400">
          {mutation.error instanceof Error
            ? mutation.error.message
            : 'Password change failed'}
        </p>
      )}
      {done && <p className="text-xs text-green-400">Password changed.</p>}

      <div className="flex justify-end">
        <button type="submit" className="btn-primary text-xs" disabled={!canSubmit}>
          {mutation.isPending ? 'Saving…' : 'Change password'}
        </button>
      </div>
    </form>
  )
}

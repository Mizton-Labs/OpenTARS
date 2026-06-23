/**
 * ConfirmDialog — reusable modal for destructive-action confirmation.
 * Shows a title, message, a danger-styled confirm button, and a cancel button.
 */
import { X } from 'lucide-react'

interface ConfirmDialogProps {
  title: string
  message: string
  /** Label for the confirm (danger) button. Defaults to "Confirm". */
  confirmLabel?: string
  /** Label for the cancel button. Defaults to "Cancel". */
  cancelLabel?: string
  onConfirm: () => void
  onCancel: () => void
}

export default function ConfirmDialog({
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-xl w-full max-w-sm mx-4 p-5 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-100">{title}</h3>
          <button
            className="btn-ghost p-1.5 text-gray-500 hover:text-gray-300"
            onClick={onCancel}
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <p className="text-xs text-gray-400">{message}</p>

        {/* Actions */}
        <div className="flex gap-2 justify-end pt-1">
          <button className="btn-ghost text-xs" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            className="px-3 py-1.5 text-xs rounded bg-red-700 hover:bg-red-600 text-white font-medium transition-colors"
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

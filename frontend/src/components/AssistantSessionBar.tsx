/**
 * AssistantSessionBar (issue-local-032).
 *
 * The session top bar: New session / Save session (rename) / Export
 * (MD/JSON/PDF) / Delete, plus a picker over the caller's saved sessions.
 * Rendered by both the full-page Assistant view and the search drawer's
 * Smart tab — both consume the same AssistantSessionProvider context, so
 * acting from either one operates on the same current session.
 *
 * Save/Export/Delete are disabled until a session actually exists (the
 * first message auto-creates one under its default timestamped name) —
 * there is nothing to name/download/remove before that.
 */
import { useState } from 'react'
import { clsx } from 'clsx'
import {
  Plus,
  Save,
  Trash2,
  ChevronDown,
  FileText,
  FileJson,
  FileCode2,
  History,
  Maximize2,
} from 'lucide-react'
import { api } from '../api/client'
import ConfirmDialog from './ConfirmDialog'
import { useAssistantSessionContext } from '../hooks/useAssistantSessionContext'

export default function AssistantSessionBar({
  onOpenInAssistant,
}: {
  /** Only passed by the drawer — renders the emphasized "Open in Assistant" button. */
  onOpenInAssistant?: () => void
}) {
  const {
    sessions,
    currentSessionId,
    currentSessionName,
    newSession,
    saveSessionAs,
    loadSession,
    deleteSession,
  } = useAssistantSessionContext()

  const [saveOpen, setSaveOpen] = useState(false)
  const [saveName, setSaveName] = useState('')
  const [saving, setSaving] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)

  const hasSession = Boolean(currentSessionId)

  function openSaveDialog() {
    setSaveName(currentSessionName ?? '')
    setSaveOpen(true)
  }

  async function confirmSave() {
    setSaving(true)
    try {
      await saveSessionAs(saveName.trim())
      setSaveOpen(false)
    } finally {
      setSaving(false)
    }
  }

  async function exportJson() {
    if (!currentSessionId) return
    const full = await api.search.sessions.get(currentSessionId)
    const blob = new Blob([JSON.stringify(full, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${(full.name || 'assistant-session').replace(/[^\w.-]+/g, '_')}.json`
    a.click()
    URL.revokeObjectURL(url)
    setExportOpen(false)
  }

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <button
        type="button"
        onClick={() => newSession()}
        className="btn-ghost text-xs flex items-center gap-1 px-2 py-1"
        title="Start a new session"
      >
        <Plus className="w-3.5 h-3.5" />
        New session
      </button>

      <button
        type="button"
        disabled={!hasSession}
        onClick={openSaveDialog}
        className="btn-ghost text-xs flex items-center gap-1 px-2 py-1 disabled:opacity-40 disabled:cursor-not-allowed"
        title="Save session (set a name)"
      >
        <Save className="w-3.5 h-3.5" />
        Save
      </button>

      <div className="relative">
        <button
          type="button"
          disabled={!hasSession}
          onClick={() => setExportOpen((v) => !v)}
          className="btn-ghost text-xs flex items-center gap-1 px-2 py-1 disabled:opacity-40 disabled:cursor-not-allowed"
          title="Export session"
        >
          <FileText className="w-3.5 h-3.5" />
          Export
          <ChevronDown className="w-3 h-3" />
        </button>
        {exportOpen && hasSession && currentSessionId && (
          <div className="absolute left-0 top-full mt-1 z-10 w-36 rounded-lg border border-gray-700 bg-gray-900 shadow-xl py-1">
            <a
              href={api.search.sessions.downloadMarkdownUrl(currentSessionId)}
              onClick={() => setExportOpen(false)}
              className="flex items-center gap-2 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800"
            >
              <FileText className="w-3.5 h-3.5 text-blue-400" /> Markdown
            </a>
            <button
              type="button"
              onClick={() => void exportJson()}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800"
            >
              <FileJson className="w-3.5 h-3.5 text-amber-400" /> JSON
            </button>
            <a
              href={api.search.sessions.downloadPdfUrl(currentSessionId)}
              onClick={() => setExportOpen(false)}
              className="flex items-center gap-2 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800"
            >
              <FileCode2 className="w-3.5 h-3.5 text-red-400" /> PDF
            </a>
          </div>
        )}
      </div>

      <button
        type="button"
        disabled={!hasSession}
        onClick={() => setConfirmDelete(true)}
        className="btn-ghost text-xs flex items-center gap-1 px-2 py-1 text-red-400 hover:text-red-300 disabled:opacity-40 disabled:cursor-not-allowed disabled:text-gray-500"
        title="Delete session"
      >
        <Trash2 className="w-3.5 h-3.5" />
        Delete
      </button>

      <div className="relative">
        <button
          type="button"
          onClick={() => setPickerOpen((v) => !v)}
          className="btn-ghost text-xs flex items-center gap-1 px-2 py-1"
          title="Saved sessions"
        >
          <History className="w-3.5 h-3.5" />
          Sessions
          <ChevronDown className="w-3 h-3" />
        </button>
        {pickerOpen && (
          <div className="absolute left-0 top-full mt-1 z-10 w-64 max-h-72 overflow-y-auto rounded-lg border border-gray-700 bg-gray-900 shadow-xl py-1">
            {sessions.length === 0 ? (
              <p className="px-3 py-2 text-xs text-gray-500 italic">No saved sessions yet.</p>
            ) : (
              sessions.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => {
                    void loadSession(s.id)
                    setPickerOpen(false)
                  }}
                  className={clsx(
                    'flex w-full flex-col items-start px-3 py-1.5 text-left hover:bg-gray-800 transition-colors',
                    s.id === currentSessionId && 'bg-gray-800/70',
                  )}
                >
                  <span className="text-xs text-gray-200 truncate w-full">{s.name}</span>
                  <span className="text-[10px] text-gray-500">
                    {s.message_count} message{s.message_count === 1 ? '' : 's'}
                  </span>
                </button>
              ))
            )}
          </div>
        )}
      </div>

      {onOpenInAssistant && (
        <button
          type="button"
          onClick={onOpenInAssistant}
          className="flex items-center gap-1 px-2 py-1 text-xs font-medium rounded bg-brand-600 text-white hover:bg-brand-500 transition-colors"
          title="Open this session in the Assistant page"
        >
          <Maximize2 className="w-3.5 h-3.5" />
          Open in Assistant
        </button>
      )}

      {saveOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-sm mx-4 p-5 space-y-4">
            <h2 className="text-base font-semibold text-gray-100">Save session</h2>
            <p className="text-sm text-gray-400">Give this session a name.</p>
            <input
              className="input w-full"
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              placeholder="Session name"
              autoFocus
              onKeyDown={(e) => {
                if (e.key === 'Enter') void confirmSave()
              }}
            />
            <div className="flex justify-end gap-2">
              <button
                className="btn-ghost text-sm"
                onClick={() => setSaveOpen(false)}
                disabled={saving}
              >
                Cancel
              </button>
              <button
                className="btn-primary text-sm"
                disabled={!saveName.trim() || saving}
                onClick={() => void confirmSave()}
              >
                {saving ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}

      {confirmDelete && currentSessionId && (
        <ConfirmDialog
          title="Delete session?"
          message={`This will permanently delete "${currentSessionName ?? 'this session'}". This cannot be undone.`}
          confirmLabel="Delete"
          onConfirm={() => {
            void deleteSession(currentSessionId)
            setConfirmDelete(false)
          }}
          onCancel={() => setConfirmDelete(false)}
        />
      )}
    </div>
  )
}

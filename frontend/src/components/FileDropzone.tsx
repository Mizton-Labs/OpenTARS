/**
 * FileDropzone — drag-and-drop / click-to-browse multi-file upload component.
 *
 * Part 2: replaces single file inputs in HuntPackageWizard and AddEvidenceModal.
 */

import { useRef, useState } from 'react'
import { clsx } from 'clsx'
import { UploadCloud } from 'lucide-react'

export interface FileDropzoneProps {
  onFiles: (files: File[]) => void
  accept?: string
  disabled?: boolean
  className?: string
}

export default function FileDropzone({
  onFiles,
  accept,
  disabled = false,
  className,
}: FileDropzoneProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [isDragging, setIsDragging] = useState(false)

  function handleDragEnter(e: React.DragEvent) {
    e.preventDefault()
    e.stopPropagation()
    if (!disabled) setIsDragging(true)
  }

  function handleDragOver(e: React.DragEvent) {
    e.preventDefault()
    e.stopPropagation()
    if (!disabled) setIsDragging(true)
  }

  function handleDragLeave(e: React.DragEvent) {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
    if (disabled) return
    const files = e.dataTransfer.files
    if (files && files.length > 0) {
      onFiles(Array.from(files))
    }
  }

  function handleClick() {
    if (!disabled) inputRef.current?.click()
  }

  function handleInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.target.files
    if (files && files.length > 0) {
      onFiles(Array.from(files))
      // Reset so the same file can be re-selected
      e.target.value = ''
    }
  }

  return (
    <div
      role="button"
      tabIndex={disabled ? -1 : 0}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') handleClick() }}
      onClick={handleClick}
      onDragEnter={handleDragEnter}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={clsx(
        'border-2 border-dashed rounded-lg p-6 text-center transition-colors',
        disabled
          ? 'border-gray-700 opacity-50 cursor-not-allowed'
          : isDragging
            ? 'border-brand-400 bg-brand-900/10 cursor-copy'
            : 'border-gray-600 hover:border-brand-500 cursor-pointer',
        className,
      )}
    >
      <input
        ref={inputRef}
        type="file"
        multiple
        accept={accept}
        disabled={disabled}
        onChange={handleInputChange}
        className="hidden"
        tabIndex={-1}
      />
      <UploadCloud
        className={clsx(
          'w-8 h-8 mx-auto mb-2',
          isDragging ? 'text-brand-400' : 'text-gray-500',
        )}
      />
      <p className="text-sm text-gray-300 font-medium">Upload files</p>
      <p className="text-xs text-gray-500 mt-0.5">or drag and drop</p>
      {accept && (
        <p className="text-[10px] text-gray-600 mt-1">{accept}</p>
      )}
    </div>
  )
}

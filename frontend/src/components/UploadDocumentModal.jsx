import { useState } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.documentation.color
const MAX_SIZE = 10 * 1024 * 1024
const ACCEPTED = '.pdf,.doc,.docx,.xls,.xlsx,.png,.jpg,.jpeg'

// Upload d'une nouvelle version pour un type de document donné (module Documentation) — pas de
// suppression de l'ancienne version : chaque upload s'ajoute à l'historique (cf.
// backend/models.py::Document, pas de table de versions séparée, juste une nouvelle ligne).
// `initialFile` : déjà sélectionné si la modale s'ouvre suite à un glisser-déposer direct sur la
// carte du type (Documentation.jsx) — évite de redemander le fichier une deuxième fois.
export default function UploadDocumentModal({ documentTypeName, initialFile, onConfirm, onClose }) {
  const { names: ANALYSTS } = useAnalysts()
  const [file, setFile] = useState(initialFile || null)
  const [dragOver, setDragOver] = useState(false)
  const [uploadedBy, setUploadedBy] = useState('')
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  function applyFile(f) {
    if (!f) return
    setError('')
    if (f.size > MAX_SIZE) {
      setError('Fichier trop volumineux — 10 Mo maximum.')
      return
    }
    setFile(f)
  }

  function handleFileChange(e) {
    const f = e.target.files[0]
    e.target.value = ''
    applyFile(f)
  }

  function handleDragOver(e) {
    e.preventDefault()
    setDragOver(true)
  }
  function handleDragLeave() {
    setDragOver(false)
  }
  function handleDrop(e) {
    e.preventDefault()
    setDragOver(false)
    applyFile(e.dataTransfer.files?.[0])
  }

  async function confirm() {
    if (!file || !uploadedBy || saving) return
    setSaving(true)
    setError('')
    try {
      await onConfirm({ file, uploadedBy, notes: notes.trim() || undefined })
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'envoyer ce document.")
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between">
            <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>Téléverser une nouvelle version</h2>
            <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{documentTypeName}</p>
        </div>
        <div className="p-6 space-y-3">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Fichier (PDF, Word, Excel ou image — 10 Mo max)</label>
            <label onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}
              className="flex items-center justify-center text-xs px-3 py-6 rounded-lg cursor-pointer text-center transition-colors"
              style={{
                background: dragOver ? `${MODULE_COLOR}14` : 'var(--bg-secondary)',
                border: `1px dashed ${dragOver || file ? MODULE_COLOR : 'var(--border)'}`,
                color: dragOver || file ? MODULE_COLOR : 'var(--text-muted)',
              }}>
              {file ? `📄 ${file.name}` : dragOver ? 'Déposez le fichier ici…' : 'Choisir un fichier, ou glissez-déposez-le ici'}
              <input type="file" accept={ACCEPTED} onChange={handleFileChange} className="hidden" />
            </label>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Téléversé par</label>
            <select value={uploadedBy} onChange={e => setUploadedBy(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
              <option value="">Sélectionner…</option>
              {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Notes (optionnel)</label>
            <textarea value={notes} onChange={e => setNotes(e.target.value)} rows={2}
              placeholder="Ex : mise à jour suite à l'audit de juillet"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none resize-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={!file || !uploadedBy || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Envoi…' : 'Téléverser'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

import { useState } from 'react'

// Modale de confirmation générique (style CBR), pour remplacer window.confirm() sur les
// actions destructrices — même charpente que les autres modales de l'app (AnnotationModal,
// IncidentFormModal...).
export default function ConfirmModal({ title, message, confirmLabel = 'Confirmer', busyLabel = 'Suppression…', color = '#f85149', onConfirm, onClose }) {
  const [busy, setBusy] = useState(false)

  async function confirm() {
    if (busy) return
    setBusy(true)
    try {
      await onConfirm()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color }}>{title}</h2>
        </div>
        <div className="p-6 text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          {message}
        </div>
        <div className="px-6 py-4 flex items-center justify-end gap-2" style={{ borderTop: '1px solid var(--border)' }}>
          <button onClick={onClose} disabled={busy}
            className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
          >Annuler</button>
          <button onClick={confirm} disabled={busy}
            className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
            style={{ background: `${color}26`, color, border: `1px solid ${color}59` }}
          >{busy ? busyLabel : confirmLabel}</button>
        </div>
      </div>
    </div>
  )
}

import { useState } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'

// Qualification groupée d'une sélection vers un statut donné. Généralisé depuis
// l'ancien FalsePositiveBulkModal (21/07/2026) : c'est le 3e flux de ce type
// (faux positif, puis "en attente de correctif", puis "risque accepté"), tous
// structurellement identiques — liste + cases à cocher + analyste + annotation.
// Dupliquer une 3e fois aurait multiplié la maintenance sans raison.
//
// Le geste reste humain dans tous les cas : le système ne fait que présenter des
// candidats identifiés sur des critères objectifs et vérifiables ; analyste
// obligatoire. Annotation obligatoire aussi, SAUF en mode `autoJustification`
// (08/08/2026, cf. son commentaire ci-dessous) — faux positifs uniquement pour
// l'instant, même principe que /bulk-validate côté CRITICAL.

// Motifs possibles, tous statuts confondus — le libellé porte la nuance, la
// couleur suit le statut cible.
const RAISON_LABEL = {
  matching_invalide: 'Rattachement erroné',
  produit_absent:    'Produit non installé',
  aucun_correctif:   'Aucun correctif publié',
}

const NOTE_PAR_DEFAUT = {
  matching_invalide:
    "Faux positif — rattachement erroné : le CPE publié par NVD pour cette CVE n'identifie aucun produit "
    + "(ni vendeur ni produit renseigné), elle ne désigne donc pas cet actif.",
  produit_absent:
    "Faux positif — produit absent de l'actif : aucun des paquets visés par cette CVE n'est installé. "
    + "La vulnérabilité est sans objet sur cette machine.",
  aucun_correctif:
    "En attente d'un correctif : la distribution n'a publié aucune version corrigée pour cette CVE "
    + "(statut « open » du Security Tracker). Rien à appliquer sur le serveur à ce jour ; bascule "
    + "automatique en corrigé dès publication.",
  mixte:
    "Qualification groupée après vérification du contrôle read-only et des règles de matching en vigueur.",
}

// Lots plutôt qu'un seul appel avec toute la sélection : donne un point de
// progression visible (même principe que BulkValidateModal.jsx, demande
// explicite du 08/08/2026 pour uniformiser les deux modales de qualification
// groupée).
const CHUNK_SIZE = 20

export default function BulkQualifyModal({
  items, onClose, apiCall, onDone,
  titre = 'Qualification groupée — faux positifs',
  sousTitre = "CVE ne concernant pas réellement l'actif",
  couleur = '#a371f7',
  confirmLabel = '🚫 Marquer faux positif',
  showReviewDate = false,
  // Justification calculée et enregistrée côté serveur, propre à chaque CVE/actif
  // (cf. routers/vulnerabilities.py::bulk_false_positive) — pas de champ texte à
  // remplir ni de gabarit partagé pour toute la sélection : deux vulns du même lot
  // n'ont pas forcément la même raison exacte.
  autoJustification = false,
}) {
  const { names: ANALYSTS } = useAnalysts()
  const [selected, setSelected] = useState(() => new Set(items.map(i => i.id)))
  const [validator, setValidator] = useState('')
  const [notes, setNotes] = useState('')
  const [reviewDate, setReviewDate] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [progress, setProgress] = useState(null) // null | { done, total, applied }
  const reviewDateMissing = showReviewDate && !reviewDate

  // Note pré-remplie selon la nature de la sélection — modifiable, jamais imposée :
  // c'est l'analyste qui assume la justification versée à la piste d'audit.
  // Sans objet en mode autoJustification (le serveur décide, par ligne).
  const raisonsSelection = new Set(items.filter(i => selected.has(i.id)).map(i => i.raison))
  const notePreremplie = raisonsSelection.size === 1
    ? NOTE_PAR_DEFAUT[[...raisonsSelection][0]]
    : NOTE_PAR_DEFAUT.mixte

  function toggle(id) {
    setSelected(s => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id); else n.add(id)
      return n
    })
  }

  function toggleAll() {
    setSelected(s => s.size === items.length ? new Set() : new Set(items.map(i => i.id)))
  }

  async function handleConfirm() {
    const texte = autoJustification ? undefined : (notes.trim() || notePreremplie).trim()
    if (!validator || selected.size === 0 || (!autoJustification && !texte) || reviewDateMissing) return
    setSubmitting(true)
    const ids = [...selected]
    const total = ids.length
    let done = 0
    let applied = 0
    setProgress({ done, total, applied })
    try {
      for (let i = 0; i < ids.length; i += CHUNK_SIZE) {
        const chunk = ids.slice(i, i + CHUNK_SIZE)
        const r = await apiCall(chunk, validator, texte, showReviewDate ? new Date(reviewDate).toISOString() : undefined)
        applied += r.data.applied?.length || 0
        done += chunk.length
        setProgress({ done, total, applied })
      }
      onDone(applied, validator)
    } finally {
      setSubmitting(false)
      setProgress(null)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-3xl w-full max-h-[88vh] flex flex-col rounded-2xl animate-modal-in"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}
        onClick={e => e.stopPropagation()}>

        <div className="px-6 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold text-lg" style={{ color: 'var(--text-primary)' }}>
            {titre}
          </h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {items.length} {sousTitre} — vous restez décisionnaire ligne par ligne
            {autoJustification && ' — justification générée automatiquement par CVE/actif, seul le validateur reste à choisir'}
          </p>
        </div>

        <div className="overflow-y-auto flex-1">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                <th className="px-4 py-2.5">
                  <input type="checkbox" checked={selected.size === items.length && items.length > 0}
                    onChange={toggleAll} className="w-3.5 h-3.5 accent-blue-500" />
                </th>
                {['CVE', 'Actif', 'Motif'].map(h => (
                  <th key={h} className="text-left px-2 py-2.5 text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map(v => {
                const texte = RAISON_LABEL[v.raison] || v.raison
                return (
                  <tr key={v.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td className="px-4 py-2.5">
                      <input type="checkbox" checked={selected.has(v.id)} onChange={() => toggle(v.id)}
                        className="w-3.5 h-3.5 accent-blue-500" />
                    </td>
                    <td className="px-2 py-2.5 font-mono text-xs font-semibold" style={{ color: '#58a6ff' }}>{v.cve?.cve_id}</td>
                    <td className="px-2 py-2.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{v.asset?.name}</td>
                    <td className="px-2 py-2.5 text-xs" title={v.justification || ''} style={{ color: couleur }}>{texte}</td>
                  </tr>
                )
              })}
              {items.length === 0 && (
                <tr><td colSpan={4} className="px-4 py-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucun candidat</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="px-6 py-4 space-y-3" style={{ borderTop: '1px solid var(--border)' }}>
          {!autoJustification && (
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                Justification (versée à la piste d'audit)
              </label>
              <textarea
                value={notes}
                onChange={e => setNotes(e.target.value)}
                placeholder={notePreremplie}
                rows={3}
                className="w-full mt-1.5 text-xs px-3 py-2 rounded-lg resize-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none' }}
              />
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                Laissez vide pour utiliser le texte proposé ci-dessus, ou reformulez-le.
              </p>
            </div>
          )}
          {showReviewDate && (
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Date de revue</label>
              <input
                type="date"
                value={reviewDate}
                onChange={e => setReviewDate(e.target.value)}
                className="w-full mt-1.5 text-xs px-3 py-2 rounded-lg"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none' }}
              />
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                Signalé « en retard de revue » passé cette date — jamais rouvert automatiquement.
              </p>
            </div>
          )}
          {progress && (
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between text-xs" style={{ color: 'var(--text-muted)' }}>
                <span>Qualification en cours — {progress.done}/{progress.total}</span>
                <span>{Math.round((progress.done / progress.total) * 100)}%</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(0,0,0,0.2)' }}>
                <div
                  className="h-full rounded-full transition-all duration-300 progress-bar-shimmer"
                  style={{ width: `${Math.round((progress.done / progress.total) * 100)}%`, background: `linear-gradient(90deg, ${couleur}99, ${couleur})` }}
                />
              </div>
            </div>
          )}
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{selected.size} sélectionnée(s)</span>
            <div className="flex items-center gap-2">
              <select value={validator} onChange={e => setValidator(e.target.value)} disabled={submitting}
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none' }}>
                <option value="">Validé par…</option>
                {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
              </select>
              <button onClick={onClose} disabled={submitting}
                className="text-xs px-3 py-2 rounded-lg active:scale-[0.97] disabled:opacity-40"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
              >Annuler</button>
              <button onClick={handleConfirm} disabled={!validator || selected.size === 0 || reviewDateMissing || submitting}
                className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-40 active:scale-[0.97]"
                style={{ background: `${couleur}26`, color: couleur, border: `1px solid ${couleur}66` }}
              >{submitting ? 'Qualification…' : `${confirmLabel} (${selected.size})`}</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

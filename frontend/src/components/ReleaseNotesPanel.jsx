import { useEffect, useState } from 'react'
import { releaseNotes, createReleaseNote, deleteReleaseNote } from '../api/client.js'
import { tintedCard } from '../utils/cardStyle.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { SYNTHETIC_RELEASE_NOTES, isSyntheticId } from '../utils/syntheticData.js'

// Panneau notes de version (18/08/2026, demande explicite) — partagé entre Paramètres
// (scope="allsafe") et la page dédiée Agents (scope="agent") : même forme des deux côtés
// (version/catégorie/titre/description), extrait dès le départ plutôt que dupliqué une
// 2e fois (cf. principe scalable, CLAUDE.md). Alimenté en fin de session par l'assistant,
// relu/validé par l'utilisateur directement sur la page — pas de statut brouillon/publié
// séparé, disproportionné pour ce besoin.
//
// Regroupé par version (18/08/2026, demande explicite) : une ligne résumé par version
// (repliée par défaut), qui se déplie au clic pour révéler le détail (titre + description
// par entrée) — plutôt qu'une liste plate de toutes les entrées à la fois, illisible dès
// qu'un historique de plusieurs semaines est chargé.
const CATEGORY_LABELS = { feature: 'Nouveauté', fix: 'Correctif' }
const CATEGORY_COLORS = { feature: '#58a6ff', fix: '#3fb950' }

function formatDate(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' })
}

// Regroupe une liste déjà triée (created_at desc, cf. backend) par version — l'ordre
// d'apparition du groupe suit celui de la 1re entrée rencontrée pour cette version,
// donc les groupes restent du plus récent au plus ancien sans re-tri explicite.
function groupByVersion(items) {
  const groups = []
  const byVersion = new Map()
  for (const n of items) {
    const key = n.version || '—'
    let g = byVersion.get(key)
    if (!g) {
      g = { version: n.version, key, date: n.created_at, entries: [] }
      byVersion.set(key, g)
      groups.push(g)
    }
    g.entries.push(n)
    if (n.created_at > g.date) g.date = n.created_at
  }
  return groups
}

export default function ReleaseNotesPanel({ scope, color, isAdmin, showVersionField }) {
  const [items, setItems] = useState(null) // null = chargement
  const [error, setError] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ version: '', category: 'feature', title: '', description: '' })
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [expanded, setExpanded] = useState(null) // clé de version dépliée, une seule à la fois
  const { isAnonymous } = usePresentation()

  function load() {
    releaseNotes(scope).then(r => setItems(r.data.items || [])).catch(() => setError('Impossible de charger les notes de version.'))
  }
  useEffect(() => { load() }, [scope])

  async function handleCreate(e) {
    e.preventDefault()
    if (saving || !form.title.trim()) return
    setSaving(true)
    try {
      await createReleaseNote({ scope, version: form.version.trim() || null, category: form.category, title: form.title.trim(), description: form.description.trim() || null })
      setForm({ version: '', category: 'feature', title: '', description: '' })
      setShowForm(false)
      load()
    } catch {
      setError("Impossible d'enregistrer cette note.")
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(id) {
    await deleteReleaseNote(id)
    setDeleteTarget(null)
    load()
  }

  const displayItems = isAnonymous ? [...(items || []), ...SYNTHETIC_RELEASE_NOTES[scope]] : items
  const groups = displayItems ? groupByVersion(displayItems) : []

  return (
    <div className="space-y-3">
      {isAdmin && (
        <div className="flex justify-end">
          <button onClick={() => setShowForm(s => !s)}
            className="text-xs font-medium px-3 py-1.5 rounded-lg"
            style={{ background: `color-mix(in srgb, ${color} 15%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 35%, transparent)` }}>
            {showForm ? 'Annuler' : '+ Ajouter une note'}
          </button>
        </div>
      )}

      {showForm && (
        <form onSubmit={handleCreate} className="p-4 rounded-xl space-y-2.5" style={tintedCard(color)}>
          <div className="flex gap-2.5 flex-wrap">
            <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
              className="text-xs rounded-lg px-2.5 py-1.5 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
              <option value="feature">Nouveauté</option>
              <option value="fix">Correctif</option>
            </select>
            {showVersionField && (
              <input value={form.version} onChange={e => setForm(f => ({ ...f, version: e.target.value }))}
                placeholder="Version (ex. 1.0.0)" className="text-xs rounded-lg px-2.5 py-1.5 outline-none w-36"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
            )}
          </div>
          <input required value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
            placeholder="Titre" className="w-full text-sm rounded-lg px-3 py-2 outline-none"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          <textarea rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            placeholder="Description (facultatif)" className="w-full text-sm rounded-lg px-3 py-2 outline-none resize-none"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          <button type="submit" disabled={saving || !form.title.trim()}
            className="text-xs font-medium px-3 py-1.5 rounded-lg disabled:opacity-50"
            style={{ background: color, color: '#fff' }}>
            {saving ? 'Enregistrement…' : 'Enregistrer'}
          </button>
        </form>
      )}

      {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}

      {items === null ? (
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Chargement…</p>
      ) : groups.length === 0 ? (
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucune note de version pour l'instant.</p>
      ) : (
        <div className="space-y-2.5">
          {groups.map(g => {
            const isOpen = expanded === g.key
            const featureCount = g.entries.filter(e => e.category === 'feature').length
            const fixCount = g.entries.filter(e => e.category === 'fix').length
            return (
              <div key={g.key} className="rounded-xl overflow-hidden" style={tintedCard(color)}>
                <button onClick={() => setExpanded(isOpen ? null : g.key)}
                  className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left">
                  <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                    <span className="inline-block transition-transform flex-shrink-0" style={{ transform: isOpen ? 'rotate(90deg)' : 'none', color: 'var(--text-muted)' }}>›</span>
                    {g.version && (
                      <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded-full flex-shrink-0" style={{ background: `color-mix(in srgb, ${color} 18%, transparent)`, color }}>
                        v{g.version}
                      </span>
                    )}
                    <span className="text-xs flex-shrink-0" style={{ color: 'var(--text-muted)' }}>{formatDate(g.date)}</span>
                    <span className="text-xs truncate" style={{ color: 'var(--text-secondary)' }}>
                      {featureCount > 0 && `${featureCount} nouveauté${featureCount > 1 ? 's' : ''}`}
                      {featureCount > 0 && fixCount > 0 && ' · '}
                      {fixCount > 0 && `${fixCount} correctif${fixCount > 1 ? 's' : ''}`}
                    </span>
                  </div>
                </button>

                {isOpen && (
                  <div className="px-4 pb-4 space-y-2.5">
                    {g.entries.map(n => (
                      <div key={n.id} className="p-3.5 rounded-lg" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
                        <div className="flex items-start justify-between gap-3">
                          <span className="text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full"
                            style={{ background: `color-mix(in srgb, ${CATEGORY_COLORS[n.category] || color} 15%, transparent)`, color: CATEGORY_COLORS[n.category] || color }}>
                            {CATEGORY_LABELS[n.category] || n.category}
                          </span>
                          {isAdmin && !isSyntheticId(n.id) && (
                            <button onClick={() => setDeleteTarget(n)} title="Supprimer"
                              className="text-xs flex-shrink-0" style={{ color: 'var(--text-muted)' }}>✕</button>
                          )}
                        </div>
                        <p className="font-semibold text-sm mt-1.5" style={{ color: 'var(--text-primary)' }}>{n.title}</p>
                        {n.description && <p className="text-xs mt-1 leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{n.description}</p>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {deleteTarget && (
        <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop" onClick={() => setDeleteTarget(null)}>
          <div className="max-w-sm w-full rounded-2xl p-5 space-y-3" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
            <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Supprimer "{deleteTarget.title}" ?</p>
            <div className="flex justify-end gap-2">
              <button onClick={() => setDeleteTarget(null)} className="text-xs px-3 py-1.5 rounded-lg" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>Annuler</button>
              <button onClick={() => handleDelete(deleteTarget.id)} className="text-xs px-3 py-1.5 rounded-lg" style={{ background: '#f85149', color: '#fff' }}>Supprimer</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

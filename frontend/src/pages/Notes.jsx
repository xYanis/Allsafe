import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  noteThemes as fetchNoteThemes, createNoteTheme, updateNoteTheme, deleteNoteTheme,
  noteSubjects as fetchNoteSubjects, createNoteSubject, deleteNoteSubject,
} from '../api/client.js'
import PageLoader from '../components/PageLoader.jsx'
import NoteThemeFormModal from '../components/NoteThemeFormModal.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('fr-FR') + ' ' + new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

// Prise de notes personnelle structurée (12/08/2026, cf. docs/Notes.md) — Thème > Sujet en
// Markdown, remplace le glossaire plat initial le même jour. Phase 1 seulement : pas de QCM
// généré par IA ici (reporté, demande explicite de l'utilisateur).
//
// Rendu délibérément SANS carte ni panneau bordé (2e itération, même session — la première
// passait par des cartes, la deuxième par un explorateur à deux volets bordés, aucune des
// deux n'a plu) : arborescence façon Notion, à plat sur le fond de page — indentation et
// surlignage au survol seuls, aucune boîte. Cf. .tree-row dans index.css.
export default function Notes() {
  const navigate = useNavigate()
  const [themes, setThemes] = useState(null)
  const [subjectsByTheme, setSubjectsByTheme] = useState({}) // theme_id -> items[] | undefined tant que pas chargé
  const [expandedIds, setExpandedIds] = useState(() => new Set())
  const [error, setError] = useState('')
  const [themeModal, setThemeModal] = useState(null) // null | 'new' | theme object
  const [deleteThemeTarget, setDeleteThemeTarget] = useState(null)
  const [deleteSubjectTarget, setDeleteSubjectTarget] = useState(null)
  const [creatingSubjectFor, setCreatingSubjectFor] = useState(null) // theme_id en cours de création

  function loadThemes() {
    fetchNoteThemes().then(r => { setThemes(r.data.items || []); setError('') })
      .catch(() => { setThemes([]); setError('Impossible de charger les thèmes — le serveur a peut-être renvoyé une erreur.') })
  }
  useEffect(() => { loadThemes() }, [])

  function loadSubjectsFor(themeId) {
    fetchNoteSubjects(themeId).then(r => {
      setSubjectsByTheme(m => ({ ...m, [themeId]: r.data.items || [] }))
      setError('')
    }).catch(() => setError('Impossible de charger les sujets — le serveur a peut-être renvoyé une erreur.'))
  }

  function toggleTheme(themeId) {
    setExpandedIds(prev => {
      const next = new Set(prev)
      if (next.has(themeId)) next.delete(themeId)
      else { next.add(themeId); if (subjectsByTheme[themeId] === undefined) loadSubjectsFor(themeId) }
      return next
    })
  }

  async function handleSaveTheme(payload) {
    if (themeModal && themeModal !== 'new') await updateNoteTheme(themeModal.id, payload)
    else await createNoteTheme(payload)
    setThemeModal(null)
    loadThemes()
  }

  async function confirmDeleteTheme() {
    try {
      await deleteNoteTheme(deleteThemeTarget.id)
      setDeleteThemeTarget(null)
      loadThemes()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la suppression.')
      setDeleteThemeTarget(null)
    }
  }

  async function handleCreateSubject(themeId) {
    if (creatingSubjectFor) return
    setCreatingSubjectFor(themeId)
    try {
      const r = await createNoteSubject({ theme_id: themeId, title: 'Nouveau sujet', content_markdown: '' })
      navigate(`/notes/${r.data.id}`)
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible de créer le sujet.")
      setCreatingSubjectFor(null)
    }
  }

  async function confirmDeleteSubject() {
    try {
      await deleteNoteSubject(deleteSubjectTarget.id)
      const themeId = deleteSubjectTarget.theme_id
      setDeleteSubjectTarget(null)
      loadSubjectsFor(themeId)
      loadThemes()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la suppression.')
      setDeleteSubjectTarget(null)
    }
  }

  if (themes === null) return <PageLoader />

  return (
    <div className="p-6 space-y-5 max-w-2xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Notes</h1>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Votre prise de notes personnelle — organisez vos fiches de cours par thème.
        </p>
      </div>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      {themes.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun thème pour l'instant.</p>
      ) : (
        <div className="stagger space-y-0.5">
          {themes.map(t => {
            const open = expandedIds.has(t.id)
            const subjects = subjectsByTheme[t.id]
            return (
              <div key={t.id}>
                <button onClick={() => toggleTheme(t.id)} onDoubleClick={() => setThemeModal(t)}
                  title="Double-clic pour modifier"
                  className="tree-row group w-full flex items-center gap-2 px-2 py-1.5 text-left"
                  style={{ '--accent': t.color }}>
                  <span className="flex-shrink-0 text-xs w-3.5 text-center" style={{ color: 'var(--text-faint)' }}>{open ? '▾' : '▸'}</span>
                  <span className="flex-shrink-0" style={{ fontSize: 15 }}>{t.icon}</span>
                  <span className="text-sm font-medium flex-1 min-w-0 truncate" style={{ color: 'var(--text-primary)' }}>{t.name}</span>
                  <span className="text-xs flex-shrink-0" style={{ color: 'var(--text-faint)' }}>{t.subject_count}</span>
                  <button onClick={e => { e.stopPropagation(); setDeleteThemeTarget(t) }}
                    className="flex-shrink-0 text-xs opacity-0 group-hover:opacity-100 transition-opacity hover:opacity-70"
                    style={{ color: 'var(--text-faint)' }} title="Supprimer">✕</button>
                </button>

                {open && (
                  <div className="route-fade" style={{ paddingLeft: 30 }}>
                    {subjects === undefined ? (
                      <div className="py-2"><PageLoader size="sm" /></div>
                    ) : (
                      <>
                        {subjects.map(s => (
                          <div key={s.id} onClick={() => navigate(`/notes/${s.id}`)}
                            className="tree-row group flex items-center gap-2 px-2 py-1.5 cursor-pointer"
                            style={{ '--accent': t.color }}>
                            <span aria-hidden="true" className="flex-shrink-0 rounded-full" style={{ width: 5, height: 5, background: t.color }} />
                            <span className="text-sm flex-1 min-w-0 truncate" style={{ color: 'var(--text-secondary)' }}>{s.title}</span>
                            <span className="text-xs flex-shrink-0" style={{ color: 'var(--text-faint)' }}>{fmtDate(s.updated_at)}</span>
                            <button onClick={e => { e.stopPropagation(); setDeleteSubjectTarget(s) }}
                              className="flex-shrink-0 text-xs opacity-0 group-hover:opacity-100 transition-opacity hover:opacity-70"
                              style={{ color: 'var(--text-faint)' }} title="Supprimer">✕</button>
                          </div>
                        ))}
                        <button onClick={() => handleCreateSubject(t.id)} disabled={creatingSubjectFor === t.id}
                          className="tree-row w-full flex items-center gap-2 px-2 py-1.5 text-left disabled:opacity-50"
                          style={{ '--accent': t.color, color: 'var(--text-faint)' }}>
                          <span className="flex-shrink-0 text-sm leading-none w-[5px] text-center">+</span>
                          <span className="text-sm">Nouveau sujet</span>
                        </button>
                      </>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      <button onClick={() => setThemeModal('new')}
        className="tree-row w-full flex items-center gap-2 px-2 py-1.5 text-left"
        style={{ '--accent': 'var(--text-faint)', color: 'var(--text-faint)' }}>
        <span className="flex-shrink-0 text-xs w-3.5 text-center leading-none">+</span>
        <span className="text-sm font-medium">Nouveau thème</span>
      </button>

      {themeModal && (
        <NoteThemeFormModal initial={themeModal !== 'new' ? themeModal : null} onConfirm={handleSaveTheme} onClose={() => setThemeModal(null)} />
      )}
      {deleteThemeTarget && (
        <ConfirmModal
          title="Supprimer ce thème ?"
          message={<>Supprimer définitivement « <strong>{deleteThemeTarget.name}</strong> » ? {deleteThemeTarget.subject_count > 0 ? 'Ce thème contient encore des sujets — supprimez-les d\'abord.' : 'Cette action est irréversible.'}</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDeleteTheme}
          onClose={() => setDeleteThemeTarget(null)}
        />
      )}
      {deleteSubjectTarget && (
        <ConfirmModal
          title="Supprimer ce sujet ?"
          message={<>Supprimer définitivement « <strong>{deleteSubjectTarget.title}</strong> » ? Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDeleteSubject}
          onClose={() => setDeleteSubjectTarget(null)}
        />
      )}
    </div>
  )
}

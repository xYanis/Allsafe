import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  noteThemes as fetchNoteThemes, createNoteTheme, updateNoteTheme, deleteNoteTheme,
  noteSubjects as fetchNoteSubjects, createNoteSubject, deleteNoteSubject,
} from '../api/client.js'
import PageLoader from '../components/PageLoader.jsx'
import PageHero from '../components/PageHero.jsx'
import NoteThemeFormModal from '../components/NoteThemeFormModal.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('fr-FR') + ' ' + new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

const CARD = tintedCard(MODULES.documentation.color)
// Gris uniforme (18/08/2026, demande explicite) : chaque thème avait sa propre couleur
// choisie librement (NoteThemeFormModal), rendant la nav thèmes/l'accent des sujets
// incohérents d'un thème à l'autre — remplacé par cette teinte fixe partout où `t.color`/
// `selectedTheme.color` servait d'accent visuel. Le champ `color` lui-même n'est pas
// retiré du modèle/formulaire (pas demandé), juste plus utilisé pour cet accent.
const THEME_ACCENT = MODULES.parametres.color

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
// Permet de réafficher instantanément les dernières données connues au remontage pendant
// qu'un rafraîchissement silencieux les met à jour en fond.
let notesThemesCache = null
let notesSubjectsCache = {}

// Prise de notes personnelle structurée (12/08/2026, cf. docs/Notes.md) — Thème > Sujet en
// Markdown, remplace le glossaire plat initial le même jour. Phase 1 seulement : pas de QCM
// généré par IA ici (reporté, demande explicite de l'utilisateur).
//
// 3e itération de layout (14/08/2026, demande explicite — reproduire la nav à icônes
// d'AdministrationSecurity.jsx) : nav de thèmes à gauche (icône = emoji du thème, teinte =
// couleur du thème, même gabarit que la nav d'Administration) + panneau de contenu à droite.
// Les deux tentatives précédentes (cartes, puis explorateur à deux volets bordés) avaient été
// rejetées — celle-ci diffère : la nav elle-même reste sans bordure (fond teinté + liseré
// gauche seulement, pas de boîte), comme dans AdministrationSecurity, et non les deux
// tentatives d'avant. Un seul thème affiché à la fois (sélection simple, pas d'accordéon
// multi-ouvert) — mêmes lignes .tree-row qu'avant pour les sujets, à l'intérieur du panneau.
export default function Notes() {
  const navigate = useNavigate()
  const [themes, setThemes] = useState(() => notesThemesCache)
  const [subjectsByTheme, setSubjectsByTheme] = useState(() => notesSubjectsCache) // theme_id -> items[] | undefined tant que pas chargé
  const [selectedThemeId, setSelectedThemeId] = useState(null)
  const [error, setError] = useState('')
  const [themeModal, setThemeModal] = useState(null) // null | 'new' | theme object
  const [deleteThemeTarget, setDeleteThemeTarget] = useState(null)
  const [deleteSubjectTarget, setDeleteSubjectTarget] = useState(null)
  const [creatingSubjectFor, setCreatingSubjectFor] = useState(null) // theme_id en cours de création

  function loadThemes() {
    fetchNoteThemes().then(r => {
      const data = r.data.items || []
      setThemes(data)
      notesThemesCache = data
      setError('')
    })
      .catch(() => { setThemes([]); setError('Impossible de charger les thèmes — le serveur a peut-être renvoyé une erreur.') })
  }
  useEffect(() => { loadThemes() }, [])

  function loadSubjectsFor(themeId) {
    fetchNoteSubjects(themeId).then(r => {
      const items = r.data.items || []
      setSubjectsByTheme(m => {
        const next = { ...m, [themeId]: items }
        notesSubjectsCache = next
        return next
      })
      setError('')
    }).catch(() => setError('Impossible de charger les sujets — le serveur a peut-être renvoyé une erreur.'))
  }

  // Sélectionne le premier thème dès le chargement initial (même défaut que l'onglet
  // "database" d'AdministrationSecurity) — seulement s'il n'y a pas déjà une sélection.
  useEffect(() => {
    if (themes && themes.length > 0 && selectedThemeId == null) selectTheme(themes[0].id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [themes])

  function selectTheme(themeId) {
    setSelectedThemeId(themeId)
    if (subjectsByTheme[themeId] === undefined) loadSubjectsFor(themeId)
  }

  async function handleSaveTheme(payload) {
    if (themeModal && themeModal !== 'new') await updateNoteTheme(themeModal.id, payload)
    else await createNoteTheme(payload)
    setThemeModal(null)
    loadThemes()
  }

  async function confirmDeleteTheme() {
    try {
      const deletedId = deleteThemeTarget.id
      await deleteNoteTheme(deletedId)
      setDeleteThemeTarget(null)
      if (selectedThemeId === deletedId) setSelectedThemeId(null)
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

  const selectedTheme = themes.find(t => t.id === selectedThemeId) || null
  const selectedSubjects = selectedThemeId != null ? subjectsByTheme[selectedThemeId] : undefined

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25"
        title="Notes" color="#e3b341"
        subtitle="Votre prise de notes personnelle — organisez vos fiches de cours par thème."
      />

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      {themes.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun thème pour l'instant.</p>
      ) : (
        <div className="flex flex-col lg:flex-row gap-5 items-start">
          <nav className="stagger w-full lg:w-64 flex-shrink-0 flex lg:flex-col gap-1.5 overflow-x-auto lg:overflow-visible pb-1">
            {themes.map(t => {
              const active = t.id === selectedThemeId
              return (
                <button key={t.id} onClick={() => selectTheme(t.id)} onDoubleClick={() => setThemeModal(t)}
                  title="Double-clic pour modifier"
                  className="group flex-shrink-0 w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors"
                  style={{
                    background: active ? `color-mix(in srgb, ${THEME_ACCENT} 14%, transparent)` : 'transparent',
                    boxShadow: active ? `inset 3px 0 0 0 ${THEME_ACCENT}` : 'none',
                  }}
                  onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--bg-secondary)' }}
                  onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent' }}
                >
                  <span className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{
                    background: active ? `color-mix(in srgb, ${THEME_ACCENT} 22%, transparent)` : 'var(--bg-secondary)',
                    fontSize: 15,
                  }}>{t.icon}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium truncate" style={{ color: active ? THEME_ACCENT : 'var(--text-primary)' }}>{t.name}</span>
                    <span className="block text-xs truncate" style={{ color: 'var(--text-muted)' }}>{t.subject_count} sujet{t.subject_count > 1 ? 's' : ''}</span>
                  </span>
                  <button onClick={e => { e.stopPropagation(); setDeleteThemeTarget(t) }}
                    className="flex-shrink-0 text-xs opacity-0 group-hover:opacity-100 transition-opacity hover:opacity-70"
                    style={{ color: 'var(--text-faint)' }} title="Supprimer">✕</button>
                </button>
              )
            })}

            <button onClick={() => setThemeModal('new')}
              className="flex-shrink-0 w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors"
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <span className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 text-sm leading-none" style={{ background: 'var(--bg-secondary)', color: 'var(--text-faint)' }}>+</span>
              <span className="text-sm font-medium" style={{ color: 'var(--text-faint)' }}>Nouveau thème</span>
            </button>
          </nav>

          <div style={CARD} className="flex-1 min-w-0 p-6">
            {!selectedTheme ? (
              <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Sélectionnez un thème.</p>
            ) : (
              <div className="route-fade" key={selectedTheme.id}>
                <div className="flex items-center gap-2 mb-4">
                  <span style={{ fontSize: 18 }}>{selectedTheme.icon}</span>
                  <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>{selectedTheme.name}</h2>
                </div>

                {selectedSubjects === undefined ? (
                  <div className="py-2"><PageLoader size="sm" /></div>
                ) : selectedSubjects.length === 0 ? (
                  <p className="text-sm mb-2" style={{ color: 'var(--text-muted)' }}>Aucun sujet dans ce thème pour l'instant.</p>
                ) : (
                  <div className="space-y-0.5 mb-2">
                    {selectedSubjects.map(s => (
                      <div key={s.id} onClick={() => navigate(`/notes/${s.id}`)}
                        className="tree-row group flex items-center gap-2 px-2 py-1.5 cursor-pointer"
                        style={{ '--accent': THEME_ACCENT }}>
                        <span aria-hidden="true" className="flex-shrink-0 rounded-full" style={{ width: 5, height: 5, background: THEME_ACCENT }} />
                        <span className="text-sm flex-1 min-w-0 truncate" style={{ color: 'var(--text-secondary)' }}>{s.title}</span>
                        <span className="text-xs flex-shrink-0" style={{ color: 'var(--text-faint)' }}>{fmtDate(s.updated_at)}</span>
                        <button onClick={e => { e.stopPropagation(); setDeleteSubjectTarget(s) }}
                          className="flex-shrink-0 text-xs opacity-0 group-hover:opacity-100 transition-opacity hover:opacity-70"
                          style={{ color: 'var(--text-faint)' }} title="Supprimer">✕</button>
                      </div>
                    ))}
                  </div>
                )}

                <button onClick={() => handleCreateSubject(selectedTheme.id)} disabled={creatingSubjectFor === selectedTheme.id}
                  className="tree-row w-full flex items-center gap-2 px-2 py-1.5 text-left disabled:opacity-50"
                  style={{ '--accent': THEME_ACCENT, color: 'var(--text-faint)' }}>
                  <span className="flex-shrink-0 text-sm leading-none w-[5px] text-center">+</span>
                  <span className="text-sm">Nouveau sujet</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

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

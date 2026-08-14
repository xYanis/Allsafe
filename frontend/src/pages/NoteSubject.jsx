import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  noteSubject as fetchNoteSubject, updateNoteSubject, deleteNoteSubject,
  noteThemes as fetchNoteThemes, uploadNoteImage,
} from '../api/client.js'
import { MODULES } from '../constants/modules.js'
import PageLoader from '../components/PageLoader.jsx'
import MarkdownNote from '../components/MarkdownNote.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'

const MODULE_COLOR = MODULES.documentation.color

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
// Map par id (route /notes/:id) — un sujet différent ne doit jamais afficher un instant le
// contenu resté en cache d'un autre id.
let noteSubjectCache = {}

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('fr-FR') + ' ' + new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

// Éditeur d'un sujet (fiche de cours en Markdown) — cf. Notes.jsx pour la liste. Écrire/
// Aperçu en deux onglets (MarkdownNote.jsx, déjà utilisé pour les annotations d'analyste,
// assure le rendu sanitizé). Images glissées-déposées ou choisies via le sélecteur de
// fichier sont uploadées puis insérées comme `![alt](url)` à la position du curseur.
export default function NoteSubject() {
  const { id } = useParams()
  const navigate = useNavigate()
  const textareaRef = useRef(null)
  const fileInputRef = useRef(null)

  const [subject, setSubject] = useState(() => noteSubjectCache[id]?.subject ?? null)
  const [theme, setTheme] = useState(() => noteSubjectCache[id]?.theme ?? null)
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [mode, setMode] = useState('write') // write | preview
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const [error, setError] = useState('')
  const [deleteTarget, setDeleteTarget] = useState(false)

  useEffect(() => {
    Promise.all([fetchNoteSubject(id), fetchNoteThemes()]).then(([s, t]) => {
      const foundTheme = (t.data.items || []).find(th => th.id === s.data.theme_id) || null
      setSubject(s.data)
      setTitle(s.data.title)
      setContent(s.data.content_markdown || '')
      setTheme(foundTheme)
      noteSubjectCache[id] = { subject: s.data, theme: foundTheme }
      setError('')
    }).catch(() => setError('Impossible de charger ce sujet — le serveur a peut-être renvoyé une erreur, ou il a été supprimé.'))
  }, [id])

  function insertAtCursor(text) {
    const el = textareaRef.current
    if (!el) { setContent(c => c + text); setDirty(true); return }
    const start = el.selectionStart ?? content.length
    const end = el.selectionEnd ?? content.length
    const next = content.slice(0, start) + text + content.slice(end)
    setContent(next)
    setDirty(true)
    requestAnimationFrame(() => {
      el.focus()
      el.selectionStart = el.selectionEnd = start + text.length
    })
  }

  async function handleFiles(files) {
    const file = files?.[0]
    if (!file || uploading) return
    setUploading(true)
    setError('')
    try {
      const r = await uploadNoteImage(file, id)
      insertAtCursor(`\n![${file.name}](${r.data.url})\n`)
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'importer cette image.")
    } finally {
      setUploading(false)
    }
  }

  function handleDrop(e) {
    e.preventDefault()
    setDragOver(false)
    handleFiles(e.dataTransfer.files)
  }

  async function handleSave() {
    if (!title.trim() || saving) return
    setSaving(true)
    setError('')
    try {
      const r = await updateNoteSubject(id, { title: title.trim(), content_markdown: content })
      setSubject(r.data)
      setDirty(false)
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'enregistrer ce sujet.")
    } finally {
      setSaving(false)
    }
  }

  async function confirmDelete() {
    try {
      await deleteNoteSubject(id)
      navigate('/notes')
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la suppression.')
      setDeleteTarget(false)
    }
  }

  if (!subject && !error) return <PageLoader />

  return (
    <div className="p-6 space-y-4 max-w-4xl">
      <button onClick={() => navigate('/notes')}
        className="group text-xs inline-flex items-center gap-1 hover:underline" style={{ color: 'var(--text-muted)' }}>
        <span className="inline-block transition-transform duration-200 group-hover:-translate-x-0.5">←</span> Retour aux notes
      </button>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      {subject && (
        <>
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              {theme && (
                <span className="text-xs font-medium px-2 py-0.5 rounded" style={{ background: `${theme.color}1f`, color: theme.color }}>
                  {theme.icon} {theme.name}
                </span>
              )}
              <input value={title} onChange={e => { setTitle(e.target.value); setDirty(true) }}
                className="w-full text-2xl font-bold mt-1.5 outline-none bg-transparent"
                style={{ color: 'var(--text-primary)' }} placeholder="Titre du sujet" />
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-faint)' }}>Modifié le {fmtDate(subject.updated_at)}</p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <button onClick={() => setDeleteTarget(true)}
                className="text-xs px-3 py-2 rounded-lg font-medium"
                style={{ background: 'rgba(248,81,73,0.08)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
                Supprimer
              </button>
              <button onClick={handleSave} disabled={!title.trim() || saving || !dirty}
                className="text-sm px-4 py-2 rounded-lg font-medium disabled:opacity-50"
                style={{ background: MODULE_COLOR, color: MODULES.documentation.dark }}>
                {saving ? 'Enregistrement…' : dirty ? 'Enregistrer' : 'Enregistré'}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative inline-flex rounded-lg p-0.5" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
              <span aria-hidden="true" className="absolute top-0.5 bottom-0.5 rounded-md"
                style={{
                  width: 68, left: mode === 'write' ? 2 : 70,
                  background: `${MODULE_COLOR}26`, transition: 'left 200ms var(--ease-out)',
                }} />
              <button onClick={() => setMode('write')}
                className="relative text-xs font-medium text-center" style={{ width: 68, padding: '6px 0', color: mode === 'write' ? MODULE_COLOR : 'var(--text-muted)' }}>
                Écrire
              </button>
              <button onClick={() => setMode('preview')}
                className="relative text-xs font-medium text-center" style={{ width: 68, padding: '6px 0', color: mode === 'preview' ? MODULE_COLOR : 'var(--text-muted)' }}>
                Aperçu
              </button>
            </div>
            {mode === 'write' && (
              <button onClick={() => fileInputRef.current?.click()} disabled={uploading}
                className="text-xs px-3 py-1.5 rounded-lg font-medium disabled:opacity-50 inline-flex items-center gap-1.5"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909M3 4.5h18M3.75 4.5v15a.75.75 0 00.75.75h15a.75.75 0 00.75-.75V4.5" /></svg>
                {uploading ? 'Import…' : 'Image'}
              </button>
            )}
            <input ref={fileInputRef} type="file" accept="image/png,image/jpeg,image/gif,image/webp" className="hidden"
              onChange={e => { handleFiles(e.target.files); e.target.value = '' }} />
          </div>

          {mode === 'write' ? (
            <textarea key="write" ref={textareaRef} value={content}
              onChange={e => { setContent(e.target.value); setDirty(true) }}
              onDragOver={e => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              placeholder="Écrivez votre fiche de cours en Markdown — glissez-déposez une image directement ici."
              rows={20}
              className="route-fade w-full text-sm rounded-xl px-4 py-3 outline-none resize-y font-mono transition-colors duration-200"
              style={{ background: 'var(--bg-secondary)', border: `1px solid ${dragOver ? MODULE_COLOR : 'var(--border)'}`, color: 'var(--text-primary)' }} />
          ) : (
            <div key="preview" className="route-fade rounded-xl px-4 py-3" style={{ background: 'var(--bg-card)', border: `1px solid ${theme?.color || 'var(--border)'}40`, minHeight: 300 }}>
              {content.trim() ? <MarkdownNote text={content} /> : (
                <p className="text-sm" style={{ color: 'var(--text-faint)' }}>Rien à prévisualiser.</p>
              )}
            </div>
          )}
        </>
      )}

      {deleteTarget && (
        <ConfirmModal
          title="Supprimer ce sujet ?"
          message={<>Supprimer définitivement « <strong>{title}</strong> » ? Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDelete}
          onClose={() => setDeleteTarget(false)}
        />
      )}
    </div>
  )
}

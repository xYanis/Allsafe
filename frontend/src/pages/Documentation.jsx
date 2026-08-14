import { useEffect, useState } from 'react'
import {
  documentTypes as fetchDocumentTypes, createDocumentType, deleteDocumentType,
  documents as fetchDocuments, uploadDocument, deleteDocument,
} from '../api/client.js'
import { useAuth } from '../contexts/AuthContext.jsx'
import { MODULES } from '../constants/modules.js'
import PageLoader from '../components/PageLoader.jsx'
import PageHero from '../components/PageHero.jsx'
import DocumentTypeFormModal from '../components/DocumentTypeFormModal.jsx'
import UploadDocumentModal from '../components/UploadDocumentModal.jsx'
import DocumentPreviewModal from '../components/DocumentPreviewModal.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'

const MODULE_COLOR = MODULES.documentation.color

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
// Permet de réafficher instantanément les dernières données connues au remontage pendant
// qu'un rafraîchissement silencieux les met à jour en fond.
let documentationCache = null

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('fr-FR') + ' ' + new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}
function fmtSize(bytes) {
  if (!bytes) return ''
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} Mo` : `${Math.round(bytes / 1024)} Ko`
}

// Une carte par type de document (PSSI, Charte Administrateur...) : version la plus récente en
// évidence, historique des versions précédentes dépliable. `docs` déjà trié par uploaded_at desc
// côté API — docs[0] est la version courante. Glisser-déposer un fichier directement sur la
// carte (admin) ouvre la modale d'upload pré-remplie, sans passer par le sélecteur de fichier.
function DocumentTypeCard({ type, docs, isAdmin, onUpload, onDeleteDoc, onDeleteType, onPreview }) {
  const [expanded, setExpanded] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const current = docs[0]
  const history = docs.slice(1)

  function handleDragOver(e) {
    if (!isAdmin) return
    e.preventDefault()
    setDragOver(true)
  }
  function handleDragLeave() {
    setDragOver(false)
  }
  function handleDrop(e) {
    if (!isAdmin) return
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files?.[0]
    if (f) onUpload(type, f)
  }

  return (
    <div className="lift-card rounded-2xl p-5 transition-colors" onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}
      style={{ background: 'var(--bg-card)', border: `1px solid ${dragOver ? MODULE_COLOR : 'var(--border)'}` }}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <h2 className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>{type.name}</h2>
        <div className="flex gap-1.5 flex-shrink-0">
          {isAdmin && (
            <button onClick={() => onUpload(type)}
              className="text-xs px-2.5 py-1 rounded-lg font-medium"
              style={{ background: `${MODULE_COLOR}1f`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}4d` }}>
              + Téléverser
            </button>
          )}
          {isAdmin && docs.length === 0 && (
            <button onClick={() => onDeleteType(type)}
              className="text-xs px-2 py-1 rounded-lg font-medium"
              style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' }}>
              Supprimer le type
            </button>
          )}
        </div>
      </div>

      {dragOver ? (
        <p className="text-xs text-center py-4" style={{ color: MODULE_COLOR }}>Déposez le fichier ici…</p>
      ) : !current ? (
        <p className="text-xs" style={{ color: 'var(--text-faint)' }}>
          Aucun document{isAdmin ? ' — téléversez-en un, ou glissez-déposez-le sur cette carte.' : '.'}
        </p>
      ) : (
        <>
          <div className="rounded-xl px-3 py-2.5" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <button onClick={() => onPreview(current)}
                  className="text-sm font-medium hover:underline truncate block text-left" style={{ color: MODULE_COLOR }}>
                  📄 {current.filename}
                </button>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                  {current.uploaded_by} · {fmtDate(current.uploaded_at)} · {fmtSize(current.size_bytes)}
                </p>
                {current.notes && <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{current.notes}</p>}
              </div>
              {isAdmin && (
                <button onClick={() => onDeleteDoc(current)} className="flex-shrink-0" style={{ color: 'var(--text-faint)' }} title="Supprimer cette version">✕</button>
              )}
            </div>
          </div>

          {history.length > 0 && (
            <div className="mt-2">
              <button onClick={() => setExpanded(v => !v)} className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {expanded ? '▾' : '▸'} Historique ({history.length})
              </button>
              {expanded && (
                <div className="mt-1.5 space-y-1.5 pl-3" style={{ borderLeft: '2px solid var(--border)' }}>
                  {history.map(d => (
                    <div key={d.id} className="flex items-start justify-between gap-2 text-xs">
                      <div className="min-w-0">
                        <button onClick={() => onPreview(d)} className="hover:underline truncate block text-left" style={{ color: 'var(--text-secondary)' }}>
                          {d.filename}
                        </button>
                        <p style={{ color: 'var(--text-faint)' }}>{d.uploaded_by} · {fmtDate(d.uploaded_at)}</p>
                      </div>
                      {isAdmin && (
                        <button onClick={() => onDeleteDoc(d)} className="flex-shrink-0" style={{ color: 'var(--text-faint)' }} title="Supprimer">✕</button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// Documents de gouvernance nécessaires à la conformité NIS 2 (PSSI, chartes, organigramme...) —
// registre de types ouvert (+ ajoutable sans code), historique des versions conservé par type
// (pas de suppression automatique à l'upload, cf. backend/models.py::Document). Sous-page
// "Documentation Entreprise" du module Documentation (12/08/2026, renommée pour laisser sa
// place à "Notes" ci-à-côté, cf. Notes.jsx) — route `/documentation` inchangée.
export default function Documentation() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [types, setTypes] = useState(() => documentationCache?.types ?? null)
  const [docsByType, setDocsByType] = useState(() => documentationCache?.docsByType ?? {})
  const [showAddType, setShowAddType] = useState(false)
  const [uploadTarget, setUploadTarget] = useState(null) // null | { type, file? }
  const [previewTarget, setPreviewTarget] = useState(null) // null | document object
  const [deleteDocTarget, setDeleteDocTarget] = useState(null)
  const [deleteTypeTarget, setDeleteTypeTarget] = useState(null)
  const [error, setError] = useState('')

  function load() {
    Promise.all([fetchDocumentTypes(), fetchDocuments()]).then(([t, d]) => {
      const typesData = t.data.items || []
      const grouped = {}
      for (const doc of (d.data.items || [])) {
        (grouped[doc.document_type_id] ||= []).push(doc)
      }
      setTypes(typesData)
      setDocsByType(grouped)
      documentationCache = { types: typesData, docsByType: grouped }
      setError('')
    }).catch(() => {
      setTypes([]); setDocsByType({})
      setError('Impossible de charger la documentation — le serveur a peut-être renvoyé une erreur.')
    })
  }
  useEffect(() => { load() }, [])

  async function handleAddType(payload) {
    await createDocumentType(payload)
    setShowAddType(false)
    load()
  }

  async function handleUpload({ file, uploadedBy, notes }) {
    await uploadDocument(file, uploadTarget.type.id, uploadedBy, notes)
    setUploadTarget(null)
    load()
  }

  async function confirmDeleteDoc() {
    try {
      await deleteDocument(deleteDocTarget.id)
      setDeleteDocTarget(null)
      load()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la suppression.')
      setDeleteDocTarget(null)
    }
  }

  async function confirmDeleteType() {
    try {
      await deleteDocumentType(deleteTypeTarget.id)
      setDeleteTypeTarget(null)
      load()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la suppression.')
      setDeleteTypeTarget(null)
    }
  }

  if (types === null) return <PageLoader />

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"
        title="Documentation Entreprise" color={MODULE_COLOR}
        subtitle="Documents de gouvernance nécessaires à la conformité NIS 2 — PSSI, chartes, organigramme..."
      >
        {isAdmin && (
          <button onClick={() => setShowAddType(true)}
            className="px-4 py-2 text-sm font-medium rounded-lg"
            style={{ background: MODULE_COLOR, color: MODULES.documentation.dark }}>
            + Ajouter un type de document
          </button>
        )}
      </PageHero>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      {types.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
          Aucun type de document {isAdmin ? '— ajoutez-en un ci-dessus.' : '.'}
        </p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {types.map(t => (
            <DocumentTypeCard key={t.id} type={t} docs={docsByType[t.id] || []} isAdmin={isAdmin}
              onUpload={(type, file) => setUploadTarget({ type, file })}
              onDeleteDoc={setDeleteDocTarget} onDeleteType={setDeleteTypeTarget} onPreview={setPreviewTarget} />
          ))}
        </div>
      )}

      {showAddType && (
        <DocumentTypeFormModal onConfirm={handleAddType} onClose={() => setShowAddType(false)} />
      )}
      {uploadTarget && (
        <UploadDocumentModal documentTypeName={uploadTarget.type.name} initialFile={uploadTarget.file}
          onConfirm={handleUpload} onClose={() => setUploadTarget(null)} />
      )}
      {previewTarget && (
        <DocumentPreviewModal document={previewTarget} onClose={() => setPreviewTarget(null)} />
      )}
      {deleteDocTarget && (
        <ConfirmModal
          title="Supprimer ce document ?"
          message={<>Supprimer définitivement « <strong>{deleteDocTarget.filename}</strong> » ? Cette version disparaîtra de l'historique. Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDeleteDoc}
          onClose={() => setDeleteDocTarget(null)}
        />
      )}
      {deleteTypeTarget && (
        <ConfirmModal
          title="Supprimer ce type de document ?"
          message={<>Supprimer définitivement « <strong>{deleteTypeTarget.name}</strong> » du registre ? Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDeleteType}
          onClose={() => setDeleteTypeTarget(null)}
        />
      )}
    </div>
  )
}

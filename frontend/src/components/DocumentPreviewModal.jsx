import { documentDownloadUrl } from '../api/client.js'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.documentation.color

// PDF et images : le navigateur les affiche nativement (Content-Disposition: inline côté
// backend, cf. services/document_storage.py::PREVIEWABLE) — vraie prévisualisation possible.
// Word/Excel : aucune API web ne peut ouvrir l'application native depuis une page (ça
// demanderait une intégration WOPI/Office Online, hors de portée ici) — le fichier ne peut être
// que téléchargé, puis ouvert par l'OS via l'application associée (Word/Excel).
const PREVIEWABLE_EXT = new Set(['.pdf', '.png', '.jpg', '.jpeg'])

function extOf(filename) {
  const i = filename.lastIndexOf('.')
  return i === -1 ? '' : filename.slice(i).toLowerCase()
}

// Contenu réel bloqué en mode Présentation (21/08/2026, retour utilisateur — cette modale
// prévisualisait/téléchargeait le vrai PSSI/Charte/etc. en clair, aucune anonymisation possible
// sur un PDF/image arbitraire contrairement à du texte structuré) : le nom de fichier/l'auteur
// affichés viennent déjà d'un `document` masqué par la page appelante (Documentation.jsx), mais
// l'aperçu et le téléchargement pointent vers le VRAI fichier quel que soit ce texte — bloqués
// ici explicitement plutôt que de risquer un contenu réel sous un nom de fichier fictif.
export default function DocumentPreviewModal({ document, onClose, isAnonymous }) {
  const ext = extOf(document.filename)
  const isImage = ext === '.png' || ext === '.jpg' || ext === '.jpeg'
  const isPdf = ext === '.pdf'
  const previewable = PREVIEWABLE_EXT.has(ext) && !isAnonymous
  const url = documentDownloadUrl(document.id)

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="w-full max-w-3xl h-[85vh] rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="min-w-0">
            <h2 className="font-semibold text-sm truncate" style={{ color: 'var(--text-primary)' }}>{document.filename}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{document.uploaded_by}</p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            {!isAnonymous && (
              <a href={url} target="_blank" rel="noopener noreferrer" download={!previewable ? document.filename : undefined}
                className="text-xs px-3 py-1.5 rounded-lg font-medium"
                style={{ background: `${MODULE_COLOR}1f`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}4d` }}>
                Télécharger
              </a>
            )}
            <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
        </div>

        <div className="flex-1 min-h-0 p-4 flex items-center justify-center overflow-auto" style={{ background: 'var(--bg-secondary)' }}>
          {isAnonymous ? (
            <div className="text-center px-6">
              <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-primary)' }}>🔒 Contenu masqué en mode Présentation</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Le contenu réel de ce document (texte libre, impossible à anonymiser de façon
                fiable) n'est ni prévisualisé ni téléchargeable tant que le mode Présentation est actif.
              </p>
            </div>
          ) : isPdf && (
            <iframe src={url} title={document.filename} className="w-full h-full rounded-lg" style={{ border: '1px solid var(--border)', background: '#fff' }} />
          )}
          {!isAnonymous && isImage && (
            <img src={url} alt={document.filename} className="max-w-full max-h-full rounded-lg object-contain" />
          )}
          {!isAnonymous && !previewable && (
            <div className="text-center px-6">
              <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-primary)' }}>Aperçu non disponible pour ce format</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Aucun navigateur ne peut ouvrir un fichier Word/Excel directement — téléchargez-le,
                votre système l'ouvrira avec l'application associée.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

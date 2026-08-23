import { Link } from 'react-router-dom'
import { MODULES } from '../constants/modules.js'
import { hexToRgba } from '../utils/color.js'

const MODULE_COLOR = MODULES.incidents.color

// Lien minimal vers le module Incidents, préchargé avec la source d'origine.
// Couplage nul avec le module appelant : aucun état ni logique Incidents n'est
// importé ici — juste une navigation. Incidents.jsx appelle GET /incidents/prefill
// et ouvre la modale de création préremplie ; rien n'est créé tant que
// l'analyste ne valide pas explicitement (cf. docs/INCIDENTS.md).
//
// `iconOnly` (23/08/2026, retour utilisateur — chevauchait "Traiter" dans les cartes de
// Watch.jsx, peu de largeur dispo) : pictogramme seul + `title` pour le tooltip, plutôt
// que de retravailler le texte au cas par cas. Défaut inchangé (texte complet) partout
// ailleurs — aucun appelant existant à toucher.
export default function DeclareIncidentButton({ sourceType, sourceId, label = 'Déclarer un incident', small = true, iconOnly = false }) {
  return (
    <Link
      to={`/incidents?from=${sourceType}&id=${sourceId}`}
      onClick={e => e.stopPropagation()}
      title={iconOnly ? label : undefined}
      className={
        iconOnly
          ? 'inline-flex items-center justify-center rounded-lg flex-shrink-0 w-7 h-7'
          : `inline-flex items-center gap-1 rounded-lg font-medium whitespace-nowrap ${small ? 'text-xs px-2 py-1' : 'text-sm px-3 py-1.5'}`
      }
      style={{ background: hexToRgba(MODULE_COLOR, 0.1), color: MODULE_COLOR, border: `1px solid ${hexToRgba(MODULE_COLOR, 0.3)}` }}
    >
      {iconOnly ? (
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
        </svg>
      ) : label}
    </Link>
  )
}

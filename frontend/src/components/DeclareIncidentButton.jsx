import { Link } from 'react-router-dom'
import { MODULES } from '../constants/modules.js'
import { hexToRgba } from '../utils/color.js'

const MODULE_COLOR = MODULES.incidents.color

// Lien minimal vers le module Incidents, préchargé avec la source d'origine.
// Couplage nul avec le module appelant : aucun état ni logique Incidents n'est
// importé ici — juste une navigation. Incidents.jsx appelle GET /incidents/prefill
// et ouvre la modale de création préremplie ; rien n'est créé tant que
// l'analyste ne valide pas explicitement (cf. docs/INCIDENTS.md).
export default function DeclareIncidentButton({ sourceType, sourceId, label = 'Déclarer un incident', small = true }) {
  return (
    <Link
      to={`/incidents?from=${sourceType}&id=${sourceId}`}
      onClick={e => e.stopPropagation()}
      className={`inline-flex items-center gap-1 rounded-lg font-medium whitespace-nowrap ${small ? 'text-xs px-2 py-1' : 'text-sm px-3 py-1.5'}`}
      style={{ background: hexToRgba(MODULE_COLOR, 0.1), color: MODULE_COLOR, border: `1px solid ${hexToRgba(MODULE_COLOR, 0.3)}` }}
    >
      {label}
    </Link>
  )
}

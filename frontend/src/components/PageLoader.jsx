import { useLocation } from 'react-router-dom'
import { moduleColorForPath } from '../constants/modules.js'

const SIZES = {
  lg: { ring: 40, border: 3, gap: 'gap-3' },
  sm: { ring: 18, border: 2, gap: 'gap-2' },
}

// Loader unifié pour tout état de chargement de page (remplace le spinner
// Heroicons générique jusqu'ici copié-collé page par page) : la couleur suit
// automatiquement le module actif (déduite de la route, cf. constants/modules.js)
// au lieu d'un gris/bleu neutre sans rapport avec la page affichée.
// `size="lg"` (défaut) : bloc plein centré. `size="sm"` : inline, pour une
// ligne de tableau ou un panneau compact.
export default function PageLoader({ label = 'Chargement…', color, size = 'lg', className = '' }) {
  const location = useLocation()
  const c = color || moduleColorForPath(location.pathname)
  const s = SIZES[size] || SIZES.lg

  const spinner = (
    <span className="relative inline-block flex-shrink-0" style={{ width: s.ring, height: s.ring, '--loader': c }}>
      {size === 'lg' && <span className="page-loader-glow" />}
      <span className="page-loader-ring" style={{ borderWidth: s.border }} />
      <span className="page-loader-arc" style={{ borderWidth: s.border }} />
    </span>
  )

  if (size === 'sm') {
    return (
      <span className={`inline-flex items-center ${s.gap} ${className}`}>
        {spinner}
        {label && <span className="text-sm font-medium" style={{ color: c }}>{label}</span>}
      </span>
    )
  }

  return (
    <div className={`flex flex-col items-center justify-center ${s.gap} min-h-[40vh] ${className}`}>
      {spinner}
      {label && <p className="text-sm font-medium" style={{ color: c }}>{label}</p>}
    </div>
  )
}

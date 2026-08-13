// Icônes de Service (Administration > Services) — palette fixe curatée, même esprit que
// SERVICE_COLOR_PALETTE (constants/serviceColors.js) : l'utilisateur choisit dans une liste
// prédéfinie plutôt qu'un champ libre, pour rester cohérent avec le style SVG épuré (feather-like,
// stroke currentColor) déjà utilisé partout ailleurs dans l'app (ex : bouton fermer des modales).
export const SERVICE_ICON_KEYS = [
  'briefcase', 'users', 'building', 'scale', 'server',
  'shield', 'euro', 'headset', 'globe', 'wrench',
]

const GLYPHS = {
  briefcase: (
    <>
      <rect x="3" y="8" width="18" height="12" rx="2" />
      <rect x="8" y="4" width="8" height="4" rx="1" />
      <line x1="3" y1="13" x2="21" y2="13" />
    </>
  ),
  users: (
    <>
      <circle cx="8" cy="8" r="3" />
      <rect x="3" y="14" width="10" height="7" rx="3" />
      <circle cx="17" cy="7" r="2.3" />
      <rect x="13" y="13" width="8" height="6" rx="2.5" />
    </>
  ),
  building: (
    <>
      <rect x="5" y="3" width="14" height="18" rx="1" />
      <rect x="8" y="6" width="2.5" height="2.5" />
      <rect x="13.5" y="6" width="2.5" height="2.5" />
      <rect x="8" y="11" width="2.5" height="2.5" />
      <rect x="13.5" y="11" width="2.5" height="2.5" />
      <rect x="10" y="16" width="4" height="5" />
    </>
  ),
  scale: (
    <>
      <line x1="12" y1="3" x2="12" y2="21" />
      <line x1="5" y1="7" x2="19" y2="7" />
      <line x1="5" y1="7" x2="4" y2="12" />
      <line x1="5" y1="7" x2="6" y2="12" />
      <line x1="19" y1="7" x2="18" y2="12" />
      <line x1="19" y1="7" x2="20" y2="12" />
      <line x1="8" y1="21" x2="16" y2="21" />
    </>
  ),
  server: (
    <>
      <rect x="4" y="4" width="16" height="7" rx="1.5" />
      <rect x="4" y="13" width="16" height="7" rx="1.5" />
      <circle cx="8" cy="7.5" r="1" />
      <circle cx="8" cy="16.5" r="1" />
    </>
  ),
  shield: (
    <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />
  ),
  euro: (
    <>
      <path d="M16 6c-1-1-2.5-1.5-4-1.5-3.5 0-6.5 2.8-6.5 7.5s3 7.5 6.5 7.5c1.5 0 3-.5 4-1.5" />
      <line x1="4" y1="10" x2="12" y2="10" />
      <line x1="4" y1="14" x2="12" y2="14" />
    </>
  ),
  headset: (
    <>
      <path d="M4 13a8 8 0 0 1 16 0" />
      <rect x="3" y="13" width="4" height="6" rx="1.5" />
      <rect x="17" y="13" width="4" height="6" rx="1.5" />
      <path d="M19 19v1a3 3 0 0 1-3 3h-3" />
    </>
  ),
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <ellipse cx="12" cy="12" rx="4" ry="9" />
      <line x1="3" y1="12" x2="21" y2="12" />
    </>
  ),
  wrench: (
    <path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.1 2.1-2-2 2.1-2.1z" />
  ),
}

// icon: une des clés de SERVICE_ICON_KEYS. Repli sur 'briefcase' si absente/inconnue (service
// créé avant l'ajout des icônes, ou clé invalide).
export default function ServiceIcon({ icon, size = 16, style, className }) {
  const glyph = GLYPHS[icon] || GLYPHS.briefcase
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"
      className={className} style={style}>
      {glyph}
    </svg>
  )
}

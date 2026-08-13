// Icônes de la colonne Catégorie (Actifs, 13/08/2026 — remplace le badge texte, gardé au
// survol via `title`) — même style feather-like (stroke currentColor) que ServiceIcon.jsx,
// une clé par valeur possible de assetCategory()/CATEGORY_STYLES (utils/assetCategory.js).
const GLYPHS = {
  'Serveur': (
    <>
      <rect x="4" y="4" width="16" height="7" rx="1.5" />
      <rect x="4" y="13" width="16" height="7" rx="1.5" />
      <circle cx="8" cy="7.5" r="1" />
      <circle cx="8" cy="16.5" r="1" />
    </>
  ),
  'Poste': (
    <>
      <rect x="3" y="4" width="18" height="12" rx="1.5" />
      <line x1="8" y1="20" x2="16" y2="20" />
      <line x1="12" y1="16" x2="12" y2="20" />
    </>
  ),
  'Borne Wi-Fi': (
    <>
      <path d="M4 11a11.3 11.3 0 0 1 16 0" />
      <path d="M7 14.5a7 7 0 0 1 10 0" />
      <circle cx="12" cy="18" r="1.2" fill="currentColor" stroke="none" />
    </>
  ),
  'Pare-feu / Routeur': (
    <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />
  ),
  'Switch': (
    <>
      <rect x="4" y="9" width="16" height="6" rx="1" />
      <line x1="7" y1="9" x2="7" y2="6" />
      <line x1="12" y1="9" x2="12" y2="6" />
      <line x1="17" y1="9" x2="17" y2="6" />
      <circle cx="7" cy="12" r="0.6" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="0.6" fill="currentColor" stroke="none" />
      <circle cx="17" cy="12" r="0.6" fill="currentColor" stroke="none" />
    </>
  ),
  'Passerelle cellulaire': (
    <>
      <line x1="5" y1="18" x2="5" y2="14" />
      <line x1="10" y1="18" x2="10" y2="10" />
      <line x1="15" y1="18" x2="15" y2="6" />
      <line x1="20" y1="18" x2="20" y2="3" />
    </>
  ),
  'Capteur': (
    <>
      <rect x="7" y="7" width="10" height="10" rx="1" />
      <line x1="9" y1="3" x2="9" y2="7" />
      <line x1="15" y1="3" x2="15" y2="7" />
      <line x1="9" y1="17" x2="9" y2="21" />
      <line x1="15" y1="17" x2="15" y2="21" />
      <line x1="3" y1="9" x2="7" y2="9" />
      <line x1="3" y1="15" x2="7" y2="15" />
      <line x1="17" y1="9" x2="21" y2="9" />
      <line x1="17" y1="15" x2="21" y2="15" />
    </>
  ),
  'Caméra': (
    <>
      <rect x="3" y="7" width="14" height="11" rx="2" />
      <circle cx="10" cy="12.5" r="3" />
      <path d="M17 10l4-2v9l-4-2z" />
    </>
  ),
  'Passerelle télétravail': (
    <>
      <path d="M4 11L12 4l8 7" />
      <path d="M6 10v10h12V10" />
      <line x1="10" y1="20" x2="10" y2="15" />
      <line x1="14" y1="20" x2="14" y2="15" />
    </>
  ),
  // Générique PRTG sans modèle exploitable (cf. assetCategory()) — boîtier + antennes,
  // plus parlant qu'un globe pour "équipement réseau" alors que ce cas concentre la
  // majorité du parc PRTG (339 actifs constatés, cf. STATUS.md 04/08/2026).
  'Équipement réseau': (
    <>
      <rect x="3" y="9" width="18" height="8" rx="1.5" />
      <line x1="8" y1="9" x2="8" y2="5" />
      <line x1="16" y1="9" x2="16" y2="5" />
      <circle cx="8" cy="4" r="1" />
      <circle cx="16" cy="4" r="1" />
      <circle cx="7" cy="13" r="0.6" fill="currentColor" stroke="none" />
      <circle cx="10" cy="13" r="0.6" fill="currentColor" stroke="none" />
      <circle cx="13" cy="13" r="0.6" fill="currentColor" stroke="none" />
    </>
  ),
  // PRTG + vendor_hint="Synology" (cf. VENDOR_CATEGORY_LABELS, assetCategory.js) —
  // baies de disques dans un boîtier, distinct du rack serveur (barres horizontales).
  'NAS': (
    <>
      <rect x="4" y="4" width="16" height="16" rx="1.5" />
      <rect x="7.5" y="7" width="3" height="10" rx="0.5" />
      <rect x="13.5" y="7" width="3" height="10" rx="0.5" />
    </>
  ),
}
const DEFAULT_GLYPH = (
  <>
    <circle cx="12" cy="12" r="9" />
    <ellipse cx="12" cy="12" rx="4" ry="9" />
    <line x1="3" y1="12" x2="21" y2="12" />
  </>
)

// category: une des clés ci-dessus (assetCategory()). Repli générique (globe) pour les
// valeurs non couvertes ("Équipement réseau" générique PRTG, "Autre"...).
export default function CategoryIcon({ category, size = 16, style, className }) {
  const glyph = GLYPHS[category] || DEFAULT_GLYPH
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"
      className={className} style={style}>
      {glyph}
    </svg>
  )
}

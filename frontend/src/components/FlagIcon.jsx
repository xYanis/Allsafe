import * as Flags from 'country-flag-icons/react/3x2'
import { COUNTRY_LABELS } from '../utils/countries.js'

// Drapeaux en SVG (country-flag-icons), pas en emoji unicode — les séquences
// d'indicateurs régionaux (🇫🇷 = "F"+"R") ne sont pas rendues comme un vrai
// drapeau par tous les systèmes/navigateurs : Windows (hors Windows 11 avec
// police emoji à jour) et certaines versions de Chrome les affichent comme du
// texte brut "FR"/"DE" au lieu d'une image, aucune fiabilité cross-plateforme.
export default function FlagIcon({ code, size = 20 }) {
  const Flag = code && Flags[code.toUpperCase()]
  const label = (code && COUNTRY_LABELS[code.toUpperCase()]) || code || 'Pays inconnu'
  if (!Flag) {
    return <span title={label} style={{ fontSize: size * 0.85, lineHeight: 1 }}>🌐</span>
  }
  return (
    <Flag
      title={label}
      style={{ width: size, height: Math.round(size * 2 / 3), borderRadius: 3, flexShrink: 0, boxShadow: '0 0 0 1px var(--border)' }}
    />
  )
}

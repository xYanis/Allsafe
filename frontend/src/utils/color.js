// hex -> rgba(...) pour les styles inline avec transparence (badges, chips,
// fonds actifs) — utilisé partout où l'app dérive une teinte à opacité
// réduite à partir d'une couleur d'accent fixe.
export function hexToRgba(hex, alpha) {
  const n = parseInt(hex.slice(1), 16)
  const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255
  return `rgba(${r},${g},${b},${alpha})`
}

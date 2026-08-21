import { useTheme } from '../contexts/ThemeContext.jsx'

// Bascule 3D à la souris pour les tuiles en grille (21/08/2026, demande explicite — extrait ici
// au 2e usage, Dashboard.jsx après Home.jsx, cf. principe scalable CLAUDE.md). Volontairement
// PAS branché sur tintedCard/cardStyle.js (relief statique cyberpunk uniquement, posé là pour
// les mêmes raisons de spécificité CSS/inline, cf. commentaire dédié dans ce fichier) : cet
// effet suit la souris et n'a de sens que sur une grille de tuiles compactes et cliquables
// (Home, KPIs Dashboard...), pas sur un tableau pleine largeur ou une section unique — à poser
// à la main, page par page.
// Atténué en deux temps (21/08/2026, retour utilisateur — 10° → 4° jugé "léger" en théorie
// puis encore "trop" une fois testé en vrai → 1.5°) : la bascule reste perceptible du coin de
// l'œil sans donner le mal de mer. Plus de scale au survol (1.02 → 1.01 → aucun) : le
// grossissement ajoutait du mouvement en plus de la rotation, seule cette dernière reste.
export const TILT_MAX_DEG = 1.5

// En style inline, pas via React state — un setState par mousemove redessinerait tout le
// composant à chaque frame pour rien, alors que muter le DOM directement (l'élément doit porter
// `will-change: transform`, cf. .tile-3d dans index.css) coûte beaucoup moins cher pour un effet
// purement visuel qui n'a besoin d'être lu par personne.
export function tiltMouseMove(e) {
  const el = e.currentTarget
  const rect = el.getBoundingClientRect()
  const px = (e.clientX - rect.left) / rect.width
  const py = (e.clientY - rect.top) / rect.height
  const rotateY = (px - 0.5) * TILT_MAX_DEG * 2
  const rotateX = (0.5 - py) * TILT_MAX_DEG * 2
  el.style.transform = `perspective(900px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`
  el.style.setProperty('--mx', `${px * 100}%`)
  el.style.setProperty('--my', `${py * 100}%`)
}

// Coupe la transition CSS sur `transform` pendant le suivi (sinon la tuile "traîne" derrière le
// curseur, effet élastique) — les autres propriétés (bordure/fond/ombre) restent animées.
export function tiltMouseEnter(e) {
  e.currentTarget.style.transition = 'border-color 240ms var(--ease-out), background 240ms var(--ease-out), box-shadow 240ms var(--ease-out)'
}

// Réactive la transition au départ de la souris, pour que le retour à plat soit lui-même animé.
export function tiltMouseLeave(e) {
  e.currentTarget.style.transition = ''
  e.currentTarget.style.transform = ''
}

// Réservé à cyberpunk (21/08/2026 : essayé un temps étendu à dark/light/neutre, revenu en
// arrière au retour utilisateur — "beaucoup trop", gardé seulement là où le reste du thème est
// déjà en mode "panneau HUD en volume"). Respecte prefers-reduced-motion + hover-only (pas de
// sens au doigt, pas de tilt tactile).
export function useTiltEnabled() {
  const { theme } = useTheme()
  if (typeof window === 'undefined') return false
  return theme === 'cyberpunk'
    && !window.matchMedia('(prefers-reduced-motion: reduce)').matches
    && window.matchMedia('(hover: hover) and (pointer: fine)').matches
}

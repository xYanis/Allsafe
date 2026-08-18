// Fond/bordure teintés à la couleur du module (18/08/2026, validé d'abord sur
// AgentHistory.jsx puis étendu à toutes les pages sur demande explicite) — même dégradé
// diagonal que .home-tile (Home.jsx/index.css) : `--tile` → bg-card, bordure `color-mix`.
// Couvre les cartes de CONTENU de page (sections sous le PageHero), jamais les tuiles module
// de Home.jsx elles-mêmes (fond, spot au survol, cascade d'entrée — laissées inchangées) ni
// les modales/dropdowns transitoires, qui gardent le style neutre `var(--bg-card)` existant.
export function tintedCard(color) {
  return {
    background: `linear-gradient(160deg, color-mix(in srgb, ${color} 14%, var(--bg-card)), var(--bg-card) 70%)`,
    border: `1px solid color-mix(in srgb, ${color} 28%, var(--border))`,
    borderRadius: '12px',
  }
}

// Exception CyberVuln (18/08/2026, retour utilisateur) : le rouge du module
// (MODULES.cybervuln.color, #f85149) reste utilisé partout ailleurs (nav, tuile Home,
// badges CRITICAL/danger) mais PAS ici — Dashboard/CVEs/Vulnérabilités sont justement les
// pages les plus chargées en vrai rouge d'alerte, un fond teinté de la même couleur
// diluait ce signal au lieu de juste rappeler le module. Bleu ardoise choisi plutôt qu'une
// autre teinte de rouge : rupture nette avec le rouge d'alerte, tout en restant distinct du
// bleu CyberVeille (#58a6ff, plus vif/saturé) pour ne pas créer une nouvelle confusion.
export const CYBERVULN_CARD_TINT = '#6e7fa3'

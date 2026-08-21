// Fond/bordure teintés à la couleur du module (18/08/2026, validé d'abord sur
// AgentHistory.jsx puis étendu à toutes les pages sur demande explicite) — même dégradé
// diagonal que .home-tile (Home.jsx/index.css) : `--tile` → bg-card, bordure `color-mix`.
// Couvre les cartes de CONTENU de page (sections sous le PageHero), jamais les tuiles module
// de Home.jsx elles-mêmes (fond, spot au survol, cascade d'entrée — laissées inchangées) ni
// les modales/dropdowns transitoires, qui gardent le style neutre `var(--bg-card)` existant.
// Structure réactive au thème (21/08/2026, demande explicite — "zero limite tu peux changer")
// : lu depuis `data-theme` À CHAQUE appel (fonction simple, pas figée à l'import comme
// MODULES.x.color) — contrairement aux couleurs de module, ceci change donc bien en direct,
// y compris pour Neutre/Cyberpunk, sans recharger la page. Neutre : plat, sec, sans ombre
// (présentation pro, zéro décoration). Cyberpunk : néon renforcé + glow + verre dépoli
// (panneau HUD). dark/light inchangés (dernier `return`, comportement d'origine).
export function tintedCard(color) {
  const theme = typeof document !== 'undefined' ? document.documentElement.getAttribute('data-theme') : null

  if (theme === 'neutral') {
    return {
      background: 'var(--bg-card)',
      border: `1px solid color-mix(in srgb, ${color} 10%, var(--border))`,
      borderRadius: '2px',
      boxShadow: 'none',
    }
  }

  if (theme === 'cyberpunk') {
    return {
      background: `linear-gradient(160deg, color-mix(in srgb, ${color} 20%, var(--bg-card)), var(--bg-card) 65%)`,
      border: `1px solid color-mix(in srgb, ${color} 45%, var(--border))`,
      borderRadius: 0,
      // Coins coupés façon panneau HUD (21/08/2026, demande explicite — "vrai" changement de
      // silhouette, pas juste une couleur) : octogone à coupe fixe, marche sur n'importe quelle
      // taille de carte. Le glow déborde volontairement au-delà du clip (2 box-shadow : un
      // liseré collé au tracé, un halo large derrière), + biseau interne ("tuiles en 3D", même
      // idiome que le carré d'icône de PageHero.jsx) donnant une épaisseur de panneau. Adouci
      // une 2e fois (21/08/2026, retour utilisateur — "trop flashy") : mélanges/glow réduits
      // d'un bon tiers par rapport à la 1re passe. En ligne (pas via `.tile-3d`, index.css) :
      // un style inline posé par un composant (ex. KpiCard, Dashboard.jsx) prime toujours sur
      // une classe CSS, écraserait sinon silencieusement le biseau porté par `.tile-3d` pour
      // tout composant utilisant `style={tintedCard(...)}` — inutile pour `.home-tile`
      // (Home.jsx), qui n'a pas de boxShadow inline et reste donc géré par `.tile-3d` seul.
      boxShadow: `0 0 0 1px color-mix(in srgb, ${color} 25%, transparent), 0 0 26px -8px color-mix(in srgb, ${color} 45%, transparent), inset 0 1px 0 rgba(255, 255, 255, 0.08), inset 0 -16px 20px -14px rgba(0, 0, 0, 0.5)`,
      backdropFilter: 'blur(6px) saturate(130%)',
    }
  }

  // dark/light — inchangé, pas de biseau (21/08/2026 : essayé un temps étendu depuis cyberpunk,
  // revenu en arrière au retour utilisateur — "beaucoup trop", réservé à cyberpunk seul).
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

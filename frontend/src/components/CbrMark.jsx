// Identité visuelle CBR — point de vérité unique pour le glyphe et sa tuile
// en dégradé. Avant cette extraction (refonte charte graphique), le même SVG
// plat était recopié à l'identique dans Layout.jsx (sidebar + barre mobile),
// Home.jsx, Login.jsx et favicon.svg — toute correction de tracé demandait
// autant d'éditions synchronisées, à l'encontre du principe scalable
// (CLAUDE.md).
//
// 5e itération (11/08/2026) : les 2 tentatives précédentes (bouclier+prompt
// terminal, puis bouclier+cadenas+empreinte+réseau) jugées illisibles par
// l'utilisateur malgré vérification par rendu SVG→PNG local ("ça ne
// ressemble à rien") — cette fois-ci, tracé fourni tel quel par l'utilisateur
// (silhouette capuche/masque façon "hacker anonyme", source svgrepo.com —
// conservé dans le repo à `docs/assets/logo-source.svg`), recoloré en jaune
// (`fill="#000000"` → `currentColor`) plutôt
// que redessiné. Silhouette pleine + zone du visage en négatif (le même tracé
// compound crée le trou, sens de parcours déjà correct dans le fichier
// source) — la tuile noire se voit à travers, sourcils/yeux redessinés par
// dessus en jaune. Bien plus lisible à petite taille que les tentatives
// précédentes : une seule grande silhouette pleine, pas de traits fins
// nichés. Vérifié à 24/32/36/56px avant intégration (même méthode de rendu
// local que les itérations précédentes).
export function CbrMark({ className = 'w-6 h-6', style }) {
  return (
    <svg className={className} style={style} fill="currentColor" viewBox="0 0 512 512">
      <path d="M475.3571,413.24a69.9,69.9,0,0,0-39.8845-57.4407l-39.9287-18.7987,21.5791-44.5621a89.4527,89.4527,0,0,0,.0025-77.9684L359.7988,96.0682C317.7933,9.3105,194.2088,9.31,152.2019,96.0666L94.87,214.4745a89.445,89.445,0,0,0,.0049,77.9692l21.581,44.5569L76.5256,355.8a69.898,69.898,0,0,0-39.8831,57.439l-3.612,43.3773a22.5157,22.5157,0,0,0,22.4381,24.3842H456.5337A22.5134,22.5134,0,0,0,478.97,456.6187ZM364,260.1205a107.9746,107.9746,0,0,1-98.1035,107.5V341.1249a9.8965,9.8965,0,0,0-19.793,0v26.4957A107.9746,107.9746,0,0,1,148,260.1205V203.44a28.8192,28.8192,0,0,1,28.8193-28.8193H335.1806A28.8193,28.8193,0,0,1,364,203.44Z" />
      <path d="M321.8213,275.9979a9.91,9.91,0,0,0-12.3135,6.6709,13.5776,13.5776,0,0,1-26.0156,0,9.9026,9.9026,0,1,0-18.9844,5.6426,33.3877,33.3877,0,0,0,63.9844,0A9.9125,9.9125,0,0,0,321.8213,275.9979Z" />
      <path d="M240.8213,275.9979a9.8908,9.8908,0,0,0-12.3135,6.6709,13.5776,13.5776,0,0,1-26.0156,0,9.9026,9.9026,0,1,0-18.9844,5.6426,33.3877,33.3877,0,0,0,63.9844,0A9.9125,9.9125,0,0,0,240.8213,275.9979Z" />
      <path d="M319,227.4384H283a9.8965,9.8965,0,1,0,0,19.7929h36a9.8965,9.8965,0,1,0,0-19.7929Z" />
      <path d="M193,247.2313h36a9.8965,9.8965,0,1,0,0-19.7929H193a9.8965,9.8965,0,1,0,0,19.7929Z" />
    </svg>
  )
}

// Tuile carrée en dégradé (var(--brand-grad)) + reflet diagonal, qui porte le
// glyphe (var(--brand-icon)) — noir/jaune en sombre, claire/or foncé en clair
// (12/08/2026, cf. commentaire index.css § tokens : la tuile suit désormais le
// thème plutôt que de rester toujours noire). `size`/`rounded` en px pour
// rester pixel-parfait aux tailles utilisées (32/40/56) sans dépendre des
// classes w-*/h-*/rounded-* Tailwind, qui n'ont pas de valeur à chaque palier
// voulu.
export function CbrLogoTile({ size = 40, rounded = 12, className = '', style, glow = true }) {
  return (
    <div
      className={`relative flex items-center justify-center flex-shrink-0 overflow-hidden ${className}`}
      style={{
        width: size, height: size, borderRadius: rounded,
        background: 'var(--brand-grad)',
        boxShadow: glow ? `0 ${Math.round(size * 0.32)}px ${Math.round(size * 0.75)}px -${Math.round(size * 0.24)}px var(--brand-glow)` : undefined,
        ...style,
      }}
    >
      {/* Reflet diagonal — la principale demande derrière ce lot était de
          s'éloigner de l'aplat "carré plein" jugé trop plat/générique. */}
      <span aria-hidden="true" style={{
        position: 'absolute', inset: 0, pointerEvents: 'none',
        background: 'linear-gradient(160deg, rgba(255,255,255,0.14), transparent 55%)',
      }} />
      <CbrMark className="relative" style={{ width: size * 0.74, height: size * 0.74, color: 'var(--brand-icon)' }} />
    </div>
  )
}

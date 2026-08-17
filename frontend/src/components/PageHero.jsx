// En-tête "hero" compact pour les pages de travail répétitif (Veille, Fuite de
// données — demande explicite de l'utilisateur : rendre visuellement attirantes
// des pages dont le contenu lui-même n'a rien de réjouissant). Extrait dès le 2e
// usage (cf. principe scalable, CLAUDE.md) plutôt que dupliqué une 3e fois.
//
// Statique — pas d'animation d'entrée : contrairement à Login/WelcomeOverlay
// (écrans rares, cf. skill emil-design-eng § fréquence), ces pages sont vues
// plusieurs fois par jour. Seule la trame de points (.hero-grid, index.css) est
// reprise ici, et elle est déjà statique sur Home.jsx malgré ses visites répétées
// — une texture immobile ne consomme pas le même "budget delight" qu'un mouvement.
import { useTheme } from '../contexts/ThemeContext.jsx'

const CARD_SHAPE = { border: '1px solid var(--border)', borderRadius: '16px' }

export default function PageHero({ icon, title, subtitle, color, children }) {
  const { isDark } = useTheme()
  // Titre en dégradé de la couleur du module (même esprit que --brand-text-grad
  // sur Login/Home) plutôt qu'une teinte diluée dans le texte : la 1re version
  // (color-mix à 60% avec --text-primary) restait trop proche du gris pour se
  // voir vraiment ("titres banals", retour utilisateur). Assombri en clair
  // (même logique que dangerColor d'AdministrationRow) — la couleur brute du
  // module est calibrée pour un fond sombre, illisible telle quelle sur blanc.
  const titleBase = isDark ? color : `color-mix(in srgb, ${color} 65%, black)`
  const titleGrad = `linear-gradient(100deg, color-mix(in srgb, ${titleBase} 75%, white), ${titleBase})`
  // Sans `children` (Settings, Notes), rien ne vient occuper la droite de la carte —
  // le masque resserré à gauche (pensé pour laisser la place à des boutons d'action)
  // faisait retomber ce côté à plat/vide ("Paramètres fait comme Notes", retour
  // utilisateur). Masque plus large et plus centré dans ce cas, pour que la trame de
  // points couvre toute la largeur au lieu de s'effacer avant la moitié de la carte.
  const gridMaskPos = children ? '10% 50%' : '32% 50%'
  const gridMaskSize = children ? '65% 90%' : '85% 100%'
  // Lueur d'ambiance derrière le logo (17/08/2026) — un cercle flou à la couleur du module,
  // sous la trame de points (peinte après elle dans le DOM, même pile z-index) pour un effet
  // "spot lumineux traversant un grillage" plutôt qu'un aplat plat. Statique comme le reste du
  // hero (cf. note de tête de fichier) : une simple forme, jamais de pulsation/déplacement.
  const glowOpacity = isDark ? 0.4 : 0.22
  return (
    <div className="relative overflow-hidden px-4 py-3 flex flex-wrap items-center justify-between gap-3" style={{
      ...CARD_SHAPE,
      background: `linear-gradient(135deg, color-mix(in srgb, ${color} 14%, var(--bg-card)), var(--bg-card) 65%)`,
      borderColor: `color-mix(in srgb, ${color} 28%, var(--border))`,
      boxShadow: isDark ? 'inset 0 1px 0 rgba(255,255,255,0.05)' : 'none',
    }}>
      <div className="absolute pointer-events-none" style={{
        left: -40, top: '50%', transform: 'translateY(-50%)', width: 220, height: 220,
        background: `radial-gradient(circle, ${color} 0%, transparent 70%)`,
        filter: 'blur(40px)', opacity: glowOpacity, zIndex: 0,
      }} />
      <div className="hero-grid" style={{
        maskImage: `radial-gradient(ellipse ${gridMaskSize} at ${gridMaskPos}, black 0%, transparent 70%)`,
        WebkitMaskImage: `radial-gradient(ellipse ${gridMaskSize} at ${gridMaskPos}, black 0%, transparent 70%)`,
      }} />
      <div className="relative z-[1] flex items-center gap-2.5 min-w-0">
        <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0" style={{
          background: `linear-gradient(155deg, ${color}, color-mix(in srgb, ${color} 55%, black))`,
          boxShadow: [
            `0 3px 12px -3px color-mix(in srgb, ${color} 55%, transparent)`,
            'inset 0 1px 0 rgba(255,255,255,0.3)',
            'inset 0 -8px 10px -6px rgba(0,0,0,0.3)',
          ].join(', '),
        }}>
          <svg className="w-[18px] h-[18px]" fill="none" stroke="#fff" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d={icon} />
          </svg>
        </div>
        <div className="min-w-0">
          <h1 className="text-xl font-extrabold tracking-tight flex items-center gap-2 flex-wrap" style={{
            backgroundImage: titleGrad,
            WebkitBackgroundClip: 'text',
            backgroundClip: 'text',
            color: 'transparent',
            fontFamily: 'var(--font-mono)',
            textShadow: isDark ? `0 0 26px color-mix(in srgb, ${color} 40%, transparent)` : 'none',
          }}>
            {title}
          </h1>
          {subtitle && <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{subtitle}</p>}
        </div>
      </div>
      {children && <div className="relative z-[1] flex-shrink-0">{children}</div>}
    </div>
  )
}

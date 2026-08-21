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

// Rayon/décor réactifs au thème (21/08/2026, demande explicite) — Neutre : plat et net
// (présentation pro, sans lueur ni dégradé). Cyberpunk : lueur/glow renforcés (panneau HUD).
const CYBERPUNK_CLIP = 'polygon(20px 0, 100% 0, 100% calc(100% - 20px), calc(100% - 20px) 100%, 0 100%, 0 20px)'
const CARD_SHAPE_BY_THEME = {
  neutral:   { border: '1px solid var(--border)', borderRadius: '2px' },
  cyberpunk: { border: '1px solid var(--border)', borderRadius: 0, clipPath: CYBERPUNK_CLIP },
}
const CARD_SHAPE_DEFAULT = { border: '1px solid var(--border)', borderRadius: '16px' }

export default function PageHero({ icon, title, subtitle, color, children }) {
  const { isDark, theme } = useTheme()
  const CARD_SHAPE = CARD_SHAPE_BY_THEME[theme] || CARD_SHAPE_DEFAULT
  const isNeutral = theme === 'neutral'
  const isCyberpunk = theme === 'cyberpunk'
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
  // Adouci (21/08/2026, retour utilisateur — "trop flashy") : glow/mélanges cyberpunk réduits.
  const glowOpacity = isCyberpunk ? 0.5 : isNeutral ? 0 : isDark ? 0.4 : 0.22
  // Police par thème (21/08/2026, demande explicite — "polices différentes", pas juste la
  // couleur du texte) : serif pour Neutre (feel rapport/audit imprimé, rompt avec le mono
  // "tech" utilisé partout ailleurs), mono capitales espacées pour Cyberpunk (déjà en place,
  // poussé plus loin), var(--font-mono) inchangé en dark/light (identité d'origine).
  const titleFont = isNeutral ? "Georgia, 'Times New Roman', serif" : 'var(--font-mono)'
  return (
    <div className="relative px-4 py-3 flex flex-wrap items-center justify-between gap-3" style={{
      ...CARD_SHAPE,
      background: isNeutral
        ? 'var(--bg-card)'
        : `linear-gradient(135deg, color-mix(in srgb, ${color} ${isCyberpunk ? 15 : 14}%, var(--bg-card)), var(--bg-card) 65%)`,
      borderColor: `color-mix(in srgb, ${color} ${isNeutral ? 16 : isCyberpunk ? 32 : 28}%, var(--border))`,
      boxShadow: isCyberpunk
        ? `0 0 0 1px color-mix(in srgb, ${color} 28%, transparent), 0 0 30px -8px color-mix(in srgb, ${color} 50%, transparent), inset 0 1px 0 rgba(255,255,255,0.05)`
        : isNeutral ? 'none'
        : isDark ? 'inset 0 1px 0 rgba(255,255,255,0.05)' : 'none',
    }}>
      {/* Décor (lueur + trame de points) isolé dans son propre wrapper clippé
          (18/08/2026, cf. audit) — auparavant l'`overflow-hidden` était posé sur le
          conteneur entier, ce qui clippait aussi tout menu déroulant ouvert depuis
          `children` (ex. NotificationHistory sur Dashboard.jsx, "l'affichage se
          cache dans la tuile") : un enfant en `position: absolute` reste borné par
          le premier ancêtre `overflow` non-`visible`, quel que soit son `z-index`.
          `border-radius` seul (sur le conteneur ci-dessus) suffit à arrondir le
          fond du hero lui-même — `overflow-hidden` n'était nécessaire que pour ces
          deux éléments décoratifs qui débordent visuellement de la boîte. */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none" style={{ borderRadius: CARD_SHAPE.borderRadius }}>
        <div className="absolute pointer-events-none" style={{
          left: -40, top: '50%', transform: 'translateY(-50%)', width: 220, height: 220,
          background: `radial-gradient(circle, ${color} 0%, transparent 70%)`,
          filter: 'blur(40px)', opacity: glowOpacity, zIndex: 0,
        }} />
        <div className="hero-grid" style={{
          maskImage: `radial-gradient(ellipse ${gridMaskSize} at ${gridMaskPos}, black 0%, transparent 70%)`,
          WebkitMaskImage: `radial-gradient(ellipse ${gridMaskSize} at ${gridMaskPos}, black 0%, transparent 70%)`,
        }} />
      </div>
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
          <h1 className="text-xl font-extrabold flex items-center gap-2 flex-wrap" style={{
            backgroundImage: titleGrad,
            WebkitBackgroundClip: 'text',
            backgroundClip: 'text',
            color: 'transparent',
            fontFamily: titleFont,
            letterSpacing: isCyberpunk ? '0.04em' : isNeutral ? '0' : '-0.01em',
            textTransform: isCyberpunk ? 'uppercase' : 'none',
            textShadow: isCyberpunk
              ? `0 0 22px color-mix(in srgb, ${color} 50%, transparent)`
              : isDark ? `0 0 26px color-mix(in srgb, ${color} 40%, transparent)` : 'none',
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

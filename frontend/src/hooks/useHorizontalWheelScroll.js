import { useEffect, useRef } from 'react'

// Convertit le scroll vertical (molette) en scroll horizontal quand le conteneur déborde
// horizontalement (19/08/2026, retour utilisateur — "je dois scroller avec la barre [...] alors
// qu'on a de l'espace en dessous") : les tableaux larges (beaucoup de colonnes, ex. Actifs)
// forcent une scrollbar horizontale en bas du tableau, fastidieuse à attraper à la souris.
// Un simple scroll vertical suffit désormais tant que le curseur survole le tableau ; le scroll
// vertical de la page reprend normalement dès que le tableau ne déborde plus horizontalement
// (écran large) ou que le curseur le quitte.
//
// `onWheel` React est attaché en écouteur passif par défaut (perf) et ne peut pas annuler le
// scroll natif — un listener natif non-passif est nécessaire pour remplacer réellement le
// scroll vertical par de l'horizontal, d'où le ref + addEventListener plutôt qu'un simple prop.
export function useHorizontalWheelScroll() {
  const ref = useRef(null)

  useEffect(() => {
    const el = ref.current
    if (!el) return

    function handleWheel(e) {
      if (el.scrollWidth <= el.clientWidth) return // pas de débordement — scroll vertical normal
      if (e.deltaY === 0) return
      el.scrollLeft += e.deltaY
      e.preventDefault()
    }

    el.addEventListener('wheel', handleWheel, { passive: false })
    return () => el.removeEventListener('wheel', handleWheel)
  }, [])

  return ref
}

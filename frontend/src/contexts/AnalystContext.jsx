import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { analysts as fetchAnalysts } from '../api/client.js'
import { usePresentation } from './PresentationContext.jsx'
import { SYNTHETIC_VALIDATORS } from '../utils/syntheticData.js'

const AnalystContext = createContext({
  analysts: [], names: [], refresh: () => {}, loading: true,
})

// Registre des analystes (cf. models.py::Analyst) — remplace la liste ANALYSTS codée en
// dur, alimente les menus déroulants d'attribution (validé par, déclaré par, jalon envoyé
// par, étape du Plan d'action...) partout dans l'app.
//
// `names` bascule sur SYNTHETIC_VALIDATORS en mode Présentation (31/07/2026) — centralisé ici plutôt
// que dans chaque dropdown consommateur (`isAnonymous ? SYNTHETIC_VALIDATORS : ANALYSTS` était fait
// au cas par cas dans Vulnerabilities.jsx/ValidateDropdown.jsx/AnnotationModal.jsx, mais absent
// de tous les dropdowns Incidents/Crise — ce correctif les couvre tous d'un coup, présents et
// futurs, sans devoir patcher chaque fichier). `PresentationProvider` englobe `AnalystProvider`
// dans App.jsx, `usePresentation()` fonctionne donc ici.
export function AnalystProvider({ children }) {
  const { isAnonymous } = usePresentation()
  const [analysts, setAnalysts] = useState([])
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(() => {
    return fetchAnalysts()
      .then(r => setAnalysts(r.data.items || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { refresh() }, [refresh])

  // Retry au focus fenêtre (03/08/2026, cf. STATUS.md § effet de bord constaté deux
  // fois le même jour) : ce fetch ne tourne qu'une fois au montage — un redémarrage
  // backend en cours de session (ECONNREFUSED, IP interne du conteneur recréée)
  // laissait tous les dropdowns d'analyste vides jusqu'à un rechargement complet de
  // page. Revenir sur l'onglet après un redémarrage relance le fetch tout seul.
  useEffect(() => {
    window.addEventListener('focus', refresh)
    return () => window.removeEventListener('focus', refresh)
  }, [refresh])

  const names = isAnonymous ? SYNTHETIC_VALIDATORS : analysts.map(a => a.name)

  return (
    <AnalystContext.Provider value={{ analysts, names, refresh, loading }}>
      {children}
    </AnalystContext.Provider>
  )
}

export const useAnalysts = () => useContext(AnalystContext)

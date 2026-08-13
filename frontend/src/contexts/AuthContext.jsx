import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { login as apiLogin, logout as apiLogout, me as apiMe } from '../api/client.js'
import LogoutOverlay from '../components/LogoutOverlay.jsx'

const AuthContext = createContext({
  user: null, loading: true, login: async () => {}, logout: async () => {}, refresh: () => {},
})

// Session par cookie HttpOnly (posé/effacé par le navigateur, jamais lu ici) — cf.
// backend/routers/auth.py. `me()` au montage vérifie si une session valide existe déjà
// (ex: retour sur l'app après un précédent login). 401 = pas connecté, pas une erreur.
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  // Écran de transition à la déconnexion (LogoutOverlay.jsx, demande explicite) — monté ici
  // plutôt que dans une page précise puisque `logout()` est appelable depuis n'importe où
  // (Settings.jsx, ProtectedRoute.jsx::ForcedPasswordChange).
  const [loggingOut, setLoggingOut] = useState(false)

  const refresh = useCallback(() => {
    return apiMe()
      .then(r => setUser(r.data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { refresh() }, [refresh])

  async function login(email, password) {
    const { data } = await apiLogin(email, password)
    setUser(data)
    return data
  }

  // L'appel API part tout de suite (best-effort, la session cookie doit être invalidée
  // côté serveur sans attendre l'animation) mais `user` n'est mis à `null` qu'au moment
  // où l'overlay commence sa sortie (`onExitStart`) — la redirection ProtectedRoute vers
  // /login se produit donc PENDANT que l'overlay est encore opaque, jamais avant qu'il ne
  // couvre l'écran (même raisonnement que WelcomeOverlay côté entrée, cf. Home.jsx).
  function logout() {
    setLoggingOut(true)
    apiLogout().catch(() => {})
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refresh }}>
      {children}
      {loggingOut && (
        <LogoutOverlay onExitStart={() => setUser(null)} onDone={() => setLoggingOut(false)} />
      )}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)

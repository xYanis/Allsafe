// Logique d'accès par page (31/07/2026) — partagée entre ProtectedRoute.jsx (bloque la
// navigation), Layout.jsx (filtre la nav) et Home.jsx (filtre les tuiles). `/settings` toujours
// vrai : un compte restreint doit pouvoir se déconnecter/changer son mot de passe forcé.
// `user.allowed_pages` : null/absent = accès total (même sémantique que côté backend,
// cf. models.py::User.allowed_pages).
export function canAccessPage(user, to) {
  if (to === '/settings') return true
  if (!user || user.role === 'admin') return true
  if (!Array.isArray(user.allowed_pages)) return true
  return user.allowed_pages.includes(to)
}

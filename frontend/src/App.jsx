import { useEffect, useRef } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import ProtectedRoute from './components/ProtectedRoute.jsx'
import Home from './pages/Home.jsx'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import CVEs from './pages/CVEs.jsx'
import Assets from './pages/Assets.jsx'
import Vulnerabilities from './pages/Vulnerabilities.jsx'
import Reports from './pages/Reports.jsx'
import Documentation from './pages/Documentation.jsx'
import Notes from './pages/Notes.jsx'
import NoteSubject from './pages/NoteSubject.jsx'
import Settings from './pages/Settings.jsx'
import ReleaseNotesPage from './pages/ReleaseNotesPage.jsx'
import AdministrationSecurity from './pages/AdministrationSecurity.jsx'
import Watch from './pages/Watch.jsx'
import Inventaire from './pages/Inventaire.jsx'
import Durcissement from './pages/Durcissement.jsx'
import Audits from './pages/Audits.jsx'
import AuditDetail from './pages/AuditDetail.jsx'
import Bastion from './pages/Bastion.jsx'
import Agents from './pages/Agents.jsx'
import AgentHistory from './pages/AgentHistory.jsx'
import AgentsGlobalHistory from './pages/AgentsGlobalHistory.jsx'
import AgentReleaseNotes from './pages/AgentReleaseNotes.jsx'
import SurveillanceIdentites from './pages/SurveillanceIdentites.jsx'
import FuiteDeDonnees from './pages/FuiteDeDonnees.jsx'
import RapportVeille from './pages/RapportVeille.jsx'
import RapportSurveillance from './pages/RapportSurveillance.jsx'
import Incidents from './pages/Incidents.jsx'
import Crises from './pages/Crises.jsx'
import RapportIncidents from './pages/RapportIncidents.jsx'
import ErrorPage from './pages/ErrorPage.jsx'
import { logConnection } from './api/client.js'
import { ThemeProvider } from './contexts/ThemeContext.jsx'
import { PresentationProvider } from './contexts/PresentationContext.jsx'
import { AnalystProvider } from './contexts/AnalystContext.jsx'
import { AnalystPreferenceProvider } from './contexts/AnalystPreferenceContext.jsx'
import { GuidePreferenceProvider } from './contexts/GuidePreferenceContext.jsx'
import { DashboardLayoutProvider } from './contexts/DashboardLayoutContext.jsx'
import { AuthProvider } from './contexts/AuthContext.jsx'

function ConnectionTracker() {
  // Garde anti-double-appel (03/08/2026, tour UX) : React 18 StrictMode
  // (main.jsx) monte/démonte/remonte chaque composant une fois en dev — sans
  // ce garde, chaque navigation posait deux lignes identiques dans
  // ConnectionLog (constaté en base, horodatages à la seconde près). `docker
  // compose up` (mode par défaut, cf. CLAUDE.md) sert la build dev, donc ce
  // doublage touchait tout usage courant, pas juste un artefact de test.
  const firedRef = useRef(false)
  useEffect(() => {
    if (firedRef.current) return
    firedRef.current = true
    logConnection().catch(() => {})
  }, [])
  return null
}

export default function App() {
  return (
    <AuthProvider>
    <PresentationProvider>
    <AnalystProvider>
    <AnalystPreferenceProvider>
    <GuidePreferenceProvider>
    <DashboardLayoutProvider>
    <ThemeProvider>
      <BrowserRouter>
        <ConnectionTracker />
        <Routes>
          {/* Connexion : seule route publique, en dehors de tout garde d'authentification */}
          <Route path="/login" element={<Login />} />

          {/* Page d'accueil : choix du module, sans sidebar */}
          <Route path="/" element={<ProtectedRoute><Home /></ProtectedRoute>} />

          <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            {/* Restriction de modules par compte analyst (31/07/2026, cf. models.py::User.
                allowed_pages) : chaque page passe par ProtectedRoute page="..." — même clé que
                côté serveur (services/access_control.py) et que le nav (Layout.jsx). Le contrôle
                serveur sur les routers de données reste la vraie barrière ; ce garde côté route
                évite juste qu'un lien direct affiche une page vide/en erreur. */}
            <Route path="dashboard" element={<ProtectedRoute page="/dashboard"><Dashboard /></ProtectedRoute>} />
            <Route path="vulnerabilities" element={<ProtectedRoute page="/vulnerabilities"><Vulnerabilities /></ProtectedRoute>} />
            <Route path="cves" element={<ProtectedRoute page="/cves"><CVEs /></ProtectedRoute>} />
            <Route path="assets" element={<ProtectedRoute page="/assets"><Assets /></ProtectedRoute>} />
            <Route path="veille" element={<ProtectedRoute page="/veille"><Watch /></ProtectedRoute>} />
            <Route path="fuite-de-donnees" element={<ProtectedRoute page="/fuite-de-donnees"><FuiteDeDonnees /></ProtectedRoute>} />
            <Route path="surveillance-identites" element={<ProtectedRoute page="/surveillance-identites"><SurveillanceIdentites /></ProtectedRoute>} />
            <Route path="inventaire" element={<ProtectedRoute page="/inventaire"><Inventaire /></ProtectedRoute>} />
            <Route path="durcissement" element={<ProtectedRoute page="/durcissement"><Durcissement /></ProtectedRoute>} />
            <Route path="audits" element={<ProtectedRoute page="/audits"><Audits /></ProtectedRoute>} />
            <Route path="audits/:id" element={<ProtectedRoute page="/audits"><AuditDetail /></ProtectedRoute>} />
            <Route path="bastion" element={<ProtectedRoute page="/bastion"><Bastion /></ProtectedRoute>} />
            <Route path="agents" element={<ProtectedRoute page="/agents"><Agents /></ProtectedRoute>} />
            <Route path="agents/:id" element={<ProtectedRoute page="/agents"><AgentHistory /></ProtectedRoute>} />
            <Route path="agents/notes-de-version" element={<ProtectedRoute page="/agents"><AgentReleaseNotes /></ProtectedRoute>} />
            <Route path="agents/historique" element={<ProtectedRoute page="/agents"><AgentsGlobalHistory /></ProtectedRoute>} />
            <Route path="reports" element={<ProtectedRoute page="/reports"><Reports /></ProtectedRoute>} />
            <Route path="documentation" element={<ProtectedRoute page="/documentation"><Documentation /></ProtectedRoute>} />
            <Route path="notes" element={<ProtectedRoute page="/notes"><Notes /></ProtectedRoute>} />
            <Route path="notes/:id" element={<ProtectedRoute page="/notes"><NoteSubject /></ProtectedRoute>} />
            <Route path="rapport-veille" element={<ProtectedRoute page="/rapport-veille"><RapportVeille /></ProtectedRoute>} />
            <Route path="rapport-surveillance" element={<ProtectedRoute page="/rapport-surveillance"><RapportSurveillance /></ProtectedRoute>} />
            <Route path="incidents" element={<ProtectedRoute page="/incidents"><Incidents /></ProtectedRoute>} />
            <Route path="crises" element={<ProtectedRoute page="/crises"><Crises /></ProtectedRoute>} />
            <Route path="rapport-incidents" element={<ProtectedRoute page="/rapport-incidents"><RapportIncidents /></ProtectedRoute>} />
            {/* Paramètres : jamais restreignable (thème, mode Présentation, son propre compte/
                déconnexion) — cf. utils/pageAccess.js::canAccessPage. */}
            <Route path="settings" element={<Settings />} />
            {/* Détaché de Paramètres (18/08/2026, demande explicite) — module à part, donc
                restreignable comme les autres (contrairement à /settings ci-dessus). */}
            <Route path="notes-de-version" element={<ProtectedRoute page="/notes-de-version"><ReleaseNotesPage /></ProtectedRoute>} />
            {/* Réservé au rôle admin — le serveur applique déjà la même restriction sur
                /api/connections et /api/security/* (cf. main.py, require_admin) */}
            <Route path="settings/administration" element={<ProtectedRoute role="admin"><AdministrationSecurity /></ProtectedRoute>} />
            <Route path="*" element={<ErrorPage code={404} />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
    </DashboardLayoutProvider>
    </GuidePreferenceProvider>
    </AnalystPreferenceProvider>
    </AnalystProvider>
    </PresentationProvider>
    </AuthProvider>
  )
}

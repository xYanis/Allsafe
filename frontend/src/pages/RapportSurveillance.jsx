import WeeklyArchives from '../components/WeeklyArchives.jsx'

// Rapport hebdomadaire de Surveillance Identités — même composant d'archives que
// les rapports CVE et Veille (cf. WeeklyArchives.jsx), seules changent la portée
// (`kind`) et les colonnes de comptage. Pas de portée par actif : les identités
// surveillées ne sont pas rattachées au parc (cf. ASSET_SCOPED_KINDS côté
// backend, services/weekly_report.py).
export default function RapportSurveillance() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Rapport Surveillance</h1>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Rapports hebdomadaires de surveillance des identités — preuve de veille continue NIS 2
        </p>
      </div>

      <WeeklyArchives
        kind="surveillance"
        countColumns={[
          { key: 'identities',   label: 'Identités surveillées', color: '#58a6ff' },
          { key: 'leak_matches', label: 'Fuites correspondantes', color: '#f85149' },
          { key: 'ip_matches',   label: 'IP blocklistées',       color: '#d29922' },
        ]}
        description="Un rapport figé par semaine (S30/2026), généré automatiquement chaque lundi à 7h : périmètre surveillé, publications de fuite analysées, correspondances trouvées et adresses IP figurant sur une liste de blocage. Un rapport sans correspondance a de la valeur — il prouve que le périmètre a bien été surveillé sur la période, ce qu'une absence de rapport ne prouve pas."
      />
    </div>
  )
}

import WeeklyArchives from '../components/WeeklyArchives.jsx'
import PageHero from '../components/PageHero.jsx'

// Rapport hebdomadaire de Surveillance Identités — même composant d'archives que
// les rapports CVE et Veille (cf. WeeklyArchives.jsx), seules changent la portée
// (`kind`) et les colonnes de comptage. Pas de portée par actif : les identités
// surveillées ne sont pas rattachées au parc (cf. ASSET_SCOPED_KINDS côté
// backend, services/weekly_report.py).
export default function RapportSurveillance() {
  return (
    <div className="p-6 space-y-6">
      <PageHero
        icon="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        title="Rapport Surveillance" color="#a371f7"
        subtitle="Rapports hebdomadaires de surveillance des identités — preuve de veille continue NIS 2"
      />

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

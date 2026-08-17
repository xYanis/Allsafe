// Criticité métier d'un actif (`asset.tags.criticite`, réglable depuis la page Actifs) —
// mêmes valeurs partout, partagées par Actifs.jsx (filtre) et Dashboard.jsx (badge +
// filtre, 04/08/2026) pour ne pas dupliquer le mapping deux fois.
// "critique" ajoutée le 17/08/2026 (au-dessus de haute) pour la politique de scan planifié
// (services/scan_policy.py) : seule cette valeur passe en scan quotidien, le reste hebdomadaire.
export const CRITICITE_LABELS = { critique: 'Critique', haute: 'Haute', moyenne: 'Moyenne', faible: 'Faible' }

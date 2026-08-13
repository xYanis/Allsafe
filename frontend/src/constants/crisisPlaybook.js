// Contenu de référence de la roadmap d'une crise : intervenants de mobilisation interne à
// prévenir et plan d'action générique. Distinct de incidentPlaybooks.js (organismes
// réglementaires ANSSI/CNIL, filtrés par catégorie d'incident) : la crise n'a pas de notion
// de catégorie, et ses intervenants sont d'ordre interne (Direction, RSSI, PR...) plutôt que
// des autorités externes — cf. CrisisContact (backend) pour les contacts personnalisés
// ajoutables sans toucher au code, même principe que IncidentNotificationContact.

// Libellés génériques, à affiner/compléter selon l'organisation réelle (rôles ajoutables sans
// code via CrisisContact — cf. Administration > Gestion de crise).
export const NATIVE_CRISIS_CONTACTS = [
  { id: 'direction', name: 'Direction générale', role: 'Décision finale, arbitrages, autorisation des mesures exceptionnelles' },
  { id: 'rssi', name: 'RSSI', role: 'Pilotage technique de la crise, coordination avec les équipes' },
  { id: 'dpo', name: 'DPO', role: 'Impact sur les données personnelles, articulation avec la CNIL' },
  { id: 'communication', name: 'Communication / RP', role: 'Communication interne et externe, gestion médias' },
  { id: 'juridique', name: 'Juridique', role: 'Obligations légales/contractuelles, dépôt de plainte' },
  { id: 'assureur', name: 'Assureur cyber', role: 'Déclaration de sinistre, prestataires mandatés' },
  { id: 'rh', name: 'RH', role: 'Personnel impacté, consignes internes' },
]

// Plan d'action générique — pas de branchement par catégorie (une crise n'en a pas,
// contrairement à un incident, cf. RESPONSE_STEPS/incidentPlaybooks.js) : la chronologie d'une
// gestion de crise est la même quelle que soit son origine (ransomware, fuite de données...),
// les incidents rattachés portent déjà leur propre plan d'action catégorisé. Même garde-fou
// que RESPONSE_STEPS : simple aide-mémoire coché par l'analyste (persisté dans
// Crisis.completed_crisis_steps), pas une pièce d'audit — la traçabilité réelle reste le
// journal (décisions/communications, activation/désactivation).
export const CRISIS_STEPS = [
  { text: 'Activer la cellule de crise et assigner les rôles', scope: 'interne' },
  { text: 'Évaluer le périmètre et la gravité de la situation', scope: 'interne' },
  { text: 'Informer la Direction générale', scope: 'interne' },
  { text: 'Rattacher les incidents concernés à la crise', scope: 'interne' },
  { text: 'Communiquer en interne aux équipes concernées', scope: 'interne' },
  { text: 'Solliciter les intervenants nécessaires (assureur, juridique, RP…)', scope: 'externe' },
  { text: 'Préparer une communication externe si nécessaire', scope: 'externe' },
  { text: 'Suivre la résolution des incidents rattachés', scope: 'interne' },
  { text: 'Décider du retour à la normale', scope: 'interne' },
  { text: 'Désactiver la crise avec justification', scope: 'interne' },
  { text: 'Réaliser un débriefing / retour d\'expérience', scope: 'interne' },
]

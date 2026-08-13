// Contenu de référence de la roadmap d'incident : organismes officiels à contacter et
// bonnes pratiques par catégorie. Coordonnées natives vérifiées le 29/07/2026 via les
// pages officielles (cert.ssi.gouv.fr/contact, cnil.fr/fr/notifier-une-violation-de-
// donnees-personnelles) — ce sont des points d'entrée publics stables (email/portail
// génériques d'un organisme), pas des contacts nominatifs. Elles peuvent changer avec le
// temps : cf. IncidentRoadmap.jsx pour l'avertissement affiché à l'utilisateur, et
// IncidentNotificationContact (backend) pour les contacts personnalisés ajoutables sans
// toucher au code (assureur cyber, avocat, cellule de communication...).
//
// `categories: []` = toujours pertinent, quelle que soit la catégorie de l'incident.
export const NATIVE_CONTACTS = [
  {
    id: 'anssi-certfr',
    name: 'ANSSI / CERT-FR',
    role: "Déclaration d'incident NIS 2, assistance technique — disponible 24/7",
    email: 'cert-fr@ssi.gouv.fr',
    phone: "3218 (gratuit, ou 09 70 83 32 18 depuis l'étranger)",
    website_url: 'https://www.cert.ssi.gouv.fr/contact/',
    portal_url: 'https://club.ssi.gouv.fr/#/declarations',
    categories: [],
  },
  {
    id: 'cnil',
    name: 'CNIL',
    role: 'Violation de données personnelles — délai légal 72h (RGPD, régime distinct de NIS 2 mais même durée)',
    website_url: 'https://www.cnil.fr/fr/notifier-une-violation-de-donnees-personnelles',
    portal_url: 'https://notifications.cnil.fr/notifications/',
    categories: ['data_breach'],
  },
  {
    id: 'police-gendarmerie',
    name: 'Police / Gendarmerie — dépôt de plainte',
    role: "Infraction pénale (extorsion, intrusion...) — commissariat/brigade, ou pré-plainte en ligne selon l'infraction",
    website_url: 'https://www.service-public.fr/particuliers/vosdroits/F1447',
    categories: ['ransomware', 'intrusion'],
  },
  {
    id: 'cybermalveillance',
    name: 'Cybermalveillance.gouv.fr',
    role: 'Orientation et mise en relation avec des prestataires qualifiés',
    website_url: 'https://www.cybermalveillance.gouv.fr/',
    categories: [],
  },
]

// Checklist de traitement par catégorie — "Plan d'action" (cf. IncidentRoadmap.jsx), dans
// l'ordre CHRONOLOGIQUE où les étapes se présentent réellement pendant le traitement d'un
// incident (containment immédiat → évaluation → qualification/notifications externes qui
// s'intercalent aux échéances légales → remédiation → clôture). Fusionne ce qui était avant
// séparé en deux listes ("bonnes pratiques" + "plan d'action") : la distinction utile n'est
// pas practique/rappel-légal mais QUAND l'étape intervient, d'où un seul flux ordonné.
// Chaque étape garde un `scope` ('interne' ou 'externe'), affiché comme simple étiquette
// (et non plus en deux colonnes séparées) pour ne pas casser l'ordre chronologique.
// Même garde-fou que précédemment : simple aide-mémoire coché par l'analyste, persisté en
// base (`completed_response_steps`), PAS une pièce d'audit — la traçabilité réelle des envois
// reste la qualification NIS 2 (justification horodatée) et les jalons "Marquer envoyé" eux-
// mêmes (§ ci-dessous). Cocher une étape externe ("envoyer l'alerte précoce...") ne déclenche
// ni n'atteste rien.
export const RESPONSE_STEPS = {
  ransomware: [
    { text: "Isoler immédiatement les systèmes touchés (débrancher le réseau) — NE PAS les éteindre, ça préserve la mémoire pour l'analyse", scope: 'interne' },
    { text: 'Alerter le RSSI / la direction', scope: 'interne' },
    { text: 'Ne jamais payer la rançon', scope: 'interne' },
    { text: 'Préserver les preuves (journaux, images disque) avant toute remédiation', scope: 'interne' },
    { text: 'Activer la cellule de crise si plusieurs systèmes sont touchés', scope: 'interne' },
    { text: 'Informer le personnel : consignes claires (ne pas rallumer/manipuler les postes)', scope: 'interne' },
    { text: "Identifier l'étendue réelle de la compromission", scope: 'interne' },
    { text: 'Qualifier l\'incident au regard de NIS 2 (section Notification NIS 2 ci-dessus)', scope: 'externe' },
    { text: 'Envoyer l\'alerte précoce sous 24h si qualifié', scope: 'externe' },
    { text: 'Déposer plainte auprès de la police/gendarmerie', scope: 'externe' },
    { text: "Restaurer depuis des sauvegardes saines, après vérification qu'elles ne sont pas compromises", scope: 'interne' },
    { text: 'Envoyer la notification sous 72h si qualifié', scope: 'externe' },
    { text: 'Envoyer le rapport final sous 1 mois si qualifié', scope: 'externe' },
  ],
  data_breach: [
    { text: 'Alerter le DPO et la direction', scope: 'interne' },
    { text: 'Évaluer précisément le périmètre (données et personnes concernées)', scope: 'interne' },
    { text: 'Révoquer les accès/identifiants compromis', scope: 'interne' },
    { text: 'Informer le personnel concerné des mesures à suivre', scope: 'interne' },
    { text: 'Qualifier l\'incident au regard de NIS 2 (section Notification NIS 2 ci-dessus)', scope: 'externe' },
    { text: 'Envoyer l\'alerte précoce sous 24h si qualifié', scope: 'externe' },
    { text: 'Notifier la CNIL sous 72h si risque pour les droits des personnes', scope: 'externe' },
    { text: 'Envoyer la notification NIS 2 sous 72h si qualifié', scope: 'externe' },
    { text: 'Informer individuellement les personnes concernées si risque élevé', scope: 'externe' },
    { text: 'Documenter nature, volumétrie, conséquences probables, mesures prises', scope: 'interne' },
    { text: 'Envoyer le rapport final sous 1 mois si qualifié', scope: 'externe' },
  ],
  intrusion: [
    { text: 'Isoler les systèmes compromis', scope: 'interne' },
    { text: 'Alerter le RSSI', scope: 'interne' },
    { text: "Analyser les journaux pour identifier le vecteur d'entrée", scope: 'interne' },
    { text: 'Changer les identifiants compromis, en priorité les comptes à privilèges', scope: 'interne' },
    { text: 'Rechercher une éventuelle persistance (comptes créés, tâches planifiées, implants)', scope: 'interne' },
    { text: 'Informer les équipes techniques concernées', scope: 'interne' },
    { text: 'Qualifier l\'incident au regard de NIS 2 (section Notification NIS 2 ci-dessus)', scope: 'externe' },
    { text: 'Envoyer l\'alerte précoce sous 24h si qualifié', scope: 'externe' },
    { text: 'Déposer plainte auprès de la police/gendarmerie', scope: 'externe' },
    { text: 'Envoyer la notification sous 72h si qualifié', scope: 'externe' },
    { text: 'Envoyer le rapport final sous 1 mois si qualifié', scope: 'externe' },
  ],
  dos: [
    { text: 'Alerter les équipes infrastructure/réseau', scope: 'interne' },
    { text: "Contacter l'hébergeur/FAI pour une mitigation (filtrage, scrubbing)", scope: 'externe' },
    { text: 'Activer le plan de continuité si un service critique est impacté', scope: 'interne' },
    { text: 'Informer le personnel/support client de la situation', scope: 'interne' },
    { text: "Documenter chronologie et volumétrie de l'attaque", scope: 'interne' },
    { text: 'Qualifier l\'incident au regard de NIS 2 (section Notification NIS 2 ci-dessus)', scope: 'externe' },
    { text: 'Communiquer publiquement si un service public/critique est impacté', scope: 'externe' },
    { text: 'Envoyer l\'alerte précoce sous 24h si qualifié', scope: 'externe' },
    { text: 'Envoyer la notification sous 72h si qualifié', scope: 'externe' },
    { text: 'Envoyer le rapport final sous 1 mois si qualifié', scope: 'externe' },
  ],
  phishing: [
    { text: "Bloquer le domaine/l'expéditeur frauduleux", scope: 'interne' },
    { text: 'Alerter en urgence les utilisateurs internes', scope: 'interne' },
    { text: 'Réinitialiser les identifiants des comptes ayant pu saisir leurs accès', scope: 'interne' },
    { text: 'Si des comptes sont compromis, traiter aussi comme une intrusion', scope: 'interne' },
    { text: 'Qualifier l\'incident au regard de NIS 2 si des comptes sensibles sont compromis', scope: 'externe' },
    { text: 'Envoyer l\'alerte précoce sous 24h si qualifié', scope: 'externe' },
    { text: 'Envoyer la notification sous 72h si qualifié', scope: 'externe' },
    { text: 'Envoyer le rapport final sous 1 mois si qualifié', scope: 'externe' },
  ],
  malware: [
    { text: 'Isoler la machine infectée du réseau', scope: 'interne' },
    { text: "Alerter l'équipe sécurité", scope: 'interne' },
    { text: "Analyser l'échantillon avec l'EDR/antivirus", scope: 'interne' },
    { text: 'Rechercher une propagation latérale', scope: 'interne' },
    { text: 'Informer le personnel concerné', scope: 'interne' },
    { text: 'Qualifier l\'incident au regard de NIS 2 si la propagation est significative', scope: 'externe' },
    { text: 'Envoyer l\'alerte précoce sous 24h si qualifié', scope: 'externe' },
    { text: 'Envoyer la notification sous 72h si qualifié', scope: 'externe' },
    { text: 'Envoyer le rapport final sous 1 mois si qualifié', scope: 'externe' },
  ],
  misconfiguration: [
    { text: 'Corriger la configuration immédiatement', scope: 'interne' },
    { text: "Alerter l'équipe technique responsable", scope: 'interne' },
    { text: "Vérifier les journaux d'accès pendant toute la fenêtre d'exposition", scope: 'interne' },
    { text: 'Si des données ont pu être consultées par un tiers : traiter aussi comme une fuite de données', scope: 'interne' },
    { text: 'Qualifier l\'incident au regard de NIS 2/notifier la CNIL selon les données exposées', scope: 'externe' },
    { text: 'Envoyer l\'alerte précoce sous 24h si qualifié', scope: 'externe' },
    { text: 'Envoyer la notification sous 72h si qualifié', scope: 'externe' },
    { text: 'Envoyer le rapport final sous 1 mois si qualifié', scope: 'externe' },
  ],
  other: [
    { text: 'Alerter le RSSI / la direction', scope: 'interne' },
    { text: 'Documenter précisément les faits connus', scope: 'interne' },
    { text: 'Mobiliser les équipes concernées', scope: 'interne' },
    { text: "Évaluer si la CNIL ou l'ANSSI/CERT-FR sont concernés selon la nature réelle de l'incident", scope: 'externe' },
    { text: 'Envoyer l\'alerte précoce sous 24h si qualifié', scope: 'externe' },
    { text: 'Envoyer la notification sous 72h si qualifié', scope: 'externe' },
    { text: 'Envoyer le rapport final sous 1 mois si qualifié', scope: 'externe' },
  ],
}

// `personalDataInvolved` : case à cocher manuelle, indépendante de la catégorie — un
// ransomware ou une intrusion s'accompagnent très souvent d'une exposition de données
// personnelles, sans que la catégorie de l'incident soit "data_breach" pour autant.
export function contactsForCategory(category, personalDataInvolved, customContacts = []) {
  const all = [...NATIVE_CONTACTS, ...customContacts]
  return all.filter(c => {
    if (!c.categories || c.categories.length === 0) return true
    if (c.categories.includes(category)) return true
    if (c.id === 'cnil' && personalDataInvolved) return true
    if (c.categories.includes('data_breach') && personalDataInvolved) return true
    return false
  })
}

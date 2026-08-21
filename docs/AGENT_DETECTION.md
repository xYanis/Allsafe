# Agent — Détection d'évènements sensibles côté poste

> ⏳ **PARTIELLEMENT IMPLÉMENTÉ (19/08/2026).** Fondations backend posées et testées de bout en bout
> (modèles `AgentSecurityEvent`/`AgentStateSnapshot`, `schema_patches.sql` appliqué en base réelle,
> `POST /agents/checkin` étendu, diff d'état + dédoublonnage du journal natif dans
> `services/agent_detection.py`, endpoints `GET/POST /agents/security-events*`). **Côté agent** :
> socle diff posé pour **Linux et Windows** (`collect/linux.rs`/`collect/windows.rs` —
> `local_users`/`admin_members`/`persistence` envoyés à chaque check-in, `audit_coverage`
> constaté), compile pour les deux cibles. **Les deux vérifiés en conditions réelles** :
> Linux (`gitlab.aer.loc`, 0.1.8 — snapshot correctement collecté, comptes/sudo/cron/systemd
> filtrés comme attendu, 0 faux évènement au 1er check-in, `audit_coverage` honnête) et Windows
> (`armadasenonches`, 0.1.19 — comptes locaux réels, ~130 tâches planifiées/services réels dont
> `AllsafeAgent` lui-même ; deux bugs trouvés et corrigés sur ces données réelles :
> `Get-LocalGroupMember -Group 'Administrators'` échouait silencieusement sur un Windows en
> français, group localisé — remplacé par le SID bien connu `S-1-5-32-544` ; sortie PowerShell
> encodée ANSI par défaut en redirection — corrompait les noms accentués, forcé en UTF-8).
> **Reste à faire** : enrichissement journal natif des
> deux côtés (Event Log Security / auditd — `suspicious_process`/`audit_tampering`, ni l'un ni
> l'autre catégorisable par diff seul, curseur persistant + buffer plafonné, § Mécanique agent
> ci-dessous) et le frontend (page Durcissement, badge nav, bandeau Dashboard). Il complète
> `docs/AGENTS.md` (agent d'inventaire existant) — même binaire `allsafe-agent`, même transport, on
> **ajoute** une capacité de détection, on ne crée pas un second agent.
>
> `Agent.audit_coverage` (dict JSONB libre, pas de schéma fixe) : clés `auditd_installed`/
> `auditd_running` côté Linux, `process_auditing`/`command_line_logging` côté Windows — chaque
> plateforme constate ce qui a du sens pour elle, l'UI ne doit pas supposer un jeu de clés commun.
>
> Cible retenue : **Niveau 2 (hybride diff d'état + journal natif)**, cf. § Stratégie. Le Niveau 3
> (corrélation / baseline / règles en base) est documenté comme trajectoire, **hors MVP**.

## Principe

L'agent lit les **journaux d'audit natifs de l'OS** (Event Log Security sur Windows, `auditd`/authlog
sur Linux) et **diffe l'état** du poste entre deux check-ins (comptes, membres des groupes privilégiés,
persistance). Il **ne provoque jamais** ces évènements et n'exécute rien — même règle de non-intervention
lecture seule que tout le reste d'Allsafe (`CLAUDE.md` §1). C'est de la **détection**, pas de l'action :
l'agent constate qu'un compte a été créé, il n'en crée aucun ; il repère qu'un `nmap` a tourné, il n'en
lance aucun.

Rattaché au **Durcissement** (module Inventaire > Agents), même logique de « constat sans intervention »
que les checks CIS-like existants — juste **évènementiel** au lieu d'un snapshot de conformité.

### ⚠️ Limite fondamentale — c'est un fil-piège, pas une boîte noire inviolable

L'agent, sa config et son credential vivent **sur le poste surveillé**. Or ces détections se déclenchent
précisément quand ce poste est compromis — au moment même où un attaquant local peut lire le credential,
tuer l'agent, ou lui faire émettre de faux check-ins. **Cette capacité ne peut pas être considérée comme
une preuve fiable de sa propre non-compromission.** Elle a de la valeur comme tripwire (la plupart des
intrus ne pensent pas à neutraliser proprement l'agent avant d'agir), pas comme rempart.

C'est exactement pourquoi la **déception DB** (`backend/db/deception_setup.sql`, hors de portée d'un
attaquant présent sur un poste) reste **complémentaire** : les deux surfaces se couvrent mutuellement,
aucune ne remplace l'autre.

## Stratégie — le spectre envisagé

Quatre niveaux ont été pesés (du plus simple au plus avancé). Le **Niveau 2** est retenu.

| Niveau | Approche | Détecte | Prérequis OS | Statut |
|---|---|---|---|---|
| **0** | Diff d'état seul (comptes/admins/persistance snapshotés, diff serveur) | Changements **persistants** (compte, admin, tâche). **Rate** l'éphémère et les process | Aucun | Socle, insuffisant seul |
| **1** | Lecture journal natif seul | Tout, y compris process (nmap) et éphémère, avec acteur + horodatage | `4688`/ligne de commande (GPO), `auditd` | Fragile : aveugle en silence si audit OFF |
| **2** ✅ | **Hybride** : diff = colonne vertébrale (marche toujours), journal = enrichissement (acteur/timing/éphémère quand dispo) | Les deux, avec **dégradation gracieuse** et couverture affichée honnêtement | Aucun pour le socle, `4688`/`auditd` pour le bonus | **Retenu (MVP)** |
| **3** | N2 + corrélation d'évènements + baseline/allowlist + règles pilotées en base | Intentions plutôt que faits isolés, bruit filtré | idem N2 | **Trajectoire, hors MVP** (EDR-like, mérite ses propres garde-fous) |

Le choix du N2 repose sur : robustesse (le socle diff ne dépend de rien), honnêteté (l'app affiche
quand elle est en couverture partielle), et coût maîtrisé (une table, un flux, réutilise le transport
check-in existant). Le champ `detection_method` + `audit_coverage` laisse la porte ouverte au N3 sans
réécriture — les évènements bruts existeront déjà, il ne resterait qu'à poser la couche findings/baseline
par-dessus (principe scalable, `CLAUDE.md`).

## Catégories détectées (MVP)

| Catégorie | Windows (Event Log Security) | Linux | Détection |
|---|---|---|---|
| `account_created` | `4720` | `useradd` (authlog/auditd) | journal + diff |
| `privilege_escalation` | `4732`/`4728`/`4756` (ajout groupe admin), `4672` filtré | `usermod -G sudo/wheel`, diff des membres | journal + diff |
| `account_reactivated` | `4722` (activé), `4724` (mdp réinitialisé) | flag `enabled` du diff | journal + diff |
| `persistence` | `4698` (tâche planifiée), `7045`/`4697` (service) | cron/unit systemd neuf | journal + diff |
| `suspicious_process` | `4688` (ex. `nmap.exe`, outils de recon) | `execve` (auditd) | journal seul (éphémère) |
| `audit_tampering` | `1102` (journal vidé), audit désactivé | `auditd` stoppé/règles retirées | journal + `audit_coverage` |
| `buffer_overflow` | — (synthétique, pas un évènement OS) | — | émis par l'agent lui-même quand son buffer de coupure (§ Mécanique agent, piège #3) dépasse son plafond — « M évènements perdus » plutôt qu'un flush silencieux ou un disque qui se remplit. À inclure dans l'enum/les filtres au même titre que les autres, pas une catégorie à part oubliée du tableau. |

**`audit_tampering` est obligatoire** : sans lui, désactiver l'audit fait retomber toutes les détections
à zéro silencieusement (l'app croirait « RAS »). C'est le signal qui protège les autres.

**Filtrage strict dès le départ** : `4672` (privilèges spéciaux) se déclenche pour quantité de sessions
admin légitimes — ne signaler que les **nouveaux** comptes admin / élévations, pas toute session
privilégiée, sinon le module crie au loup et perd sa valeur. Le volume normal doit rester de quelques
lignes par poste et par jour.

Hors MVP (N3) : défenses désactivées (pare-feu/AV/exclusion antivirus), brute-force `4625`→`4624`.

## Modèle de données

Journal **append-only** par agent, table dédiée — **pas** fusionné avec `SecurityEvent` (honeypot DB),
cohérent avec la décision projet de ne pas fusionner les journaux (`vuln_history` / `incident_timeline`
/ `audit_finding_history` restent séparés).

```python
class AgentSecurityEvent(Base):
    """Détections d'évènements sensibles côté poste (lecture des journaux d'audit natifs de
    l'OS, jamais une exécution — cf. docs/AGENT_DETECTION.md). Append-only, un évènement = une
    ligne, plutôt qu'un JSON snapshot écrasé au scan suivant comme Asset.last_scan_result.compliance
    (un évènement ponctuel n'est pas un état à remplacer).

    agent_id nullable + ON DELETE SET NULL + hostname/os en snapshot : un agent supprimé (toujours
    après révocation) ne doit pas emporter son historique de détections — même logique que
    AssetDeletionLog, à l'inverse d'AgentCheckinLog (CASCADE, télémétrie sans valeur d'audit).

    (agent_id, native_event_id) unique : dédoublonnage. Le check-in relit une fenêtre du journal OS
    à chaque cycle ; sans clé naturelle (RecordID Windows / clé ausearch Linux) un même évènement
    réapparaîtrait tant qu'il reste dans la fenêtre relue. NULL pour les détections state_diff (pas
    de ligne de journal derrière) — le dédoublonnage y est assuré par le diff lui-même."""
    __tablename__ = "agent_security_events"

    id               = Column(UUID, primary_key=True, default=uuid4)
    agent_id         = Column(UUID, ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True)
    hostname         = Column(String, nullable=False)   # snapshot au moment de l'évènement
    os               = Column(String, nullable=False)   # snapshot, "windows" | "linux"
    category         = Column(String, nullable=False)   # cf. tableau ci-dessus
    severity         = Column(String, nullable=False, default="info")   # info | warning | critical, déclaratif agent
    detection_method = Column(String, nullable=False)   # state_diff | native_log
    occurred_at      = Column(DateTime(timezone=True), nullable=False)  # horloge du POSTE (indicatif, falsifiable)
    reported_at      = Column(DateTime(timezone=True), server_default=now())  # horloge SERVEUR (fiable)
    native_source    = Column(String, nullable=True)    # windows_security_log | linux_auditd | linux_authlog
    native_event_id  = Column(String, nullable=True)    # RecordID / clé ausearch — dédoublonnage (NULL si state_diff)
    summary          = Column(String, nullable=False)   # résumé humain généré côté agent, ex. "Compte local créé : bob"
    detail           = Column(JSONB)                    # champs bruts par catégorie (username, groupe, image_path, cmdline...)
    acknowledged     = Column(Boolean, nullable=False, default=False)
    ack_by           = Column(String)
    ack_at           = Column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("agent_id", "native_event_id", name="uq_agent_security_event_native"),)
```

Deux champs ajoutés à `Agent` :

```python
class Agent(Base):
    # ... existant ...
    audit_coverage = Column(JSONB)   # {process_auditing: bool, auditd_running: bool, ...} — l'agent
                                     # CONSTATE si l'audit OS est actif ; l'UI affiche "détection
                                     # partielle" au lieu de laisser croire à une couverture totale
```

Pour le socle diff, l'état précédent doit être conservé pour comparer :

```python
class AgentStateSnapshot(Base):
    """Dernier état connu par agent, comparé au check-in suivant pour générer les détections
    state_diff. Mis à jour en place (pas un historique — un instantané, cf. Asset.last_scan_result).
    CASCADE : cet état n'a de sens que tant que l'agent existe."""
    __tablename__ = "agent_state_snapshots"
    agent_id      = Column(UUID, ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True)
    local_users   = Column(JSONB)   # [{name, sid_or_uid, enabled}]
    admin_members = Column(JSONB)   # membres Administrators / sudo / wheel
    persistence   = Column(JSONB)   # tâches planifiées / services / cron / units
    captured_at   = Column(DateTime(timezone=True))
```

> `schema_patches.sql` : ajouter la création de `agent_security_events`, `agent_state_snapshots` et
> les colonnes `agents.audit_coverage` (`ADD COLUMN IF NOT EXISTS`). Pas d'Alembic dans le projet,
> `create_all` ne modifie jamais une table existante. À exécuter avec le rôle superuser `cybervuln`.

## Transport

Piggyback sur le check-in existant — **pas** de nouvel endpoint côté agent. Le payload `checkin`
(`routers/agents.py::AgentCheckinPayload`) gagne une clé :

```python
class AgentCheckinPayload(BaseModel):
    # ... existant (detected, hardware, compliance, offline_since...) ...
    security_events: list[dict] = []   # évènements neufs depuis le dernier check-in réussi
    audit_coverage: dict = {}          # état de l'audit OS constaté côté poste
    state_snapshot: dict = {}          # comptes/admins/persistance pour le diff serveur
```

Réutilise l'auth (`require_agent`), le modèle de coupure et tout le rodé. Le **serveur** fait le diff
(`state_snapshot` reçu vs `AgentStateSnapshot` stocké), écrit les `AgentSecurityEvent` (journal + diff),
met à jour le snapshot et `audit_coverage`.

⚠️ **Plafond côté serveur obligatoire sur `security_events`** (19/08/2026, cf. audit/AUDIT_SECURITE.md
#35 — même leçon appliquée le même jour à `packages`/`compliance.checks` sur ce même endpoint
`/checkin`) : le § « Mécanique agent » ci-dessous prévoit déjà un plafond **côté agent** (buffer
pendant coupure), mais rien ne doit dépendre de ce que le client respecte réellement cette limite —
un agent compromis ou buggé pourrait envoyer un `security_events` démesuré. Tronquer explicitement
côté serveur à l'écriture (ex. `[:300]`, même ordre de grandeur que le plafond déjà posé sur
`packages`), indépendamment du plafond client. Le throttle 1 check-in/minute déjà en place
(`routers/agents.py::CHECKIN_MIN_INTERVAL_SECONDS`) s'applique aussi à cet endpoint sans changement —
sans incidence sur la détection : les check-ins normaux restent à l'heure, ce plafond ne vise que le
spam.

Même vigilance sur `audit_coverage` et `state_snapshot` : ce sont des `dict` libres (pas de schéma
Pydantic strict clé par clé), donc rien n'empêche un agent compromis/buggé d'y glisser un objet
démesuré au lieu d'un état compact attendu. `audit_coverage` reste petit par nature (quelques
booléens) mais mérite quand même une taille max côté serveur avant stockage JSONB (ex. rejeter/tronquer
au-delà de quelques Ko) ; `state_snapshot` (comptes/admins/persistance d'un poste réel) est plus gros
et plus variable — même traitement que `security_events` : plafonner explicitement côté serveur
(nombre d'entrées par catégorie, ex. comptes/admins/tâches planifiées) avant le diff et l'écriture,
indépendamment de ce que l'agent est censé respecter.

Exposition en lecture : nouveau `routers/agents.py` (ou `routers/agent_events.py`) —
`GET /api/agents/security-events` (+ `?unack_only`, pagination), `POST .../{id}/ack`, `.../ack-all`,
même schéma d'acquittement que `routers/security.py`. Réservé admin (comme `/api/security/*`).

⚠️ **Sauf le compteur.** Le § « Décisions figées » ci-dessous prévoit un badge compteur dans la nav
Inventaire — visible à tout connecté, pas seulement admin (comme le badge `/api/security/*`
équivalent). Il faudra donc une route dédiée non gatée admin pour juste le nombre (ex.
`GET /api/agents/security-events/count`), sur le modèle exact de l'exception déjà posée sur
`routers/security.py::/api/security/events/count` — sans elle, la règle "Réservé admin" ci-dessus
empêcherait le badge de s'afficher pour un compte `analyst`.

## Mécanique agent — les pièges à traiter

1. **Pas de backfill au 1er run.** Au premier check-in après enrôlement, poser un high-water mark =
   maintenant. Sinon l'agent remonte **tout l'historique du journal** comme détections neuves →
   inondation le jour 1.
2. **Curseur persistant.** Le point de reprise (RecordID Windows / position ausearch) est stocké à côté
   de la config locale (comme `DaemonState`, `agent/src/config.rs`) — survit au reboot. Sans ça : après
   redémarrage, soit re-remontée totale, soit trou.
3. **Buffer pendant coupure, plafonné.** Les évènements survenus pendant une coupure réseau (déjà
   suivie par `offline_since`/`failed_attempts`) sont gardés localement et flushés à la reconnexion,
   avec un **plafond** (ex. N derniers) : au-delà, émettre un évènement synthétique
   `category=buffer_overflow` (« M évènements perdus ») plutôt que remplir le disque ou noyer le signal.
4. **Horloge non fiable.** `occurred_at` vient du poste (falsifiable par l'attaquant local) — garder
   **les deux** horodatages : `occurred_at` (poste, indicatif) et `reported_at` (serveur, fiable). Le
   tri et les alertes s'appuient sur `reported_at`.
5. **Anonymisation (`CLAUDE.md` §2).** Ces évènements sont bourrés de nominatif (usernames, hostnames,
   lignes de commande) → **local strict, jamais vers l'API Claude**, comme le reste des données actif.

## Prérequis OS (déploiement, pas code)

- **Windows** : le socle diff marche sans rien. Pour `suspicious_process` (`4688`), l'**audit de
  création de processus + ligne de commande** doit être activé par GPO. L'agent doit pouvoir lire le
  journal Security (groupe *Event Log Readers* ou SYSTEM).
- **Linux** : le diff marche sans rien. Pour l'éphémère (`execve`), `auditd` doit être installé et
  configuré. Lecture de `/var/log/audit` = root.

L'agent **constate** ces prérequis (`audit_coverage`) et l'UI affiche « détection partielle » quand ils
manquent — il ne les active jamais lui-même (ce serait une écriture système, hors non-intervention).

## Décisions figées (19/08/2026)

- **Bannières séparées.** Les évènements agent **ne partagent pas** la bannière rouge du Dashboard avec
  le honeypot DB. Raison : le honeypot est un signal quasi-certain (personne ne touche un objet leurre
  par accident), l'évènement agent est indicatif et plus bruyant (l'IT crée des comptes légitimement) —
  les mélanger diluerait le honeypot et, après quelques faux positifs agent, plus personne ne
  regarderait la bannière. Les évènements agent vivent sur la page **Agents / Durcissement** (contexte
  « quel poste » déjà présent) + badge compteur dans la nav Inventaire ; le Dashboard peut porter un
  **second bandeau distinct** (couleur ≠ rouge) pour la visibilité globale, visuellement dissocié.
- **Conservation totale, pas de purge auto.** Piste d'audit NIS 2 : « compte admin créé le X, acquitté
  par Y » doit rester consultable des mois plus tard, comme `AgentCheckinLog` et le journal honeypot ne
  se purgent pas seuls. Le volume est maîtrisé **en amont** (filtrage strict + dédoublonnage), pas par
  la purge. Garde-fou optionnel : purge **manuelle** admin (« purger les évènements acquittés de plus
  de X jours »), jamais automatique — cohérent avec le projet (rien ne s'efface tout seul).

## Pont vers Incidents

Un évènement confirmé (ex. compte admin créé sur un serveur de prod) est du matériau incident NIS 2 pur.
Réutiliser `DeclareIncidentButton.jsx` (préremplissage depuis un autre module, pattern existant) pour
créer un incident prérérempli depuis un `AgentSecurityEvent` — jamais de création auto (`docs/INCIDENTS.md`).

## Découpage

**MVP (Niveau 2)** : catégories `account_created` / `privilege_escalation` / `account_reactivated` /
`persistence` / `suspicious_process` / `audit_tampering` ; diff comme socle + journal en enrichissement ;
no-backfill + curseur persistant + buffer plafonné ; `audit_coverage` honnête ; ack admin ; bannière
séparée ; conservation totale ; pont Incidents. Limite d'auto-protection documentée.

**Plus tard (Niveau 3)** : corrélation d'évènements (findings), baseline/allowlist par agent (ne
signaler que les écarts au connu-bon), règles pilotées en base (seuils éditables sans coder, façon
`ScanPolicy`/`WatchSource`), défenses désactivées, brute-force. À traiter comme un chantier avec ses
propres garde-fous (EDR-like), pas un ajout silencieux.

## À vérifier à l'implémentation

- Test de garde-fou (dossier `backend/tests/`, sans base) : dédoublonnage `native_event_id`, absence de
  backfill au 1er run, flush après coupure, plafond de buffer.
- Le diff serveur ne doit **jamais** requalifier/écraser un évènement déjà acquitté (append-only strict).
- Réutiliser `services/asset_scanner.py::apply_scan_result` n'a pas de sens ici (shape différent) — les
  détections sont écrites par une fonction dédiée côté `checkin`, pas par le pipeline de scan.
- Alternatives hors agent notées pour mémoire (non retenues pour le MVP) : **Windows Event Forwarding /
  WinRM** (lecture des évènements Security sans agent, mais Windows-only et n'atteint pas les postes
  éteints/VPN qui justifient l'agent) ; **Sysmon** (télémétrie process/réseau bien plus riche que
  `4688`, mais dépendance lourde à déployer sur le parc).

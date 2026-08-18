-- ============================================================================
-- schema_patches.sql — Ajouts de colonnes/tables à un schéma déjà existant.
--
-- create_all (init_db) ne modifie JAMAIS une table existante (cf. database.py) :
-- seules les tables absentes sont créées. Toute colonne ajoutée ou table créée
-- sur une base déjà en place doit donc passer par du DDL explicite, ici — sur
-- une base neuve, `create_all` couvre déjà tout (les modèles dans models.py
-- font foi), ce fichier ne sert qu'au rattrapage d'une base existante.
--
-- Idempotent (IF NOT EXISTS). Rejouable. À exécuter avec le rôle superuser
-- `cybervuln` (PAS `cbr_app`, qui n'a aucun droit DDL — cf. ddl_guard.sql —
-- toute tentative via l'app elle-même serait bloquée et journalisée).
-- ============================================================================

-- Workflow "risque accepté avec expiration" (27/07/2026) : date de revue
-- obligatoire quand une vuln passe en accepted_risk. Reste un statut terminal
-- (cf. CLAUDE.md) — cette colonne ne sert qu'à calculer un signal "revue en
-- retard" à la lecture, jamais à rouvrir automatiquement la vuln.
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS accepted_risk_until TIMESTAMPTZ;

-- Historique des changements de statut de vulnérabilité (27/07/2026) — chaque
-- transition (manuelle ET automatique) écrit une ligne, jamais écrasée, jamais
-- supprimée. Motivé par un incident réel où une réouverture/rebascule sans
-- piste d'audit a compliqué le diagnostic (cf. STATUS.md). Prospectif, pas
-- rétroactif : ne couvre que les transitions à partir de sa mise en service.
-- Pas de défaut DB sur `id` : comme le reste du projet, uuid.uuid4() est posé
-- côté Python par le modèle SQLAlchemy (models.py), jamais côté SQL.
CREATE TABLE IF NOT EXISTS vulnerability_status_history (
    id               UUID PRIMARY KEY,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    old_status       VARCHAR,
    new_status       VARCHAR NOT NULL,
    changed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    validated_by     VARCHAR,
    notes            TEXT
);
CREATE INDEX IF NOT EXISTS idx_vuln_status_history_vuln_id ON vulnerability_status_history(vulnerability_id);
-- L'app tourne en cbr_app (DML only, cf. app_role.sql) — une table CRÉÉE APRÈS
-- app_role.sql n'hérite d'aucun droit automatiquement, sans ce GRANT explicite
-- l'app ne pourrait ni lire ni écrire cette table (permission denied).
GRANT SELECT, INSERT, UPDATE, DELETE ON vulnerability_status_history TO cbr_app;

-- Perf (28/07/2026, cf. project_ad_widening_scale_incident) : `cves.published`
-- et `vulnerabilities.status` n'ont jamais été indexés, alors qu'ils sont
-- filtrés par des endpoints interrogés en continu par le Dashboard —
-- `GET /patch-check/status` (poll 3s, deux COUNT sur `status`),
-- `compute_stats`/`GET /stats` (plusieurs COUNT sur `status`), `max_age_years`
-- sur `GET /vulnerabilities` (filtre `cves.published`). Chacun faisait un scan
-- séquentiel des ~270k `vulnerabilities`/~181k `cves`. Constaté en réel :
-- `/api/health` ralenti à plusieurs secondes sous charge normale du Dashboard.
-- N'accélère PAS les 3 endpoints "candidats" (awaiting-fix/false-positive/
-- critical-review) : leur pagination par keyset trie par `vulnerabilities.id`,
-- un ordre sans rapport avec ces filtres — Postgres continue d'y scanner en
-- ordre d'id quels que soient les index posés ici. Ce chantier-là reste ouvert.
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);

-- Module Incidents (29/07/2026) — registre d'incidents + suivi des délais légaux de
-- notification NIS 2 (Directive, Art. 23 : alerte précoce 24h, notification 72h,
-- rapport final 1 mois après `aware_at`). `requires_notification` et les 3 jalons
-- `*_sent_at` ne sont JAMAIS posés automatiquement par le code, quel que soit l'appelant
-- (création manuelle, tâche planifiée, préremplissage depuis security_events/
-- vulnerabilities/watch_items) — toujours un acte humain explicite avec justification
-- obligatoire (cf. services/nis2_deadlines.py). Même esprit que la règle CRITICAL
-- toujours manuel de CyberVuln (CLAUDE.md). Pas de défaut DB sur `id` : uuid.uuid4()
-- posé côté Python, comme le reste du projet.
CREATE TABLE IF NOT EXISTS incidents (
    id                             UUID PRIMARY KEY,
    title                          VARCHAR NOT NULL,
    description                    TEXT,
    category                       VARCHAR NOT NULL,
    severity                       VARCHAR NOT NULL,
    status                         VARCHAR NOT NULL DEFAULT 'declared',
    detected_at                    TIMESTAMPTZ,
    aware_at                       TIMESTAMPTZ NOT NULL,
    aware_at_locked                BOOLEAN NOT NULL DEFAULT false,
    reported_by                    VARCHAR NOT NULL,
    created_at                     TIMESTAMPTZ DEFAULT now(),
    updated_at                     TIMESTAMPTZ,
    requires_notification          BOOLEAN NOT NULL DEFAULT false,
    notification_qualified_by      VARCHAR,
    notification_qualified_at      TIMESTAMPTZ,
    notification_justification     TEXT,
    early_warning_due_at           TIMESTAMPTZ,
    early_warning_sent_at          TIMESTAMPTZ,
    early_warning_sent_by          VARCHAR,
    incident_notification_due_at   TIMESTAMPTZ,
    incident_notification_sent_at  TIMESTAMPTZ,
    incident_notification_sent_by  VARCHAR,
    final_report_due_at            TIMESTAMPTZ,
    final_report_sent_at           TIMESTAMPTZ,
    final_report_sent_by           VARCHAR,
    security_event_id              BIGINT REFERENCES security_events(id) ON DELETE SET NULL,
    vulnerability_id                UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    watch_item_id                  UUID REFERENCES watch_items(id) ON DELETE SET NULL,
    affected_asset_ids             JSON DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_requires_notification ON incidents(requires_notification);
GRANT SELECT, INSERT, UPDATE, DELETE ON incidents TO cbr_app;

-- Timeline auditable, append-only, d'un incident (cf. Incident ci-dessus) — générique
-- (statut, note, qualification/déqualification, jalon envoyé, aware_at modifié), pas
-- seulement les transitions de statut (contrairement à vulnerability_status_history).
CREATE TABLE IF NOT EXISTS incident_timeline_entries (
    id          UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_type  VARCHAR NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    author      VARCHAR NOT NULL,
    old_value   VARCHAR,
    new_value   VARCHAR,
    notes       TEXT,
    meta        JSONB
);
CREATE INDEX IF NOT EXISTS idx_incident_timeline_incident_id ON incident_timeline_entries(incident_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON incident_timeline_entries TO cbr_app;

-- Contacts personnalisés pour la roadmap d'incident (29/07/2026) — en complément des
-- organismes officiels codés en dur côté frontend (ANSSI/CERT-FR, CNIL, police/gendarmerie,
-- cybermalveillance.gouv.fr, cf. frontend/src/constants/incidentPlaybooks.js). Même principe
-- que watch_sources pour la veille : natif en code, personnalisé en base.
CREATE TABLE IF NOT EXISTS incident_notification_contacts (
    id          UUID PRIMARY KEY,
    name        VARCHAR NOT NULL,
    role        VARCHAR,
    email       VARCHAR,
    phone       VARCHAR,
    website_url VARCHAR,
    categories  JSON DEFAULT '[]',
    notes       TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON incident_notification_contacts TO cbr_app;

-- Checklist "bonnes pratiques" de la roadmap : indices cochés par l'analyste (aide-mémoire,
-- pas une pièce d'audit) — persistés pour ne pas perdre la progression entre deux
-- ouvertures de l'incident (29/07/2026).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS completed_playbook_steps JSON DEFAULT '[]';

-- Pièces jointes PDF du rapport final (29/07/2026) — fichier sur disque (volume Docker
-- incident_attachments), métadonnées seules ici. Cf. services/incident_attachments.py
-- pour la validation (5 Mo max, signature %PDF-).
CREATE TABLE IF NOT EXISTS incident_attachments (
    id              UUID PRIMARY KEY,
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    milestone       VARCHAR NOT NULL DEFAULT 'final_report',
    filename        VARCHAR NOT NULL,
    stored_filename VARCHAR NOT NULL,
    size_bytes      INTEGER NOT NULL,
    uploaded_by     VARCHAR NOT NULL,
    uploaded_at     TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incident_attachments_incident_id ON incident_attachments(incident_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON incident_attachments TO cbr_app;

-- Checklist "Plan d'action" de la roadmap (29/07/2026) : mêmes principe et garde-fou que
-- completed_playbook_steps ci-dessus (aide-mémoire cochée par l'analyste, pas un instantané
-- d'audit) — étapes internes/externes de traitement (isolement, personnel, autorités, rapports).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS completed_response_steps JSON DEFAULT '[]';

-- La checklist "bonnes pratiques" séparée est retirée (29/07/2026) : elle faisait doublon avec
-- "Plan d'action" ci-dessus une fois celui-ci étoffé — contenu fusionné dans RESPONSE_STEPS
-- (frontend/src/constants/incidentPlaybooks.js), colonne devenue inutile.
ALTER TABLE incidents DROP COLUMN IF EXISTS completed_playbook_steps;

-- Chaque étape cochée du Plan d'action porte désormais qui l'a réalisée (29/07/2026) :
-- la colonne passe de list[int] (indices seuls) à list[{index, by, at}]. Le JSON existant
-- ([] partout à ce stade, aucune vraie donnée perdue) reste compatible, pas de migration
-- de contenu nécessaire — cf. routers/incidents.py pour la nouvelle forme du payload.

-- Registre des analystes (29/07/2026, cf. models.py::Analyst) : remplace la liste ANALYSTS
-- codée en dur. Seed des 3 analystes historiques pour ne rien casser côté menus déroulants
-- déjà utilisés partout (validated_by, reported_by...).
CREATE TABLE IF NOT EXISTS analysts (
    id          UUID PRIMARY KEY,
    name        VARCHAR NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON analysts TO cbr_app;
INSERT INTO analysts (id, name) VALUES
    (gen_random_uuid(), 'Nicolas Szebesta'),
    (gen_random_uuid(), 'Tanguy Delamare'),
    (gen_random_uuid(), 'Yanis Hortholary')
ON CONFLICT (name) DO NOTHING;

-- Retrait du module Bastion / sélecteur "Je suis..." (30/07/2026, cf. STATUS.md) : la
-- personnalisation d'affichage par visible_modules disparaît, remplacée à terme par une
-- vraie authentification. Le registre de noms (ci-dessus) reste pour validated_by.
ALTER TABLE analysts DROP COLUMN IF EXISTS visible_modules;

-- Authentification réelle (30/07/2026, cf. models.py::User/UserSession/AuthAuditLog et
-- docs/ARCHITECTURE.md). RBAC binaire (role admin/analyst) : pas de table roles/user_roles
-- séparée, une simple colonne CHECK suffit pour deux valeurs. Séparée du registre `analysts`
-- ci-dessus (noms d'attribution validated_by) : pas de fusion pour cette phase.
CREATE TABLE IF NOT EXISTS users (
    id                    UUID PRIMARY KEY,
    email                 VARCHAR NOT NULL UNIQUE,
    full_name             VARCHAR NOT NULL,
    password_hash         VARCHAR NOT NULL,
    role                  VARCHAR NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst')),
    is_active             BOOLEAN NOT NULL DEFAULT true,
    must_change_password  BOOLEAN NOT NULL DEFAULT false,
    created_at            TIMESTAMPTZ DEFAULT now(),
    updated_at            TIMESTAMPTZ DEFAULT now()
);

-- Session par cookie HttpOnly : seul le hash SHA-256 du token est stocké, jamais le token
-- en clair (un dump de la table ne redonne pas de session valide). Session glissante 8h
-- (plafond absolu 7 jours depuis created_at) — cf. services/auth.py.
CREATE TABLE IF NOT EXISTS sessions (
    id                  UUID PRIMARY KEY,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash  VARCHAR NOT NULL UNIQUE,
    ip_address          VARCHAR,
    user_agent          TEXT,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Journal d'audit des tentatives de connexion — traçabilité (cohérent avec la culture
-- NIS 2 du reste de l'app) + base du verrou anti-bruteforce (comptage par email/IP dans
-- une fenêtre glissante, cf. services/auth.py::count_recent_failures). Loggue TOUTES les
-- tentatives, y compris email inexistant, sinon le comptage par email n'a aucun sens.
CREATE TABLE IF NOT EXISTS auth_audit_logs (
    id            UUID PRIMARY KEY,
    event_type    VARCHAR NOT NULL,  -- LOGIN_SUCCESS | LOGIN_FAILED | LOGOUT | ROLE_CHANGE
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    email_attempt VARCHAR,
    ip_address    VARCHAR,
    user_agent    TEXT,
    details       JSONB,
    created_at    TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_auth_audit_email_created ON auth_audit_logs (email_attempt, created_at);
CREATE INDEX IF NOT EXISTS ix_auth_audit_ip_created     ON auth_audit_logs (ip_address, created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, auth_audit_logs TO cbr_app;

-- Correspondance nom d'application Windows -> produit CPE (31/07/2026, cf.
-- models.py::WindowsAppMapping) : les paquets Linux se dérivent par convention
-- (services/cpe_matcher.py::_package_candidates), mais un nom d'application Windows
-- est du texte libre de registre sans convention exploitable. `pattern` : sous-chaîne
-- insensible à la casse, réglable sans toucher au code (CRUD Administration).
CREATE TABLE IF NOT EXISTS windows_app_mappings (
    id           UUID PRIMARY KEY,
    pattern      VARCHAR NOT NULL UNIQUE,
    cpe_product  VARCHAR NOT NULL,
    cpe_vendor   VARCHAR,
    created_at   TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON windows_app_mappings TO cbr_app;

-- Gestion de crise (31/07/2026, module Incidents — cf. models.py::Crisis/
-- CrisisTimelineEntry, ROADMAP_RNCP42335.md Bloc 1.5). Escalade d'un ou plusieurs
-- incidents en crise : cellule de crise (rôles nommés, JSON — même pattern que
-- Incident.affected_asset_ids), journal de décisions/communications internes/externes.
-- Activation/désactivation toujours un acte humain explicite (activated_by/stood_down_by
-- obligatoires), jamais automatique.
CREATE TABLE IF NOT EXISTS crises (
    id                        UUID PRIMARY KEY,
    title                     VARCHAR NOT NULL,
    description               TEXT,
    status                    VARCHAR NOT NULL DEFAULT 'active',
    activated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_by              VARCHAR NOT NULL,
    stood_down_at             TIMESTAMPTZ,
    stood_down_by             VARCHAR,
    stand_down_justification  TEXT,
    crisis_roles              JSON DEFAULT '[]',
    created_at                TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON crises TO cbr_app;

-- Timeline auditable, append-only, d'une crise — sibling exact d'incident_timeline_entries.
CREATE TABLE IF NOT EXISTS crisis_timeline_entries (
    id          UUID PRIMARY KEY,
    crisis_id   UUID NOT NULL REFERENCES crises(id) ON DELETE CASCADE,
    event_type  VARCHAR NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    author      VARCHAR NOT NULL,
    old_value   VARCHAR,
    new_value   VARCHAR,
    notes       TEXT,
    meta        JSONB
);
CREATE INDEX IF NOT EXISTS idx_crisis_timeline_crisis_id ON crisis_timeline_entries(crisis_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON crisis_timeline_entries TO cbr_app;

-- Rattachement d'un incident à une crise — SET NULL et non CASCADE : supprimer la crise
-- ne doit pas supprimer les incidents qu'elle regroupait (même logique que les 3 FK
-- optionnelles déjà sur incidents : security_event_id/vulnerability_id/watch_item_id).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS crisis_id UUID REFERENCES crises(id) ON DELETE SET NULL;

-- Gestion de crise v2 (31/07/2026, même session) : intervenants à prévenir + plan d'action.
-- Intervenants personnalisés (cf. models.py::CrisisContact) — même principe qu'
-- incident_notification_contacts, mais sans `categories` : une crise n'a pas de catégorie.
CREATE TABLE IF NOT EXISTS crisis_contacts (
    id          UUID PRIMARY KEY,
    name        VARCHAR NOT NULL,
    role        VARCHAR,
    email       VARCHAR,
    phone       VARCHAR,
    website_url VARCHAR,
    notes       TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON crisis_contacts TO cbr_app;

-- Plan d'action de la crise — étapes cochées de CRISIS_STEPS (frontend/src/constants/
-- crisisPlaybook.js), même forme {index, by, at} qu'Incident.completed_response_steps.
ALTER TABLE crises ADD COLUMN IF NOT EXISTS completed_crisis_steps JSON DEFAULT '[]';

-- Registre « Rôles » (organigramme, 31/07/2026, cf. models.py::OrganizationRole) : quel poste
-- (RSSI, DPO, Direction générale...) est tenu par quelle personne — utilisé par la Gestion de
-- crise (CrisisRoadmap.jsx) et les Incidents (IncidentRoadmap.jsx) pour savoir à qui se référer.
-- Lecture ouverte à tout connecté, écriture réservée admin (même convention qu'analysts).
CREATE TABLE IF NOT EXISTS organization_roles (
    id          UUID PRIMARY KEY,
    position    VARCHAR NOT NULL,
    name        VARCHAR NOT NULL,
    email       VARCHAR,
    created_at  TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON organization_roles TO cbr_app;

-- Services/départements (31/07/2026, même session, cf. models.py::Service) : RH, DSI, Juridique,
-- Direction... liste ouverte, ajoutable sans code (Administration > onglet Services). Regroupent
-- les postes du registre Rôles (organization_roles.service_id) avec un code couleur.
CREATE TABLE IF NOT EXISTS services (
    id          UUID PRIMARY KEY,
    name        VARCHAR NOT NULL UNIQUE,
    color       VARCHAR NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON services TO cbr_app;

-- Rattachement d'un poste à un service — SET NULL et non CASCADE : supprimer un service ne doit
-- pas supprimer les postes qui y étaient rattachés, seulement les détacher.
ALTER TABLE organization_roles ADD COLUMN IF NOT EXISTS service_id UUID REFERENCES services(id) ON DELETE SET NULL;

-- Seed des 4 services demandés initialement — l'utilisateur peut en ajouter/renommer/recolorer
-- librement ensuite depuis Administration > Services (liste ouverte, pas figée).
INSERT INTO services (id, name, color) VALUES
    (gen_random_uuid(), 'RH', '#3fb950'),
    (gen_random_uuid(), 'DSI', '#58a6ff'),
    (gen_random_uuid(), 'Juridique', '#a371f7'),
    (gen_random_uuid(), 'Direction', '#f85149')
ON CONFLICT (name) DO NOTHING;

-- Icône de service (31/07/2026, même session) : clé d'une palette fixe côté frontend
-- (components/ServiceIcon.jsx::SERVICE_ICON_KEYS), pas un champ libre. Nullable — le frontend
-- replie sur une icône par défaut ('briefcase') pour les services déjà existants sans icône choisie.
ALTER TABLE services ADD COLUMN IF NOT EXISTS icon VARCHAR;
UPDATE services SET icon = 'users' WHERE name = 'RH' AND icon IS NULL;
UPDATE services SET icon = 'server' WHERE name = 'DSI' AND icon IS NULL;
UPDATE services SET icon = 'scale' WHERE name = 'Juridique' AND icon IS NULL;
UPDATE services SET icon = 'building' WHERE name = 'Direction' AND icon IS NULL;

-- Mini organigramme par service (31/07/2026, même session) : hiérarchie entre postes
-- (`reports_to_id`, auto-référence sur organization_roles). SET NULL comme service_id — supprimer
-- un manager détache ses subordonnés plutôt que de les supprimer. Cycles empêchés côté API
-- (routers/organization_roles.py), jamais au niveau DB.
ALTER TABLE organization_roles ADD COLUMN IF NOT EXISTS reports_to_id UUID REFERENCES organization_roles(id) ON DELETE SET NULL;

-- Module Documentation (31/07/2026, même session) — documents de gouvernance NIS 2 (PSSI,
-- chartes, organigramme...). Registre de types ouvert (cf. models.py::DocumentType) + fichiers
-- uploadés (cf. models.py::Document) : pas de table de versions séparée, chaque upload crée une
-- nouvelle ligne du même document_type_id, triée par uploaded_at desc à la lecture — l'historique
-- est la liste elle-même, pas une hiérarchie à part.
CREATE TABLE IF NOT EXISTS document_types (
    id          UUID PRIMARY KEY,
    name        VARCHAR NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON document_types TO cbr_app;

-- Pas de ON DELETE sur document_type_id (défaut Postgres NO ACTION) : supprimer un type encore
-- utilisé par des documents est bloqué au niveau DB, intercepté en 409 côté API
-- (routers/documents.py) plutôt que de laisser remonter une erreur SQL brute.
CREATE TABLE IF NOT EXISTS documents (
    id                UUID PRIMARY KEY,
    document_type_id  UUID NOT NULL REFERENCES document_types(id),
    filename          VARCHAR NOT NULL,
    stored_filename   VARCHAR NOT NULL,
    size_bytes        INTEGER NOT NULL,
    uploaded_by       VARCHAR NOT NULL,
    notes             TEXT,
    uploaded_at       TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_documents_type_id ON documents(document_type_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON documents TO cbr_app;

-- Seed des 4 types demandés initialement — liste ouverte, l'utilisateur peut en ajouter d'autres
-- librement depuis la page Documentation (pas promu dans Administration, contrairement à
-- Rôles/Services : ce registre est spécifique à ce module).
INSERT INTO document_types (id, name) VALUES
    (gen_random_uuid(), 'PSSI'),
    (gen_random_uuid(), 'Charte Administrateur'),
    (gen_random_uuid(), 'Charte Utilisateur'),
    (gen_random_uuid(), 'Organigramme')
ON CONFLICT (name) DO NOTHING;

-- Droits d'accès par module/page pour un compte analyst (31/07/2026, cf. models.py::User,
-- services/access_control.py). NULL = accès total (défaut à la création) ; une liste JSON de
-- clés de page = restriction. `role == 'admin'` ignore toujours ce champ.
ALTER TABLE users ADD COLUMN IF NOT EXISTS allowed_pages JSON;

-- Module Audits (03/08/2026, cf. docs/AUDITS.md, models.py::Audit et suivants) — hub de suivi
-- des audits techniques (architecture/configuration/code/pentest/redteam), un seul modèle pour
-- les 5 types. Garde-fou central : scope/rules_of_engagement/authorized_by/authorized_at posés
-- ensemble et immuables ensuite (appliqué côté API), aucun finding saisissable avant `autorise`.
CREATE TABLE IF NOT EXISTS audits (
    id                    UUID PRIMARY KEY,
    title                 VARCHAR NOT NULL,
    type                  VARCHAR NOT NULL,
    methodology           VARCHAR,
    referential           VARCHAR,
    status                VARCHAR NOT NULL DEFAULT 'cadrage',
    scope                 TEXT,
    rules_of_engagement   TEXT,
    authorized_by         VARCHAR,
    authorized_at         TIMESTAMPTZ,
    conducted_by          VARCHAR,
    started_at            TIMESTAMPTZ,
    ended_at              TIMESTAMPTZ,
    executive_summary     TEXT,
    created_at            TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON audits TO cbr_app;

-- Liaison audit <-> actif déjà connu de CBR — vraie table (pas un JSON comme
-- Incident.affected_asset_ids) : un audit cible un périmètre technique précis.
CREATE TABLE IF NOT EXISTS audit_assets (
    audit_id  UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    asset_id  UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (audit_id, asset_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_assets TO cbr_app;

CREATE TABLE IF NOT EXISTS audit_findings (
    id                   UUID PRIMARY KEY,
    audit_id             UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    title                VARCHAR NOT NULL,
    description          TEXT,
    severity             VARCHAR NOT NULL,
    cvss_vector          VARCHAR,
    cvss_score           FLOAT,
    cwe_id               VARCHAR,
    owasp_ref            VARCHAR,
    affected_asset_id    UUID REFERENCES assets(id) ON DELETE SET NULL,
    affected_component   VARCHAR,
    cve_id               VARCHAR REFERENCES cves(cve_id),
    proof_of_concept     TEXT,
    impact               TEXT,
    recommendation       TEXT,
    status               VARCHAR NOT NULL DEFAULT 'ouvert',
    mitre_techniques     JSONB DEFAULT '[]',
    discovered_at        TIMESTAMPTZ DEFAULT now(),
    retested_at          TIMESTAMPTZ,
    retest_result        VARCHAR,
    retested_by          VARCHAR,
    created_at           TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_findings_audit_id ON audit_findings(audit_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_findings TO cbr_app;

-- Transitions de statut d'un finding, append-only — même pattern que
-- vulnerability_status_history, pas incident_timeline_entries (journal d'événements libres).
CREATE TABLE IF NOT EXISTS audit_finding_history (
    id          UUID PRIMARY KEY,
    finding_id  UUID NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    old_status  VARCHAR,
    new_status  VARCHAR NOT NULL,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    changed_by  VARCHAR NOT NULL,
    notes       TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_finding_history_finding_id ON audit_finding_history(finding_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_finding_history TO cbr_app;

-- Pièce jointe (PDF/PNG/JPEG, cf. services/audit_attachments.py) : mandat d'audit
-- (audit_id posé, finding_id NULL) ou capture d'écran de preuve (finding_id posé, audit_id
-- NULL) — une seule table, même schéma/validation dans les deux cas.
CREATE TABLE IF NOT EXISTS audit_attachments (
    id              UUID PRIMARY KEY,
    audit_id        UUID REFERENCES audits(id) ON DELETE CASCADE,
    finding_id      UUID REFERENCES audit_findings(id) ON DELETE CASCADE,
    kind            VARCHAR NOT NULL DEFAULT 'mandate',
    filename        VARCHAR NOT NULL,
    stored_filename VARCHAR NOT NULL,
    size_bytes      INTEGER NOT NULL,
    uploaded_by     VARCHAR NOT NULL,
    uploaded_at     TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_attachments_audit_id ON audit_attachments(audit_id);
CREATE INDEX IF NOT EXISTS idx_audit_attachments_finding_id ON audit_attachments(finding_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_attachments TO cbr_app;

-- Finding d'audit à l'origine d'une déclaration d'incident (03/08/2026, cf. models.py::Incident,
-- routers/incidents.py::prefill_incident) — même SET NULL que security_event_id/vulnerability_id/
-- watch_item_id : l'incident survit à la suppression du finding source.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS audit_finding_id UUID REFERENCES audit_findings(id) ON DELETE SET NULL;

-- État réseau remonté par une sonde externe (04/08/2026, cf. models.py::NetworkStatus,
-- services/meraki_client.py/meraki_matcher.py) — comble le vide identifié lors de la discussion
-- PRTG du 31/07/2026 (jamais codée, remplacée par Meraki). Une ligne par (actif, source),
-- mise à jour en place à chaque cycle — pas un historique. `metrics` en JSON pour scaler vers
-- d'autres métriques (bande passante, CPU...) plus tard sans nouvelle migration.
CREATE TABLE IF NOT EXISTS network_status (
    id                UUID PRIMARY KEY,
    asset_id          UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source            VARCHAR NOT NULL DEFAULT 'meraki',
    status            VARCHAR,
    last_reported_at  TIMESTAMPTZ,
    metrics           JSON DEFAULT '{}',
    updated_at        TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_network_status_asset_source ON network_status(asset_id, source);
GRANT SELECT, INSERT, UPDATE, DELETE ON network_status TO cbr_app;

-- Copie légère de last_scan_result.reachable/.error (04/08/2026, cf. models.py::Asset,
-- ConnectivityDot.jsx) : colonnes dédiées plutôt que reparser le blob JSON complet, pour
-- que les endpoints candidats (false-positive-candidates...) puissent afficher la pastille
-- de connectivité sans charger last_scan_result/installed_packages, exclus de leur
-- load_only(raiseload=True) suite à l'incident de perf déjà documenté (~190 Mo/appel).
ALTER TABLE assets ADD COLUMN IF NOT EXISTS scan_reachable BOOLEAN;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS scan_error TEXT;

-- "system" (composant OS) / "application" (paquet/logiciel installé) / NULL
-- (indéterminé) — distingue mise à jour système vs applicative sur la page
-- Actifs (07/08/2026, cf. models.py::Vulnerability, routers/assets.py).
-- Rattachements déjà en base : NULL jusqu'au backfill (cf.
-- services/cpe_matcher.py::backfill_component_types, POST /api/sync/backfill-component-types).
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS component_type VARCHAR;

-- Protocoles d'admin non chiffrés détectés par TCP passif sur les actifs réseau
-- (07/08/2026, switches/pare-feux PRTG/Meraki, cf. models.py::Asset § network_compliance
-- et services/network_protocol_check.py).
ALTER TABLE assets ADD COLUMN IF NOT EXISTS network_compliance JSON;

-- Statut du cycle référencé par sync_state.key (10/08/2026) — seul "patch_check_cycle"
-- l'utilise pour l'instant : distingue un cycle interrompu par un redémarrage du backend
-- (--reload en dev, tue la tâche de fond en mémoire sans laisser de trace jusqu'ici) d'un
-- cycle terminé proprement. Cf. services/patch_checker.py et main.py::_check_interrupted_patch_cycle.
ALTER TABLE sync_state ADD COLUMN IF NOT EXISTS status VARCHAR;

-- Anti-doublon (asset_id, cve_id) sur vulnerabilities (11/08/2026, incident réel : 6 paires
-- dupliquées trouvées en base, cf. AUDIT_SECURITE.md/STATUS.md). Le check "exists" applicatif
-- dans run_cpe_matching (services/cpe_matcher.py) n'est pas atomique : deux passes de matching
-- concurrentes (bouton manuel + cycle automatique, ou deux clics rapprochés) peuvent toutes les
-- deux constater "pas encore là" et insérer chacune leur ligne. La contrainte fait respecter
-- l'unicité au niveau DB ; le code gère désormais IntegrityError en repli (cf. cpe_matcher.py).
-- Suppose la base déjà dédupliquée manuellement au moment de ce patch (6 doublons nettoyés le
-- 11/08/2026, tous strictement identiques, aucun n'avait de statut/annotation modifié — sans
-- dédup préalable, ce ALTER échoue).
CREATE UNIQUE INDEX IF NOT EXISTS uq_vulnerabilities_asset_cve ON vulnerabilities(asset_id, cve_id);

-- Journal "actif terminé sa passe de contrôle patch" (11/08/2026, demande explicite —
-- cf. models.py::PatchCheckAssetCompletion). La notification toast correspondante côté
-- Dashboard.jsx disparaissait sans laisser de trace après 6s, contrairement aux bascules
-- de CVE (déjà consultables après coup via Vulnerability.patched_at/false_positive_at) —
-- rien ne permettait de rejouer "cet actif a fini" une fois le toast disparu. Pas de FK
-- sur asset_id : l'actif peut être supprimé entre-temps (DeleteAssetModal), l'historique
-- doit rester lisible sans jointure obligatoire, asset_name/hostname sont donc dupliqués
-- en texte au moment de l'écriture (même raisonnement que _current_check/_last_completed
-- en mémoire, services/patch_checker.py).
CREATE TABLE IF NOT EXISTS patch_check_asset_completions (
    id                  UUID PRIMARY KEY,
    asset_id            UUID,
    asset_name          VARCHAR NOT NULL,
    hostname            VARCHAR,
    checked_count       INTEGER NOT NULL,
    auto_bascule_count  INTEGER NOT NULL DEFAULT 0,
    completed_at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_patch_check_asset_completions_completed_at ON patch_check_asset_completions(completed_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON patch_check_asset_completions TO cbr_app;

-- Module Notes (12/08/2026, module Documentation > Notes) — v1 glossaire plat (terme/
-- définition/maîtrisé) abandonnée le même jour au profit d'une vraie prise de notes
-- structurée (cf. docs/Notes.md fourni par l'utilisateur après coup) : aucune donnée
-- réelle n'existait encore dans cette table, DROP sans migration de contenu.
DROP TABLE IF EXISTS notes;

-- Thèmes (cf. models.py::NoteTheme) — registre ouvert, seedé avec les 4 thèmes demandés
-- dans docs/Notes.md, l'utilisateur peut en ajouter/renommer/recolorer librement ensuite.
CREATE TABLE IF NOT EXISTS note_themes (
    id          UUID PRIMARY KEY,
    name        VARCHAR NOT NULL UNIQUE,
    icon        VARCHAR NOT NULL DEFAULT '📁',
    color       VARCHAR NOT NULL DEFAULT '#8b949e',
    created_at  TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON note_themes TO cbr_app;
INSERT INTO note_themes (id, name, icon, color) VALUES
    (gen_random_uuid(), 'Cybersécurité', '🛡️', '#f85149'),
    (gen_random_uuid(), 'Réseau', '🌐', '#58a6ff'),
    (gen_random_uuid(), 'Système', '💻', '#3fb950'),
    (gen_random_uuid(), 'IA', '🧠', '#a371f7')
ON CONFLICT (name) DO NOTHING;

-- Sujets (fiches de cours, cf. models.py::NoteSubject) — contenu Markdown.
CREATE TABLE IF NOT EXISTS note_subjects (
    id                UUID PRIMARY KEY,
    theme_id          UUID NOT NULL REFERENCES note_themes(id) ON DELETE CASCADE,
    title             VARCHAR NOT NULL,
    content_markdown  TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ DEFAULT now(),
    updated_at        TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_note_subjects_theme_id ON note_subjects(theme_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON note_subjects TO cbr_app;

-- Images insérées dans un sujet (cf. models.py::NoteImage, services/note_images.py) —
-- fichier sur disque (volume note_images), même principe que documents/incident_attachments.
CREATE TABLE IF NOT EXISTS note_images (
    id               UUID PRIMARY KEY,
    subject_id       UUID REFERENCES note_subjects(id) ON DELETE CASCADE,
    filename         VARCHAR NOT NULL,
    stored_filename  VARCHAR NOT NULL,
    size_bytes       INTEGER NOT NULL,
    uploaded_at      TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON note_images TO cbr_app;

-- Module Agents (12/08/2026, Sécurité > Agents) — agent Rust posé sur les postes Windows/
-- Linux, complète le scan centralisé SSH/WinRM pour les postes que celui-ci atteint mal.
-- `collection_method` distingue comment un actif est ACTIVEMENT scanné (service_account =
-- pull existant inchangé ; agent = push par un agent enrôlé), séparé de `source` qui
-- documente comment il a été DÉCOUVERT/importé (cf. models.py::Asset).
ALTER TABLE assets ADD COLUMN IF NOT EXISTS collection_method VARCHAR DEFAULT 'service_account';

-- Identité d'appareil non-humaine (cf. models.py::Agent) — révocation par flag (status/
-- revoked_at), pas de suppression : un agent est une identité digne d'audit trail, plus
-- proche de users.is_active que de sessions (supprimée pour de bon au logout).
CREATE TABLE IF NOT EXISTS agents (
    id               UUID PRIMARY KEY,
    asset_id         UUID REFERENCES assets(id) ON DELETE SET NULL,
    hostname         VARCHAR NOT NULL,
    os               VARCHAR NOT NULL,
    credential_hash  VARCHAR NOT NULL UNIQUE,
    status           VARCHAR NOT NULL DEFAULT 'enrolled',
    enrolled_at      TIMESTAMPTZ DEFAULT now(),
    last_seen_at     TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ,
    revoked_by       VARCHAR
);
CREATE INDEX IF NOT EXISTS idx_agents_asset_id ON agents(asset_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON agents TO cbr_app;

-- Jeton d'enrôlement à usage unique (cf. models.py::AgentEnrollmentToken) — même principe
-- TOFU que services/ssh_trust.py : échangé une seule fois (used_at posé), jamais réutilisable,
-- jamais de ré-apprentissage silencieux. asset_id nullable : un jeton "libre" laisse le
-- premier check-in de l'agent créer l'actif lui-même (poste encore inconnu d'Allsafe).
CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id                 UUID PRIMARY KEY,
    token_hash         VARCHAR NOT NULL UNIQUE,
    asset_id           UUID REFERENCES assets(id) ON DELETE CASCADE,
    label              VARCHAR,
    created_by         VARCHAR NOT NULL,
    created_at         TIMESTAMPTZ DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    used_at            TIMESTAMPTZ,
    used_by_agent_id   UUID REFERENCES agents(id) ON DELETE SET NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_enrollment_tokens TO cbr_app;

-- Version du binaire allsafe-agent (13/08/2026), déclarée à chaque check-in — pas de
-- mécanisme de mise à jour automatique côté agent (MVP), cette colonne sert juste à
-- repérer côté Allsafe quels postes tournent une version périmée (cf. routers/agents.py::
-- CURRENT_AGENT_VERSION). NULL pour un agent enrôlé avant l'ajout de ce champ, tant qu'il
-- n'a pas encore fait de check-in avec un binaire qui le déclare.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_version VARCHAR;

-- Scan à la demande + rapport de coupure (13/08/2026, boucle persistante de l'agent,
-- cf. agent/src/daemon.rs) — pending_scan_requested_at posé par un admin, lu seulement par
-- l'agent (jamais l'inverse, CLAUDE.md §1) ; last_gap_* déclaré par l'agent à son prochain
-- check-in réussi après une coupure, jamais effacé silencieusement.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS pending_scan_requested_at TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_gap_started_at TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_gap_failed_attempts INTEGER;

-- Enrôlement à l'échelle (13/08/2026) — un jeton devient réutilisable (max_uses/use_count)
-- au lieu de strictement à usage unique (used_at/used_by_agent_id, retirés : refonte propre,
-- aucune donnée de production à préserver sur ce schéma, cf. models.py::AgentEnrollmentToken).
-- Agent.enrollment_token_id reprend la traçabilité qu'offrait used_by_agent_id, en sens
-- inverse et sans limite à un seul agent.
ALTER TABLE agent_enrollment_tokens ADD COLUMN IF NOT EXISTS max_uses INTEGER NOT NULL DEFAULT 1;
ALTER TABLE agent_enrollment_tokens ADD COLUMN IF NOT EXISTS use_count INTEGER NOT NULL DEFAULT 0;
UPDATE agent_enrollment_tokens SET use_count = 1 WHERE used_at IS NOT NULL AND use_count = 0;
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS used_at;
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS used_by_agent_id;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS enrollment_token_id UUID REFERENCES agent_enrollment_tokens(id) ON DELETE SET NULL;

-- Badge "Nouveau" sur Actifs (13/08/2026, demande utilisateur, affiché 24h après création).
-- Colonne ajoutée SANS défaut d'abord, backfillée à une date sentinelle passée pour tous les
-- actifs déjà en base — sinon le DEFAULT now() les daterait tous du jour de cette migration et
-- ils apparaîtraient tous "nouveaux" pendant 24h, à l'exact opposé de l'intention du badge. Le
-- DEFAULT n'est posé qu'ENSUITE, donc seuls les actifs insérés après cette migration l'utilisent.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;
UPDATE assets SET created_at = '2020-01-01T00:00:00Z' WHERE created_at IS NULL;
ALTER TABLE assets ALTER COLUMN created_at SET DEFAULT now();

-- KEV (17/08/2026, cf. docs/MATCHING.md § Exploitation active) — CISA Known Exploited
-- Vulnerabilities, source publique gratuite sans clé (services/kev_fetcher.py). Index partiel
-- (pas un index plein sur 191k lignes dont l'immense majorité est kev=false) pour que le filtre
-- "KEV" reste rapide sur CVEs.jsx/Vulnerabilities.jsx.
ALTER TABLE cves ADD COLUMN IF NOT EXISTS kev BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS kev_date_added DATE;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS kev_ransomware BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev) WHERE kev = true;

-- Maturité d'exploit (17/08/2026, même session) — présence dans le framework Metasploit
-- (services/exploit_maturity_fetcher.py), équivalent gratuit de la définition même de
-- Cyberwatch ("rouge = présent dans Metasploit"). msf_best_rank reprend l'échelle de fiabilité
-- native du framework (0=manual à 600=excellent), pas une échelle réinventée.
ALTER TABLE cves ADD COLUMN IF NOT EXISTS msf_module BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS msf_best_rank INTEGER;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS msf_module_count INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_cves_msf_module ON cves(msf_module) WHERE msf_module = true;

-- CVSS-BTE (17/08/2026, même session) — score CVSS v3.1 Temporal+Environmental réel, par
-- (CVE, actif) donc porté par Vulnerability et non CVE (cf. services/cvss_bte.py). Coexiste
-- avec risk_score existant (formule maison cvss×epss×criticité) sans le remplacer — décision
-- utilisateur, cf. plan de session. cvss_bte_vector conserve le détail E/RL/RC/CR/IR/AR pour
-- traçabilité, même esprit que patch_check_result.
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_bte FLOAT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_bte_vector VARCHAR;

-- Durcissement étoffé (17/08/2026, cf. docs/AGENTS.md § Checks collectés) — nouveau type
-- d'actif "website" : `url` est la seule donnée nécessaire, `web_compliance` porte ses checks
-- passifs (en-têtes HTTP, protocole TLS), même principe que `network_compliance` déjà en place
-- pour asset_type="network" (cf. services/web_hardening.py).
ALTER TABLE assets ADD COLUMN IF NOT EXISTS url VARCHAR;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS web_compliance JSON;

-- Politiques de scan planifié par criticité (17/08/2026, cf. models.py::ScanPolicy) — 4 lignes
-- fixes (une par valeur de asset.tags.criticite), éditables depuis Paramètres > Intégrations,
-- pilotant services/scan_policy.py via le poller horaire tasks.scheduled_tasks.check_scan_policies.
-- Seed par défaut : critique en quotidien minuit, le reste en hebdomadaire dimanche minuit
-- (weekday : 0=lundi..6=dimanche, cf. date.weekday()) — chaque ligne reste éditable ensuite
-- indépendamment, ce seed ne fait que reproduire la demande initiale de l'utilisateur.
CREATE TABLE IF NOT EXISTS scan_policies (
    id         UUID PRIMARY KEY,
    criticite  VARCHAR NOT NULL UNIQUE,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    frequency  VARCHAR NOT NULL,
    hour       INTEGER NOT NULL DEFAULT 0,
    weekday    INTEGER,
    updated_at TIMESTAMPTZ DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_policies TO cbr_app;
INSERT INTO scan_policies (id, criticite, frequency, hour, weekday) VALUES
    (gen_random_uuid(), 'critique', 'daily',  0, NULL),
    (gen_random_uuid(), 'haute',    'weekly', 0, 6),
    (gen_random_uuid(), 'moyenne',  'weekly', 0, 6),
    (gen_random_uuid(), 'faible',   'weekly', 0, 6)
ON CONFLICT (criticite) DO NOTHING;

-- Journal "actif supprimé" (18/08/2026, cf. models.py::AssetDeletionLog) — la ligne
-- `assets` disparaît sans laisser de trace à la suppression, contrairement à un ajout
-- (assets.created_at, toujours consultable) : sans ce journal, le bandeau "depuis votre
-- dernière visite" du Dashboard ne pourrait jamais signaler une suppression après coup.
-- Pas de FK sur assets (l'actif n'existe plus par définition) — même raisonnement que
-- patch_check_asset_completions ci-dessus, asset_name/hostname dupliqués en texte.
CREATE TABLE IF NOT EXISTS asset_deletion_logs (
    id          UUID PRIMARY KEY,
    asset_name  VARCHAR NOT NULL,
    hostname    VARCHAR,
    asset_type  VARCHAR,
    deleted_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_deletion_logs_deleted_at ON asset_deletion_logs(deleted_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON asset_deletion_logs TO cbr_app;

-- « Mot de passe oublié » (18/08/2026, cf. models.py::PasswordResetRequest) — pas d'infra
-- SMTP dans ce projet (cf. routers/users.py) : la demande créée depuis Login.jsx (public)
-- reste visible par un admin (Administration > Utilisateurs) jusqu'à traitement manuel
-- (mot de passe provisoire + must_change_password, communiqué hors application). CASCADE
-- sur user_id : la demande n'a plus lieu d'être si le compte est supprimé avant traitement.
CREATE TABLE IF NOT EXISTS password_reset_requests (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message      TEXT,
    status       VARCHAR NOT NULL DEFAULT 'pending',
    requested_at TIMESTAMPTZ DEFAULT now(),
    resolved_at  TIMESTAMPTZ,
    resolved_by  VARCHAR
);
CREATE INDEX IF NOT EXISTS idx_password_reset_requests_user_id ON password_reset_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_requests_status ON password_reset_requests(status);
GRANT SELECT, INSERT, UPDATE, DELETE ON password_reset_requests TO cbr_app;

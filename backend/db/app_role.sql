-- ============================================================================
-- app_role.sql — Rôle applicatif à privilèges réduits (least privilege).
--
-- L'app CBR tourne avec `cbr_app` (DML seulement, NON superuser, aucun DDL) au
-- lieu du superuser `cybervuln` (réservé désormais à l'admin/migrations/déception).
-- Bénéfice clé : cbr_app n'a **pas** DELETE sur `security_events` → un attaquant
-- disposant des creds de l'app ne peut pas effacer les traces de déception.
--
-- Idempotent. Rejouable. Le mot de passe est posé séparément (ALTER ROLE ...
-- PASSWORD) pour ne pas le stocker dans ce fichier. À rejouer sur toute base.
--
-- ⚠️ Conséquence : create_all (init_db) n'émet aucun DDL sur une base existante,
-- donc cbr_app suffit. Mais une NOUVELLE table de modèle doit être créée par
-- l'owner (cybervuln) AVANT le déploiement, sinon le démarrage échoue.
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cbr_app') THEN
        CREATE ROLE cbr_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
    END IF;
END $$;

GRANT CONNECT ON DATABASE cybervuln TO cbr_app;
GRANT USAGE   ON SCHEMA public      TO cbr_app;

-- DML sur l'existant (les tables restent la propriété de cybervuln)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO cbr_app;
GRANT USAGE, SELECT, UPDATE          ON ALL SEQUENCES  IN SCHEMA public TO cbr_app;

-- Table d'audit de déception : lecture + acquittement (colonnes limitées)
-- uniquement. Pas d'INSERT (les événements naissent des fonctions SECURITY
-- DEFINER), pas de DELETE (traces inviolables même avec les creds app volées).
REVOKE ALL ON security_events FROM cbr_app;
GRANT SELECT ON security_events TO cbr_app;
GRANT UPDATE (acknowledged, ack_by, ack_at) ON security_events TO cbr_app;

-- Futures tables/séquences créées par l'owner → DML auto-accordé à cbr_app
-- (évite de re-grant à la main à chaque nouvelle table créée par l'owner).
ALTER DEFAULT PRIVILEGES FOR ROLE cybervuln IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cbr_app;
ALTER DEFAULT PRIVILEGES FOR ROLE cybervuln IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO cbr_app;

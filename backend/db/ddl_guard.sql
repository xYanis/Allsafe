-- ============================================================================
-- ddl_guard.sql — Event trigger : bloque ET journalise toute commande DDL lancée
-- par un rôle NON autorisé (défense active / défense en profondeur).
--
-- Whitelist : seul `cybervuln` (superuser d'admin/migrations) peut faire du DDL.
-- Tout autre rôle (cbr_app, rôles leurres, ou un rôle compromis) qui tente un
-- CREATE / ALTER / DROP / GRANT... est bloqué (RAISE EXCEPTION) et l'attempt est
-- enregistré dans security_events (source = 'ddl_attempt') → bannière/console.
--
-- ⚠️ Journalisation AUTONOME (dblink) : le RAISE EXCEPTION qui bloque annule la
-- transaction courante — donc un simple INSERT serait annulé avec elle. dblink
-- ouvre une connexion séparée qui committe le log indépendamment. Connexion
-- locale en trust (cf. pg_hba `host ... 127.0.0.1/32 trust`).
--
-- Idempotent. À rejouer sur toute base (comme deception_setup.sql / app_role.sql).
--
-- Rappel : `cbr_app` n'a déjà PAS le droit de faire du DDL — ce trigger est une
-- 2e barrière (rôle qui gagnerait des droits) et surtout donne la VISIBILITÉ que
-- les privilèges seuls ne donnent pas. create_all sur base existante n'émet aucun
-- DDL, donc aucun faux positif en fonctionnement normal (une nouvelle table de
-- modèle doit toujours être créée par `cybervuln` avant déploiement).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS dblink;

-- Verrou : dblink est exécutable par PUBLIC par défaut → un rôle compromis
-- pourrait s'en servir pour se connecter ailleurs (mouvement latéral). On le
-- réserve au superuser (et donc à nos fonctions SECURITY DEFINER qui tournent
-- avec les droits de cybervuln).
DO $lock$
DECLARE f record;
BEGIN
  FOR f IN
    SELECT p.oid::regprocedure AS sig
    FROM pg_depend d
    JOIN pg_extension e ON e.oid = d.refobjid AND e.extname = 'dblink'
    JOIN pg_proc p ON p.oid = d.objid
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f.sig);
  END LOOP;
END $lock$;

CREATE OR REPLACE FUNCTION guard_ddl()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public
AS $$
DECLARE v_sql text;
BEGIN
    -- session_user = rôle réellement authentifié (insensible à SET ROLE et à
    -- SECURITY DEFINER) : le bon critère pour « qui s'est connecté ».
    IF session_user IN ('cybervuln') THEN
        RETURN;   -- admin/migrations autorisés
    END IF;

    -- Log autonome (committe même si le RAISE EXCEPTION annule la transaction).
    v_sql := format(
        'INSERT INTO security_events(source, object_name, operation, db_user, client_addr, detail) '
        'VALUES (%L, %L, %L, %L, %L::inet, %L::jsonb)',
        'ddl_attempt', TG_TAG, 'DDL', session_user,
        host(inet_client_addr()),
        jsonb_build_object('command', TG_TAG, 'event', TG_EVENT, 'session_user', session_user)::text
    );
    BEGIN
        PERFORM dblink_exec('host=127.0.0.1 dbname=' || current_database() || ' user=cybervuln', v_sql);
    EXCEPTION WHEN OTHERS THEN
        NULL;   -- un échec de log ne doit jamais empêcher le blocage
    END;

    -- Double canal : le WARNING part dans le log serveur (hors transaction),
    -- second témoin si jamais le log en base était contourné.
    RAISE WARNING 'SECURITY DECEPTION: ddl_attempt % by "%" from %', TG_TAG, session_user, inet_client_addr();

    RAISE EXCEPTION 'Commande DDL non autorisée bloquée (%). Incident de sécurité journalisé.', TG_TAG
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- ddl_command_start couvre CREATE / ALTER / DROP / GRANT / REVOKE / COMMENT... des
-- objets de la base. Ne couvre pas les objets partagés (rôles, tablespaces, ALTER
-- SYSTEM) — limite native des event triggers ; l'essentiel (schéma + objets
-- leurres) est protégé.
DROP EVENT TRIGGER IF EXISTS trg_guard_ddl;
CREATE EVENT TRIGGER trg_guard_ddl ON ddl_command_start EXECUTE FUNCTION guard_ddl();

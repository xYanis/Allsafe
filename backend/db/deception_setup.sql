-- ============================================================================
-- deception_setup.sql — Objets de déception (honeypots DB) pour CBR.
--
-- Principe : AUCUN code applicatif ne référence les objets leurres ci-dessous
-- (vues api_keys/app_users/ssh_credentials_backup/admin_tokens, rôles admin/root/
-- dba/backup/postgres_admin). Tout accès à l'un d'eux = intrusion (zéro faux
-- positif). La détection se fait AU MOMENT DE LA REQUÊTE via des fonctions
-- SECURITY DEFINER — pas de parsing de logs.
--
-- Idempotent : réexécutable sans dommage. À rejouer sur toute base :
--   docker compose exec -T db psql -U cybervuln -d cybervuln -f - < backend/db/deception_setup.sql
--
-- ⚠️ Ne JAMAIS ajouter de référence à ces objets dans le code de l'app : ce sont
-- des pièges, leur seule légitimité d'accès est un attaquant.
-- ============================================================================

-- ─── Couche D : socle d'alerte ──────────────────────────────────────────────
-- Table réelle (pas un leurre) : journal des événements de déception. Lue par
-- l'API /api/security/events. Modèle SQLAlchemy miroir : SecurityEvent (models.py).
CREATE TABLE IF NOT EXISTS security_events (
    id           bigserial PRIMARY KEY,
    occurred_at  timestamptz NOT NULL DEFAULT now(),
    source       text        NOT NULL,   -- honey_read | honey_write | decoy_role
    object_name  text,                   -- vue/table leurre touchée
    operation    text,                   -- SELECT | INSERT | UPDATE | DELETE
    db_user      text        NOT NULL DEFAULT current_user,
    client_addr  inet,
    detail       jsonb,
    acknowledged boolean     NOT NULL DEFAULT false,
    ack_by       text,
    ack_at       timestamptz
);
CREATE INDEX IF NOT EXISTS idx_security_events_unack
    ON security_events (occurred_at DESC) WHERE NOT acknowledged;

-- Fonction de journalisation. SECURITY DEFINER : s'exécute avec les droits du
-- propriétaire, donc un rôle leurre SANS droit sur security_events logge quand
-- même. Ne fait jamais échouer la requête de l'attaquant (ne pas se trahir).
-- RAISE WARNING → double trace dans le log serveur (hors table, contre l'effacement).
CREATE OR REPLACE FUNCTION record_security_event(
    p_source text, p_object text, p_op text, p_detail jsonb DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    INSERT INTO security_events(source, object_name, operation, db_user, client_addr, detail)
    VALUES (p_source, p_object, p_op, current_user, inet_client_addr(), p_detail);
    RAISE WARNING 'SECURITY DECEPTION: % % on % by "%" from %',
        p_source, COALESCE(p_op,''), COALESCE(p_object,''), current_user, inet_client_addr();
EXCEPTION WHEN OTHERS THEN
    NULL;  -- ne jamais propager d'erreur vers l'attaquant
END;
$$;

-- Écriture sur une vue leurre (INSTEAD OF) : logge et avale silencieusement.
CREATE OR REPLACE FUNCTION honey_view_write() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    PERFORM record_security_event('honey_write', TG_TABLE_NAME, TG_OP, NULL);
    RETURN NULL;  -- l'écriture n'a aucun effet, mais aucune erreur n'est levée
END;
$$;

-- ─── Couches B + C : vues leurres (lecture journalisée) + honeytokens ───────
-- Chaque "table" juteuse est en réalité une VUE adossée à une fonction qui
-- journalise à la lecture et renvoie des faux enregistrements crédibles (les
-- honeytokens, couche C — valeurs bidon self-hosted, aucun callback externe).

-- api_keys
CREATE OR REPLACE FUNCTION honey_api_keys()
RETURNS TABLE(id int, service text, api_key text, environment text, created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    PERFORM record_security_event('honey_read', 'api_keys', 'SELECT', NULL);
    RETURN QUERY SELECT * FROM (VALUES
        (1, 'stripe'::text,   'sk_live_51NfAqL2eZvKYxT8pQ3rW9hBc'::text, 'production'::text, (now() - interval '210 days')::timestamptz),
        (2, 'aws_iam'::text,  'AKIA4JF7K2MNPQ6RSTUV'::text,              'production'::text, (now() - interval '160 days')::timestamptz),
        (3, 'sendgrid'::text, 'SG.aB3dEf6HiJkLmNoPqRsT.uVwXyZ012345'::text,'production'::text,(now() - interval '95 days')::timestamptz)
    ) AS t(id, service, api_key, environment, created_at);
END;
$$;
CREATE OR REPLACE VIEW api_keys AS SELECT * FROM honey_api_keys();

-- app_users
CREATE OR REPLACE FUNCTION honey_app_users()
RETURNS TABLE(id int, username text, email text, password_hash text, role text, last_login timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    PERFORM record_security_event('honey_read', 'app_users', 'SELECT', NULL);
    RETURN QUERY SELECT * FROM (VALUES
        (1, 'admin'::text,     'admin@aer.loc'::text,   '$2b$12$Kx8pQzR3sT7uVwXyZ0aBcOeFgHiJkLmNoPqRsTuVwXyZ012345678'::text, 'superadmin'::text, (now() - interval '2 days')::timestamptz),
        (2, 'svc-backup'::text,'backup@aer.loc'::text,  '$2b$12$aB3cDeF6gHiJkLmNoPqRsOtUvWxYz012345678aBcDeFgHiJkLmNoP'::text, 'admin'::text,      (now() - interval '9 days')::timestamptz)
    ) AS t(id, username, email, password_hash, role, last_login);
END;
$$;
CREATE OR REPLACE VIEW app_users AS SELECT * FROM honey_app_users();

-- ssh_credentials_backup (honeytoken "actif privilégié" DC-PRIV-01)
CREATE OR REPLACE FUNCTION honey_ssh_credentials_backup()
RETURNS TABLE(id int, hostname text, ip_address text, username text, password text, note text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    PERFORM record_security_event('honey_read', 'ssh_credentials_backup', 'SELECT', NULL);
    RETURN QUERY SELECT * FROM (VALUES
        (1, 'DC-PRIV-01'::text, '10.0.0.5'::text,  'Administrateur'::text, 'W1nter#2026!Dom'::text, 'contrôleur de domaine principal'::text),
        (2, 'BACKUP-NAS'::text, '10.0.0.20'::text, 'root'::text,           'nas-r00t-2026'::text,   'sauvegardes hebdo'::text)
    ) AS t(id, hostname, ip_address, username, password, note);
END;
$$;
CREATE OR REPLACE VIEW ssh_credentials_backup AS SELECT * FROM honey_ssh_credentials_backup();

-- admin_tokens
CREATE OR REPLACE FUNCTION honey_admin_tokens()
RETURNS TABLE(id int, label text, token text, scope text, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    PERFORM record_security_event('honey_read', 'admin_tokens', 'SELECT', NULL);
    RETURN QUERY SELECT * FROM (VALUES
        (1, 'ci-deploy'::text,  'cbr_pat_9fK2mNpQ7rStUvWxYz012345'::text, 'admin:all'::text,   (now() + interval '120 days')::timestamptz),
        (2, 'grafana-sa'::text, 'cbr_pat_aB3cDeF6gHiJkLmNoPqRsT'::text,   'read:metrics'::text,(now() + interval '300 days')::timestamptz)
    ) AS t(id, label, token, scope, expires_at);
END;
$$;
CREATE OR REPLACE VIEW admin_tokens AS SELECT * FROM honey_admin_tokens();

-- Triggers d'écriture + ouverture en lecture à tous (l'app légitime n'y touche
-- jamais ; un rôle leurre ou une réutilisation des creds app s'y trahit).
DO $$
DECLARE v text;
BEGIN
    FOREACH v IN ARRAY ARRAY['api_keys','app_users','ssh_credentials_backup','admin_tokens'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I_wr ON %I', v, v);
        EXECUTE format('CREATE TRIGGER %I_wr INSTEAD OF INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION honey_view_write()', v, v);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO PUBLIC', v);
    END LOOP;
END $$;

-- ─── Couche A : rôles PostgreSQL leurres ────────────────────────────────────
-- Noms alléchants jamais utilisés par l'app (qui se connecte en "cybervuln").
-- Mot de passe aléatoire inconnu : leur existence/usage est le piège. Ils n'ont
-- accès à AUCUNE table réelle (non accordé) — seulement aux vues leurres via le
-- GRANT PUBLIC ci-dessus, donc toute activité de données de leur part se trahit.
-- log_connections trace en plus la connexion (forensique).
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['admin','root','dba','backup','postgres_admin'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', r, replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''));
        END IF;
        -- défense : pas d'accès aux tables réelles de l'app
        EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys, app_users, ssh_credentials_backup, admin_tokens TO %I', r);
    END LOOP;
END $$;

-- Journalisation des connexions (forensique des rôles leurres) — persiste dans
-- postgresql.auto.conf du volume, pas besoin de monter un fichier.
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';
SELECT pg_reload_conf();

-- security_events : lecture/insertion ok pour l'app ; empêcher l'effacement des
-- traces par un rôle non-propriétaire (un attaquant en cybervuln=superuser peut
-- toujours contourner — limite assumée, d'où le RAISE WARNING en doublon).
REVOKE DELETE, UPDATE ON security_events FROM PUBLIC;

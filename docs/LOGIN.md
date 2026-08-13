# Architecture & Spécification : Module d'Authentification Locale & Préparation SSO (Microsoft Entra ID)

Ce document est la spécification technique pour l'implémentation de l'authentification et de l'autorisation (RBAC) pour une application de cybersécurité.

## Objectif Stratégique (En deux temps)
- **PHASE 1 (Immersion & Dev immédiat) :** Implémenter une authentification locale sécurisée (Email / Mot de passe crypté) avec gestion de session et contrôle d'accès basé sur les rôles (RBAC).
- **PHASE 2 (Évolution future sans réécriture) :** Activer l'authentification SSO d'entreprise via **Microsoft Entra ID (anciennement Azure AD)** en protocole **OpenID Connect (OIDC / OAuth 2.0 avec PKCE)**.

---

## 1. Exigences de Cybersécurité & Principes de Conception (Secure by Design)

1. **Zéro Token dans le LocalStorage (Anti-XSS) :**
   - La gestion des sessions client/serveur doit se faire **exclusivement par Cookies HTTP-only, Secure et SameSite=Lax/Strict**.
   - Aucun jeton ou identifiant de session ne doit être lisible par JavaScript côté navigateur.
2. **Hachage Moderne des Mots de Passe (Phase 1) :**
   - Les mots de passe locaux doivent être hachés en utilisant **Argon2id** (recommandé) ou **bcrypt** (cost minimal : 12).
3. **Séparation entre Identité (AuthN) et Autorisation (AuthZ) :**
   - Une table `users` centralise les profils.
   - Une table `user_identities` sépare la méthode de connexion (local aujourd'hui, Azure AD demain).
   - Les rôles et permissions (`roles`, `user_roles`) restent internes à l'application et ne dépendent pas du moyen de connexion.
4. **Traçabilité & Audit (Mandatoire pour une App de Cybersécurité) :**
   - Journaliser de manière infalsifiable chaque tentative de login (réussite/échec), déconnexion, création de session et changement de privilège.

---

## 2. Schéma de Base de Données SQL (Prêt pour Phase 1 + Phase 2)

Ce schéma est conçu pour fonctionner **immédiatement avec le login local**, tout en ayant déjà la structure nécessaire pour accueillir Microsoft Entra ID.

```sql
-- 1. Table principale des utilisateurs
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Table des identités / méthodes d'authentification
-- PHASE 1 : provider = 'local', provider_subject_id = email, password_hash est rempli.
-- PHASE 2 : provider = 'azure-ad', provider_subject_id = l'OID/SUB Azure, password_hash est NULL.
CREATE TABLE user_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- 'local' ou 'azure-ad'
    provider_subject_id VARCHAR(255) NOT NULL, -- Email (en local) ou 'sub'/'oid' (SSO Azure)
    password_hash VARCHAR(255) NULL, -- Utilisé UNIQUEMENT lorsque provider = 'local'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_provider_subject UNIQUE (provider, provider_subject_id)
);

-- 3. Modèle RBAC : Rôles & Autorisations
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL, -- Ex: 'admin', 'sec_analyst', 'auditor', 'read_only'
    description TEXT
);

CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

-- 4. Table des sessions actives
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash VARCHAR(255) UNIQUE NOT NULL, -- Hash SHA-256 du token aléatoire stocké dans le cookie client
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Journal d'Audit de Sécurité
CREATE TABLE auth_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL, -- 'LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'ROLE_CHANGE', 'SSO_LOGIN'
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    email_attempt VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
//! Client HTTPS vers `backend/routers/agents.py` — `enroll()` échange le jeton
//! d'enrôlement (premier contact, pas de credential encore émis) ; `checkin()` pousse
//! le résultat de collecte via l'en-tête `X-Agent-Token` (cf. `auth_deps.py::require_agent`).

use crate::model::{CheckinPayload, EnrollRequest, EnrollResponse, PendingResponse};
use anyhow::{bail, Context, Result};

/// Avertissement HTTPS (18/08/2026, cf. audit/AUDIT_SECURITE.md #17) — appelé sur le
/// chemin de mise à jour (`install::check_update`/`apply_update`), le plus critique : c'est
/// là que transite le `.msi` exécuté ensuite avec des droits admin (#13). Un MITM réseau
/// local (ARP spoofing/VLAN partagé, même classe que le SSH déjà corrigé) suffirait sinon à
/// substituer le paquet. **Non bloquant pour l'instant** (décision explicite, 18/08/2026) :
/// le serveur de prod tourne encore en HTTP aujourd'hui (`COOKIE_SECURE=false`, aucun
/// reverse-proxy TLS en place, cf. CHECKLIST_DOCKER.md) — bloquer casserait la mise à jour
/// en conditions réelles. Combiné au check SHA-256 (#13), cette combinaison ne protège pas
/// contre un MITM actif tant que ce n'est qu'un avertissement (rien n'empêche de réécrire le
/// hash publié ET le .msi dans la même requête HTTP) — **à repasser en blocage strict au
/// moment du déploiement du reverse-proxy TLS**, cf. le reste des points HTTPS de
/// CHECKLIST_DOCKER.md. Le reste des appels (`enroll`/`pending`/`checkin`) n'est même pas
/// averti pour l'instant, même raisonnement.
pub fn warn_if_not_https(server: &str) {
    if !server.starts_with("https://") {
        eprintln!(
            "⚠️  Serveur Allsafe joint en HTTP ({server}) — la vérification d'intégrité du \
             paquet de mise à jour (SHA-256) ne protège pas contre une interception active \
             tant que ce canal n'est pas en HTTPS. À corriger avant un déploiement de parc \
             (cf. CHECKLIST_DOCKER.md § reverse-proxy TLS)."
        );
    }
}

/// Normalise l'URL serveur saisie par l'utilisateur (CLI `--server` ou champ GUI) avant
/// toute requête (19/08/2026, incident réel) — protège contre un schéma doublé
/// (`http://http://192.168.1.10:3000`), piège classique quand un champ de saisie est
/// pré-rempli avec `http://` et que l'utilisateur tape l'URL complète sans effacer ce
/// préfixe d'abord (cf. `ui/index.html`, qui pré-remplissait `value="http://"` au lieu
/// d'un vrai `placeholder` — corrigé le même jour, mais CLI et anciens binaires GUI restent
/// exposés à la même faute de frappe). `reqwest` ne signale pas cette erreur clairement —
/// il tente une résolution DNS littérale sur `http` comme s'il s'agissait d'un nom d'hôte
/// ("os error 11001", Windows). En cas de schéma doublé, le second (le plus interne) fait
/// foi : c'est lui qui reflète ce que l'utilisateur a réellement tapé, le premier n'étant
/// que le résidu du préremplissage.
pub fn normalize_server(server: &str) -> String {
    let mut s = server.trim();
    for prefix in ["http://", "https://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            if rest.starts_with("http://") || rest.starts_with("https://") {
                s = rest;
                break;
            }
        }
    }
    s.trim_end_matches('/').to_string()
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("construction du client HTTP")
}

pub async fn enroll(server: &str, token: &str, hostname: &str, os: &str) -> Result<EnrollResponse> {
    let url = format!("{}/api/agents/enroll", server.trim_end_matches('/'));
    let resp = client()?
        .post(&url)
        .json(&EnrollRequest { token: token.to_string(), hostname: hostname.to_string(), os: os.to_string() })
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("enrôlement refusé ({status}) : {body}");
    }
    resp.json::<EnrollResponse>().await.context("réponse d'enrôlement invalide")
}

/// Interrogée par la boucle persistante (`daemon.rs`) à intervalle court — lecture seule,
/// ne modifie rien côté serveur (le flag n'est effacé qu'au check-in qui le satisfait,
/// cf. `routers/agents.py::checkin`). Échec réseau traité comme "rien en attente" par
/// l'appelant plutôt que de faire remonter l'erreur — un scan à la demande manqué se
/// rattrape au prochain sondage, pas la peine de faire échouer tout le cycle pour ça.
pub async fn pending(server: &str, credential: &str) -> Result<PendingResponse> {
    let url = format!("{}/api/agents/pending", server.trim_end_matches('/'));
    let resp = client()?
        .get(&url)
        .header("X-Agent-Token", credential)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    if !resp.status().is_success() {
        bail!("pending refusé ({})", resp.status());
    }
    resp.json::<PendingResponse>().await.context("réponse pending invalide")
}

/// Réponse légère à un ping admin — enregistre la latence côté serveur, efface le flag.
/// Jamais de throttle, jamais d'inventaire complet (contrairement à `checkin`).
pub async fn pong(server: &str, credential: &str) -> Result<()> {
    let url = format!("{}/api/agents/pong", server.trim_end_matches('/'));
    let resp = client()?
        .post(&url)
        .header("X-Agent-Token", credential)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    if !resp.status().is_success() {
        bail!("pong refusé ({})", resp.status());
    }
    Ok(())
}

pub async fn checkin(server: &str, credential: &str, payload: &CheckinPayload) -> Result<()> {
    let url = format!("{}/api/agents/checkin", server.trim_end_matches('/'));
    let resp = client()?
        .post(&url)
        .header("X-Agent-Token", credential)
        .json(payload)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("check-in refusé ({status}) : {body}");
    }
    Ok(())
}

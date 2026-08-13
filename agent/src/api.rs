//! Client HTTPS vers `backend/routers/agents.py` — `enroll()` échange le jeton
//! d'enrôlement (premier contact, pas de credential encore émis) ; `checkin()` pousse
//! le résultat de collecte via l'en-tête `X-Agent-Token` (cf. `auth_deps.py::require_agent`).

use crate::model::{CheckinPayload, EnrollRequest, EnrollResponse, PendingResponse};
use anyhow::{bail, Context, Result};

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
pub async fn pending(server: &str, credential: &str) -> Result<bool> {
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
    Ok(resp.json::<PendingResponse>().await.context("réponse pending invalide")?.scan_requested)
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

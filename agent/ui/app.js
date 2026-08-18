// UI vanille (pas de bundler/npm — cf. tauri.conf.json::app.withGlobalTauri) : la logique
// reste entièrement côté Rust (install.rs), ce fichier ne fait que la saisie/l'affichage et
// le pont `invoke` vers les commandes Tauri déclarées dans gui.rs.
const { invoke } = window.__TAURI__.core;

function showView(name) {
  document.querySelectorAll(".view").forEach(el => {
    el.dataset.active = el.id === `view-${name}` ? "true" : "false";
  });
}

document.querySelectorAll("[data-nav]").forEach(el => {
  el.addEventListener("click", () => showView(el.dataset.nav));
});

document.getElementById("btn-quit").addEventListener("click", () => {
  invoke("cmd_quit");
});

function setStatus(elId, kind, text) {
  const el = document.getElementById(elId);
  el.textContent = text;
  if (kind) {
    el.dataset.kind = kind;
  } else {
    delete el.dataset.kind;
  }
}

function setBusy(...buttons) {
  buttons.forEach(b => (b.disabled = true));
  return () => buttons.forEach(b => (b.disabled = false));
}

// Préremplit le serveur si ce poste est déjà enrôlé (agent.json présent) — évite de
// retaper une URL déjà connue. Jamais de prérempli côté Installation (jamais de jeton
// déjà connu) ni Réparation/Désinstallation (aucun champ).
invoke("cmd_known_server").then(server => {
  if (server) {
    document.getElementById("update-server").value = server;
  }
});

// ─── Installation ───────────────────────────────────────────────────────────
const btnInstallGo = document.getElementById("btn-install-go");
btnInstallGo.addEventListener("click", async () => {
  const server = document.getElementById("install-server").value.trim();
  const token = document.getElementById("install-token").value.trim();
  if (!server || !token) {
    setStatus("install-status", "error", "Le serveur et le jeton sont obligatoires.");
    return;
  }
  setStatus("install-status", "info", "Installation en cours…");
  const release = setBusy(btnInstallGo);
  try {
    await invoke("cmd_install", { server, token });
    setStatus("install-status", "success", "Installation réussie — le poste apparaît dans Inventaire > Agents.");
  } catch (e) {
    setStatus("install-status", "error", `Échec : ${e}`);
    release();
  }
});

// ─── Réparation ─────────────────────────────────────────────────────────────
const btnRepairGo = document.getElementById("btn-repair-go");
btnRepairGo.addEventListener("click", async () => {
  setStatus("repair-status", "info", "Réparation en cours…");
  const release = setBusy(btnRepairGo);
  try {
    await invoke("cmd_repair");
    setStatus("repair-status", "success", "Service et PATH réparés.");
  } catch (e) {
    setStatus("repair-status", "error", `Échec : ${e}`);
  } finally {
    release();
  }
});

// ─── Mise à jour ────────────────────────────────────────────────────────────
const btnUpdateCheck = document.getElementById("btn-update-check");
const btnUpdateGo = document.getElementById("btn-update-go");

btnUpdateCheck.addEventListener("click", async () => {
  const server = document.getElementById("update-server").value.trim();
  if (!server) {
    setStatus("update-status", "error", "L'URL du serveur est obligatoire.");
    return;
  }
  setStatus("update-status", "info", "Vérification…");
  btnUpdateGo.disabled = true;
  const release = setBusy(btnUpdateCheck);
  try {
    const latest = await invoke("cmd_check_update", { server });
    if (latest) {
      setStatus("update-status", "info", `Nouvelle version disponible : ${latest}`);
      btnUpdateGo.disabled = false;
    } else {
      setStatus("update-status", "success", "Déjà à jour.");
    }
  } catch (e) {
    setStatus("update-status", "error", `Échec : ${e}`);
  } finally {
    release();
  }
});

btnUpdateGo.addEventListener("click", async () => {
  const server = document.getElementById("update-server").value.trim();
  setStatus("update-status", "info", "Mise à jour en cours…");
  const release = setBusy(btnUpdateGo, btnUpdateCheck);
  try {
    await invoke("cmd_apply_update", { server });
    setStatus("update-status", "success", "Mise à jour installée avec succès.");
  } catch (e) {
    setStatus("update-status", "error", `Échec : ${e}`);
    release();
  }
});

// ─── Désinstallation ────────────────────────────────────────────────────────
const btnUninstallGo = document.getElementById("btn-uninstall-go");
btnUninstallGo.addEventListener("click", async () => {
  setStatus("uninstall-status", "info", "Désinstallation en cours…");
  const release = setBusy(btnUninstallGo);
  try {
    await invoke("cmd_uninstall");
    setStatus("uninstall-status", "success", "Service désinstallé.");
  } catch (e) {
    setStatus("uninstall-status", "error", `Échec : ${e}`);
    release();
  }
});

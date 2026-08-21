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

// Fermeture automatique après une installation réussie (19/08/2026, retour utilisateur) —
// tant que cette fenêtre reste ouverte, elle EST le process qui verrouille le .exe lancé
// depuis Téléchargements (comportement Windows normal, pas un bug) : sans ce délai, rien
// n'indique qu'il faut fermer la fenêtre soi-même pour libérer le fichier, forçant à passer
// par le Gestionnaire des tâches. Uniquement sur un succès — un échec doit rester affiché,
// l'utilisateur a besoin de lire le message d'erreur.
function autoQuitAfterSuccess(elId, baseText) {
  let remaining = 3
  const el = document.getElementById(elId)
  const tick = () => {
    el.textContent = `${baseText} Fermeture automatique dans ${remaining}s…`
    if (remaining <= 0) { invoke("cmd_quit"); return }
    remaining -= 1
    setTimeout(tick, 1000)
  }
  tick()
}

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

// Barre de progression indéterminée (19/08/2026, demande explicite) — visible pendant
// qu'une opération tourne, masquée sur succès/échec (cf. style.css).
function setProgress(id, visible) {
  document.getElementById(id).hidden = !visible;
}

// Version affichée dans le bandeau (19/08/2026, demande explicite).
invoke("cmd_version").then(v => {
  document.getElementById("banner-version").textContent = `v${v}`;
}).catch(() => {});

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
  setProgress("install-progress", true);
  const release = setBusy(btnInstallGo);
  try {
    await invoke("cmd_install", { server, token });
    setProgress("install-progress", false);
    setStatus("install-status", "success", "Installation réussie — le poste apparaît dans Inventaire > Agents.");
    autoQuitAfterSuccess("install-status", "Installation réussie — le poste apparaît dans Inventaire > Agents.")
  } catch (e) {
    setProgress("install-progress", false);
    setStatus("install-status", "error", `Échec : ${e}`);
    release();
  }
});

// ─── Réparation ─────────────────────────────────────────────────────────────
const btnRepairGo = document.getElementById("btn-repair-go");
btnRepairGo.addEventListener("click", async () => {
  setStatus("repair-status", "info", "Réparation en cours…");
  setProgress("repair-progress", true);
  const release = setBusy(btnRepairGo);
  try {
    await invoke("cmd_repair");
    setStatus("repair-status", "success", "Service et PATH réparés.");
  } catch (e) {
    setStatus("repair-status", "error", `Échec : ${e}`);
  } finally {
    setProgress("repair-progress", false);
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
  setProgress("update-progress", true);
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
    setProgress("update-progress", false);
    release();
  }
});

btnUpdateGo.addEventListener("click", async () => {
  const server = document.getElementById("update-server").value.trim();
  setStatus("update-status", "info", "Mise à jour en cours…");
  setProgress("update-progress", true);
  const release = setBusy(btnUpdateGo, btnUpdateCheck);
  try {
    await invoke("cmd_apply_update", { server });
    setProgress("update-progress", false);
    const msg = "Mise à jour installée avec succès."
    setStatus("update-status", "success", msg);
    // Fermeture automatique obligatoire ici (pas juste un confort, contrairement à
    // l'installation) : sur un poste déjà installé, `apply_update` détecte l'auto-
    // verrouillage et lance `msiexec` via une aide détachée qui ATTEND la fin de cette
    // fenêtre avant de démarrer (cf. install.rs::apply_update, correctif du 19/08/2026) —
    // sans cette fermeture, la mise à jour reste bloquée indéfiniment en attente.
    autoQuitAfterSuccess("update-status", msg)
  } catch (e) {
    setProgress("update-progress", false);
    setStatus("update-status", "error", `Échec : ${e}`);
    release();
  }
});

// ─── Désinstallation ────────────────────────────────────────────────────────
const btnUninstallGo = document.getElementById("btn-uninstall-go");
btnUninstallGo.addEventListener("click", async () => {
  setStatus("uninstall-status", "info", "Désinstallation en cours…");
  setProgress("uninstall-progress", true);
  const release = setBusy(btnUninstallGo);
  try {
    await invoke("cmd_uninstall");
    setProgress("uninstall-progress", false);
    const msg = "Service et fichiers supprimés."
    setStatus("uninstall-status", "success", msg);
    // Fermeture automatique obligatoire (19/08/2026, même raison que la mise à jour ci-dessus) :
    // le dossier d'installation contient cet exe lui-même, une aide détachée attend la
    // fermeture de cette fenêtre avant de le supprimer (cf. install.rs::uninstall).
    autoQuitAfterSuccess("uninstall-status", msg)
  } catch (e) {
    setProgress("uninstall-progress", false);
    setStatus("uninstall-status", "error", `Échec : ${e}`);
    release();
  }
});

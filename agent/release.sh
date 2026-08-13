#!/bin/bash
# Build + empaquette allsafe-agent (Linux .deb + Windows .msi) en une seule commande —
# regroupe les ~4 commandes Docker enchaînées à la main lors des sessions de build
# précédentes (cf. STATUS.md 12-13/08/2026). Toujours séquentiel, jamais deux conteneurs
# Docker en parallèle sur le même cache Cargo (.cargo-cache) : un piège de verrou de
# fichier déjà rencontré (flock peu fiable sur bind-mount WSL2/Docker Desktop).
#
# Usage : ./release.sh   (depuis n'importe où, se recale sur son propre dossier)
#
# Ne touche PAS backend/routers/agents.py::CURRENT_AGENT_VERSION — ce bump-là reste
# volontairement manuel (cf. README.md § Mise à jour), publier un binaire n'implique pas
# forcément de vouloir l'annoncer tout de suite comme "la" version courante.
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$AGENT_DIR"

CARGO_VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
WIX_VERSION=$(grep -m1 'Version="' wix/main.wxs | sed -E 's/.*Version="([^"]+)".*/\1/')

echo "== allsafe-agent release =="
echo "Cargo.toml   : $CARGO_VERSION"
echo "wix/main.wxs : $WIX_VERSION"

# Piège du 13/08/2026 : wix/main.wxs porte sa propre Version (4 segments), séparée de
# Cargo.toml — oubliée une fois, le .msi gardait un ProductVersion périmé alors que le
# binaire à l'intérieur était déjà à jour. On bloque plutôt que de publier un paquet
# incohérent.
if [ "$WIX_VERSION" != "${CARGO_VERSION}.0" ]; then
    echo
    echo "ERREUR : version wix/main.wxs ($WIX_VERSION) ne correspond pas à Cargo.toml ($CARGO_VERSION)."
    echo "Bumpez Version=\"${CARGO_VERSION}.0\" dans wix/main.wxs avant de publier."
    exit 1
fi

mkdir -p .cargo-cache

echo
echo "-- 1/4 : build Linux + .deb --"
docker run --rm -v "$AGENT_DIR:/agent" -v "$AGENT_DIR/.cargo-cache:/usr/local/cargo/registry" -w /agent rust:1-bookworm \
    bash -c "cargo build --release && cargo install cargo-deb --quiet && cargo deb"

echo
echo "-- 2/4 : cross-compile Windows (mingw-w64) --"
docker run --rm -v "$AGENT_DIR:/agent" -v "$AGENT_DIR/.cargo-cache:/usr/local/cargo/registry" -w /agent rust:1-bookworm bash -c "
set -e
apt-get -qq update >/dev/null
apt-get -qq install -y mingw-w64 >/dev/null
rustup target add x86_64-pc-windows-gnu >/dev/null
cargo build --release --target x86_64-pc-windows-gnu
"

echo
echo "-- 3/4 : .msi (wixl -a x64) --"
docker run --rm -v "$AGENT_DIR:/agent" -w /agent debian:bookworm bash -c "
set -e
apt-get -qq update >/dev/null
apt-get -qq install -y wixl msitools >/dev/null 2>&1
wixl -a x64 -v wix/main.wxs -o allsafe-agent.msi
msiinfo suminfo allsafe-agent.msi | grep Template
msiinfo export allsafe-agent.msi Property | grep -i productversion
"

echo
echo "-- 4/4 : publication dans dist/ --"
rm -f dist/*.deb dist/*.msi
cp target/debian/allsafe-agent_${CARGO_VERSION}-*_amd64.deb dist/
mv allsafe-agent.msi dist/
ls -la dist/

echo
echo "== Terminé =="
echo "N'oubliez pas : CURRENT_AGENT_VERSION dans backend/routers/agents.py -> \"$CARGO_VERSION\" (reste manuel, cf. commentaire en tête de ce script)"

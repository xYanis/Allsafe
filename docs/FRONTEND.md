# FRONTEND.md
## Charger uniquement pour les tâches liées au frontend React

---

## Stack Frontend

- React 18 + Vite
- Tailwind CSS (classes utilitaires) + **styles inline avec variables CSS** (`var(--bg-card)`,
  `var(--text-secondary)`... définies dans `index.css`, cf. `ThemeContext`/dark-light mode) pour tout
  ce qui est couleur/thème — c'est le système de design réellement utilisé partout (Dashboard,
  Vulnerabilities, Assets, Inventaire, Watch...)
- `recharts` pour les graphiques (PieChart, BarChart — pas Tremor)
- `marked` + `dompurify` (22/07/2026) — rendu Markdown des annotations d'analyste (`MarkdownNote.jsx`),
  sanitizé avant `dangerouslySetInnerHTML` : plusieurs analystes se partagent ces notes, l'un ne doit pas
  pouvoir en faire exécuter du script dans le navigateur d'un autre. Style dédié en CSS pur dans
  `index.css` (`.markdown-note`) sur les variables de thème existantes — pas de plugin
  `@tailwindcss/typography`, cohérent avec le reste (aucune dépendance de design en plus pour quelques
  balises)
- `country-flag-icons` — drapeaux pays en SVG (composants React par code ISO), utilisé pour Fuite de
  données (cf. VEILLE.md § 9.2) ; préféré à l'emoji unicode, pas fiable cross-plateforme (Windows/Chrome
  affichent parfois le code pays en texte brut au lieu du drapeau)
- Axios (appels API vers :8000)
- React Router v6

**Deux modes de service** (27/07/2026) : `npm run dev` (Vite dev server, HMR — mode par défaut,
`docker-compose.yml` § service `frontend`) et un build de production (`npm run build` + nginx, service
`frontend-prod`, profil Compose opt-in). Détail complet (Dockerfile multi-stage, `nginx.conf`, proxy
`/api` + forwarding d'IP) dans `docs/ARCHITECTURE.md` § Services Docker — concerne le déploiement, pas
les composants React eux-mêmes.

⚠️ **`@tremor/react` est listé dans `package.json` mais n'est importé nulle part dans `src/`** (vérifié :
`grep -rl "@tremor/react" src/` → aucun résultat). Malgré la mention dans `CLAUDE.md` ("la librairie UI
principale est Tremor"), le design réel de l'app est 100% Tailwind + styles inline/CSS vars, page après
page, depuis le début — **ne pas introduire de composant Tremor** dans du code neuf, ça détonnerait avec
le reste de l'app (dark/light mode, palette, densité) et forcerait une double maintenance de thème. Pour
un nouveau composant, reproduire le pattern des fichiers existants (`CARD`, `selectStyle`, badges inline
avec `rgba(...)` — cf. `SeverityBadge.jsx` pour l'exemple le plus simple).

**Identité de marque** (11/08/2026, cf. § dédiée ci-dessous) : tokens centralisés dans `index.css`
(`--brand`, `--brand-grad`, `--brand-dark`, `--brand-glow`, `--font-mono`) — avant cette session, le
même violet à plat (`#5b21b6`) était recopié en dur dans 5 fichiers. `components/CbrMark.jsx`
(`CbrMark`/`CbrLogoTile`) est désormais le seul point de vérité pour le glyphe et la tuile de logo,
repris par `Layout.jsx`, `Home.jsx`, `Login.jsx` et `WelcomeOverlay.jsx`.

**Cache module par page, contre le "rechargement" perçu à chaque navigation** (14/08/2026, retour
utilisateur — "j'ai l'impression que les pages sont sans cesse rechargées") : React Router démonte/
remonte entièrement chaque page à chaque changement de route (pas de cache de route ni de
keep-alive), donc toute page qui gate son rendu sur `if (loading) return <PageLoader/>` (ou
équivalent, ex. `if (data === null)`) rejoue cet écran plein écran à CHAQUE retour dessus, pas
seulement au premier chargement de la session. Convention adoptée pour toute page dont le fetch au
montage est coûteux ou visible :
```jsx
// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
let xxxCache = null   // ou {} si la page est paramétrée par id (route dynamique) — alors une MAP par id

export default function MaPage() {
  const [data, setData] = useState(() => xxxCache ?? initialValue)
  const [loading, setLoading] = useState(() => xxxCache == null)
  useEffect(() => {
    fetchData().then(r => { setData(r.data); xxxCache = r.data }).finally(() => setLoading(false))
  }, [...])
  if (loading && !data) return <PageLoader />   // déjà faux si xxxCache existait au montage
  ...
}
```
Le fetch continue de tourner à chaque montage (rafraîchissement silencieux en fond) — seul
l'AFFICHAGE du loader plein écran saute s'il y a déjà quelque chose à montrer. Règles suivies sur
les 12 pages où c'est appliqué (`Dashboard.jsx`, `Notes.jsx`, `NoteSubject.jsx`, `Documentation.jsx`,
`AuditDetail.jsx`, `Agents.jsx`, `Audits.jsx`, `Incidents.jsx`, `Crises.jsx`, `Assets.jsx`,
`Inventaire.jsx`, `Durcissement.jsx`) :
- **Une variable de cache par page**, jamais partagée entre deux fichiers même quand ils appellent le
  même endpoint (`Assets.jsx`/`Inventaire.jsx`/`Durcissement.jsx` appellent tous `fetchAssets()` mais
  ont chacun leur propre `xxxPageCache` — pas de déduplication inter-pages dans cette passe, jugé plus
  risqué pour le gain obtenu).
- **Map par `id`** (pas une valeur unique) pour les pages paramétrées par route dynamique
  (`NoteSubject.jsx`, `AuditDetail.jsx`) — sinon ouvrir l'item B affiche un instant le contenu de
  l'item A resté en cache.
- **Seul le premier écran non filtré/non paginé est mis en cache** sur les pages à filtres serveur
  (`Audits.jsx`, `Incidents.jsx` : cache écrit seulement quand aucun filtre n'est actif et
  `page === 1`, jamais un résultat déjà filtré par l'utilisateur).
- Le cache stocke la réponse **brute** de l'API (avant tri/filtrage/anonymisation côté client) —
  `Assets.jsx`/`Inventaire.jsx`/`Durcissement.jsx` appliquent `anonymizeAsset`/`FAKE_ASSETS` (mode
  Présentation) *après* lecture du cache, jamais sur la valeur mise en cache elle-même.

Pages volontairement non touchées (fetch trop léger pour valoir le coût, ou déjà sans gate plein
écran) : `Watch.jsx`/`FuiteDeDonnees.jsx`/`Vulnerabilities.jsx`/`CVEs.jsx` (loader seulement inline
dans le tableau/la grille, jamais plein écran), `Settings.jsx` (déjà en chargement à la demande par
section), `Reports.jsx`/`RapportVeille.jsx`/`RapportSurveillance.jsx`/`RapportIncidents.jsx`/
`SurveillanceIdentites.jsx`/`AdministrationSecurity.jsx` (fetch léger ou local à un onglet),
`Home.jsx`/`Login.jsx`/`Bastion.jsx` (aucun fetch).

Complément côté serveur, même session : `DB_MAX_CONCURRENT_SESSIONS` relevé de 5 à 15
(`backend/database.py`, cf. CLAUDE.md) — le Dashboard à lui seul génère 8 requêtes simultanées
toutes les 30s (+1/3s), suffisant pour saturer le sémaphore dès qu'un 2e onglet/utilisateur était
actif en même temps, aggravant la lenteur perçue sur les autres pages pendant ces rafales.

---

## Animations & polish (session 24/07/2026)

Lot de polish suivant les principes du skill **emil-design-eng** (motion en **CSS**, hors main-thread
et interruptible ; pas de framer-motion). Tout est neutralisé sous `prefers-reduced-motion` et les
survols sont gardés derrière `@media (hover: hover) and (pointer: fine)` (pas de faux hover au tap).

**Courbe & keyframes** : variable `--ease-out: cubic-bezier(0.23,1,0.32,1)` (les easings CSS natifs
manquent de punch). Keyframes de modale/toast dans `tailwind.config.js` (`modal-in`, `backdrop-in`,
`row-leave`, `toast-in/out`) ; le reste dans `index.css`.

**Global (une fois, partout)** :
- **Transition d'entrée de page** (`Layout.jsx`) : `<div key={location.pathname} className="route-fade">`
  autour de `<Outlet/>` → fade seul à chaque changement de route (**180 ms**, court car la nav est
  fréquente). **Plus de montée (`translateY`) depuis le 27/07/2026** : `animation: ... both` fige la
  dernière valeur de `transform` indéfiniment (pas seulement pendant l'animation) — tout `transform`
  non-`none` sur un ancêtre crée un nouveau containing block pour ses descendants `position: fixed`.
  Comme ce wrapper englobe **toutes** les pages sur **toutes** les routes, chaque modale rendue par une
  page (donc quasiment toutes, elles ne passent pas par un portail React) se positionnait par rapport à
  cette div au lieu du viewport : mal centrée, tronquée, clic sur le fond sans effet (fermeture
  impossible sans recharger la page). Bug systémique, pas propre à une page — repéré via les modales
  d'Actifs/Inventaire mais aurait fini par toucher n'importe quelle autre.
- **Feedback au press** : `button:not(:disabled):active { transform: scale(0.97) }` (les règles
  composant plus spécifiques gardent la priorité). Les items de nav (`<a>`) ont leur propre
  `.nav-item:active` (scale 0.98).
- **Cohérence des modales** : toutes les modales utilisent `animate-modal-in` + fond `.modal-backdrop
  animate-backdrop-in` (flou). Uniformisé sur celles qui ne l'avaient pas (Watch, Assets, Inventaire,
  AddSourceModal, EventDetailModal).

**Utilitaires réutilisables** (`index.css`) :
- `.lift-card` : lift + ombre + bordure au survol (grilles de cartes cliquables). Peu utilisé — l'app
  est surtout à base de tableaux.
- `.stagger` (cartes, montée 14px) et `.stagger-rows` (**version douce lignes**, 6px, cap 8) : cascade
  d'apparition. `.stagger-rows` appliqué aux `<tbody>` de **Vulnérabilités, Veille, CVE**. Ne rejoue
  qu'au (re)montage d'une ligne (clés stables ⇒ pas de replay au simple re-render). **Volontairement
  pas** sur les tableaux en polling (Dashboard) — un stagger qui rejoue à chaque refresh devient pénible.

**Sidebar (`Layout.jsx`, `.nav-item`)** : au survol, le fond et le texte se teintent de la **couleur du
module** (`color-mix` + variable `--nav` injectée par item) — même « feel » que les tuiles d'accueil.
La sidebar n'avait jusque-là aucun état de survol sur les items inactifs.

**Home.jsx** : cascade d'entrée (en-tête → tuiles décalées de 55 ms), halo violet qui respire, hover
premium teinté (lift, bordure/fond/liseré à la couleur, flèche qui glisse), et **spotlight à inertie**
qui suit la souris (radial-gradient positionné en `--mx/--my`, lissage exponentiel via `requestAnimation
Frame` écrit **directement sur la tuile** — aucun re-render — et s'arrête une fois stabilisé). Détail
d'implémentation dans la section Home.jsx ci-dessous.

---

## Identité de marque + delight Login/Bienvenue Boss (session 11/08/2026)

Demande explicite de l'utilisateur : la charte visuelle "faisait trop site fait par l'IA" (logo carré
violet à plat générique, wordmark sans caractère) — refonte visible plutôt qu'une simple retouche.

**Centralisation** (avant : `#5b21b6` recopié en dur dans `Layout.jsx`/`Home.jsx`/`Login.jsx`/
`WelcomeOverlay.jsx`/`ProtectedRoute.jsx`) :
- `index.css` § tokens : `--brand` (`#7c3aed`), `--brand-dark` (`#4c1d95`), `--brand-grad` (dégradé
  3 tons, diagonal, remplace l'aplat), `--brand-glow`, `--font-mono` (JetBrains Mono, chargée via
  `<link>` Google Fonts dans `index.html` — pas `@import`, pour ne pas bloquer le premier rendu).
- `components/CbrMark.jsx` (nouveau) : `CbrMark` (glyphe SVG seul) + `CbrLogoTile` (tuile en dégradé +
  reflet diagonal + glyphe blanc, `size`/`rounded` en px). Remplace les 4 copies identiques du même
  SVG.

**Nouveau glyphe** : premier jet — bouclier conservé (silhouette déjà propre), ornement intérieur (deux
clés superposées en étoile, peu lisible à petite taille) remplacé par un prompt de terminal `> ▬` —
clin d'œil à la lecture seule en ligne de commande (SSH/WinRM, cf. `CLAUDE.md` § 1), plus parlant qu'un
cadenas générique. **Simplifié dans la foulée (même session, retour utilisateur "regarde surtout le
logo")** : le bouclier imbriqué autour d'un petit `>_` restait chargé/flou aux tailles réellement
utilisées (32-40px, deux contours nichés à distinguer). Bouclier retiré — le glyphe `> ▬` seul, plus
grand (`strokeWidth` 2.6 au lieu de 1.9, ratio icône/tuile 0.64 au lieu de 0.62), porté directement par
la tuile en dégradé plutôt que niché dans un second contour. Plus proche des monogrammes d'outils dev
modernes (Linear, Raycast) qu'un blason encapsulé dans un carré déjà arrondi. `favicon.svg` régénéré à
l'identique (glyphe recentré/réduit via `transform`, coordonnées SVG statiques — pas de React ici).

**3e itération, même session, suite** : l'utilisateur a fourni un `Logo.png` de référence (bouclier à
contour circuit imbriquant un cadenas + empreinte digitale sur un maillage réseau, dégradé bleu/vert)
en demandant de s'en inspirer en gardant le violet. Repris : bouclier + cadenas (les deux grands
aplats reconnaissables), en violet. Volontairement pas repris : le maillage de nœuds et l'empreinte
digitale — même leçon que l'itération précédente, ce niveau de détail ne survit pas à 24-40px.
`favicon.svg` régénéré à l'identique.

**4e itération, session suivante (11/08/2026)** : retour utilisateur — veut *plus* de la référence
(empreinte + réseau *dans* le cadenas, pas retirés) et une 2e palette, noir + jaune, à la place du
violet. Deux changements distincts :
- **Outillage de vérification** — avant cette itération, les 3 versions précédentes du logo n'avaient
  jamais été vues (aucun navigateur disponible dans ce sandbox, cf. § Login/Bienvenue Boss plus haut).
  `@resvg/resvg-js` (npm, binaire Rust autonome — contrairement à Playwright/Chromium, aucune lib
  système manquante) installé dans le scratchpad de session pour rendre le SVG en PNG et l'inspecter
  réellement avant de livrer, à toutes les tailles utilisées (24/32/36/40/56px, pas seulement en
  grand). A immédiatement payé : le premier jet empreinte+réseau (arcs mal paramétrés, maillage en
  triangle plat façon poignée d'outil vectoriel) ne ressemblait à rien à l'écran — invisible sans ce
  rendu, aurait été livré tel quel comme les itérations précédentes.
- **Glyphe** : cadenas passé de plein à *tracé* (`fill: none`, contour seul) pour que l'empreinte se
  lise à travers sans cutout/masque SVG. Empreinte = 3 arcs elliptiques concentriques (`A rx ry ...`,
  même centre, mêmes flags) — une première tentative en beziers approximés donnait des arcs presque
  confondus (bug de paramétrage, pas de rendu pour le voir). Réseau = 2 petits amas de 2 nœuds sur le
  bouclier, de part et d'autre du cadenas (pas comprimé dedans, testé et écarté — l'empreinte seule
  remplissait déjà le corps du cadenas).
- **Palette** : `--brand`/`--brand-grad` passent de violet à noir + jaune (`#f5c518`). Un jaune assez
  vif pour "faire jaune" n'a pas un contraste suffisant en texte sur fond blanc (problème connu, pire
  couleur de texte sur blanc) — nouveaux tokens séparés : `--brand-icon`/`--brand-grad`/`--brand-glow`
  (toujours noir+jaune vif, la tuile de logo ne dépend jamais du thème de l'app) vs `--brand`/
  `--brand-text-grad` (texte lisible sur le fond de PAGE, qui lui change de thème — override
  `[data-theme="light"]` en or plus sombre, `#8a6a00`). `.brand-text-shimmer`/`.welcome-title`
  utilisaient un dégradé violet codé en dur mêlé à `var(--brand)` — remplacés par `var(--brand-text-grad)`
  seul (bug latent identifié en repassant dessus : le stop clair `#c4b5fd` était resté violet même
  après le premier changement de palette, invisible tant que personne ne comparait au rendu réel).

**5e itération, même session, tout de suite après** : la 4e (empreinte+réseau *dans* le cadenas)
rejetée telle quelle par l'utilisateur ("ça ne ressemble à rien") malgré la vérification par rendu —
le rendu avait bien été regardé, mais à 400px zoomé plutôt qu'en priorité aux tailles réelles, et le
jugement "ça a l'air lisible" restait celui de l'auteur du tracé, pas un œil neuf. Plutôt que
retenter un 3e dessin à l'aveugle, présenté 3 pistes nettement plus simples (rendues aux vraies
tailles avant envoi) ; l'utilisateur a préféré fournir directement un SVG source
(silhouette capuche/masque façon "hacker anonyme", svgrepo.com — conservé dans le repo, rangé depuis
à `docs/assets/logo-source.svg`) plutôt que choisir parmi
elles. Repris **tel quel**, recoloré (`fill="#000000"` → `currentColor`, viewBox natif `0 0 512 512`
conservé — pas remis à l'échelle 24 comme les tentatives précédentes, inutile) : une seule grande
silhouette pleine avec la zone du visage en négatif (le tracé compound source a déjà le bon sens de
parcours pour créer le trou) plutôt que plusieurs traits fins nichés — beaucoup plus lisible à petite
taille, vérifié à 24/32/36/56px avant intégration. Ratio icône/tuile ajusté à `0.74` (au lieu de
`0.64`) pour ce nouveau tracé, qui a moins de marge intérieure dans son propre viewBox que le
précédent. `favicon.svg` régénéré à l'identique.

⚠️ Silhouette "capuche/masque" à connotation *hacker/attaquant* plutôt que *défense* — signalé à
l'utilisateur en le livrant, pas un problème bloquant en soi (imagerie très courante dans le
secteur cyber, cf. `docs/SONDE.md` § BAS/Red Team pour le volet offensif déjà dans la roadmap du
produit) mais à garder en tête si la question revient plus tard.

**Wordmark** : "Allsafe" passe en `--font-mono`, en dégradé de marque (`background-clip: text`,
`var(--brand-text-grad)`) sur Home/Login (trop petit pour rester lisible en dégradé dans la sidebar —
y reste en `--brand` uni).

**Sidebar** (`Layout.jsx`, `.nav-item.active-nav::before`) : liseré coloré à gauche sur l'item actif
(façon Linear/Vercel), en plus du fond teinté déjà en place — masqué en mode réduit (icône seule,
`.nav-item-collapsed`, la barre collerait à l'icône sans la marge du libellé).

**Hero** (Home + Login, `.hero-grid`) : trame de points technique sous le halo existant (masquée en
dégradé radial pour ne jamais toucher net les bords) — évite le pattern "blob + gradient" très
reconnaissable des landing pages génériques.

**Favicon** régénéré pour matcher (dégradé + nouveau glyphe).

### Animations Login/WelcomeOverlay — delight scopé aux écrans rares

Suite immédiate, même session : "des animations bien visibles et qualitatives" sur Login et l'écran
"Bienvenue Boss". Skills chargées pour ce lot : **emil-design-eng** (cadre de décision par fréquence —
occasionnel/rare peut se permettre du delight, contrairement à une action répétée 100+ fois/jour) et
**apple-design** (physicalité du mouvement — traduit ici en overshoot CSS, pas de vrais springs
puisque le projet reste volontairement sans framer-motion).

**Règle appliquée** : Login (une fois par session) et WelcomeOverlay (une fois par connexion, admin
seulement) sont les deux seuls écrans "rares" de l'app — Home.jsx, revisité plusieurs fois par jour
via le logo de la sidebar, garde volontairement des animations sobres. D'où des classes CSS dédiées
(préfixe `brand-`/`login-`/`welcome-`), jamais réutilisées sur une page fréquente, et une nouvelle
courbe `--ease-bounce: cubic-bezier(0.34, 1.56, 0.64, 1)` (overshoot) réservée à ces deux écrans.

- **Logo** (`.brand-pop`) : atterrit avec un overshoot + léger tour (`scale(0.4) rotate(-8deg)` →
  dépassement à 108% → `scale(1)`) plutôt qu'un simple `scale(0.9→1)`, accompagné d'un ping façon radar
  qui se dissipe autour (`.brand-ring`, cercle qui grandit et s'efface).
- **Wordmark** (`.brand-text-shimmer` sur Login, `.welcome-title` sur WelcomeOverlay — même keyframe
  `brand-text-reveal`, déclarée deux fois plutôt que composée en deux classes empilées : deux
  `animation` distinctes animant chacune `transform` sur le même élément ne se combinent pas
  nativement en CSS) : balayage lumineux qui traverse le texte en dégradé une fois puis se fige — pas
  de boucle infinie, même sur un écran qui se permet plus de delight.
- **Champs de connexion** (`.login-enter`) : montée + flou qui se dissipe ("matérialisation", cf.
  emil-design-eng § blur) plutôt qu'un simple fondu.
- **Bouton de connexion** (`.login-button-enter`) : même overshoot que le logo — la CTA de l'écran
  mérite plus de présence qu'un fondu.
- **Erreur de connexion** (`.login-error`) : apparaît puis tremble légèrement (indication d'état, pas
  décoration pure) — une seule keyframe (`login-error-in`), même raison que le wordmark ci-dessus
  (éviter deux animations simultanées sur `transform`). `key={error}` côté JSX force le remontage à
  chaque tentative ratée pour rejouer l'animation même si le message reste identique.
- **Trame de points** (`.hero-grid-boot`, Login seulement) : révélée en cercle depuis le centre façon
  "mise sous tension" (`clip-path: circle()`, 0% → 75%) plutôt que statique.
- **Couronne** (`.welcome-crown`, WelcomeOverlay) : tour marqué (`rotate(-25deg)` → dépassement à
  `rotate(10deg)` → `rotate(0)`, façon couronne qu'on pose sur une tête) + halo doré qui pulse et se
  dissipe une fois derrière (`.welcome-crown-glow`, teinte or `rgba(227,179,65,*)` — distincte du
  violet de marque, cohérente avec l'emoji 👑).
- **Lignes de récap** (`.welcome-recap-row`) : glissent depuis la gauche (`welcome-row-in`) plutôt
  qu'une simple montée verticale, pour varier du reste de l'app.
- **Bouton "Continuer"** (`.welcome-continue`) : overshoot à l'entrée puis halo qui respire en boucle
  (`welcome-continue-glow`) pour attirer l'œil avant l'auto-dismiss à 9s — delight à visée
  fonctionnelle, pas seulement décoratif.

Toutes ces classes sont neutralisées sous `prefers-reduced-motion: reduce` (`animation: none`, états
finaux figés) — bloc dédié dans `index.css`, en plus du bloc `.welcome-*` déjà existant.

### Animation de déconnexion (`LogoutOverlay.jsx`, même session, demande explicite)

Pendant du `WelcomeOverlay.jsx` côté sortie : sans lui, `logout()` basculait `user` sur `null`
instantanément et `ProtectedRoute.jsx` redirigeait vers `/login` dans le même rendu — un cut sec depuis
n'importe quelle page, sans transition.

- `AuthContext.jsx` : `logout()` n'est plus `async` côté appelant — il déclenche l'appel API en
  best-effort (`.catch(() => {})`, ne bloque pas l'animation sur la latence réseau) et bascule un
  nouvel état `loggingOut`. `LogoutOverlay` est monté juste à côté de `{children}` dans le retour
  d'`AuthProvider` (pas dans une page précise : `logout()` est appelable depuis `Settings.jsx` **et**
  `ProtectedRoute.jsx::ForcedPasswordChange`).
- Séquence : l'overlay couvre l'écran (`CbrLogoTile` + `.brand-pop`, même bounce que Login/Welcome, +
  "Déconnexion…" en `--font-mono`) → tenu 550ms (`HOLD_MS`) → `onExitStart` bascule `user` sur `null`
  **pendant** que l'overlay est encore opaque (la redirection `ProtectedRoute` vers `/login` se produit
  donc invisible, sous l'overlay) → fondu+flou de sortie (`.welcome-overlay-exit`, réutilisé tel quel)
  → `onDone` démonte l'overlay, révélant Login déjà monté dessous. Même choréographie que
  `WelcomeOverlay` (`onExitStart`/`onDone`), même raisonnement anti-flash.
- Non interactif — pas de bouton "continuer" : la déconnexion est déjà décidée au clic, rien à
  reconfirmer une deuxième fois (contrairement à `WelcomeOverlay`, dismissable par choix).
- Contrairement à `WelcomeOverlay` (admin seulement), concerne **tout compte** — texte neutre
  ("Déconnexion…"), pas de personnalisation par rôle.

---

## Tour visuel (11/08/2026)

Demande explicite ("regarde ce que tu peux améliorer visuellement"), audit de code (pas de rendu
navigateur disponible dans ce sandbox) sur les 19 pages restantes via un agent Explore dédié, chaque
point vérifié ligne par ligne avant correction. Corrections appliquées :

- **Couleurs hors-hue** : `Incidents.jsx`/`Crises.jsx` peignaient le texte de leur CTA principal
  (« + Déclarer un incident », « + Activer une crise ») en `#04262a` — un brun-noir pensé pour un fond
  **vert/cyan** (repris tel quel depuis `Audits.jsx`, où il est juste sur `MODULES.securite.color`),
  posé sur un fond **brun** (`MODULES.incidents.color`, `#b5793a`). Corrigé en `#2b1c08`, même logique
  que `Documentation.jsx` (déjà correct : `#3a2a04` sur son propre ambre).
- **`StatusBadge.jsx`** (statuts de vulnérabilité/incident/audit) désaligné de `SeverityBadge.jsx`/
  `CriticiteBadge.jsx` — opacités fond/bordure 0.1/0.25 au lieu de 0.12/0.3, `fontSize` 12px au lieu de
  11px — visible côte à côte dans les mêmes lignes de tableau (Dashboard, Vulnérabilités). Aligné sur
  le même gabarit inline (`borderRadius: 6, padding: '2px 8px', fontSize: 11`).
- **`--accent-blue` (nouveau token, `#1f6feb`)** : bleu d'action recopié en dur — 8 endroits trouvés
  par l'agent (`Assets.jsx`, `Vulnerabilities.jsx`, `Watch.jsx`, `Settings.jsx`), **6 de plus trouvés
  en vérifiant après coup** (`ErrorBoundary.jsx`, `WatchProfileModal.jsx`, `Dashboard.jsx` ×4) — 14 au
  total, tous remplacés par `var(--accent-blue)`. **Exception volontaire** : les 3 occurrences dans
  `ReportMarkdown.jsx` (§ export PDF) restent en dur — ce sont des styles CSS injectés dans un document
  HTML autonome ouvert dans une fenêtre séparée pour l'impression, sans accès aux tokens `:root` de
  l'app (scope CSS différent).
- **Hover manquant** sur 3 `<tr>` sans `onMouseEnter`/`onMouseLeave` alors que toutes les autres tables
  de l'app en ont un : `SurveillanceIdentites.jsx` (tableaux IP surveillées + emails/domaines
  vérifiés, `hexToRgba(ACCENT, 0.04)`) et `RapportIncidents.jsx` (registre, `${MODULE_COLOR}0a` —
  neutralisé quand la ligne est déjà sélectionnée/`isOpen`, pour ne pas écraser ce fond-là).
- **`Documentation.jsx`** : carte de type de document (upload/aperçu/suppression, plusieurs actions
  cliquables) sans `.lift-card` alors que la classe existe déjà et est pensée pour exactement ce cas
  (grille de cartes cliquables) — ajoutée, aucun nouveau style à écrire.

**Laissé en attente d'arbitrage** (structurant, pas une correction ponctuelle) : les pages plus
anciennes (`Vulnerabilities.jsx`, `Assets.jsx`, `CVEs.jsx`, `Watch.jsx`, `Inventaire.jsx`,
`Reports.jsx`/`RapportVeille.jsx`/`RapportSurveillance.jsx`) n'importent jamais `MODULES` et
retombent sur du bleu générique pour leur CTA/hover — contrairement aux pages plus récentes
(`Documentation.jsx`, `Incidents.jsx`, `Crises.jsx`, `Audits.jsx`) qui teintent bien leur CTA/hover de
la couleur de leur propre module (sidebar → page cohérentes). Reteindre ~7 pages est un vrai chantier
(pas une valeur à changer), volontairement pas fait sans validation.

**Vérifié mais écarté par l'agent** (pour référence, ne pas re-signaler) : le mélange `✕`/SVG sur les
boutons de suppression inline est un pattern volontaire (chips retirables vs fermeture de modale) ;
`.stagger-rows` n'est appliqué qu'à 3 pages par choix déjà documenté ; aucune trace de `--brand`/
`#5b21b6` recopié en dur dans les 19 pages auditées — la centralisation de la refonte d'identité a
bien tenu.

### Reteinte des pages « historiques » avec leur couleur de module (même jour, suite)

Point C1 ci-dessus tranché par l'utilisateur ("oui, même patron que Documentation/Incidents").
`constants/modules.js` gagne un champ `dark` par module (teinte quasi-noire de la même famille,
utilisée comme texte sur un CTA rempli en couleur pleine) — centralise une valeur que
`Incidents.jsx`/`Crises.jsx`/`Documentation.jsx`/`Audits.jsx`/`AuditDetail.jsx` avaient déjà en dur
(et recopiée à tort d'un module à l'autre pour Incidents/Crises, cf. § ci-dessus) ; ces 5 fichiers
référencent désormais `MODULES.xxx.dark` au lieu du hex.

Pages reteintées :
- **`Vulnerabilities.jsx`/`CVEs.jsx`** (CyberVuln, rouge) : **survol de ligne seulement**, pas les
  boutons d'action — le rouge y est déjà le code "sévérité CRITICAL/statut open", le réutiliser pour
  "action principale" aurait créé une confusion que les autres modules n'ont pas.
- **`Assets.jsx`** (Inventaire, cyan) : CTA "+ Ajouter un actif" (fond plein + texte
  `MODULES.inventaire.dark`, hover JS retiré — même sobriété que le patron Incidents/Documentation)
  + survol de ligne. Les autres boutons (scan groupé, actions par ligne) restent en `--accent-blue`,
  volontairement — pas la "signature" de la page.
- **`Inventaire.jsx`** (Inventaire, cyan) : survol de ligne seulement — pas de CTA coloré en en-tête
  sur cette page ("Scanner tout"/"Exporter en PDF" sont neutres par nature, une case à cocher un peu
  spéciale n'a pas à être la couleur de marque).
- **`Watch.jsx`** (CyberVeille, bleu) : le survol de ligne (`rowBg()`) utilisait déjà
  `rgba(88,166,255,*)` — c'est très exactement `#58a6ff`, la couleur du module, rien à changer là.
  Le composant `Btn` (variant `primary`, utilisé par "Synchroniser" + "Enregistrer") passe de
  `--accent-blue` (`#1f6feb`, plus foncé) à `WATCH_ACCENT`/`MODULES.cyberveille.dark`.
- **`Reports.jsx`/`RapportVeille.jsx`/`RapportSurveillance.jsx`** (Rapports, violet) : déjà largement
  teintées via le composant partagé `WeeklyArchives.jsx` (CTA "📅 Générer…", libellé de semaine, ligne
  ouverte — tous déjà en violet) — il ne manquait que le survol au repos sur les lignes non ouvertes,
  ajouté (un seul correctif dans le composant partagé, profite aux 3 pages à la fois).

**Non touchées, déjà correctes** : `FuiteDeDonnees.jsx`/`SurveillanceIdentites.jsx` (CyberVeille)
avaient déjà leur propre constante `ACCENT` sur `#58a6ff`.

---

## `PageHero.jsx` + refonte Paramètres/Veille/Fuite de données + self-service compte (14/08/2026)

Enchaînement de demandes explicites de l'utilisateur dans une même session, du visuel (une page
"chargée" à retravailler) au fonctionnel (gérer son propre compte). Résumé regroupé ici plutôt que
scindé par page, pour garder la logique de la session lisible d'un coup.

### `components/PageHero.jsx` (nouveau, extrait dès le 2e usage)

En-tête compact pour les pages de travail répétitif (dégradé teinté à la couleur du module, tuile
d'icône en dégradé + ombre colorée, trame de points `.hero-grid` en fond, titre en dégradé de la
couleur du module rendu via `useTheme()` — assombri en clair, cf. `dangerColor` d'`AdministrationRow`
pour la même logique de recalibrage). Props : `icon` (path SVG, peut contenir plusieurs sous-tracés
`M...z M...z`), `title`, `subtitle`, `color`, `children` (actions à droite). Pas de prop `count` —
retiré après coup, retour utilisateur ("pas besoin des chiffres à côté du titre").

Sans `children` (Settings.jsx, Notes.jsx), le masque de la trame de points est recentré et élargi
(`gridMaskPos`/`gridMaskSize` conditionnels) plutôt que de garder le masque resserré à gauche pensé
pour laisser la place à des boutons — sans ce recentrage, le côté droit de la carte retombait à plat/
vide ("Paramètres fait comme Notes", retour utilisateur).

Déployé sur la quasi-totalité des pages de contenu (remplace un en-tête `h1`+`p` plat), une couleur
par module (`constants/modules.js`) : Dashboard/Vulnerabilities/CVEs (rouge), Incidents/Crises
(marron), Audits/Bastion (vert), Watch/FuiteDeDonnees/SurveillanceIdentites (bleu),
Documentation/Notes (or), Assets/Inventaire/Durcissement/Agents (cyan), Reports/RapportVeille/
RapportSurveillance/RapportIncidents (violet), Settings/AdministrationSecurity (gris). Non concerné :
pages de détail avec leur propre patron retour+titre (`AuditDetail.jsx`, `NoteSubject.jsx`), Login/Home
(hors `<Layout>`).

### Veille technologique + Fuite de données — densité et couleur

Retour utilisateur : "je trouve ça gros et chargé, les tuiles sont immenses". Trois correctifs
successifs sur les mêmes cartes KPI/stat :
- Largeur plafonnée côté grille (`minmax(180px, min(240px, 1fr))` — le `min(...,1fr)` permet aux
  tuiles de s'étirer pour remplir la ligne quand il y en a peu, sans jamais dépasser le plafond quand
  il y en a beaucoup — corrige un 2e retour, l'espace vide à droite du bandeau de 3 stats sur Fuite de
  données avec le plafond fixe précédent).
- **Rangée forcée à l'horizontale** (`flex flex-nowrap overflow-x-auto`, pas un `grid` qui peut
  retomber à une tuile par ligne sur un écran étroit) + gabarit très resserré (`px-3/py-2`, valeur
  `text-base`) — 3e retour ("réduit la taille... range-les horizontalement").
- Une couleur d'identité par KPI/stat (rouge/ambre/vert/bleu sur Veille, violet/cyan/bleu sur Fuite de
  données) au lieu du gris/violet uniforme — liseré gauche teinté (`boxShadow: inset 3px 0 0 0 ...`) +
  icône colorée + micro-interaction (`group-hover:scale-110`).
- Cartes de résultat (Fuite de données) : `.lift-card` + même liseré gauche teinté par source, pour
  lire comme un seul système visuel avec les tuiles KPI au-dessus.

### `Notes.jsx` — 3e itération de layout (nav à icônes + panneau, sans les tuiles rejetées)

Cf. commentaire en tête du fichier pour l'historique complet (cartes puis explorateur à deux volets
bordés, tous deux rejetés le 12/08/2026). Cette 3e tentative diffère des deux précédentes : nav des
thèmes à gauche **sans bordure** (fond teinté à la couleur du thème + liseré gauche seulement, même
gabarit que la nav d'`AdministrationSecurity.jsx`), panneau de contenu à droite. Sélection simple (un
thème affiché à la fois, plus d'accordéon multi-ouvert) — auto-sélection du premier thème au chargement.
Les sujets restent en lignes `.tree-row` plates à l'intérieur du panneau, pas de tuile par sujet.

### `Settings.jsx` (Paramètres) — nav à deux volets + self-service compte

Même schéma que `Notes.jsx` (nav à icônes sans bordure à gauche, panneau à droite, plus aucune tuile
par réglage) plutôt que l'ancien empilement de cartes une par section. Sections : Présentation,
Apparence, **Compte**, **Sessions** (nouveau), **Intégrations** (nouveau), **Sécurité** (lien vers
Administration, pas un onglet — pas de contenu propre).

- **Compte** : bouton "Modifier" à côté de "Se déconnecter" → déplie deux formulaires indépendants
  (changer l'email, changer le mot de passe avec `PasswordStrengthHint.jsx`) — chacun son état de
  soumission/erreur. Juste au-dessus : `<select>` "Nom d'analyste par défaut" (cf.
  `AnalystPreferenceContext.jsx` ci-dessous).
- **Sessions** : liste des appareils connectés au compte (`GET /api/auth/sessions`), badge "Cet
  appareil" sur la session courante, bouton "Révoquer" sur les autres. Chargé à la demande (au premier
  passage sur la section), pas au montage de la page.
- **Intégrations** : statut configuré/non configuré + dernière synchro de NVD/GitHub/AD/SSH/
  WithSecure/Meraki/PRTG/GLPI/vSphere (`GET /api/integrations/status`), lecture seule, aucun secret
  affiché.

### `AdministrationSecurity.jsx` — nav réductible en icônes seules

Bouton "Réduire" en haut de la colonne de nav (état local, pas persisté — nav secondaire, contrairement
à la sidebar principale de `Layout.jsx`) : bascule la largeur (`lg:w-64` ↔ `lg:w-16`), masque
labels/description, ajoute un `title` (tooltip) sur chaque item en mode réduit. Couleur d'accent des
onglets alignée sur `var(--accent-blue)` au passage (était en `#58a6ff` codé en dur).

### `components/PasswordStrengthHint.jsx` (nouveau)

Barre de force colorée + checklist des 5 critères de `services/auth.py::validate_password_strength`
(dupliqués en JS — pas de logique partagée possible entre Python et JS, à garder synchronisés si la
politique change), cochés en direct pendant la saisie. Utilisé dans `Settings.jsx` (changement de mot
de passe) et `ProtectedRoute.jsx::ForcedPasswordChange` (écran de changement forcé) — le bouton de
validation de ce dernier passe en `disabled` tant que `passwordMeetsPolicy()` est faux, pour ne plus
laisser découvrir les critères manquants seulement au rejet serveur.

### `contexts/AnalystPreferenceContext.jsx` (nouveau) — nom d'analyste par défaut

Préférence 100% client (`localStorage`, clé `preferred_analyst`), même patron exact que
`ThemeContext.jsx`/`PresentationContext.jsx` (lecture lazy au premier rendu, écriture par effet).
Volontairement séparée du registre `Analyst` (backend) et d'`AnalystContext.jsx` (liste des noms) —
une préférence d'affichage locale, pas une donnée à synchroniser entre postes. Appliquée à 2
composants (sur 21 qui consomment `useAnalysts()` dans l'app — périmètre volontairement limité aux
plus utilisés, pas d'audit systématique des 19 autres) :
- `ValidateDropdown.jsx` : pas de valeur contrôlée à pré-remplir (menu qui valide au clic, pas de
  submit) — le nom préféré remonte en tête de liste + mis en avant (gras vert, étiquette "Moi").
- `AnnotationModal.jsx` : le `<select>` "Validé par" se pré-remplit avec le nom préféré, **seulement**
  quand `initialValidator` est vide (nouvelle annotation) — sur une ré-édition (seul appelant :
  `Dashboard.jsx`), `initialValidator` porte déjà le nom réellement enregistré, jamais écrasé.

---

## Pages

### Home.jsx (route `/`, page d'accueil — sans `<Layout>`/sidebar)
- Sélecteur de module : 7 tuiles cliquables (`MODULES`), une par groupe de nav — même couleur que dans
  `Layout.jsx` `NAV_GROUPS` (CyberVuln rouge `#f85149`, CyberVeille bleu `#58a6ff`, Inventaire marron
  `#b5793a`, Sécurité vert `#3fb950` (Audits + Bastion, tous deux placeholder), Rapports violet
  `#a371f7`, Incidents cyan `#39c5cf`, Paramètres gris `#8b949e`) — redirige vers la première page du
  module choisi. Pas de tuile « Administration » (module Bastion/sélecteur retiré le 30/07/2026,
  Administration se rejoint depuis Paramètres)
- Le logo/titre "Allsafe" (sidebar, `Layout.jsx`) ramène toujours ici
- **Refonte 24/07/2026** (cf. § Animations & polish) : en-tête Allsafe + tagline « Plateforme cybersécurité
  on-premise », tags « Bientôt » sur les modules placeholder, entrée en cascade, hover premium teinté et
  **spotlight à inertie** qui suit la souris. `handleMove`/`handleLeave` + WeakMap `_spot` gèrent le
  suivi (écriture directe des variables `--mx/--my` sur la tuile, boucle rAF qui s'arrête une fois
  stabilisée — aucun `setState`).
- **Grille sans scroll** (24/07/2026) : `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4` (`max-w-5xl`) plutôt
  que 3 colonnes — avec 7 tuiles, 3 colonnes donnait 3 rangées (3+3+**1**), la dernière (Paramètres)
  isolée et souvent coupée par la hauteur de viewport. 4 colonnes → 2 rangées (4+3), aucune tuile
  orpheline. Espacements resserrés en même temps (padding page `p-6`, en-tête `mb-6`, logo `w-14`, titre
  `text-3xl`, tuiles `p-4`, icône `w-10`) pour que l'ensemble (en-tête + grille) tienne dans une hauteur
  d'écran standard sans scroll.
- **Cascade en deux temps distincts** (11/08/2026, demande explicite) : `TILE_BASE_DELAY` passé de
  260ms à 520ms — l'en-tête (logo + titre + tagline) se lisait auparavant en même temps que le début
  des tuiles, les deux vagues se chevauchant plutôt que de se succéder. Toujours les classes `.home-*`
  sobres (pas `.brand-pop`/`--ease-bounce`, réservées aux écrans rares Login/WelcomeOverlay) — Home
  reste visité en boucle, seul le *timing* a changé, pas l'intensité du mouvement.

### Dashboard.jsx
- KPIs (4 cards, `grid-cols-4`) : actifs exposés, vulns ouvertes, **"En attente d'un patch"** (session
  02/07/2026 — `awaiting_fix_vulnerabilities`/`awaiting_fix_rate_percent` côté `stats.py`, même base
  `total_vulns` que `patch_rate_percent` pour rester comparable côte à côte, thème ambre `#d29922`),
  taux de correction global
  - Couleur du taux global alignée sur la logique "Taux de correction par sévérité" : vert ≥80%, orange ≥50%, rouge sinon
- Bloc "Taux de correction par sévérité" (CRITICAL/HIGH/MEDIUM/LOW), barres colorées avec les mêmes seuils
  - ⚠️ **Bug réel corrigé (11/08/2026)** : la colonne "corrigées/total" (ex. `23350/67327` sur HIGH,
    parc réel) débordait de sa case — `w-12` (48px, largeur fixe) au lieu de `min-w-*`, alors que
    HIGH porte largement le plus de vulns des 4 sévérités. Les 4 lignes partagent la même classe, donc
    des largeurs fixes garantissaient un alignement... jusqu'à ce qu'une case déborde plutôt que de
    s'agrandir. Corrigé : `min-w-[5.5rem]` (colonne "corrigées/total") et `min-w-[3rem]` (colonne "%"),
    + `tabular-nums` sur les deux — la barre `flex-1` au milieu de chaque ligne cède la place
    automatiquement, l'alignement reste correct tant qu'aucune ligne n'a besoin de plus que ce
    minimum (à revoir si le parc grossit encore d'un ordre de grandeur).
- Graphiques (recharts, pas Tremor) : DonutChart répartition sévérité, BarChart top actifs exposés
- Boutons header : "Matching CVE" + **"Patch check global"** (`PatchCheckRunButton`) — relance
  `POST /api/patch-check/run` (rattrapage + check des vulns jamais vérifiées), protégé contre les clics
  concurrents (`already_running`)
  - **Bouton ⟳ accolé** (session 21/07/2026) : "Forcer une réévaluation complète" →
    `POST /api/patch-check/run?force=true`, lève le garde-fou des 24h. **Confirmation obligatoire**
    via modale : contrairement au check standard, il peut basculer un gros volume de vulns en
    `patched` d'un coup (non-CRITICAL uniquement). Nécessaire après l'amélioration d'un signal de
    détection — sans quoi le stock déjà contrôlé garde le résultat de l'ancienne logique jusqu'à
    expiration du délai.
- "Matching CVE" (`MatchingCveButton`, session 20/07/2026) affiche désormais "Dernière sync : jj/mm/aaaa
  hh:mm" sous le bouton — lu au montage via `GET /api/sync/match-status`, mis à jour après clic
  (`synced_at` dans la réponse de `POST /api/sync/match`). Persisté côté backend (table générique
  `sync_state`, clé `cpe_match`) plutôt qu'en state local : le matching tourne aussi automatiquement au
  démarrage de l'app (`main.py` → `_startup_matching`), pas seulement au clic — cf. `docs/ARCHITECTURE.md`
- Bandeau "Analyse en cours" (poll `GET /api/patch-check/status` toutes les 3s) avec **barre de
  progression** (X/Y, capturée via `runTotalRef` au premier tick actif) — visible que ce soit le check
  auto au démarrage ou le bouton manuel
- ⚠️ **Bug réel corrigé (11/08/2026)** : le bandeau restait affiché en permanence, y compris hors
  cycle, à chaque rechargement de page — signalé par l'utilisateur ("bien bugé, se lance à chaque
  actualisation et reste bloqué"). Cause côté frontend : `const active = data.current !== null ||
  data.pending > 0` — `pending` n'est qu'un décompte du **backlog** de vulns à revérifier (`GET
  /api/patch-check/status`, `routers/patch_check.py`), quasi toujours > 0 sur un vrai parc (rien à
  voir avec un cycle réellement en cours). `is_patch_check_cycle_running()` existait déjà côté
  backend (`services/patch_checker.py`, `_cycle_running`) mais n'était exposé nulle part côté API.
  Corrigé : nouveau champ `running` dans la réponse de `/status`, `active = data.running === true`
  côté `Dashboard.jsx` — `pending` reste utilisé (légitimement) pour le total de la barre de
  progression une fois un cycle confirmé actif, plus comme signal d'activité à lui seul.
- ⚠️ **Bug réel corrigé, suite (11/08/2026)** : la notification toast "actif terminé" (§ ci-dessous)
  ne se déclenchait plus — signalé par l'utilisateur ("je ne reçois pas la notification... avant
  j'avais l'info"). Cause : `firstPollRef`, une garde propre à cette notification (absente de son
  équivalent CVE juste au-dessus, `lastCompletedRef`) — "rien au tout premier poll après montage,
  sinon rouvrir la page mi-cycle spammerait un toast par actif déjà fini". Effet de bord non prévu :
  un actif qui terminait pendant que l'onglet était fermé/rechargé était marqué silencieusement
  "déjà notifié" (`notifiedDoneAssetsRef.add()`, avant le `continue` sur `firstPollRef`) **sans que
  le toast n'ait jamais été affiché** — silence permanent sur cet actif jusqu'au prochain cycle.
  Retiré : la notification par actif suit désormais exactement la même logique que celle des CVE
  (dédoublonnage par clé déjà vue via `notifiedDoneAssetsRef`, jamais de garde "premier poll").
  Vérifié par rejeu de la logique réelle de `poll()` en Node contre le scénario exact du bug (pas de
  navigateur disponible dans ce sandbox), y compris le cas "page rouverte pile quand l'actif est déjà
  à 100%" — confirmé corrigé.
- **Panneau "Notifications" (🔔) — fusion CVE + complétions d'actif (11/08/2026, suite immédiate,
  demande explicite)** : le panneau ne montrait que les bascules de CVE (`autoBasculeSummary`), rien
  sur les complétions d'actif (purement client, disparaissaient sans trace après le toast). Nouvelle
  table `patch_check_asset_completions` (`models.py`), écrite par
  `services/patch_checker.py::record_asset_completion` à la fin de la passe de chaque actif (dans
  `run_startup_patch_checks`, pas seulement à la toute fin du cycle) ; nouvel endpoint `GET
  /api/patch-check/asset-completions` (`routers/patch_check.py`, `assetCompletionSummary` côté
  `api/client.js`) — **volontairement séparé** de `/vulnerabilities/auto-bascule-summary`, jamais
  fusionné côté backend : ce dernier alimente aussi le bandeau "depuis votre dernière visite" et le
  récap `WelcomeOverlay`, tous deux déjà écrits pour un format de ligne CVE
  (`cve_id`/`severity`/`asset_name`) — y mélanger un format différent les aurait cassés. La fusion se
  fait **côté frontend uniquement**, dans `NotificationHistory` (`Dashboard.jsx`) : les deux endpoints
  interrogés en parallèle (`Promise.all`), résultats fusionnés + triés par date, chaque ligne portant
  un `kind` ('cve' | 'asset') qui pilote son rendu (icône, texte, clic pour justificatif — seul les
  lignes CVE sont cliquables).
  ⚠️ **Incident réel pendant l'implémentation** (backend, pas frontend) — cf. `STATUS.md` pour le
  détail : nouvelle table ajoutée à `models.py` avant d'être créée en base a fait planter le
  redémarrage du backend (`create_all` bloqué par `ddl_guard.sql` sous le rôle `cbr_app`, exception
  non rattrapée). Toujours exécuter `schema_patches.sql` (rôle superuser) **avant** tout edit de
  `models.py` qui ajoute une table, jamais après.
- **Modale patch check — 3 verdicts, pas 2** (session 21/07/2026) : au ✅ "Patch détecté" (vert) et
  ❌ "Patch non détecté" (rouge) s'ajoute 🚫 **"CVE sans objet sur cet actif"** (violet `#a371f7`)
  quand `not_applicable` est vrai, plus un bandeau "Produit non installé sur la machine" détaillant
  les paquets absents. Le rouge serait trompeur : la CVE n'est ni corrigée ni exploitable, elle ne
  concerne simplement pas la machine. Le message de bascule automatique est lui aussi conditionné —
  "Qualifiée automatiquement en faux positif" et non "Corrigée automatiquement".
- **Modale résultat patch check** (`patchModal`, dupliquée à l'identique dans `Vulnerabilities.jsx` —
  pas de composant partagé) : jusqu'à la session 20/07/2026, n'affichait que le badge ✅/❌
  `patch_detected` + la liste des KB — les signaux 2/3 (`build_verdict`, `date_heuristic`, cf.
  `docs/MATCHING.md` § Détection Windows) étaient calculés côté backend mais **jamais montrés**,
  rendant un "❌ Patch non détecté" indiscernable d'un vrai échec alors qu'un signal indicatif
  "probablement déjà corrigé" existait parfois juste en dessous dans la réponse JSON (repéré par
  l'utilisateur : "elle devrait apparaître comme patched"). Ajout de deux blocs : bandeau build/révision
  (`build_installed` + verdict coloré si `build_verdict` est un booléen) et bandeau bleu "Signal
  indicatif" (si `date_heuristic` est un booléen) reprenant `last_update_installed`/
  `date_heuristic_reference`/`date_heuristic_source` — bleu plutôt que vert/rouge pour bien marquer
  que ce n'est jamais un verdict définitif, juste un repère pour la validation manuelle.
- Tableau "Vulnérabilités à traiter" : badge **"Correctif détecté ?"** (vert `#3fb950`, **contour
  pointillé + point d'interrogation**) dès qu'un correctif est détecté sur une ligne encore `open` —
  typiquement une CRITICAL, que la règle CLAUDE.md interdit de basculer automatiquement. À ne pas
  confondre avec le badge **plein** "Patched" de "traitées", qui signale une clôture effective : les
  deux étaient identiques jusqu'au 21/07/2026, ce qui a fait douter l'utilisateur de l'état réel de
  ses lignes (« je vois que celles-ci sont patched, c'est sûr ? »). **Même grammaire que le badge
  "Faux positif ?"** : pointillé = proposition du système, plein = décision actée ; badge **"Faux positif ?"** (violet
  `#a371f7`, **contour pointillé + point d'interrogation** — c'est une *proposition* du système sur
  une ligne encore `open`, à distinguer du badge plein de "traitées" qui signale une qualification
  actée ; les deux étaient initialement identiques, ce qui laissait croire à une décision déjà
  prise, session 21/07/2026) sur les CVE sans objet sur l'actif, avec la ligne teintée en gris et
  le motif en infobulle (`title`) — même grammaire visuelle que "Patched" (vert) et "En attente"
  (ambre), pour que l'état se lise dans le tableau sans ouvrir de modale. Le vert reste prioritaire
  si les deux s'appliquent : un correctif prouvé prime sur "sans objet". Badge en `whitespace-nowrap`,
  la colonne CVE étant étroite (sans quoi il se coupe en "Faux"/"positif") ; boutons "Analyser", "Patch check",
  **"⏳ En attente"** et **"🚫 Faux positif"** (session 02/07/2026 — ouvrent `AnnotationModal`,
  annotation obligatoire, basculent en `awaiting_fix`/`false_positive`), "✓ Corrigé" (dropdown analyste)
- Tableau "Vulnérabilités en attente d'un patch correctif" (session 02/07/2026, entre "à traiter" et
  "traitées") : même mise en forme que "traitées" (thème ambre `#d29922` au lieu du vert), colonnes
  CVE/Sévérité/Score/Actif/**En attente depuis**/**Annotation** (contenu de `notes`, tronqué avec
  `title` au survol)/Actions ; boutons "🔍 Patch check" et "↩ Réouvrir" (`handleReopen`, partagé avec
  le tableau "traitées"). Statut `awaiting_fix` inclus dans le cycle de patch check autonome
  (cf. `docs/MATCHING.md`) — bascule automatiquement en `patched` dès qu'un correctif est détecté,
  sans repasser par "à traiter"
- Tableau "Vulnérabilités traitées" : regroupe deux issues terminales (session 02/07/2026) — `patched`
  (badge vert "Patched") et `false_positive` (badge **violet `#a371f7`** "Faux positif" — la doc
  annonçait un gris `#8b949e` jusqu'au 21/07/2026, c'était faux : le code utilise le violet) ; colonne "Clôturé le" (`patched_at || false_positive_at`, renommée
  depuis "Corrigé le" pour rester correcte dans les deux cas) ; colonne "Validé par / Annotation" —
  affiche le dropdown analyste pour un `patched`, ou l'annotation (cliquable → `AnnotationDetailModal`)
  pour un `false_positive` ; boutons "🔍 Patch check" (re-vérification ponctuelle) et "↩ Réouvrir"
- Bouton "🚫 Faux positif" (thème gris `#8b949e`) ajouté au tableau "à traiter", à côté de "⏳ En
  attente" — CVE dont le matching (CPE/mots-clés) était erroné, ne concerne pas réellement l'actif
  (cf. `docs/MATCHING.md` § Bugs de matching corrigés). Annotation obligatoire, comme "En attente".
  **Volontairement absent du cycle de patch check autonome** (`awaiting_fix` y est, `false_positive`
  non) — rien à revérifier, la CVE n'a jamais été le sujet.
- `AnnotationModal.jsx` (généralisé depuis l'ancien `AwaitingFixModal.jsx`) : modale d'annotation
  obligatoire réutilisée pour "En attente" (`color="#d29922"`) et "Faux positif" (`color="#8b949e"`) —
  props `color`/`subtitle`/`helpText`/`placeholder`/`confirmLabel` paramétrables. Depuis le
  02/07/2026, exige aussi un analyste (`<select>` réutilisant `ANALYSTS` de `ValidateDropdown.jsx`) —
  bouton de confirmation désactivé tant que note **et** analyste ne sont pas tous les deux renseignés,
  `onConfirm(note, validator)`. **Même mise en forme dans les deux tableaux** ("en attente" et
  "traitées") : une seule colonne "Validé par / Annotation" — badge analyste (bleu) empilé au-dessus
  de l'annotation (cliquable → `AnnotationDetailModal` si `notes` renseigné), pas deux colonnes
  séparées
- `AnnotationDetailModal.jsx` (nouveau) : lecture seule, affiche le texte complet d'une annotation
  (tronquée en ligne dans les tableaux) — déclenché en cliquant sur l'annotation dans "en attente" et
  "traitées" (uniquement si `v.notes` est renseigné)
- `moveVulnToPatched` (bascule auto détectée par le polling ou un patch check manuel) cherche la vuln
  dans `openVulnsRef` **et** `awaitingVulnsRef` — une vuln "en attente" peut être basculée en `patched`
  directement par le cycle autonome, sans repasser par "à traiter". `handleReopen` vide aussi
  `false_positive_at` désormais (partagé par les deux tableaux "traitées"/"en attente")
- Recherche CVE (session 02/07/2026) : input texte (substring sur `cve.cve_id`, insensible à la
  casse) dans les 3 tableaux — "à traiter" (`dashFilter.search`, dans la barre "Filtres" partagée avec
  le select sévérité), "en attente" (`awaitingSearch` → `filteredAwaitingVulns`) et "traitées"
  (`patchedSearch` → `filteredPatchedVulns`), chacun avec son propre état, indépendant des autres
  tableaux. Les badges de comptage (`X ouvertes`/`X en attente`/`X corrigées`) restent volontairement
  sur le total non filtré, comme le filtre sévérité déjà en place
- **Filtre "Actifs"** (session 02/07/2026, `AssetDropdown`, même pattern que `SourceDropdown` de
  `Watch.jsx`) : un/plusieurs/tous les actifs (case vide = tous), dans la barre "Filtres". Contrairement
  à sévérité/recherche (filtres locaux, n'affectent que le contenu d'un tableau), le filtre actif est
  un vrai changement de périmètre — il s'applique à **tout** : les 4 cartes KPI, "Taux de correction
  par sévérité", les 2 graphiques (répartition sévérité, top actifs exposés), les badges de comptage
  **et** le contenu des 3 tableaux. Implémentation :
  - `GET /api/stats?asset_id=uuid1,uuid2` côté backend (`routers/stats.py`) — tous les compteurs
    recalculés sur le sous-ensemble via un helper `scoped(q)` qui ajoute
    `.where(Vulnerability.asset_id.in_(asset_ids))` ; `total_assets` devient la taille de la
    sélection (pas la taille du parc) pour que "X exposés sur Y actifs" reste cohérent. **Recalcul
    côté backend plutôt qu'un simple filtre client** : les taux (`patch_rate_percent`, etc.) auraient
    été subtilement faux calculés depuis les tableaux déjà chargés sur le dashboard, qui ne couvrent
    pas les statuts `in_progress`/`accepted_risk` (jamais fetchés côté Dashboard.jsx)
  - `assetScopedOpen`/`assetScopedAwaiting`/`assetScopedPatched` (dérivés de `openVulns`/
    `awaitingVulns`/`patchedVulns` via `matchesAssetFilter`) servent de base à tout le reste
    (`filteredOpenVulns` etc. filtrent ensuite par sévérité/recherche par-dessus)
  - `selectedAssetIdsRef` — même pattern que `openVulnsRef`/`awaitingVulnsRef` : le polling
    (`useEffect(...,[])`) doit lire la sélection *courante* via `refreshStats()`, pas celle figée au
    montage
- Patch check manuel par ligne : modale avec détail des KB (installés/manquants) + `kb_os_hint` informatif
  (le KB installé correspond-il à l'OS déclaré de l'actif ? — jamais bloquant pour `patch_detected`)
- **Fraîcheur des données** (corrigé le 21/07/2026, cf. STATUS.md) — trois pièges à ne pas réintroduire :
  - Les badges de comptage (`X ouvertes` / `X en attente` / `X corrigées`) s'appuient sur l'état
    `totals`, alimenté par le champ `total` de la réponse API — **jamais** sur `assetScopedX.length`,
    qui n'est que la taille de la page chargée (`per_page: 200`). Utiliser la longueur de liste
    affichait "50 corrigées" pour 4600 en base, et contredisait la carte KPI juste au-dessus.
    `asset_id` est passé au serveur pour que ces totaux respectent le filtre "Actifs".
    Exception : en mode Présentation, c'est bien la longueur de liste qui compte (les vulns fictives
    sont fusionnées côté client et ignorées du serveur).
  - Le chargement des 3 tableaux vit dans `loadLists()` (useCallback), **pas** dans un `useEffect` de
    montage : un `setInterval` de 30s le rejoue en mode silencieux (`{ silent: true }`, sans spinner).
    Sans ça, les tableaux restaient figés sur l'état du chargement de page pendant que le cycle de
    patch check et la sync NVD modifiaient la base — il fallait changer de page pour resynchroniser.
  - Le polling de progression (3s) ne voit que `last_completed`, soit **une seule** vérification par
    tick. Le cycle en enchaîne davantage : ne pas compter dessus pour maintenir les listes à jour,
    c'est le rôle du rafraîchissement périodique.
  - Garde-fous : rafraîchissement suspendu pendant un patch check groupé (`batchProgressRef`, sinon
    `batchRowStatus` saute), purge des `selectedIds` devenus obsolètes, et `bumpTotals()` pour ajuster
    les compteurs immédiatement après une action au lieu d'attendre 30s.
- **Piège React à connaître** : le polling (`useEffect(..., [])`) capte `openVulns` tel qu'il était au
  montage (tableau vide, fetch pas encore résolu). Toute fonction appelée depuis ce polling qui a besoin
  de lire l'état courant (`moveVulnToPatched`) doit passer par un `useRef` maintenu à jour
  (`openVulnsRef`), jamais lire la closure directement — sinon le lookup échoue silencieusement pour
  toujours, peu importe le temps d'attente.
- **Bouton "✓ Corrigé (N)"** (session 21/07/2026, à côté de "🔍 Patch check (N)", tableau "à traiter") :
  réutilise `ValidateDropdown` pour choisir un analyste puis `POST /api/vulnerabilities/bulk-patch` sur
  toute la sélection — aucune restriction de sévérité (même action manuelle que le "✓ Corrigé" unitaire,
  juste groupée). À ne pas confondre avec "🛡️ Validation groupée CRITICAL" de `Vulnerabilities.jsx`
  (réservé aux candidats à signal positif, cf. plus bas).
- **Filtre "🚫 Faux positifs uniquement (N)"** + **bouton groupé "🚫 Faux positif (N)"** (session
  21/07/2026, pendants exacts de "✓ Patch détecté uniquement" / "✓ Corrigé (N)") : même flux de
  travail, mais pour les CVE **sans objet** sur l'actif. La liste des candidats vient du backend
  (`GET /false-positive-candidates`, rechargée avec les listes toutes les 30s) — le frontend ne
  décide pas lui-même de ce qui est un faux positif, il ne fait qu'indexer les ids reçus
  (`fpCandidateIds`). Le bouton groupé n'apparaît que si la sélection contient au moins un candidat,
  et n'agit **que** sur cette part éligible : marquer faux positif reste un jugement, on ne l'ouvre
  pas à une sélection arbitraire. Ouvre `BulkQualifyModal.jsx` (annotation + analyste requis).
- **Filtre "✓ Patch détecté uniquement"** (checkbox, barre "Filtres" du tableau "à traiter", session
  21/07/2026) : n'affiche que les vulns dont `v.patch_detected` (persisté en base par le dernier patch
  check, pas seulement un check lancé dans la session en cours) est vrai.
  - **Bug corrigé le 21/07/2026** : `toggleSelectAll` sélectionnait sur `openVulns` (liste brute) au
    lieu de `filteredOpenVulns` (liste réellement affichée après filtres) — invisible avec peu de
    filtres actifs, très visible avec ce nouveau filtre qui réduit la liste à quelques lignes. La
    checkbox d'en-tête (`allVisibleSelected`) utilisait déjà la bonne liste ; seule la fonction de clic
    avait la mauvaise source.
- **Bouton "📋 Justificatif"** (session 21/07/2026, tableau "traitées", juste avant "🔍 Patch check")
  — **couvre tous les motifs de clôture** : annotation d'analyste (`notes`) et/ou détail technique du
  patch check (`patch_check_details`), concaténés et préfixés quand les deux coexistent. Il ne
  couvrait initialement que les corrections automatiques : une ligne qualifiée à la main n'avait
  aucun bouton, alors que c'est précisément là que le raisonnement humain doit rester consultable
  (audit NIS 2). Couleur alignée sur le statut (vert `patched` / violet `false_positive`).
- *(ancienne description, conservée pour le contexte)* Bouton "📋 Justificatif"
  (masqué pour les faux positifs) : affiche `v.patch_check_details` (texte déjà généré par
  `patch_checker.py`, ex. "✅ bash : bash 5.2.15-2+b13 installé — corrigé à partir de 4.3-9.2") via
  `AnnotationDetailModal.jsx` généralisé (props `text`/`title`/`emptyText` optionnels, en plus de
  l'usage existant sur `vuln.notes`).
- **Modale patch check** : badge "en cache — il y a Xs" + bouton "🔄 Relancer un scan" quand le résultat
  vient du cache court terme (`MIN_RECHECK_GAP`, cf. `docs/MATCHING.md`) — même ajout que sur
  `Vulnerabilities.jsx`, toujours dupliqué entre les deux pages (pas de composant modale partagé).
- **Annotations en Markdown + modale uniforme pour "✓ Corrigé"** (session 22/07/2026) : les 3 boutons
  "✓ Corrigé" du Dashboard (ligne individuelle, validation groupée `(N)`, modale de patch check)
  ouvrent désormais `AnnotationModal` — même apparence que "En attente"/"Faux positif" — au lieu du
  dropdown `ValidateDropdown`. Seule différence : `noteRequired={false}`, la note reste facultative
  (corriger une vuln non-CRITICAL est une action rapide, cf. `CLAUDE.md`). `bulkPatch` (API + backend
  `BulkPatch`) accepte désormais un `notes` optionnel appliqué à toute la sélection.
  Les annotations acceptent la syntaxe Markdown et sont rendues (`MarkdownNote.jsx`) partout où elles
  s'affichent en entier — popup "📋 Justificatif" (qui distingue désormais bloc annotation Markdown vs
  bloc technique brut, cf. `AnnotationDetailModal.jsx` ci-dessus), détail "en attente"/"faux positif",
  bloc d'annotation de la modale de patch check — et en aperçu clampé 2 lignes directement dans les
  tableaux "en attente"/"traitées" (plus besoin de cliquer pour voir un rendu, seul le texte complet
  reste derrière le clic).
- **Édition d'une annotation "en attente"** (session 22/07/2026) : bouton "✏️ Modifier" sur chaque ligne
  du tableau "en attente d'un patch correctif", à côté de "🔍 Patch check"/"↩ Réouvrir" — ouvre
  `AnnotationModal` pré-rempli (`initialNote`/`initialValidator`) et appelle `handleUpdateNote`, qui ne
  touche que `notes`/`validated_by` via `PATCH /api/vulnerabilities/{id}` (sans `status`) — le statut,
  `awaiting_fix_at` et le cycle de recheck restent intacts.

- **Bandeau de rattrapage "depuis votre dernière visite"** (session 22/07/2026) : au montage du
  Dashboard, compare `localStorage['last_seen_auto_bascule']` à
  `GET /api/vulnerabilities/auto-bascule-summary?since=` pour résumer les bascules **automatiques**
  (jamais les validations manuelles — l'analyste sait déjà ce qu'il a cliqué lui-même) survenues
  depuis. Répond au vrai trou du flash existant (`actionMsg`, disparaît en 4s, ne fonctionne que
  Dashboard ouvert) : le cycle autonome tourne aussi la nuit (toutes les 6h) sans personne devant
  l'écran, donc rien n'était rattrapable. Persistant (fermeture manuelle, pas de `setTimeout`),
  échantillon de 8 lignes + total exact (backend), première visite sur un navigateur = pas de
  rattrapage (juste amorce du repère). **Absent en mode Présentation** : l'endpoint renvoie de vrais
  `cve_id`/noms d'actifs, jamais anonymisés côté serveur.
  Pas de compte utilisateur dans Allsafe (cf. `CLAUDE.md`) — "depuis votre dernière visite" est donc par
  **navigateur** (localStorage), pas par session serveur : deux postes distincts ont chacun leur
  propre rattrapage.

### Reports.jsx — Archives hebdomadaires (session 22/07/2026)

**Page simplifiée le 22/07/2026 à la demande de l'utilisateur** : le filtre de période (7 j / 30 j /
tout l'historique) et la carte « Résumé exécutif » à la demande ont été **supprimés** — les rapports
hebdomadaires les remplacent (la période, c'est la semaine). Il ne reste que le filtre Actifs,
l'export CSV du backlog et les archives (626 → ~320 lignes).

**Le filtre Actifs pilote la portée des archives** : aucune sélection = rapports du parc entier ;
un ou plusieurs actifs = leurs rapports (une ligne par semaine et par actif, colonne « Portée »).
Le rapport ouvert est refermé au changement de portée, sinon il resterait affiché hors contexte.
`useEffect` sur `selectedAssetIds.join(',')` et non sur le tableau lui-même — une nouvelle référence
de tableau à chaque rendu relancerait le chargement en boucle.

Section « Archives hebdomadaires » sous les cartes Résumé/Export CSV : un tableau des rapports
**figés**, une ligne par semaine ISO (`S30/2026`), avec compteurs (corrigées / en attente / faux
positifs), date de génération et auteur (`Auto (hebdomadaire)` ou `Manuel`).

- Bouton **« 📅 Générer la semaine écoulée »** — cible la dernière semaine ISO complète, la même que
  la tâche planifiée du lundi 7h. Si le rapport existe déjà, le backend renvoie `created: false` et
  l'UI l'affiche tel qu'il a été figé au lieu de le réécrire.
- Badge **« en cours »** (ambre, pointillé — même grammaire que les autres badges « proposition »,
  cf. `STATUS.md`) quand `complete: false` : le rapport couvre une semaine encore en cours au moment
  de sa génération, ses chiffres sont partiels et il sera régénéré automatiquement une fois la
  semaine close.
- **« 👁 Consulter »** affiche le markdown figé via `renderMd` (le moteur déjà utilisé pour le résumé
  à la demande, non extrait — cf. dette ci-dessous), avec export **PDF** (`exportPdf`) et **CSV**
  (`GET /reports/weekly/{id}/csv`, reconstruit depuis le snapshot).
- Mode Présentation : `redactText` appliqué au markdown affiché, au PDF **et** au CSV téléchargé —
  un rapport archivé contient des noms d'hôtes et d'analystes réels.

✅ **Dette réglée le 22/07/2026, avant d'écrire le 2e rapport** : le moteur Markdown (`renderMd`,
`Inline`, `MdTable`, coloration des sévérités) et le convertisseur Markdown→HTML du PDF (`exportPdf`)
étaient enfermés dans `Reports.jsx`. Extraits tels quels dans `components/ReportMarkdown.jsx`
(`Reports.jsx` : 626 → 416 lignes), pour que les rapports Veille et Surveillance s'en servent au lieu
de les recopier — le sort de la modale de patch check, toujours dupliquée entre `Dashboard.jsx` et
`Vulnerabilities.jsx`. **Toute évolution du rendu d'un rapport se fait désormais dans ce seul
fichier.**

Deux moteurs de rendu Markdown coexistent volontairement, ne pas les fusionner :
- `MarkdownNote.jsx` (`marked` + `dompurify`) → **annotations d'analyste**, texte libre saisi par un
  humain, donc sanitizé.
- `ReportMarkdown.jsx` (maison) → **rapports**, texte généré par le backend. Colore les mots de
  sévérité (CRITICAL/ÉLEVÉ/…) et produit en plus une sortie HTML autonome pour l'impression PDF, deux
  besoins que `marked` ne couvre pas.

### RapportVeille.jsx — rapport hebdomadaire de veille (session 22/07/2026)

La page conserve son export CSV du registre (filtrable par thème) et gagne la section « Archives
hebdomadaires » via le **même composant** `WeeklyArchives.jsx` que le Rapport exécutif CVE — seules
changent `kind="veille"` et les colonnes de comptage (Collectés / Traités / Critiques ouverts). Pas
de portée par actif : le registre de veille n'est pas rattaché au parc.

**Le composant a été extrait avant d'écrire ce 2e rapport**, pas après : c'est ce qui a évité de
dupliquer ~120 lignes de tableau, modale et handlers d'export. `Reports.jsx` est passé de 626 lignes
(avant la session) à ~150.

### RapportSurveillance.jsx — rapport hebdomadaire de surveillance (session 22/07/2026)

Anciennement une page « Module à venir » vide. Réécrite en **26 lignes** : uniquement
`<WeeklyArchives kind="surveillance" …>` avec ses colonnes de comptage (Identités surveillées /
Fuites correspondantes / IP blocklistées). C'est la démonstration que l'extraction du composant a
tenu sa promesse — aucun tableau, aucune modale, aucun handler d'export à réécrire.

### Watch.jsx — profil de veille (session 22/07/2026)

Icône ⚙️ à gauche de « Synchroniser » → `WatchProfileModal`. L'icône passe en bleu dès qu'au moins un
terme est configuré, et la case de filtre « Concerne mon parc » **n'apparaît que dans ce cas** : sans
termes elle ne filtrerait rien et laisserait croire à un bug.

Dans la modale, cocher un OS **restreint la liste des logiciels** aux machines de cet OS (recoupement
client sur le champ `assets` déjà porté par chaque suggestion, sans appel supplémentaire), et
« Tout sélectionner » agit sur la liste affichée — pas sur les 176 suggestions.

Badge `★ terme` sur les lignes correspondantes, à gauche des thèmes. Le décompte de termes vient de
`profile_terms`, renvoyé par la liste — pas d'appel séparé.

⚠️ Sous `profile_only`, la pagination est calculée **en Python** côté backend (la correspondance est
textuelle, non exprimable en SQL) : `total` reste juste, vérifié sur 22 résultats paginés par 10.

### Watch.jsx — filtre « Traitement » (session 22/07/2026)

4e ligne de la barre de filtres, entre Sévérité et Thèmes : puces multi-sélection **Nouveau / En cours
/ Traité / Non concerné**, plus un raccourci **« Reste à traiter »** (= Nouveau + En cours en un clic,
le geste de suivi quotidien ; re-cliquer le désactive).

- Les puces sélectionnées utilisent `STATUS_FILTER_STYLES`, une version **renforcée** de
  `STATUS_STYLES` (fond 0,28–0,35 au lieu de 0,12, bordure pleine, texte éclairci). Les 12% des
  badges du tableau suffisent sur fond neutre mais ne se voient pas quand il s'agit de signaler
  « ce filtre est actif » — les 4 puces sont désormais à ≥ 5:1 de contraste (WCAG AA).
- **`not_applicable` est passé du gris au violet `#a371f7`**, badges du tableau compris : il était
  strictement identique à `new` (même gris), donc indistinguable. Le violet est déjà la couleur de
  « Faux positif » côté vulnérabilités — même idée sémantique.
- Le libellé de ligne est en `w-24` (et non `w-16`) sur les trois lignes : « Traitement » débordait de
  sa colonne et collait à la première puce.
- Aucun changement backend : `GET /api/watch?status=` acceptait déjà une liste séparée par virgules
  (`_apply_multi`), comme `source`/`severity`/`themes`.
- Vérifié : les sous-totaux partitionnent exactement le total (1144 + 1 + 6 + 8 = 1159).

### Watch.jsx — consultation et décisions en Markdown (session 22/07/2026)

- **Badge de statut cliquable** dans le tableau → ouvre le détail de l'élément. Le geste naturel quand
  on cherche « pourquoi cet élément est dans cet état ». `StatusBadge` ne devient cliquable que si un
  `onClick` lui est passé — ailleurs (modale) il reste un simple `<span>`, sans faux affordage.
- **Bouton d'action contextuel** : « Traiter » (neutre) tant que l'élément est `new`/`in_review`,
  « **Consulter** » (vert, variante `success`) une fois `treated`/`not_applicable`. Un élément déjà
  qualifié n'est plus « à traiter » — l'analyste voit ce qui lui reste à faire sans lire la colonne
  Statut. Complète la date de traitement déjà affichée en vert.
- **Décision rendue en Markdown** (`MarkdownNote`, le composant des annotations d'analyste) dans un
  bloc « Décision enregistrée » en tête de la zone de traitement, avec analyste et date. Le champ de
  saisie reste juste en dessous, son libellé passant à « Modifier la décision / action » — on consulte
  et on corrige au même endroit, sans second écran.

### Watch.jsx — actifs concernés (session 22/07/2026)

La modale « Traiter » gagne un champ **« Actifs concernés »** (facultatif), entre « CVE liée » et
« Décision / Action ». Réutilise `AssetDropdown` (multi-sélection), déjà partagé par Dashboard et
Reports — aucun nouveau composant.

Deux détails qui comptent à l'enregistrement :
- la comparaison avant/après se fait sur le **contenu trié** (`[...].sort().join(',')`) : un tableau
  JS neuf est toujours `!==` de l'ancien, et l'ordre de sélection n'est pas une modification ;
- le champ n'est envoyé que s'il a changé, cohérent avec le reste du PATCH partiel de cette modale.

### CVEs.jsx
- TextInput recherche full-text + Select filtres sévérité
- Table Tremor paginée
- Colonnes : CVE ID, description (tronquée), CVSS, EPSS, Badge sévérité, source, date
- Clic sur une ligne → panneau latéral détail CVE

### Assets.jsx
- Table : nom, OS, type, source (Badge, dont "Ajout manuel" en violet), dernier scan, apps (badge
  cliquable → modale sans re-scanner), nb vulns ouvertes (barre), actions
- Bouton "Ajouter un actif" (haut droit) → modale `AssetFormModal` (nom, hostname, IP, OS, version,
  type — pas de mot de passe, un seul compte de service sert pour tout le parc)
- Actions par ligne : **Scanner** (modale `ScanResultModal`), **Modifier** (réutilise `AssetFormModal`
  en mode édition), **Supprimer** (modale `DeleteAssetModal` — exige de retaper le nom exact de
  l'actif pour activer le bouton, avertit si des vulns liées seront supprimées en cascade)
- **Le bouton "Scanner" privilégie le cache** (session 27/07/2026, `handleRowScanClick`) : si
  `asset.last_scan` existe, ouvre le dernier résultat déjà en base (`getAssetPackages`, rapide) plutôt
  que de relancer systématiquement une connexion SSH/WinRM. Seul un actif jamais scanné déclenche un
  scan live d'emblée. Un scan live reste toujours possible via le bouton "🔄 Relancer un scan"
  **à l'intérieur** de `ScanResultModal` (prop `onRescan`/`rescanning`) — même geste que le bouton
  "🔄 Relancer un scan" du patch check (`Vulnerabilities.jsx`).
- **Badge vulnérabilité par paquet** (session 27/07/2026, tableau "Applications installées" de
  `ScanResultModal`) : colonne "Vulnérabilités" — `SeverityBadge` + compte, `title` listant les CVE au
  survol, alimenté par `vuln_count`/`severity`/`cve_ids` (cf. `docs/ARCHITECTURE.md` §
  `get_installed_package_vulnerabilities`). **Linux uniquement** — n'affiche que "—" côté Windows
  (limitation backend documentée, pas un bug frontend).
- Bloc "Durcissement / conformité" de `ScanResultModal` : liste de checks bornée
  (`max-h-40 overflow-y-auto`) pour ne pas allonger excessivement la modale — ajouté le même jour que
  le badge ci-dessus, la modale avait bien grossi avec les deux nouveaux blocs (compliance + vuln par
  paquet) en plus de "Fiabilité"/"Specs matérielles" déjà présents.
- **Correction automatique du nom au scan** (session 02/07/2026, `routers/assets.py`) : un actif
  ajouté à la main porte souvent un nom saisi sans vérification (ex: "hortholary", le nom de
  l'utilisateur ayant rempli le formulaire, pas le nom réel de la machine). Dès que le scan détecte un
  hostname différent de celui déclaré, `hostname` **et** `name` (le nom affiché partout dans l'UI)
  sont alignés automatiquement sur la valeur détectée — même logique que la correction de CPE déjà
  appliquée à l'OS déclaré après scan. `ScanResultModal` affiche un bandeau bleu "Nom corrigé
  automatiquement" quand ça arrive ; un bandeau orange si la correction échoue (hostname détecté déjà
  utilisé par un autre actif — contrainte unique sur `Asset.hostname`, le reste du scan est conservé).
  `Inventaire.jsx` répercute aussi le renommage dans sa propre liste (pas de bandeau dédié, page
  patrimoine pas fiabilité)
- **Version OS jamais persistée après scan** (bug réel, session 02/07/2026) : le numéro de version
  détecté (`VERSION_ID`, ex: "12") servait déjà à reconstruire le CPE mais n'était jamais écrit sur
  `asset.os_version` — le champ restait vide indéfiniment même après scan. Même correction que le
  hostname : `os_version` alignée sur la valeur détectée à chaque scan ; `os` (champ court, ex.
  "Debian") seulement rempli s'il était vide, pour ne jamais écraser un libellé court par le
  PRETTY_NAME complet ("Debian GNU/Linux 12 (bookworm)")
- **Nom d'actif cliquable** (`Assets.jsx`, colonne "Nom") : ouvre `ScanResultModal` via
  `handleViewPackages` (même action que le bouton "X apps") — fiabilité déclaré/détecté **et**
  desormais **specs matérielles** (CPU/**architecture**/cœurs/RAM/disques/MAC/ports, section portée
  depuis `PackagesModal` d'Inventaire.jsx, absente de `ScanResultModal` jusque-là — c'était la cause
  du "il manque les infos CPU" côté Actifs)
- **Architecture 32/64 bits** (session 03/07/2026, `hardware.arch`) : ligne "Architecture" dans
  `ScanResultModal`, sous CPU/RAM — cf. `docs/ARCHITECTURE.md` § scan d'actif pour la collecte
  backend
- **Criticité métier** (session 27/07/2026) : `<select>` Haute/Moyenne/Faible dans `AssetFormModal`
  (copié du pattern du select "Type d'actif"), badge `CriticiteBadge.jsx` en colonne du tableau.
  Pondère le score de risque des vulns de l'actif (`scoring.py`, ×1.5/×1.0/×0.7) — recalculé
  automatiquement à l'enregistrement, cf. `docs/MATCHING.md` § Criticité métier.
- **Bloc "Durcissement / conformité"** (session 27/07/2026, `ScanResultModal`) : entre "Fiabilité des
  infos déclarées" et "Specs matérielles", liste de checks CIS-like (`ComplianceRow`, calqué sur
  `MatchRow` — icône ✓/⚠/— + couleur) alimentés par `result.compliance.checks` (cf.
  `docs/ARCHITECTURE.md` § Durcissement / conformité pour le détail backend). "—" = indéterminé
  (droits insuffisants en lecture seule), jamais une non-conformité.
- **Filtres OS + recherche par nom** (session 28/07/2026) : `<select>` piloté par les OS réellement
  présents dans `assetList` (`[...new Set(assetList.map(a => a.os))]`, jamais codé en dur — cohérent
  avec le principe scalable) + `<input>` de recherche substring sur le nom, tous deux en filtrage
  client (72 actifs, pas d'aller-retour serveur). Combinables. Le compteur d'en-tête affiche
  `filtré / total` dès qu'un filtre réduit la liste.

### Inventaire.jsx (route `/inventaire`)
- Table : nom, CPU, **architecture**, cœurs, RAM, disques, apps (badge), dernier scan, action Scanner
- Vue *patrimoine IT*, distincte d'Actifs (vue *sécurité*) — mêmes actifs en base, présentation différente
- Bouton "Scanner" par ligne → même endpoint que Assets.jsx (`POST /api/assets/{id}/scan`), ouvre
  `PackagesModal` (specs matérielles, dont **architecture** + liste d'applications avec recherche)
- **Même cache-first + "Relancer un scan"** que Assets.jsx (session 27/07/2026, `handleRowScanClick`) :
  ouvre le cache si déjà scanné, scan live seulement au premier scan ou via le bouton dédié dans
  `PackagesModal`. Même badge vulnérabilité par paquet (Linux uniquement) que `ScanResultModal`.
- **Bouton "Exporter en PDF"** (session 28/07/2026, haut droit) : télécharge
  `GET /api/reports/inventory/pdf` (blob) — un tableau récapitulatif de tous les actifs (nom, OS, CPU,
  arch, cœurs, RAM, disques, **nombre** d'applications). Pas la liste des applications : l'appendice
  détaillé a été retiré le jour même à la demande de l'utilisateur (cf. `docs/ARCHITECTURE.md` § Export
  PDF Inventaire) — le détail nom + version reste consultable à l'écran via `PackagesModal`.
  Détail backend : `services/inventory_export.py`, `reportlab`. **Bloqué en mode Présentation** (bannière
  d'erreur explicite) : contrairement au CSV des Rapports, pas de redaction possible côté client pour
  un PDF déjà généré — exporter exposerait noms d'actifs/IP réels en pleine démo.

### Audits.jsx (route `/audits`, ex-`Pentest.jsx` / `/pentest` jusqu'au 30/07/2026)
- Placeholder, mais contrairement à Bastion le module est **spécifié** : cf. `docs/AUDITS.md`
  (modèle de données, garde-fou d'autorisation bloquante, intégrations). Chantier prioritaire.
- Renommé « Pentest » → « Audits » le 30/07/2026 : un seul modèle couvrira les 5 types d'audit
  (architecture, configuration, code, pentest, Red Team) plutôt qu'un module pentest-only.
- La page liste déjà ces 5 types, pour que le placeholder annonce le périmètre au lieu d'un simple
  « rien pour l'instant ».

### Bastion.jsx (route `/bastion`, session 30/07/2026)
- Placeholder ("En cours de développement"), même charpente visuelle que `Audits.jsx` — futur accès
  bastion/jump host vers les serveurs critiques, portée à définir. Sans rapport avec l'ancien module
  « Bastion » (sélecteur « Je suis… », `visible_modules`) retiré la même session, cf. § Nav ci-dessous
  et `docs/ARCHITECTURE.md` § Authentification pour la distinction. Le texte du placeholder signale
  explicitement la tension à venir avec la règle de non-intervention (CLAUDE.md § 1) — un bastion de
  connexion directe aux serveurs ira à l'encontre de « CyberVuln n'exécute et n'écrit jamais rien sur
  un serveur », à trancher avant toute implémentation réelle.

### Watch.jsx (route `/veille`, groupe nav CyberVeille) — registre auditable NIS 2
Détail complet du module (workflow, sources, thèmes, SLA) dans `docs/VEILLE.md`. Ci-dessous, ce qui
concerne spécifiquement le frontend. ⚠️ En-tête + KPIs retravaillés le 14/08/2026 (`PageHero`, rangée
forcée à l'horizontale, une couleur par KPI) — cf. section dédiée plus haut.
- KPIs (4 cards), filtres multi-sélection (sources en dropdown 4 colonnes, sévérité/thèmes en chips,
  toggle SLA), tableau avec modale de traitement (statut/**sévérité** (session 20/07/2026, cf. ci-dessous)
  /analyste/CVE liée/décision), export CSV
- Thème **IA** ajouté (session 20/07/2026, cf. `docs/VEILLE.md` § 3) — `THEMES` (const `Watch.jsx` +
  `RapportVeille.jsx`) trié par **ordre alphabétique** (demande explicite) plutôt que dans l'ordre
  d'origine, un peu arbitraire, du `THEME_KEYWORDS` backend (lui aussi retrié pareil, par cohérence,
  bien que son ordre de dict n'ait aucun effet fonctionnel)
- Bouton "Synchroniser" (session 20/07/2026) affiche "Dernière sync : jj/mm/aaaa hh:mm" sous le bouton —
  même mécanique que "Matching CVE" sur `Dashboard.jsx` (`GET /api/watch/sync-status`, `sync_state` clé
  `watch` — partagé avec `FuiteDeDonnees.jsx` puisque `run_watch_sync` est un job unique commun aux deux
  pages, cf. `docs/ARCHITECTURE.md`)
- Modale de traitement : sélecteur **Sévérité** (Critique/Important/Informatif, mêmes badges que
  `SEV_STYLES`/`SEV_LABELS`) ajouté au-dessus du workflow de statut (session 20/07/2026) — `PATCH
  /api/watch/{id}` body `{severity}`. Changer la sévérité d'un item modifie rétroactivement son
  inclusion dans le SLA 48h et l'export CSV auditeur (§ 4.1/6, `docs/VEILLE.md`), qui ne portent que sur
  `severity=critical` — aucune trace de qui a changé quoi n'est gardée pour ce champ spécifiquement
  (contrairement au statut, qui a `reviewed_by`/`reviewed_at`/`decision`)
- `SourceDropdown` : panneau horizontal — 3 colonnes fixes (Officielles / Médias & trackers / Éditeurs
  sécu, dérivées de `SOURCES`/`SOURCE_GROUPS`) + une 4e colonne **"Personnalisées"**, dynamique,
  peuplée par `GET /api/watch/sources?category=general` (`reloadCustomSources`) — chaque source y a
  une case à cocher (filtre, comme les sources natives) et un bouton `×` (suppression, confirm()
  navigateur puis `DELETE /api/watch/sources/{id}`). Lien **"+ Ajouter une source"** en bas de cette
  colonne → `components/AddSourceModal.jsx` (`category="general"`, accent `#58a6ff`)
- `BUILTIN_LEAK_SOURCES` (export nommé) : liste de secours des sources natives "fuite" utilisée avant
  la résolution de `GET /api/watch/leak-sources` (laquelle inclut aussi les sources personnalisées
  `category=leak`) — cette liste résolue (`leakSources`, state) alimente `exclude_source` sur
  `loadItems`/`loadKpis`, pour que les sources dédiées fuite (natives ou ajoutées depuis Fuite de
  données) n'apparaissent jamais dans ce registre

### FuiteDeDonnees.jsx (route `/fuite-de-donnees`, groupe nav CyberVeille) — onglet informatif
Détail complet du module (sources, pays, modèle de données) dans `docs/VEILLE.md` § 9. Ci-dessous, ce
qui concerne spécifiquement le frontend. ⚠️ En-tête + bandeau de stats + cartes retravaillés le
14/08/2026 (`PageHero`, grille plafonnée `min(...,1fr)`, liseré coloré par source) — cf. section
dédiée plus haut.
- Grille de cards responsive (1/2/3 colonnes), pas de tableau — chaque card : badge source coloré +
  nom de l'entité à côté (extrait via `parseCompany()` pour ransomware.live, titre brut pour les
  autres sources), drapeau pays (`components/FlagIcon.jsx`) en haut à droite, résumé tronqué, date
- Filtres : chips source (natives + personnalisées, couleur fixe pour les natives via `SOURCE_COLORS`,
  dérivée du slug via `colorForSlug()` pour les personnalisées) + filtre pays (France par défaut /
  Monde entier / sélection multiple via `CountryDropdown`, `utils/countries.js`)
- Ajout/suppression de source personnalisée : même mécanique que `Watch.jsx` mais `category="leak"`,
  accent `#a371f7` (violet, cohérent avec le reste de la page) — bouton "+ Ajouter une source" dans la
  barre de chips, `handleAddSource` déclenche un `syncWatch()` immédiat après création pour voir le
  résultat sans action supplémentaire
- Bouton "Synchroniser" (session 20/07/2026) affiche "Dernière sync : jj/mm/aaaa hh:mm" sous le bouton —
  cf. `Watch.jsx` ci-dessus pour le détail (endpoint et table partagés)

### SurveillanceIdentites.jsx (route `/surveillance-identites`, groupe nav CyberVeille) — session 20/07/2026
Détail complet du module (matching, sources, limite) dans `docs/VEILLE.md` § 9bis/9ter. Frontend :
- Card "Identités surveillées" : formulaire d'ajout (toggle **Nom/Domaine/IP/Plage IP**, `KIND_OPTIONS`
  + placeholder par type via `KIND_PLACEHOLDERS`) et chips groupés par type (Noms / Domaines / IP /
  Plages IP) avec `×` de suppression. `POST`/`DELETE /api/identities` puis rechargement (les matches
  dépendent des identités, donc `reload()` refait les deux appels)
- Résultats **name/domain** en cards responsive (même style que `FuiteDeDonnees.jsx`) : badge source,
  nom d'entité (`displayTitle` isole la victime pour ransomware.live), drapeau pays, résumé, date — plus
  des **badges rouges** listant les identités ayant matché (`matched_identities`)
- Résultats **ip/ip_range** (session 20/07/2026) — section **séparée**, en tableau plutôt qu'en cards
  (donnée tabulaire, pas d'article/titre/résumé) : colonnes Votre identité / IP détectée / Source /
  Détail (`ip_matches` de la réponse `/api/identities/matches`, forme différente de `items`)
- États vides distincts : aucune identité (invite à en ajouter) vs aucun résultat des deux types
  (message vert "Aucune fuite détectée" — bonne nouvelle, pas une erreur). Compteur d'en-tête =
  `matches.total + ipMatches.length` (les deux signaux additionnés pour un coup d'œil rapide)
- Accent bleu `#58a6ff` (couleur du module CyberVeille).
- **Mode Anonyme** (session 20/07/2026, `usePresentation`) — cas le plus sensible du mode Présentation :
  les identités surveillées contiennent littéralement le nom/domaine réel de l'entreprise, et les
  fuites matchées sont des articles publics en texte libre qui les citent nommément. Contrairement à
  `anonymizeAsset` (substitution de champs structurés), impossible d'anonymiser un titre d'article par
  simple remplacement de propriété : `anonymizeIdentity`/`anonymizeIdentityMatch` (`utils/fakeData.js`)
  redirigent donc chaque occurrence du nom/domaine réel **dans le texte** (titre + résumé) vers son
  équivalent fictif, déterministe par hash — même technique que `redactText` (`Reports.jsx`). Complété
  par `FAKE_IDENTITIES`/`FAKE_IDENTITY_MATCHES` (entreprise "Norvenia Group" 100% fictive) pour que la
  démo reste parlante même sans fuite réelle. Ajout/suppression désactivés en mode Anonyme (cohérent
  avec "rien n'est jamais persisté en mode Présentation") plutôt que d'écrire le vrai nom d'entreprise
  en base pendant une démo, ou d'appeler `DELETE` sur un id `demo-*` inexistant côté serveur.
- IP/plage IP anonymisées pareil (`FAKE_PUBLIC_IPS`/`FAKE_PUBLIC_IP_RANGES` — plages RFC 5737/TEST-NET,
  jamais routées sur Internet, donc sûres à afficher). `anonymizeIpMatch` ne redirige que
  `identity_value` (votre IP surveillée réelle) ; l'IP blocklistée (`ip`) est une donnée publique — IP
  attaquante tierce, pas la vôtre — donc jamais anonymisée.

### Vulnerabilities.jsx — bouton « 📋 Justificatif » (session 22/07/2026)

Même bouton que le Dashboard, à gauche de « ↩ Réouvrir » : n'apparaît que si `notes` ou
`patch_check_details` existe, et ouvre `AnnotationDetailModal` avec les mêmes `blocks` (annotation
d'analyste en Markdown + résultat technique en texte brut). Couleur alignée sur le statut — vert
`patched`, violet `false_positive`, ambre `awaiting_fix`.

### Vulnerabilities.jsx
**Section réécrite le 21/07/2026 — l'ancienne version (table "Tremor", boutons "Analyser IA"/"Voir
correctif"/"Marquer corrigé"/"Risque accepté") ne correspondait plus à rien de réel depuis longtemps ;
cf. § Stack Frontend, aucun composant Tremor n'est utilisé dans l'app.**

- Barre "Filtres" : statut, sévérité, valideur (`ANALYSTS`, `validated_by`), checkbox "Masquer les
  CVE > 2 ans" (`max_age_years`, session 20/07/2026, cf. `docs/ARCHITECTURE.md`)
- Table triable (sévérité/score/date), colonnes CVE / Actif / Statut / Sévérité / Score / Publié /
  Détecté / Date patch (si filtre = patched) / Validé par (idem) / Actions
- Actions par ligne : "Analyser" (`POST /api/analysis/cve`), "🔍 Patch check", "Recommandation"
  (`POST /api/remediation/recommend`), "Script" (`POST /api/remediation/script`), puis soit
  `ValidateDropdown` "✓ Corrigé" (bascule `patched`) soit "↩ Réouvrir" (vuln déjà `patched`)
- **Bouton "🛡️ Validation groupée CRITICAL (N)"** (session 21/07/2026, à côté du titre, visible
  seulement s'il y a des candidats) → ouvre `BulkValidateModal.jsx` (nouveau composant) : liste des
  CVE CRITICAL avec un signal de patch check positif (`GET /api/vulnerabilities/critical-review-
  candidates`), cases à cocher (tout présélectionné), sélecteur d'analyste, un clic
  (`POST /api/vulnerabilities/bulk-validate`) pour valider la sélection. Garde la règle CLAUDE.md
  (CRITICAL toujours validé manuellement) : l'analyste choisit explicitement quoi confirmer, ce n'est
  pas une bascule automatique du système.
- **`BulkQualifyModal.jsx`** (généralisé depuis `FalsePositiveBulkModal.jsx` le 21/07/2026) — sert
  **quatre** flux de qualification groupée, structurellement identiques (liste + cases à cocher +
  analyste + annotation obligatoires) : faux positifs, "en attente de correctif", "risque accepté"
  (27/07/2026, avec `showReviewDate`), et extensible. Props `titre`/`sousTitre`/`couleur`/
  `confirmLabel` ; la couleur suit le statut cible (violet `#a371f7` faux positif, ambre `#d29922` en
  attente, gris `#8b949e` risque accepté). Dupliquer une 4e fois aurait multiplié la maintenance — cf.
  principe "penser scalable" (`CLAUDE.md`).
- **Bouton "⏳ En attente de correctif (N)"** (page Vulnérabilités, session 21/07/2026) — CVE dont la
  distribution n'a publié **aucun** correctif (`GET /awaiting-fix-candidates`). Comble une asymétrie :
  les flux groupés existaient pour "corrigé" et "faux positif", mais ces lignes — surtout des
  CRITICAL, que la règle interdit de basculer automatiquement — devaient être traitées une par une.
- **Bouton "🚫 Faux positifs à qualifier (N)"** (session 21/07/2026, à côté de la validation groupée
  CRITICAL) → `FalsePositiveBulkModal.jsx`. Liste les CVE ne concernant pas réellement l'actif
  (`GET /false-positive-candidates`, 2 motifs objectifs : rattachement erroné / produit non installé),
  avec cases à cocher, sélecteur d'analyste et **zone de justification obligatoire** (texte
  pré-rempli selon le motif, modifiable — c'est l'analyste qui assume ce qui part dans la piste
  d'audit). Bouton de confirmation désactivé tant qu'aucun analyste n'est choisi.
  **Distinct de "corrigé" à dessein** : rien n'a été corrigé, le produit n'était pas là — la
  distinction compte pour l'audit NIS 2.
- **Modale résultat patch check** (`patchModal`, dupliquée à l'identique dans `Dashboard.jsx` — pas de
  composant partagé) : badge ✅/❌ `patch_detected`, bandeau build/révision, bandeau bleu "Signal
  indicatif" (date_heuristic), liste des KB avec `kb_os_hint`. Depuis le 21/07/2026 : badge "en cache
  — il y a Xs" si le résultat vient du cache court terme (`MIN_RECHECK_GAP`, cf. `docs/MATCHING.md`)
  et bouton "🔄 Relancer un scan" (`handlePatchCheck(vuln, force=true)`) pour forcer un vrai contrôle.
- `handlePatchCheck(vuln, force)` → `patchCheck(vuln.id, force)` (`api/client.js`) ; `force` ajoute
  `?force=true` à la requête, absent par défaut (comportement caching géré côté backend)
- **Workflow "Risque accepté" — unitaire et groupé** (session 27/07/2026) : jusque-là, le statut
  `accepted_risk` existait en base/dans les libellés mais **aucun chemin dans l'UI** ne permettait de
  l'appliquer (`STATUSES_OPEN`/`STATUS_LABELS_DASH` de `Dashboard.jsx` étaient du code mort jamais
  branché). Ajouté :
  - Bouton unitaire "🛡 Risque accepté" (à côté de "↩ Réouvrir") → `AnnotationModal` avec la nouvelle
    prop `showReviewDate` (ajoute un `<input type="date">`, obligatoire comme la note/le validateur) →
    `updateVuln(id, { status: 'accepted_risk', notes, validated_by, accepted_risk_until })`.
  - Bouton groupé "🛡 Accepter en masse (N)" → `BulkQualifyModal` (même prop `showReviewDate` ajoutée)
    sur les vulns **actuellement affichées** (`open`/`in_progress`/`awaiting_fix`) — contrairement aux
    3 flux groupés existants, il n'y a pas de critère technique objectif pour "candidat" à ce statut
    (décision humaine pure), donc pas de nouvel endpoint `*-candidates`.
  - Badge ⚠ "revue en retard" sur la colonne Statut si `review_overdue` (calculé côté API, jamais
    stocké) — même triptyque visuel que `sla_exceeded` sur `Watch.jsx`.
  - `api/client.js` : `bulkAcceptedRisk(vuln_ids, validated_by, notes, accepted_risk_until)`, même
    forme que `bulkAwaitingFix`.
- **Bouton "🕒 Historique"** (session 27/07/2026, à côté de "📋 Justificatif") — **toujours affiché**
  (contrairement à Justificatif, conditionnel au contenu), ouvre `StatusHistoryModal.jsx` (nouveau
  composant, table Date/Ancien statut/Nouveau statut/Validateur/Raison, réutilise le pattern visuel du
  tableau "Connexions IP" d'`AdministrationSecurity.jsx`) via `getVulnStatusHistory(vuln.id)`. État
  vide explicite pour une vuln jamais qualifiée depuis la mise en service de l'historique (cf.
  `docs/ARCHITECTURE.md` § `vulnerability_status_history`) — prospectif, pas rétroactif.

### Reports.jsx (session 02/07/2026 — refonte cohérence, pensée pour un envoi hebdomadaire à
l'équipe sécurité)
- Barre "Filtres" partagée par les deux sections ci-dessous : `AssetDropdown` (composant partagé
  avec Dashboard.jsx depuis cette session, `components/AssetDropdown.jsx`) + select période
  ("7 derniers jours" par défaut / "30 derniers jours" / "Vue d'ensemble")
- "Résumé exécutif" → `POST /api/reports/executive-summary` avec `{period_days, asset_id}` — génère
  une section "Ce qui a été fait" (corrigées/en attente/faux positifs/nouvelles détections, avec
  validateur + annotation) en plus de l'état actuel, si une période est sélectionnée. Rendu markdown
  (`renderMd`) + export PDF (`exportPdf`, ouvre une fenêtre d'impression navigateur)
- "Export CSV — backlog courant" (nouveau — `exportCsv`/`GET /api/reports/csv` existaient déjà côté
  API mais **aucun bouton n'y était relié**, fonctionnalité orpheline découverte pendant cette
  refonte) → respecte le filtre actifs, pas la période (instantané du backlog, pas un delta)
- Zone affichage résumé généré (texte markdown rendu) — **renderer markdown maison étendu aux
  tableaux** (session 02/07/2026, retour "plus lisible en tableau qu'en puces imbriquées") :
  `renderMd`/`exportPdf` détectent une ligne d'en-tête `| a | b |` suivie d'un séparateur
  `|---|---|` et rendent un vrai `<table>` (pas juste du texte brut avec des `|`) — les deux chemins
  de rendu (écran + PDF) parsent les tableaux indépendamment, à garder synchronisés si le format du
  résumé évolue côté backend. `Bold` renommé `Inline`, gère `**gras**` et `*italique*`

### Settings.jsx (Paramètres)
⚠️ **Layout à deux volets depuis le 14/08/2026** (nav à icônes + panneau, plus l'empilement de cartes
décrit historiquement ici) — détail complet dans `## PageHero.jsx + refonte Paramètres/Veille/Fuite de
données + self-service compte (14/08/2026)` ci-dessus. Sections : Présentation (switch "Anonyme",
`PresentationContext`), Apparence (toggle dark/light, `ThemeContext`), **Compte** (nom/email + changer
email/mot de passe + sessions actives + nom d'analyste par défaut), **Sessions**, **Intégrations**,
**Sécurité** (lien vers Administration, pas un onglet).
- Pas de gestion de sources/sync ici. L'onglet "Synchronisation" qui existait (Sync NVD, import actifs,
  recalcul scores) a été retiré de la nav, jugé redondant avec le bouton "Actualiser" (7/15j) de la page
  CVE — les endpoints `POST /api/sync/assets`/`POST /api/sync/rescore` restent disponibles côté API.

### AdministrationSecurity.jsx (route `/settings/administration`)
Page **réservée au rôle admin** — protégée à la fois côté client (`<ProtectedRoute role="admin">` dans
`App.jsx`) et côté serveur (`require_admin` sur `/api/connections`, `/api/security/*`, `/api/users` et
l'écriture `/api/analysts`, cf. `docs/ARCHITECTURE.md` § Authentification). ⚠️ Avant le 30/07/2026 cette
page était protégée par un mot de passe codé en clair dans le bundle JS (`ACCESS_PASSWORD`), vérifié
uniquement côté client — un vrai trou de sécurité, fermé avec l'arrivée de l'authentification réelle.
Lien "← Retour aux paramètres". Nav à icônes verticale (14/08/2026, remplace l'ancienne barre
d'onglets horizontale — cf. section `PageHero.jsx`/refonte ci-dessus), réductible en icônes seules via
un bouton "Réduire" en haut de la colonne (état local, non persisté). **Sept onglets** :
- **Base de données** (`DatabaseTab`, onglet par défaut) : **console de déception / administration BDD**.
  Bandeau d'état (déception active, objets leurres, app en rôle `cbr_app` non-superuser, verrou DDL) +
  bloc **« Alertes à traiter »** (non acquittées, cliquables) au-dessus du **journal `security_events`**
  complet (`GET /api/security/events`) : date, type (lecture/écriture leurre, rôle leurre, **DDL
  bloquée**), objet, opération, rôle DB, IP source, statut ; **Acquitter tout** (`ack-all`) et
  **Acquitter** par événement depuis la modale (`ack/{id}`). Cliquer un objet ouvre `EventDetailModal`.
- **Connexions IP** (`ConnectionsTab`) : historique des accès à l'app (`GET /api/connections`, réservé
  admin — seul `POST /api/connections`, la journalisation elle-même, reste public), anonymisé en mode
  Présentation.
- **Utilisateurs** (`UsersTab`, 30/07/2026) : CRUD des comptes de connexion (`UserFormModal.jsx`) — créer,
  changer rôle/statut actif, forcer un reset de mot de passe, "Déconnecter partout"
  (`POST /api/users/{id}/revoke-sessions`). Si le compte modifié est celui de l'admin connecté, appelle
  `useAuth().refresh()` après la sauvegarde (sinon Paramètres > Compte et le reste de l'app affichent des
  infos périmées jusqu'au prochain rechargement de page).
- **Analystes** (`AnalystsTab`, 30/07/2026, déplacé depuis Settings.jsx) : CRUD du registre `analysts`
  (`AnalystFormModal.jsx`, nom seul) — la lecture reste ouverte à tout connecté ailleurs dans l'app, mais
  la gestion (créer/modifier/supprimer) est réservée admin depuis ce déplacement.
- **Services** (`ServicesTab`, 31/07/2026) : registre RH/DSI/Juridique/Direction (`ServiceFormModal.jsx`,
  nom + couleur + icône), consommé par l'onglet Rôles et par Incidents/Gestion de crise.
- **Rôles** (`OrganizationRolesTab`, 31/07/2026) : organigramme poste → personne → email
  (`OrganizationRoleFormModal.jsx`), poste optionnellement rattaché à un service (couleur de la carte
  reprise du service).
- **Correspondances Windows** (`WindowsAppMappingsTab`) : motif de nom d'application Windows → produit
  CPE (`WindowsAppMappingFormModal.jsx`), consommé par `services/cpe_matcher.py` pour le matching CVE
  Windows (texte libre des noms d'applis, sans rapport avec les conventions Debian/RPM).
- **`EventDetailModal` — explication grand public** (session 24/07/2026) : la modale ne montre pas que
  les champs techniques. `explainEvent(e)` génère, par type d'événement, un texte **compréhensible par un
  non-technicien** — « Ce qui s'est passé », « Pourquoi c'est une alerte », un « ✓ bloqué » pour les DDL,
  et une reco « À faire » (encadré rouge). Le compte et l'IP sont injectés dans les phrases. Le **détail
  technique** reste dessous, séparé et étiqueté. C'est la surface de consultation de la couche déception
  (cf. `docs/ARCHITECTURE.md § Déception` / `§ Verrou DDL`).

**Signalement** : il n'y a **pas** de bannière sur le Dashboard (retirée le 24/07/2026 — elle exposait le
détail sans contrôle d'accès). À la place, la sidebar (`Layout.jsx`) poll `GET /api/security/events/count`
(~30 s, ouvert à tout utilisateur connecté — pas réservé admin, contrairement au reste de `/api/security/*`)
et affiche un **badge rouge (nombre) sur l'item « Paramètres »** dès qu'il y a une alerte non acquittée
(`NotifBadge` ; déplié = badge à droite, réduit = pastille sur l'icône ; masqué en Présentation). Le
compteur ne renvoie qu'un nombre : le détail complet reste réservé admin (onglet Base de données
ci-dessus). Le badge s'efface quand les événements sont acquittés.

---

## Mode Présentation ("Anonyme") — session 03/07/2026

**Objectif** : permettre une démo de l'app (ex : prospect) sans jamais afficher de vraie donnée du
parc (noms d'actifs, IP, noms d'analystes). Purement frontend/affichage — aucune donnée fictive n'est
écrite en base, aucune vraie donnée n'est envoyée nulle part. Activé via le switch "Anonyme" dans
Paramètres (`PresentationContext`), persistant en `localStorage`.

### `frontend/src/utils/fakeData.js` — cœur du mode

- **`FAKE_ASSETS`** : 24 actifs 100% inventés (`id` préfixé `demo-asset-`), noms/hostnames/IP/OS/
  hardware/apps plausibles et variés (Windows Server 2016-2022, Windows 10/11, Ubuntu, Debian).
- **`FAKE_VULNERABILITIES`** : 2 à 6 vulnérabilités par actif fictif, statuts variés (open/patched/
  awaiting_fix/false_positive), tirées de **`FAKE_CVE_POOL`** — CVE entièrement inventées
  (`CVE-2026-710xx`), jamais une vraie CVE réutilisée pour éviter toute confusion.
- **`FAKE_VALIDATORS`** : 6 faux noms d'analystes, distincts des vrais `ANALYSTS`
  (`ValidateDropdown.jsx`).
- **`isFakeId(id)`** : convention `demo-*`. Distingue une entité **100% fictive** (padding, jamais en
  base, aucune action ne doit toucher le backend) d'une entité **réelle affichée sous nom anonymisé**
  (id réel conservé, les actions qui n'écrivent pas d'identité continuent de fonctionner normalement).
- **`anonymizeAsset`/`anonymizeVuln`/`anonymizeValidator`/`anonymizeConnection`** : remplacent nom/
  hostname/IP/analyste réels par un équivalent fictif **déterministe** (hash du vrai id/nom → même
  faux nom à chaque appel, cohérent sur toutes les pages de la session) — ne touchent jamais l'id réel.
  **Deux pools de noms séparés** (`FAKE_ASSET_NAMES` pour le padding `FAKE_ASSETS`, `ANON_REAL_NAMES`
  pour les vrais actifs anonymisés) — un pool unique aurait fait porter par coïncidence le même nom à
  un vrai actif et à un actif de démo affichés côte à côte (bug constaté et corrigé en session).
- **`redactText(text, realAssets, realValidatorNames)`** : reformate un texte libre (résumé exécutif,
  export CSV) en y remplaçant toute occurrence de nom/hostname/IP d'actif réel **et** de nom
  d'analyste réel par leur équivalent fictif — utilisé par `Reports.jsx`.
- **`computeDashboardStats(...)`** : recalcule les KPI (taux de correction, actifs exposés,
  `severity_rates`) **localement** depuis les listes déjà fusionnées réel(anonymisé)+fictif, sur le
  même modèle que `backend/services/stats.py` — le backend ne connaît rien des données de démo.
- **`fakePatchCheckResult`/`fakeAnalysis`/`fakeRecommendation`/`fakeScript`** : simulent localement le
  résultat des actions (Analyser, Patch check, Recommandation, Script) sur les vulns fictives, sans
  aucun appel réseau, avec un texte explicite "(simulation — mode Présentation)".
- **⚠️ Piège rencontré** : `h >> 8` (décalage signé) appliqué à un hash déjà `>>> 0` (non-signé) —
  pour `h >= 2^31`, `>>` traite la valeur comme négative et produit un octet d'IP négatif (ex :
  `10.99.227.-201`, observé sur les connexions IP anonymisées). Corrigé en `>>> 8` partout dans ce
  fichier — à respecter pour tout nouveau calcul dérivé d'un hash `>>> 0`.

### Câblage par page

- **`Dashboard.jsx`** : au fetch initial (`useEffect([isAnonymous])`), fusionne actifs/vulns réels
  (anonymisés via `anonymizeAsset`/`anonymizeVuln`) avec `FAKE_ASSETS`/`FAKE_VULNERABILITIES` dans le
  state React existant — pas de re-fetch au toggle du switch, juste un re-merge côté client.
  `displayKpis` bascule entre `kpis` (fetch backend, mode normal) et `computeDashboardStats(...)`
  (local, mode Anonyme) ; `refreshStats()` devient un no-op en mode Anonyme.
- **`Assets.jsx` / `Inventaire.jsx`** : les 24 actifs fictifs sont ajoutés à la liste affichée. Scan
  d'une ligne fictive = relit directement `hardware`/`installed_packages` déjà en mémoire (pas
  d'appel réseau, `fakeScanResult()`) ; Modifier/Supprimer désactivés sur ces lignes (pas de ligne DB
  derrière — `updateAsset`/`deleteAsset` échoueraient en 404).
- **`Vulnerabilities.jsx`** : pagination/tri/filtres backend en mode normal ; en mode Anonyme, un seul
  fetch (**`per_page=200`** — limite dure backend `Query(..., le=200)`, un essai à `per_page=1000`
  renvoyait un 422) puis fusion + `sortVulnList(...)` + pagination **côté client** avec le pool
  fictif filtré par les mêmes filtres actifs (statut/sévérité/analyste).
- **`Reports.jsx`** : `realAssetList` (brut, base pour `redactText`) distinct de `displayAssetList`
  (anonymisé + complété par les 24 actifs fictifs, utilisé par le filtre `AssetDropdown`) — **piège
  rencontré** : ne garder qu'une seule liste anonymisée aurait suffi pour l'affichage mais cassé
  `redactText`, qui a besoin des **vrais** noms pour savoir quoi chercher/remplacer dans le texte
  généré par le backend. Résumé exécutif/export CSV : seuls les ids d'actifs **réels** de la
  sélection sont envoyés au backend (`realSelectedIds()`) ; si la sélection ne contient que des
  actifs de démo, `onlyFakeAssetsSelected()` bloque l'appel avec un message d'erreur plutôt que de
  renvoyer un résumé trompeur sur tout le parc réel. Connexions IP anonymisées
  (`anonymizeConnection`).
- **`ValidateDropdown.jsx` / `AnnotationModal.jsx`** : listent `FAKE_VALIDATORS` au lieu des vrais
  `ANALYSTS` dès que `isAnonymous` est actif. **Corollaire important** : comme le nom choisi est
  désormais toujours fictif en mode Anonyme, `handleMarkPatched`/`handleMarkAwaitingFix`/
  `handleMarkFalsePositive` (`Dashboard.jsx`) et `handleMarkPatched`/`handleStatus`
  (`Vulnerabilities.jsx`) sont gardés par `isAnonymous` (pas seulement `isFakeId`) — **aucune**
  écriture backend tant que le mode est actif, même sur une vraie vulnérabilité affichée sous nom
  anonymisé, pour ne jamais polluer son historique de validation avec une identité inventée. Les
  actions read-only (Analyser, Patch check) restent gardées par `isFakeId` uniquement — elles
  n'écrivent aucune identité, pas de raison de les bloquer sur du réel.

### Méthodologie de test

Vérification systématique en navigateur réel (conteneur `mcr.microsoft.com/playwright`,
`--network host`) plutôt que sur la seule lecture de code — a permis de détecter les 3 bugs
ci-dessus (limite `per_page`, collision de noms de pool, décalage de bits signé), tous invisibles en
review.

---

## Couleur du statut `false_positive` — violet `#a371f7`

**Une seule couleur pour ce statut dans toute l'app** (aligné le 21/07/2026) : badge du tableau
"traitées", badge et teinte de ligne dans "à traiter", bouton unitaire "🚫 Faux positif", bouton
groupé, filtre "Faux positifs uniquement", `FalsePositiveBulkModal`, `AnnotationModal` de saisie et
`AnnotationDetailModal` de lecture. Avant cet alignement, seul le badge de "traitées" était violet ;
tous les autres points d'entrée du même statut étaient en gris `#8b949e` — incohérence héritée, à ne
pas réintroduire. Le gris reste réservé à `accepted_risk`.

## Palette couleurs sévérité (à respecter dans toute l'app)

Utiliser les classes Tailwind suivantes via className :

| Sévérité | Badge Tremor color | Fond | Texte |
|----------|--------------------|------|-------|
| CRITICAL | `color="rose"` | #FCEBEB | #A32D2D |
| HIGH | `color="orange"` | #FAEEDA | #633806 |
| MEDIUM | `color="blue"` | #E6F1FB | #0C447C |
| LOW | `color="green"` | #EAF3DE | #27500A |
| PATCHED | `color="green"` | #EAF3DE | #27500A |
| OPEN | `color="rose"` | #FCEBEB | #A32D2D |
| IN_PROGRESS | `color="orange"` | #FAEEDA | #633806 |
| ACCEPTED_RISK | `color="gray"` | — | — |

### Composant SeverityBadge (à créer dans components/)
```jsx
// components/SeverityBadge.jsx
import { Badge } from '@tremor/react'

const COLORS = {
  CRITICAL: 'rose', HIGH: 'orange',
  MEDIUM: 'blue',   LOW: 'green',
  PATCHED: 'green', OPEN: 'rose',
  IN_PROGRESS: 'orange', ACCEPTED_RISK: 'gray',
}

export default function SeverityBadge({ value }) {
  return <Badge color={COLORS[value] ?? 'gray'}>{value}</Badge>
}
```

---

## Structure des composants (état réel)

```
frontend/
├── public/favicon.svg        → Logo Allsafe (bouclier + épées croisées, fond violet), référencé dans index.html
└── src/
    ├── App.jsx                  → Router (react-router-dom) : "/" = Home (sans Layout), le reste sous <Layout>
    ├── main.jsx                 → <React.StrictMode> — attention aux doubles-invocations d'updaters
    ├── index.css                 → CSS vars dark/light + `.sidebar-scroll`/`.main-scroll` (scrollbar
    │                                 fine, suit le thème — cf. § Notes design) + `.modal-backdrop`
    │                                 (fond flouté des modales, session 21/07/2026)
    ├── contexts/
    │   ├── ThemeContext.jsx        → dark/light mode
    │   ├── PresentationContext.jsx → mode Présentation ("Anonyme"), cf. section dédiée plus haut
    │   ├── AnalystContext.jsx      → registre de noms (cf. models.py::Analyst) pour les dropdowns
    │   │                             d'attribution — indépendant de l'authentification ci-dessous
    │   ├── AnalystPreferenceContext.jsx → (14/08/2026) "nom d'analyste par défaut" — préférence 100%
    │   │                             client (`localStorage`), même patron que ThemeContext/PresentationContext
    │   └── AuthContext.jsx         → (30/07/2026) session utilisateur — `me()` au montage, `user`,
    │                                 `loading`, `login()`, `logout()`, `refresh()`. `refresh()` doit
    │                                 être rappelé après qu'un admin modifie SON PROPRE compte (email/
    │                                 nom) via UserFormModal, sinon l'UI garde les infos périmées
    │                                 jusqu'au prochain rechargement de page (cf. AdministrationSecurity.jsx)
    ├── utils/
    │   ├── fakeData.js          → pools d'actifs/vulns/analystes fictifs + helpers d'anonymisation
    │   │                           (mode Présentation, cf. section dédiée plus haut)
    │   ├── countries.js         → `COUNTRIES`/`COUNTRY_LABELS`, ~40 pays — filtre pays Fuite de données
    │   │                           + formulaire d'ajout de source (Watch.jsx + FuiteDeDonnees.jsx)
    │   └── color.js             → `hexToRgba(hex, alpha)` — dérive une teinte transparente depuis un hex
    ├── pages/
    │   ├── Login.jsx              → route "/login" (30/07/2026) — seule route publique, formulaire
    │   │                            email/mot de passe, style visuel repris de Home.jsx
    │   ├── Home.jsx              → route "/" — page d'accueil, sélecteur de module (PAS de sidebar)
    │   ├── Dashboard.jsx         → CyberVuln (route /dashboard — déplacé depuis "/")
    │   ├── Vulnerabilities.jsx   → CyberVuln
    │   ├── Assets.jsx            → CyberVuln (vue sécurité des actifs)
    │   ├── CVEs.jsx              → CyberVuln
    │   ├── Watch.jsx             → CyberVeille — Veille technologique (route /veille), registre NIS 2
    │   ├── FuiteDeDonnees.jsx    → CyberVeille — Fuite de données (route /fuite-de-donnees), informatif
    │   ├── SurveillanceIdentites.jsx → CyberVeille (route /surveillance-identites) — fuites concernant
    │   │                          l'entreprise : gère les identités surveillées (nom/domaine, éditables)
    │   │                          + cards des fuites matchées (cf. docs/VEILLE.md § 9bis)
    │   ├── Inventaire.jsx        → Inventaire (route /inventaire) — specs matérielles + apps installées
    │   ├── Audits.jsx            → Sécurité (route /audits, ex-Pentest.jsx) — placeholder, mais
    │   │                            module spécifié : cf. docs/AUDITS.md (chantier prioritaire)
    │   ├── Bastion.jsx           → Sécurité (route /bastion, 30/07/2026) — placeholder, futur jump host
    │   │                            serveurs critiques, sans rapport avec l'ancien module Bastion retiré
    │   ├── Reports.jsx           → Rapports — Rapport exécutif CVE (route /reports) : filtre Actifs,
    │   │                            export CSV backlog, archives hebdo (déclinées par actif)
    │   ├── RapportVeille.jsx     → Rapports (route /rapport-veille) — export CSV du registre + archives hebdo
    │   ├── RapportSurveillance.jsx → Rapports (route /rapport-surveillance) — archives hebdo
    │   ├── Settings.jsx          → Paramètres (14/08/2026, nav à deux volets sans tuile) : Présentation,
    │   │                            Apparence, Compte (+ changer email/mot de passe, sessions actives,
    │   │                            nom d'analyste par défaut), Sessions, Intégrations, Sécurité (lien)
    │   └── AdministrationSecurity.jsx → page dédiée (route /settings/administration, réservée admin
    │                              côté client ET serveur depuis le 30/07/2026 — l'ancien verrou mdp
    │                              client-only est supprimé) : nav à icônes réductible (14/08/2026),
    │                              7 onglets — Base de données (déception) / Connexions IP / Utilisateurs /
    │                              Analystes / Services / Rôles / Correspondances Windows
    ├── components/
    │   ├── Layout.jsx           → Sidebar Allsafe (logo cliquable → "/", réductible) + nav à 2 niveaux
    │   │                          (6 groupes colorés + Paramètres, cf. ci-dessous) + <Outlet/> — n'englobe PAS Home.jsx.
    │   │                          Pas de badge utilisateur/déconnexion dans le pied de sidebar (retiré
    │   │                          30/07/2026, cf. Settings.jsx > section Compte)
    │   ├── PasswordInput.jsx    → (30/07/2026) champ mot de passe + bascule afficher/masquer, réutilisé
    │   │                          sur Login.jsx, le changement de mot de passe forcé (ProtectedRoute.jsx),
    │   │                          UserFormModal.jsx et Settings.jsx — politique de complexité imposée par
    │   │                          les appelants (cf. PasswordStrengthHint.jsx ci-dessous)
    │   ├── PasswordStrengthHint.jsx → (14/08/2026) barre de force + checklist des 5 critères de
    │   │                          `services/auth.py::validate_password_strength`, dupliqués en JS —
    │   │                          Settings.jsx + ProtectedRoute.jsx::ForcedPasswordChange
    │   ├── PageHero.jsx         → (14/08/2026) en-tête compact coloré par module, extrait dès le 2e
    │   │                          usage — déployé sur la quasi-totalité des pages de contenu, cf. section
    │   │                          dédiée plus haut pour le détail complet
    │   ├── ProtectedRoute.jsx   → (30/07/2026) garde de route : redirige vers /login si pas de session,
    │   │                          prop `role="admin"` optionnelle (redirige vers "/" sinon), affiche un
    │   │                          écran de changement de mot de passe bloquant si `must_change_password`
    │   ├── UserFormModal.jsx    → (30/07/2026) création/édition d'un compte (`routers/users.py`,
    │   │                          réservé admin) — email éditable en édition (contrôle d'unicité serveur)
    │   ├── AnalystFormModal.jsx → création/édition d'une entrée du registre `analysts` (nom seul) —
    │   │                          utilisé depuis l'onglet Analystes d'AdministrationSecurity.jsx
    │   ├── ErrorBoundary.jsx    → (27/07/2026) autour de <Outlet/> dans Layout.jsx — une page qui
    │   │                          plante n'emporte pas la sidebar/nav, cf. section dédiée ci-dessus
    │   ├── SeverityBadge.jsx    → Badge coloré selon sévérité/statut (CRITICAL/HIGH/MEDIUM/LOW/PATCHED...)
    │   ├── CriticiteBadge.jsx   → (nouveau, 27/07/2026) Badge Haute/Moyenne/Faible, calqué sur
    │   │                          SeverityBadge.jsx — criticité métier d'un actif (Assets.jsx)
    │   ├── FlagIcon.jsx         → Drapeau pays en SVG (`country-flag-icons`), pas en emoji — cf. VEILLE.md § 9.2
    │   ├── AddSourceModal.jsx   → Modale d'ajout de source RSS/Atom personnalisée, partagée Watch.jsx +
    │   │                          FuiteDeDonnees.jsx (`category` fixé par l'appelant, cf. VEILLE.md § 10.1)
    │   ├── AnalysisModal.jsx    → Panneau résultat analyse Claude
    │   ├── ValidateDropdown.jsx → Dropdown "Validé par" (analystes, ou faux analystes en mode Présentation) +
    │   │                          textarea "Annotation (optionnelle)" intégrée au menu (22/07/2026) — toujours
    │   │                          utilisé tel quel sur Vulnerabilities.jsx ; Dashboard.jsx est passé à
    │   │                          AnnotationModal pour "✓ Corrigé" (cf. ci-dessous), pour une modale uniforme
    │   │                          avec "En attente"/"Faux positif"
    │   ├── AnnotationModal.jsx  → Saisie annotation, généralisée (22/07/2026) : `title`/`detail` (chaînes
    │   │                          libres, remplace l'ancien prop `vuln`), `noteRequired` (true par défaut —
    │   │                          "En attente"/"Faux positif" ; false pour "✓ Corrigé", note facultative),
    │   │                          `initialNote`/`initialValidator` (pré-remplissage, mode édition),
    │   │                          `showReviewDate` (27/07/2026, ajoute un `<input type="date">` requis —
    │   │                          "🛡 Risque accepté", cf. § Vulnerabilities.jsx)
    │   ├── AnnotationDetailModal.jsx → Lecture seule — `text` (une seule annotation Markdown) OU `blocks`
    │   │                          (liste `{heading, body, markdown}`, 22/07/2026) pour le "📋 Justificatif" qui
    │   │                          concatène annotation d'analyste (Markdown) + détail technique du patch
    │   │                          check (texte système, jamais interprété comme Markdown) — clic dans les
    │   │                          tableaux, ou bouton "📋 Justificatif" (patch check) dans "traitées"
    │   ├── WeeklyArchives.jsx  → (nouveau, 22/07/2026) Archives hebdomadaires figées, **partagées** par
    │   │                          toutes les pages de rapport (liste, consultation, génération, export
    │   │                          PDF/CSV). Props : `kind`, `countColumns`, `assetScoped`, `description`
    │   ├── ReportMarkdown.jsx  → (nouveau, 22/07/2026) Rendu d'un **rapport** : markdown → React pour
    │   │                          l'écran (`renderMd`, coloration des sévérités) + markdown → HTML
    │   │                          imprimable pour le PDF (`exportPdf`). Extrait de Reports.jsx avant
    │   │                          l'ajout des rapports Veille/Surveillance — à ne pas redupliquer
    │   ├── WatchProfileModal.jsx → (nouveau, 22/07/2026, étoffé le même jour à 5 catégories) Profil
    │   │                          de veille : OS/logiciels proposés depuis l'inventaire, Firewall/
    │   │                          SaaS/Matériel en saisie manuelle uniquement (cf. VEILLE.md)
    │   ├── MarkdownNote.jsx     → (nouveau, 22/07/2026) Rendu Markdown sanitizé (`marked` + `dompurify`) des
    │   │                          annotations d'analyste — utilisé dans `AnnotationDetailModal`, la modale de
    │   │                          patch check, et en aperçu clampé (`line-clamp-2`) dans les tableaux "en
    │   │                          attente"/"traitées" du Dashboard
    │   ├── BulkQualifyModal.jsx → Qualification groupée généralisée aux 3 flux (correctif CRITICAL, faux
    │   │                          positif, en attente de correctif) — annotation + analyste requis.
    │   │                          `showReviewDate` (27/07/2026, même principe qu'AnnotationModal.jsx) —
    │   │                          4e flux "risque accepté groupé", cf. § Vulnerabilities.jsx
    │   ├── BulkValidateModal.jsx → (nouveau, 21/07/2026) Validation groupée des candidats CRITICAL à
    │   │                          signal de patch check positif — cf. § Vulnerabilities.jsx
    │   ├── StatusHistoryModal.jsx → (nouveau, 27/07/2026) Historique des transitions de statut d'une
    │   │                          vuln (table Date/Ancien/Nouveau/Validateur/Raison) — prospectif,
    │   │                          cf. § Vulnerabilities.jsx et docs/ARCHITECTURE.md
    │   └── AssetDropdown.jsx    → Multi-select actifs (un/plusieurs/tous), partagé Dashboard.jsx + Reports.jsx
    └── api/
        └── client.js            → Axios instance, baseURL '/api' (proxy Vite → backend:8000)
```

### Nav à 6 groupes colorés + Paramètres, réductible (`Layout.jsx`)
La sidebar affiche le logo/nom **Allsafe** en en-tête (lien vers `/`), un bouton `<` en haut à droite pour
réduire la sidebar en fine bande d'icônes (tooltip au survol, état persisté), puis 6 groupes avec
label — chacun repris de la couleur de sa tuile `Home.jsx`, appliquée à l'état actif **et** à l'icône
au repos :

```
CyberVuln       #f85149 rouge  → Dashboard / Vulnérabilités / Actifs / CVE
CyberVeille     #58a6ff bleu   → Veille technologique / Fuite de données / Surveillance Identités
Inventaire      #b5793a marron → Inventaire Complet
Sécurité        #3fb950 vert   → Audits / Bastion (30/07/2026, tous deux placeholder)
Rapports        #a371f7 violet → Rapport exécutif CVE / Rapport Veille / Rapport Surveillance
Incidents       #39c5cf cyan   → Registre incidents
Paramètres      #8b949e gris   → (pas de label de groupe, item unique)
```

⚠️ **Deux "Bastion" différents, à ne pas confondre** (30/07/2026) : l'ancien module Bastion
(sélecteur « Je suis… », `visible_modules`, groupe nav « Administration ») a été retiré — aucune
authentification réelle derrière, remplacé par un vrai système de login (cf. STATUS.md,
`docs/ARCHITECTURE.md` § Authentification). Le nom a été **réutilisé le même jour** pour un nouveau
placeholder sans rapport, sous le groupe nav « Sécurité » (`pages/Bastion.jsx`, route `/bastion`) :
futur accès bastion/jump host vers les serveurs critiques, portée pas encore définie. Le registre de
noms d'analystes (ancien module) reste, déplacé dans Administration (onglet « Analystes »,
`AdministrationSecurity.jsx`) — plus dans Paramètres directement depuis le même jour.

Structure de données : `NAV_GROUPS = [{ label: 'CyberVuln', color: '#f85149', items: [...] }, ...]` —
un `label: null` n'affiche pas d'en-tête de section (seul Paramètres désormais ; Audits — alors
nommé Pentest — est passé sous un en-tête de groupe « Sécurité » le 24/07/2026). Le conteneur nav
(`<nav className="sidebar-scroll ...">`) utilise la classe `.sidebar-scroll` (`index.css`) pour une
scrollbar fine et colorée sur le thème (`--border` au repos, `--text-faint` au survol), plutôt que la
scrollbar par défaut du navigateur (blanche/grise avec son propre fond, visible réduite ou non).

### Routing "/" à deux couches (`App.jsx`)
`Home.jsx` (sélecteur de module) et le groupe de routes sous `<Layout>` partagent tous les deux
`path="/"` comme deux `<Route>` sœurs — ce n'est PAS un conflit : la première (`element={<Home />}`,
sans `children`) capte l'exact `/`, la seconde n'est qu'un wrapper de layout pour ses routes filles
(`/dashboard`, `/veille`, etc.). Si un jour Home doit à nouveau vivre *dans* la sidebar, il faudra la
sortir de cette structure à deux routes sœurs.

### `ErrorBoundary.jsx` (session 27/07/2026)

Classe React (`components/ErrorBoundary.jsx`) — obligatoirement une classe, pas d'équivalent hook pour
`getDerivedStateFromError`/`componentDidCatch`. Placée dans `Layout.jsx` autour de `<Outlet/>`, **pas**
au sommet de l'app (`App.jsx`) : une erreur de rendu sur une page laisse la sidebar/nav utilisable,
l'utilisateur peut naviguer ailleurs plutôt que de recharger l'onglet en entier. Avant elle, un import
manquant sur une seule page (`SeverityBadge` dans `Assets.jsx`, 27/07/2026) démontait l'app React
entière — écran noir total, incident réel documenté dans `STATUS.md`.

Le `<div key={location.pathname}>` qui entoure déjà `<Outlet/>` (transition de page) démonte aussi la
boundary à chaque changement de route — `hasError` se réinitialise donc tout seul en changeant de
page, sans logique de reset dédiée à écrire. Fallback : icône + message + détail technique replié
(`<details>`) + lien retour à l'accueil, stylé avec les mêmes variables CSS (`var(--bg-...)`,
`var(--text-...)`) que le reste de l'app pour rester cohérent en mode clair/sombre. Aucun service de
suivi d'erreurs externe (Sentry etc.) — la console reste la seule trace, suffisante pour un outil
interne sans télémétrie (cf. `CLAUDE.md` § anonymisation).

---

## Layout global (App.jsx)

```jsx
// Sidebar fixe à gauche (200px), contenu scrollable à droite
<div className="flex h-screen bg-gray-50">
  <Sidebar />
  <main className="flex-1 overflow-auto p-6">
    <Outlet />   {/* React Router */}
  </main>
</div>
```

---

## client.js (API)

```js
// api/client.js
import axios from 'axios'

const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  timeout: 30000,
})

export default api
```

---

## Notes design

**Section réécrite le 21/07/2026 — l'ancienne version ("fond blanc", "gray-50", "Cards Tremor") décrivait
une maquette initiale jamais réalisée telle quelle ; cf. § Stack Frontend, le design réel est 100%
Tailwind + CSS vars dark/light, sans Tremor.**

- Thème dark/light entièrement piloté par variables CSS (`index.css` `:root`/`:root[data-theme="light"]`
  — `--bg-app`, `--bg-card`, `--bg-secondary`, `--border`, `--border-subtle`, `--text-primary/secondary/
  muted/faint`), jamais de couleur en dur dans les composants pour ce qui doit suivre le thème
- Scrollbars themées (session 21/07/2026, avant ça seule la sidebar l'était) : `.sidebar-scroll` (nav,
  6px) et `.main-scroll` (`<main>`, 10px, `Layout.jsx`) — même piste/curseur dérivés de `--bg-app`/
  `--border`/`--text-faint`, sur Firefox (`scrollbar-color`) et Chrome/Edge/Safari (`::-webkit-scrollbar-*`)
- `.modal-backdrop` (session 21/07/2026) : fond des modales — `rgba(0,0,0,0.5)` + `backdrop-filter:
  blur(4px)` plutôt qu'un aplat noir plein (`rgba(0,0,0,0.75)` avant cette session, jugé trop dur)
- **Animations** (`tailwind.config.js` `theme.extend.keyframes/animation`, session 21/07/2026) :
  - `animate-modal-in` (panneau de modale, scale 0.95→1 + fondu, 180ms) / `animate-backdrop-in`
    (fondu du fond, 150ms) — appliquées sur toutes les modales de `Dashboard.jsx`/`Vulnerabilities.jsx`
    et les composants `*Modal.jsx` correspondants (pas un passage sur toute l'app : Assets/Inventaire/
    Watch/AddSourceModal non touchés, même motif de backdrop mais sans animation ni blur)
  - `animate-row-leave` (fondu + léger repli, 180ms) — une ligne qui bascule de "à traiter"/"en
    attente" vers "traitées" (`moveVulnToPatched`, `Dashboard.jsx`) s'estompe brièvement au lieu de
    disparaître d'un coup ; géré via un état `leavingIds` (Set), la mutation réelle de liste est
    différée de 180ms derrière un `setTimeout`
  - `active:scale-[0.97]` sur les boutons partagés (`Btn` de `Vulnerabilities.jsx`,
    `ValidateDropdown.jsx`) — feedback au clic, pas posé bouton par bouton sur toute l'app
  - Toujours utiliser des propriétés de transition explicites (`transition-[color,transform]` etc.),
    jamais `transition-all` — cf. skills installés ci-dessous
  - **Skills installés dans `.claude/skills/`** (portée projet, `github.com/emilkowalski/skills`) :
    `emil-design-eng`, `review-animations`, `improve-animations`, `find-animation-opportunities`,
    `animation-vocabulary`, `apple-design` — charger pour toute nouvelle animation/transition ou
    review de motion design ; encodent aussi la restraint (ne pas animer les actions à haute
    fréquence, ex. les checkboxes de sélection cliquées des dizaines de fois par jour)

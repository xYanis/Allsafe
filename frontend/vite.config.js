import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    // usePolling : le projet vit sous /mnt/c (chemin Windows via WSL2) — le watcher
    // natif de Vite (chokidar/inotify) ne voit pas les écritures faites côté Windows/WSL
    // sur ce type de montage, donc HMR ne se déclenchait jamais malgré des fichiers à
    // jour sur le disque ET dans le conteneur (repéré le 28/07/2026 : plusieurs
    // modifications de pages restées invisibles jusqu'à un redémarrage manuel du
    // conteneur frontend). Le polling contourne ça au prix d'un peu de CPU.
    watch: { usePolling: true, interval: 300 },
    proxy: {
      '/api': {
        target: 'http://backend:8000',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq, req) => {
            // Adresse socket réelle uniquement (10/08/2026, cf. audit/AUDIT_SECURITE.md #9) —
            // ne JAMAIS faire confiance à un `x-forwarded-for` envoyé par le client
            // lui-même : ce serveur dev est le seul hop entre le client et le backend
            // (exposé sur 0.0.0.0:3000), donc rien à préserver d'une chaîne de proxy.
            // L'ancienne version priorisait l'en-tête client, donc falsifiable à volonté
            // (contournait le verrou anti-bruteforce par IP et la piste d'audit NIS 2).
            const clientIp = req.socket?.remoteAddress || 'unknown'
            proxyReq.setHeader('X-Forwarded-For', clientIp)
            proxyReq.setHeader('X-Real-IP', clientIp)
          })
        },
      },
    },
  },
})

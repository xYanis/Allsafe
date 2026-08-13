export default {
  content: [
    './index.html',
    './src/**/*.{js,jsx}',
    './node_modules/@tremor/**/*.{js,jsx,ts,tsx}',
  ],
  theme: {
    extend: {
      keyframes: {
        // Entrée de modale : jamais depuis scale(0) — un panneau ne surgit pas
        // de nulle part. Départ légèrement visible (0.95) + fondu, ease-out
        // fort pour un rendu réactif (cf. skill emil-design-eng).
        'modal-in': {
          '0%':   { opacity: '0', transform: 'scale(0.95)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        'backdrop-in': {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        // Sortie d'une ligne de tableau (ex: vuln basculée en "corrigée") —
        // fondu + léger repli plutôt qu'une disparition instantanée.
        'row-leave': {
          '0%':   { opacity: '1', transform: 'scale(1)' },
          '100%': { opacity: '0', transform: 'scale(0.98)' },
        },
        // Toast (bascule auto en direct, cf. Toast.jsx) : glisse depuis le bas,
        // même logique que modal-in (jamais depuis un scale(0)) — translateY
        // au lieu de scale seul, cohérent avec sa position ancrée en bas d'écran.
        'toast-in': {
          '0%':   { opacity: '0', transform: 'translateY(8px) scale(0.96)' },
          '100%': { opacity: '1', transform: 'translateY(0) scale(1)' },
        },
        'toast-out': {
          '0%':   { opacity: '1', transform: 'translateY(0) scale(1)' },
          '100%': { opacity: '0', transform: 'translateY(8px) scale(0.96)' },
        },
      },
      animation: {
        'modal-in': 'modal-in 180ms cubic-bezier(0.23,1,0.32,1)',
        'backdrop-in': 'backdrop-in 150ms ease-out',
        'row-leave': 'row-leave 180ms cubic-bezier(0.23,1,0.32,1) forwards',
        'toast-in': 'toast-in 200ms cubic-bezier(0.23,1,0.32,1)',
        'toast-out': 'toast-out 150ms ease-in forwards',
      },
    },
  },
  plugins: [],
}

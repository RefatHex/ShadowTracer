# ShadowTracer console (frontend)

React + Vite + TypeScript + Tailwind. See
[shadowtracer/docs/PHASE4_CONSOLE.md](../../docs/PHASE4_CONSOLE.md) for
the design and verification.

```
npm install
npm run dev      # local dev server
npm run build    # production build (tsc -b && vite build)
npx vitest run    # tests
```

`VITE_API_BASE` (see `.env.example`) points at the backend; leave unset
for same-origin (the lab setup, Caddy proxies `/auth`, `/api`, `/health`
to the backend).

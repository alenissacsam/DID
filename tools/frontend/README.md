# Modular Identity Frontend

This Vite + React application lives under `tools/frontend` and provides a landing experience for both organizations and users interacting with the identity smart contracts.

## Features

- Landing page with role-based entry points (organization vs user portals)
- Wallet connection via injected providers (MetaMask, Rabby, etc.)
- Automatic loading of the deployment artifact written by `DeployFullStackWithConfig.s.sol`
- Organization dashboard summarizing contract addresses and next steps
- User portal highlighting available credential contracts and user journey guidance
- Query caching through TanStack Query and layout-level state management with Zustand (ready for future hooks)
- Typed environment parsing with Zod-backed deployment config normalization

## Getting started

```bash
cd tools/frontend
npm install
npm run dev
```

The app will start on `http://localhost:5173`. Environment variables prefixed with `VITE_` are exposed to the client (see below).

## Build and quality checks

```bash
npm run lint   # ESLint with TypeScript, React, hooks, import sorting, Prettier compatibility
npm run build  # Production build (outputs to tools/frontend/dist)
```

## Deployment config flow

The Foundry script `script/deploy/DeployFullStackWithConfig.s.sol` now mirrors its JSON artifact to the frontend when the environment variable `FRONTEND_CONFIG_PATH` is set. By default we point this to `tools/frontend/public/config/deployment.json` so the UI always displays the most recent deployment once the script completes.

A sample config lives at `public/config/deployment.sample.json`. When a live deployment file is missing, the app falls back to the sample so local development always has data.

## Environment variables

Update `.env` (copy from the root `env.example`) with the following values before running the deploy script or frontend build:

- `FRONTEND_CONFIG_PATH` – location where the deploy script should copy the JSON artifact (default `tools/frontend/public/config/deployment.json`).
- `VITE_API_BASE_URL` – optional REST API for credential status and history (shown in future iterations).
- `VITE_STATUS_API_URL` – optional health/status endpoint surfaced in the UI.
- `VITE_IPFS_GATEWAY` – IPFS gateway to resolve off-chain metadata (defaults to the Pinata public gateway).
- `VITE_SENTRY_DSN` / `VITE_POSTHOG_KEY` – optional analytics & error reporting hooks.

Remember that any `VITE_*` variable is baked into the client bundle at build time.

## Frontend file structure

```
src/
  App.tsx                # Route composition + layout provider
  components/            # Layout primitives (header, footer, layout shell)
  contexts/              # WalletProvider context for injected wallet support
  hooks/                 # React Query hooks (deployment config loader, etc.)
  pages/                 # Landing, organization, and user dashboards
  services/              # Contract helpers (instantiation and network checks)
  styles/global.css      # Global theming and layout styles
  types/global.d.ts      # Ambient type definitions for window.ethereum
```

## Next steps

- Use the contract helpers to surface live on-chain data (roles, credential counts, etc.)
- Add Zustand-powered shared stores for organization/user workflows
- Layer in form flows for identity registration and metadata updates
- Integrate with off-chain services using the `VITE_API_BASE_URL`

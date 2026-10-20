# SecureLens frontend

The SecureLens browser interface is built with React, TypeScript, and Vite. It lets a reviewer choose an SSDLC phase, paste evidence or upload a supported document, and inspect the resulting assessment draft.

## Run the frontend

Start the FastAPI backend by following the instructions in the [project README](../README.md), then run:

```powershell
npm install
npm run dev
```

Vite normally serves the app at `http://localhost:5173`. The default API base is `http://127.0.0.1:8010/api`. To point it elsewhere, set `VITE_API_BASE_URL` to the API prefix before running `npm run dev`.

## Available scripts

- `npm run dev` — start the development server
- `npm run build` — type-check and create a production build in `dist/`
- `npm run lint` — run Oxlint
- `npm run preview` — preview the production build locally

See the main [SecureLens README](../README.md) for supported evidence formats, data handling, backend setup, and limitations.

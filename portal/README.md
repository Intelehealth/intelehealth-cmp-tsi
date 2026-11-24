# Developer portal

A [Docusaurus](https://docusaurus.io) site: hand-written guides plus an API reference generated from the OpenAPI specs in [`../docs/api/`](../docs/api/README.md).

| Section | Source |
|---|---|
| Docs (guides) | `docs/*.md`, written by hand |
| Integrator API | `../docs/api/openapi-public.json` |
| Internal API | `../docs/api/openapi-internal.json` |

The API pages are not committed. `npm run gen` writes them to `docs/integrator-api/` and `docs/internal-api/` (both git-ignored), so they always match the spec files.

## Run it

Needs Node 20 or later.

```bash
cd portal
npm ci
npm start        # generate API pages, then serve with live reload
npm run build    # generate, then build the static site into build/
npm run serve    # serve build/ at http://localhost:3000/intelehealth-cmp-tsi/
```

## When the API changes

1. Regenerate the specs: `cd python_port && python -m dpdpcms_py.openapi_gen`.
2. Commit the two JSON files. The portal rebuilds from them; nothing in `portal/` needs editing unless a guide mentions the changed function.

`python_port/tests/test_portal_examples.py` checks every `curl` example in the guides against the server's validator schemas, so an example that the server would refuse fails CI.

## Publishing

`.github/workflows/portal.yml` builds on every pull request that touches `portal/` or `docs/api/`, and publishes to GitHub Pages on a push to `main`. It needs one repository setting: **Settings > Pages > Source = GitHub Actions**.

The site is configured for `https://intelehealth.github.io/intelehealth-cmp-tsi/`. To host it elsewhere, change `url` and `baseUrl` in `docusaurus.config.ts`.

## Notes

- `scripts/prepare-specs.mjs` makes portal copies of the specs (in `.specs/`) with presentation-only changes: a placeholder server URL, tags grouped by API category, and "(GET)" on the GET variant of a read. The files in `docs/api/` are not modified.
- `future.faster` in `docusaurus.config.ts` is required: the OpenAPI plugin and theme (5.x) do not bundle correctly under the default webpack/Babel toolchain.
- The request console on each API page targets the placeholder host. It can only reach a real CMS whose CORS allow-list includes the portal's origin.
- The portal is a static site, separate from the CMS application. It does not change what a CMS deployment serves.

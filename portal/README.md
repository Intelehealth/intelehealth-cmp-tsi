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

`.github/workflows/portal.yml` builds the site on every pull request that touches `portal/` or `docs/api/`, and on a push to `ih-cmp-suite` it also publishes it. The site is not published from this repository's own Pages. It is pushed to the `gh-pages` branch of a separate documentation repository, so the docs have their own address: `https://<owner>.github.io/<docs-repo>/`.

One-time setup:

1. Create the documentation repository (for example `Intelehealth/ih-cmp-suite-docs`). It needs no content.
2. Make a deploy key: `ssh-keygen -t ed25519 -N "" -C portal-publish -f portal_deploy`.
3. In the documentation repository, **Settings > Deploy keys > Add deploy key**: paste `portal_deploy.pub` and tick **Allow write access**.
4. In this repository, **Settings > Secrets and variables > Actions**:
   - variable `PORTAL_DOCS_REPO` = `owner/name` of the documentation repository
   - secret `PORTAL_DEPLOY_KEY` = the contents of `portal_deploy` (the private half). Delete both key files afterwards.
5. Run the workflow once (**Actions > Developer portal > Run workflow**, branch `ih-cmp-suite`). It creates `gh-pages`.
6. In the documentation repository, **Settings > Pages**: Source = **Deploy from a branch**, branch `gh-pages`, folder `/ (root)`.

Until the variable and the secret exist, the workflow builds the site and stops; nothing is published and the run stays green.

The whole portal is published, the Internal API reference included. A Pages site is public unless the organisation's plan allows private Pages and the documentation repository is set to use it.

The site's address comes from two environment variables read by `docusaurus.config.ts`: `PORTAL_URL` and `PORTAL_BASE_URL`. The workflow derives them from `PORTAL_DOCS_REPO`. To host the site somewhere else, set them to that address when you build.

## Notes

- `scripts/prepare-specs.mjs` makes portal copies of the specs (in `.specs/`) with presentation-only changes: a placeholder server URL, and tags grouped by BRD module. The files in `docs/api/` are not modified.
- Both API references are arranged by BRD module, in the BRD's order: the module, then each of its services split by API category (`consent / admin`, `consent / client`). What the BRD does not name (breach, ROPA, certificates, reports) is under "Extensions (not in the BRD)". The modules and their titles come from `x-modules` in the spec files, which the generator reads from each package's `manifest.py`; `scripts/group-by-module.mjs` does the grouping and `npm test` checks it. A module with no functions (Cookie Consent) has no entry.
- The use-case guides sit under the same module titles. `sidebars.ts` maps each guide to its module; add a new guide there.
- `future.faster` in `docusaurus.config.ts` is required: the OpenAPI plugin and theme (5.x) do not bundle correctly under the default webpack/Babel toolchain.
- The request console on each API page targets the placeholder host. It can only reach a real CMS whose CORS allow-list includes the portal's origin.
- The portal is a static site, separate from the CMS application. It does not change what a CMS deployment serves.

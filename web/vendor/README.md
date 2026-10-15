# Vendored third-party scripts

Served same-origin so the Content-Security-Policy can be `script-src 'self'`
(no third-party script hosts, no `'unsafe-inline'`) - security finding P12-08.
Files are byte-for-byte copies of the upstream builds; do not edit them. To
upgrade, download the new version, update the page `<script src>` references and
refresh the table below.

| File | Version | Source URL | Licence | SHA-256 |
|------|---------|------------|---------|---------|
| `tailwindcss-3.4.16.js` | Tailwind CSS Play CDN 3.4.16 | https://cdn.tailwindcss.com/3.4.16 | MIT | `3f81aa7f6ecdb1acc14c202e513dfee00b6c7703cd81ce1be25bf5215a92e8cb` |
| `qrcode-1.0.0.min.js` | qrcodejs 1.0.0 | https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js | MIT | `c541ef06327885a8415bca8df6071e14189b4855336def4f36db54bde8484f36` |
| `xlsx-0.18.5.full.min.js` | SheetJS Community Edition 0.18.5 | https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js | Apache-2.0 | `c9506197caf809a075b6dee1da0d36fb19da7158ffe8a88e7b0c96c5d8623c99` |

Verify with `sha256sum web/vendor/*.js`.

Supply-chain audit (P13-05): `scripts/supply_chain/vendor_manifest.json` lists
every file here with its npm package, version and SHA-256, and
`scripts/supply_chain/vendor_audit.py` runs in CI. It fails on a file that is not
in the manifest or does not match its hash, and on any OSV.dev advisory for a
listed version that is not recorded under `accepted` with a reason and a
`review_by` date that has not passed. When upgrading, update the manifest too.

SheetJS 0.18.5 carries two accepted advisories (GHSA-4r6h-8v6p-xvw6 prototype
pollution, GHSA-5pgg-2g8v-p4x9 ReDoS). Both need the library to PARSE a crafted
file; the console only writes workbooks, and a test fails the build if any page
calls `XLSX.read`/`XLSX.readFile`. If parsing is ever needed, move to a
maintained SheetJS build (0.20.2 or later from the SheetJS CDN) first.

Note: the Tailwind Play runtime generates CSS in the browser and injects it as a
`<style>` element, so `style-src` still needs `'unsafe-inline'` (the pages also
use inline `style` attributes). It does not use `eval`/`new Function`, so
`script-src` needs no `'unsafe-eval'`.

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

Note: the Tailwind Play runtime generates CSS in the browser and injects it as a
`<style>` element, so `style-src` still needs `'unsafe-inline'` (the pages also
use inline `style` attributes). It does not use `eval`/`new Function`, so
`script-src` needs no `'unsafe-eval'`.

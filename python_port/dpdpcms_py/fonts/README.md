# Bundled fonts

Used by `pdfgen.py` to render the UD-04 consent-history PDF in every Eighth
Schedule language. All are [Noto](https://notofonts.github.io/) fonts, hinted
TTF, downloaded from `github.com/notofonts/notofonts.github.io` (`fonts/<Family>/hinted/ttf/`),
licensed under the SIL Open Font License 1.1 (`OFL.txt`).

| File | Scripts / languages |
| --- | --- |
| `NotoSans-Regular.ttf` | Latin (English labels, ids) - primary font |
| `NotoSansDevanagari-Regular.ttf` | hi, mr, ne, sa, kok, mai, doi, brx |
| `NotoSansBengali-Regular.ttf` | bn, as, mni (Bengali script) |
| `NotoSansGujarati-Regular.ttf` | gu |
| `NotoSansGurmukhi-Regular.ttf` | pa |
| `NotoSansOriya-Regular.ttf` | or |
| `NotoSansTamil-Regular.ttf` | ta |
| `NotoSansTelugu-Regular.ttf` | te |
| `NotoSansKannada-Regular.ttf` | kn |
| `NotoSansMalayalam-Regular.ttf` | ml |
| `NotoNaskhArabic-Regular.ttf` | ur, ks, sd (Perso-Arabic script) |
| `NotoSansOlChiki-Regular.ttf` | sat |
| `NotoSansMeeteiMayek-Regular.ttf` | mni (Meetei Mayek script) |

Only the glyphs a document uses are embedded (fpdf2 subsets), so a PDF stays small.

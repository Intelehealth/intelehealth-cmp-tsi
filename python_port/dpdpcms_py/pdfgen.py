"""PDF rendering for UD-04's consent-history download.

Text is shaped with HarfBuzz (through fpdf2) and drawn with bundled Noto fonts,
so a principal can read the export in any Eighth Schedule language: Indic
conjuncts and vowel signs are composed correctly, and Urdu, Kashmiri and Sindhi
run right-to-left. Each character falls back to the first bundled font that
covers it, so mixed-script lines (English labels, a Hindi purpose name) work.
Fonts are OFL-licensed; see fonts/README.md.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from fontTools.ttLib import TTFont
from fpdf import FPDF

FONT_DIR = Path(__file__).with_name("fonts")
# Primary font first; the rest are per-character fallbacks.
FONTS = (
    "NotoSans",
    "NotoSansDevanagari",  # hi, mr, ne, sa, kok, mai, doi, brx (and ks/sd in Devanagari)
    "NotoSansBengali",  # bn, as, mni (Bengali script)
    "NotoSansGujarati",
    "NotoSansGurmukhi",  # pa
    "NotoSansOriya",  # or
    "NotoSansTamil",
    "NotoSansTelugu",
    "NotoSansKannada",
    "NotoSansMalayalam",
    "NotoNaskhArabic",  # ur, ks, sd (Perso-Arabic script)
    "NotoSansOlChiki",  # sat
    "NotoSansMeeteiMayek",  # mni (Meetei Mayek script)
)
FONT_SIZE = 9
TITLE_SIZE = 14
LINE_HEIGHT = 5  # mm
MARGIN = 15  # mm
LRM = "‎"  # LEFT-TO-RIGHT MARK: fixes the base direction of a line


@lru_cache(maxsize=1)
def _font_paths() -> tuple[tuple[str, Path], ...]:
    paths = tuple((name, FONT_DIR / f"{name}-Regular.ttf") for name in FONTS)
    missing = [str(path) for _, path in paths if not path.exists()]
    if missing:
        raise FileNotFoundError(f"PDF fonts missing: {', '.join(missing)}")
    return paths


@lru_cache(maxsize=1)
def _coverage() -> dict[str, frozenset[int]]:
    return {name: frozenset(TTFont(str(path), lazy=True).getBestCmap()) for name, path in _font_paths()}


def _fonts_for(text: str) -> list[str]:
    """The primary font plus each fallback that covers a character the fonts
    before it do not - so a document embeds only the scripts it uses."""
    coverage = _coverage()
    pending = {ord(ch) for ch in text if not ch.isspace()} - coverage[FONTS[0]]
    chosen = [FONTS[0]]
    for name in FONTS[1:]:
        if pending & coverage[name]:
            chosen.append(name)
            pending -= coverage[name]
    return chosen


class _Doc(FPDF):
    def footer(self) -> None:
        self.set_y(-12)
        self.set_font(FONTS[0], size=8)
        self.cell(0, 5, f"Page {self.page_no()} of {{nb}}", align="R")


def text_pdf(title: str, lines: list[str]) -> bytes:
    """Render `title` and `lines` as a paginated A4 PDF document (any script)."""
    pdf = _Doc(format="A4")
    pdf.set_margins(MARGIN, MARGIN, MARGIN)
    pdf.set_auto_page_break(True, margin=MARGIN + 5)
    paths = dict(_font_paths())
    fonts = _fonts_for(title + "".join(str(line) for line in lines))
    for name in fonts:
        pdf.add_font(name, fname=str(paths[name]))
    if len(fonts) > 1:
        pdf.set_fallback_fonts(fonts[1:], exact_match=False)
    pdf.set_text_shaping(True)
    pdf.add_page()
    pdf.set_font(FONTS[0], size=TITLE_SIZE)
    pdf.multi_cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font(FONTS[0], size=FONT_SIZE)
    for line in lines:
        text = str(line).replace("\t", "    ")
        if text.strip():
            # Labels are English, so every line runs left-to-right at its base;
            # an RTL run inside it (an Urdu purpose name) is still reordered.
            pdf.multi_cell(0, LINE_HEIGHT, LRM + text, new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.ln(LINE_HEIGHT)
    return bytes(pdf.output())

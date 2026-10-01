"""A minimal PDF writer: monospaced text pages, no dependencies.

Enough for UD-04's consent-history download. Text uses the built-in Courier
font with WinAnsi encoding, so characters outside Latin-1 are replaced with '?'
(the CSV export carries the exact values).
"""

from __future__ import annotations

FONT_SIZE = 9
LEADING = 12
MARGIN = 40
PAGE_W, PAGE_H = 595, 842  # A4 in points
LINES_PER_PAGE = (PAGE_H - 2 * MARGIN) // LEADING
MAX_CHARS = 95  # Courier 9pt across A4 minus margins


def _escape(text: str) -> str:
    safe = text.encode("latin-1", errors="replace").decode("latin-1")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in lines:
        line = str(line).replace("\t", "    ")
        while len(line) > MAX_CHARS:
            out.append(line[:MAX_CHARS])
            line = "  " + line[MAX_CHARS:]
        out.append(line)
    return out


def text_pdf(title: str, lines: list[str]) -> bytes:
    """Render `title` and `lines` as a paginated A4 PDF document."""
    body = _wrap([title, "=" * min(len(title), MAX_CHARS), "", *lines])
    pages = [body[i : i + LINES_PER_PAGE] for i in range(0, len(body), LINES_PER_PAGE)] or [[]]

    objects: list[bytes] = []
    # 1 catalog, 2 pages tree, 3 font; then a (page, content) pair per page.
    kids = " ".join(f"{4 + 2 * i} 0 R" for i in range(len(pages)))
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
    for i, page in enumerate(pages):
        stream_lines = [f"BT /F1 {FONT_SIZE} Tf {LEADING} TL {MARGIN} {PAGE_H - MARGIN} Td"]
        for line in page:
            stream_lines.append(f"({_escape(line)}) Tj T*")
        stream_lines.append(
            f"ET BT /F1 8 Tf {PAGE_W - MARGIN - 60} {MARGIN / 2} Td (Page {i + 1} of {len(pages)}) Tj ET"
        )
        stream = "\n".join(stream_lines).encode("latin-1")
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {5 + 2 * i} 0 R >>".encode()
        )
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)

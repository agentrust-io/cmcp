"""Build paper.pdf from paper.md with ReportLab and embedded TrueType fonts.

Usage: python build_paper.py [--source DIR] [--output paper.pdf] [--fonts DIR]

Requires reportlab and pymupdf. Fonts come from --fonts (default C:/Windows/Fonts):
times.ttf, timesbd.ttf, timesi.ttf, arial.ttf and cour.ttf. Adapted from the
confidential-handoffs builder, adding a subtitle, code blocks, inline code and
tables with any column count. Render and inspect every page after a rebuild.
"""
import argparse
from functools import partial
from html import escape
from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

FOOTER = "OPAQUE Systems | Technical report, version 1 | Software experiments; no hardware claims"
p = argparse.ArgumentParser()
p.add_argument("--source", type=Path, default=Path(__file__).resolve().parent)
p.add_argument("--output", type=Path, default=None)
p.add_argument("--fonts", type=Path, default=Path("C:/Windows/Fonts"))
a = p.parse_args()
ROOT = a.source
OUT = a.output or ROOT / "paper.pdf"
for name, filename in [("PaperSerif", "times.ttf"), ("PaperBold", "timesbd.ttf"), ("PaperItalic", "timesi.ttf"),
                       ("PaperSans", "arial.ttf"), ("PaperMono", "cour.ttf")]:
    pdfmetrics.registerFont(TTFont(name, str(a.fonts / filename)))
pdfmetrics.registerFontFamily("PaperSerif", normal="PaperSerif", bold="PaperBold", italic="PaperItalic",
                              boldItalic="PaperBold")
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="PaperTitle", fontName="PaperBold", fontSize=23, leading=27, spaceAfter=6,
                          textColor=colors.HexColor("#15334b")))
styles.add(ParagraphStyle(name="PaperSubtitle", fontName="PaperItalic", fontSize=13.5, leading=17, spaceAfter=12,
                          textColor=colors.HexColor("#2d4a61")))
styles.add(ParagraphStyle(name="PaperHeading", fontName="PaperBold", fontSize=13, leading=17, spaceBefore=13,
                          spaceAfter=6, keepWithNext=True))
styles.add(ParagraphStyle(name="PaperSubheading", fontName="PaperBold", fontSize=11.2, leading=15, spaceBefore=9,
                          spaceAfter=4, keepWithNext=True))
styles.add(ParagraphStyle(name="PaperBody", fontName="PaperSerif", fontSize=10.6, leading=14.3, spaceAfter=6,
                          alignment=TA_LEFT, splitLongWords=True))
styles.add(ParagraphStyle(name="PaperRef", parent=styles["PaperBody"], fontSize=9.6, leading=12.6, leftIndent=18,
                          firstLineIndent=-18))
styles.add(ParagraphStyle(name="PaperCell", fontName="PaperSerif", fontSize=8.8, leading=11, spaceAfter=1,
                          splitLongWords=True))
styles.add(ParagraphStyle(name="PaperCode", fontName="PaperMono", fontSize=8.2, leading=10.4, leftIndent=8,
                          spaceBefore=2, spaceAfter=8, textColor=colors.HexColor("#1d2d3a")))


def markup(text):
    out, last = [], 0
    for m in re.finditer(r"\[([^\]]+)\]\((https?://[^)]+)\)", text):
        out.append(_plain(text[last:m.start()]))
        out.append(f'<link href="{escape(m.group(2))}" color="#174d76">{_plain(m.group(1))}</link>')
        last = m.end()
    out.append(_plain(text[last:]))
    return "".join(out)


def _plain(text):
    t = escape(text, quote=False)
    t = re.sub(r"https://[^\s<]+[^\s<.,)]", lambda m: f'<link href="{m[0]}" color="#174d76">{m[0]}</link>', t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<![\w*])\*([^*]+)\*(?![\w*])", r"<i>\1</i>", t)
    t = re.sub(r"`([^`]+)`", r'<font face="PaperMono" size="9">\1</font>', t)
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#ccd5dc"))
    canvas.line(0.8 * inch, 0.57 * inch, 7.7 * inch, 0.57 * inch)
    canvas.setFont("PaperSans", 8)
    canvas.setFillColor(colors.HexColor("#52616e"))
    canvas.drawString(0.8 * inch, 0.4 * inch, FOOTER)
    canvas.drawRightString(7.7 * inch, 0.4 * inch, str(doc.page))
    canvas.restoreState()


def table(lines):
    rows = []
    for line in lines:
        cells = [v.strip() for v in line.strip().strip("|").split("|")]
        if not all(re.fullmatch(r"[-: ]+", c) for c in cells):
            rows.append([Paragraph(markup(c), styles["PaperCell"]) for c in cells])
    n = len(rows[0])
    weights = [max(len(r[i].text) for r in rows) ** 0.5 + 4 for i in range(n)]
    widths = [6.9 * inch * w / sum(weights) for w in weights]
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5edf3")),
        ("FONTNAME", (0, 0), (-1, 0), "PaperBold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, 0), 0.7, colors.HexColor("#9aaebc")),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, colors.HexColor("#d9e0e5")),
    ]))
    return t


def build():
    lines = (ROOT / "paper.md").read_text(encoding="utf-8-sig").splitlines()
    story, title, i, in_refs = [], "", 0, False
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        if line.startswith("```"):
            block = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            story.append(Preformatted("\n".join(block), styles["PaperCode"]))
            i += 1
            continue
        if line.startswith("|"):
            block = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                block.append(lines[i])
                i += 1
            story.extend([table(block), Spacer(1, 8)])
            continue
        if line.startswith("# "):
            title = line[2:]
            story.append(Paragraph(markup(title), styles["PaperTitle"]))
        elif line.startswith("## "):
            story.append(Paragraph(markup(line[3:]), styles["PaperSubtitle"]))
        elif line.startswith("### "):
            in_refs = line[4:].strip() == "References"
            story.append(Paragraph(markup(line[4:]), styles["PaperHeading"]))
        elif line.startswith("#### "):
            story.append(Paragraph(markup(line[5:]), styles["PaperSubheading"]))
        elif line.startswith("- "):
            story.append(Paragraph("&#8226; " + markup(line[2:]), styles["PaperBody"]))
        else:
            paragraph = [line]
            while (i + 1 < len(lines) and lines[i + 1].strip()
                   and not lines[i + 1].lstrip().startswith(("#", "|", "- ", "```"))
                   and not (in_refs and lines[i + 1].startswith("["))):
                i += 1
                paragraph.append(lines[i].strip())
            story.append(Paragraph(markup(" ".join(paragraph)), styles["PaperRef" if in_refs else "PaperBody"]))
        i += 1
    doc = SimpleDocTemplate(str(OUT), pagesize=(8.5 * inch, 11 * inch), rightMargin=0.8 * inch,
                            leftMargin=0.8 * inch, topMargin=0.65 * inch, bottomMargin=0.8 * inch, title=title,
                            author="Imran Siddique", pageCompression=1, invariant=1)
    doc.build(story, onFirstPage=footer, onLaterPages=footer,
              canvasmaker=partial(Canvas, initialFontName="PaperSans"))


if __name__ == "__main__":
    build()
    # Remove ReportLab's unused base-font resource; keep the embedded font streams.
    import pymupdf
    with pymupdf.open(OUT) as pdf:
        for page in pdf:
            page.clean_contents()
        cleaned = pdf.tobytes(garbage=4, deflate=True)
    OUT.write_bytes(cleaned)
    print(OUT)

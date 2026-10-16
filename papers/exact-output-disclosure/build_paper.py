"""Build paper.pdf from paper.md with ReportLab and embedded Times/Arial/Courier TrueType fonts.

Usage: python build_paper.py --source . --output paper.pdf [--fonts DIR]
Requires reportlab and pymupdf; fonts are read from --fonts (default C:/Windows/Fonts).
Adapted from agentrust-io/confidential-handoffs/build_paper.py, adding code blocks,
inline code, numbered lists and tables of any width.
"""
from html import escape
from pathlib import Path
import argparse
from functools import partial
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

FOOTER = "OPAQUE Systems | Technical report, version 1 | Software experiments; not peer reviewed"
TEXT_WIDTH = 6.9 * inch

p = argparse.ArgumentParser()
p.add_argument("--source", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
p.add_argument("--fonts", type=Path, default=Path("C:/Windows/Fonts"))
a = p.parse_args()
for name, filename in [("PaperSerif", "times.ttf"), ("PaperBold", "timesbd.ttf"), ("PaperItalic", "timesi.ttf"),
                       ("PaperSans", "arial.ttf"), ("PaperMono", "cour.ttf")]:
    pdfmetrics.registerFont(TTFont(name, str(a.fonts / filename)))
pdfmetrics.registerFontFamily("PaperSerif", normal="PaperSerif", bold="PaperBold", italic="PaperItalic",
                              boldItalic="PaperBold")
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="PaperTitle", fontName="PaperBold", fontSize=23, leading=27, spaceAfter=8,
                          textColor=colors.HexColor("#15334b")))
styles.add(ParagraphStyle(name="PaperSubtitle", fontName="PaperSerif", fontSize=14, leading=18, spaceAfter=10,
                          textColor=colors.HexColor("#15334b")))
styles.add(ParagraphStyle(name="PaperHeading", fontName="PaperBold", fontSize=13, leading=17, spaceBefore=13,
                          spaceAfter=6, keepWithNext=True))
styles.add(ParagraphStyle(name="PaperSubheading", fontName="PaperBold", fontSize=11.2, leading=15, spaceBefore=9,
                          spaceAfter=4, keepWithNext=True))
styles.add(ParagraphStyle(name="PaperBody", fontName="PaperSerif", fontSize=10.6, leading=14.3, spaceAfter=6,
                          alignment=TA_LEFT, splitLongWords=True))
styles.add(ParagraphStyle(name="PaperCell", fontName="PaperSerif", fontSize=8.7, leading=11, spaceAfter=2,
                          splitLongWords=True))
styles.add(ParagraphStyle(name="PaperRef", parent=styles["PaperBody"], fontSize=9.6, leading=12.6,
                          leftIndent=16, firstLineIndent=-16))
styles.add(ParagraphStyle(name="PaperCode", fontName="PaperMono", fontSize=8.4, leading=10.6, leftIndent=8,
                          spaceBefore=2, spaceAfter=8, textColor=colors.HexColor("#1d2d3a")))


def markup(text):
    """Markdown links, bold, italics and inline code to ReportLab paragraph markup."""
    codes = []
    text = re.sub(r"`([^`]+)`", lambda m: codes.append(m[1]) or f"\x00{len(codes) - 1}\x00", text)
    text = escape(text, quote=False)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<link href="\2" color="#174d76">\1</link>', text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<![\w*])\*([^*]+)\*(?![\w*])", r"<i>\1</i>", text)
    return re.sub(r"\x00(\d+)\x00",
                  lambda m: f'<font face="PaperMono" size="8.9">{escape(codes[int(m[1])], quote=False)}</font>', text)


def table(rows_text):
    rows = [[Paragraph(markup(c), styles["PaperCell"]) for c in r] for r in rows_text]
    n = len(rows_text[0])
    lengths = [max(len(r[k]) for r in rows_text) for k in range(n)]
    words = [max(len(w) for r in rows_text for w in (r[k].split() or [""])) for k in range(n)]
    weights = [max(min(max(x, 8), 45), 1.6 * w) for x, w in zip(lengths, words)]
    widths = [TEXT_WIDTH * w / sum(weights) for w in weights]
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5edf3")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, 0), 0.7, colors.HexColor("#9aaebc")),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, colors.HexColor("#d9e0e5")),
    ]))
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


def build():
    story, title = [], ""
    lines = (a.source / "paper.md").read_text(encoding="utf-8-sig").splitlines()
    i = 0
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
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [v.strip() for v in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r"[-: ]+", c) for c in cells):
                    rows.append(cells)
                i += 1
            story.extend([table(rows), Spacer(1, 9)])
            continue
        if line.startswith("# "):
            title = line[2:]
            story.append(Paragraph(markup(title), styles["PaperTitle"]))
        elif line.startswith("## "):
            story.append(Paragraph(markup(line[3:]), styles["PaperSubtitle"]))
        elif line.startswith("### "):
            story.append(Paragraph(markup(line[4:]), styles["PaperHeading"]))
        elif line.startswith("#### "):
            story.append(Paragraph(markup(line[5:]), styles["PaperSubheading"]))
        elif re.match(r"^\d+\. ", line):
            num, rest = line.split(" ", 1)
            story.append(Paragraph(f"[{num.rstrip('.')}]&nbsp;&nbsp;" + markup(rest), styles["PaperRef"]))
        elif line.startswith("- "):
            story.append(Paragraph("&#8226; " + markup(line[2:]), styles["PaperBody"]))
        else:
            paragraph = [line]
            while (i + 1 < len(lines) and lines[i + 1].strip()
                   and not lines[i + 1].lstrip().startswith(("#", "|", "- ", "```"))
                   and not re.match(r"^\d+\. ", lines[i + 1].strip())):
                i += 1
                paragraph.append(lines[i].strip())
            story.append(Paragraph(markup(" ".join(paragraph)), styles["PaperBody"]))
        i += 1
    doc = SimpleDocTemplate(str(a.output), pagesize=(8.5 * inch, 11 * inch), rightMargin=0.8 * inch,
                            leftMargin=0.8 * inch, topMargin=0.65 * inch, bottomMargin=0.8 * inch,
                            title=title, author="Imran Siddique", pageCompression=1, invariant=1)
    doc.build(story, onFirstPage=footer, onLaterPages=footer,
              canvasmaker=partial(Canvas, initialFontName="PaperSans"))


if __name__ == "__main__":
    build()
    # Remove ReportLab's unused base-font resource; retain embedded font streams.
    import pymupdf
    with pymupdf.open(a.output) as pdf:
        for page in pdf:
            page.clean_contents()
        cleaned = pdf.tobytes(garbage=4, deflate=True)
    a.output.write_bytes(cleaned)

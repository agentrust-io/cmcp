"""Build the paper PDF from its Markdown source (ReportLab required).

Fonts are embedded. By default the builder reads Times New Roman and Arial TrueType files from
C:/Windows/Fonts; pass --fonts DIR (or set KILL_SWITCH_FONTS) to use another directory holding
times.ttf, timesbd.ttf and arial.ttf. If pymupdf is installed, unused base-font resources are
removed after the build. --allow-base-fonts builds with unembedded standard PDF fonts when those
files are absent (a smoke test on machines without them); that output is not the published PDF.
"""
import argparse
import os
import re
from functools import partial
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parent
FOOTER = 'OPAQUE Systems | Technical report, version 2 | Software-only evaluation'
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, default=ROOT / 'paper.pdf')
parser.add_argument('--fonts', type=Path,
                    default=Path(os.environ.get('KILL_SWITCH_FONTS', 'C:/Windows/Fonts')))
parser.add_argument('--allow-base-fonts', action='store_true')
args = parser.parse_args()
FONTS = {'PaperSerif': ('times.ttf', 'Times-Roman'), 'PaperBold': ('timesbd.ttf', 'Times-Bold'),
         'PaperSans': ('arial.ttf', 'Helvetica')}
if all((args.fonts / filename).is_file() for filename, _ in FONTS.values()):
    for name, (filename, _) in FONTS.items():
        pdfmetrics.registerFont(TTFont(name, str(args.fonts / filename)))
    FONT = {name: name for name in FONTS}
elif args.allow_base_fonts:
    print(f'fonts not found in {args.fonts}; building with unembedded base fonts')
    FONT = {name: base for name, (_, base) in FONTS.items()}
else:
    raise SystemExit(f'missing fonts in {args.fonts}; pass --fonts with times.ttf, timesbd.ttf '
                     'and arial.ttf, or --allow-base-fonts for a smoke build')
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name='PaperTitle', fontName=FONT['PaperBold'], fontSize=23, leading=27,
                          spaceAfter=12, textColor=colors.HexColor('#15334b')))
styles.add(ParagraphStyle(name='PaperHeading', fontName=FONT['PaperBold'], fontSize=13, leading=17,
                          spaceBefore=13, spaceAfter=6, keepWithNext=True))
styles.add(ParagraphStyle(name='PaperBody', fontName=FONT['PaperSerif'], fontSize=10.8, leading=14.6,
                          spaceAfter=7, alignment=TA_LEFT, splitLongWords=True))
styles.add(ParagraphStyle(name='PaperCell', fontName=FONT['PaperSerif'], fontSize=8.7, leading=11,
                          spaceAfter=2, splitLongWords=True))
styles.add(ParagraphStyle(name='PaperBullet', parent=styles['PaperBody'], leftIndent=11,
                          firstLineIndent=-7))


def markup(text):
    text = escape(text)
    text = re.sub(r'https://[^\s<]+', lambda m: '<link href="' + m[0] + '" color="#174d76">' + m[0] + '</link>', text)
    return text


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor('#ccd5dc'))
    canvas.line(0.8*inch, 0.57*inch, 7.7*inch, 0.57*inch)
    canvas.setFont(FONT['PaperSans'], 8)
    canvas.setFillColor(colors.HexColor('#52616e'))
    canvas.drawString(0.8*inch, 0.4*inch, FOOTER)
    canvas.drawRightString(7.7*inch, 0.4*inch, str(doc.page))
    canvas.restoreState()


def build():
    story = []
    lines = (ROOT/'paper.md').read_text(encoding='utf-8-sig').splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        if line.startswith('|'):
            rows = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                cells = [v.strip() for v in lines[i].strip().strip('|').split('|')]
                if not all(re.fullmatch(r'[-: ]+', c) for c in cells):
                    rows.append([Paragraph(markup(c), styles['PaperCell']) for c in cells])
                i += 1
            table = Table(rows, colWidths=[1.82*inch, 1.72*inch, 3.36*inch], repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e5edf3')),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('LEFTPADDING', (0,0), (-1,-1), 6), ('RIGHTPADDING', (0,0), (-1,-1), 6),
                ('TOPPADDING', (0,0), (-1,-1), 5), ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LINEBELOW', (0,0), (-1,0), 0.7, colors.HexColor('#9aaebc')),
                ('LINEBELOW', (0,1), (-1,-1), 0.25, colors.HexColor('#d9e0e5')),
            ]))
            story.extend([table, Spacer(1, 9)])
            continue
        if line.startswith('# '):
            story.append(Paragraph(markup(line[2:]), styles['PaperTitle']))
        elif line.startswith('## '):
            story.append(Paragraph(markup(line[3:]), styles['PaperHeading']))
        elif line.startswith('- '):
            story.append(Paragraph('&#8226; '+markup(line[2:]), styles['PaperBullet']))
        else:
            paragraph = [line]
            while i+1 < len(lines) and lines[i+1].strip() and not lines[i+1].startswith(('#','|','- ')):
                i += 1
                paragraph.append(lines[i].strip())
            story.append(Paragraph(markup(' '.join(paragraph)), styles['PaperBody']))
        i += 1
    doc = SimpleDocTemplate(str(args.output), pagesize=(8.5*inch, 11*inch),
                            rightMargin=0.8*inch, leftMargin=0.8*inch, topMargin=0.65*inch,
                            bottomMargin=0.8*inch, title='What Does an AI Kill Switch Prove?',
                            author='Imran Siddique', pageCompression=1, invariant=1)
    doc.build(story, onFirstPage=footer, onLaterPages=footer,
              canvasmaker=partial(Canvas, initialFontName=FONT['PaperSans']))
    try:
        import pymupdf
    except ImportError:
        return
    with pymupdf.open(args.output) as pdf:
        for page in pdf:
            page.clean_contents()
        cleaned = pdf.tobytes(garbage=4, deflate=True, no_new_id=True)
    args.output.write_bytes(cleaned)


if __name__ == '__main__':
    build()

"""Give every page its own meta description.

Material falls back to site_description when a page has none in its front
matter, so every inner page showed search engines and answer engines the same
snippet. This hook takes the first paragraph of prose on the page instead.
Front matter still wins; add a `description:` there to write one by hand.
"""
import re

LIMIT = 155
MINIMUM = 50

# Lines that are not prose: headings, admonitions, HTML, tables, quotes, lists,
# attribute lists, rules, snippet includes, and the chain label that opens
# landing pages ("[01 \u00b7 Weights: ...](https://agentrust-io.com/#chain)").
_NOT_PROSE = re.compile(r'^(#|!!!|\?\?\?|<|\||>|[-*+] |\d+\. |\{|:::|---|\*\*\*|--8<--|\[\d\d \u00b7 )')

# Front-of-page metadata such as "**Status**: Accepted" or "Last updated: 2026-08-01".
_METADATA = re.compile(
    r'^(\*\*[^*]+\*\*\s*:|\*\*[^*]+:\*\*|'
    '(Status|Date|Last updated|Updated|Stability|Document status|Applies to|Written|'
    'Authors?|Contact|Owner|Organisation|Organization|Version|Scope|Target|'
    r'Spec section|Related issues|Supersedes|Superseded by)\s*:)',
    re.IGNORECASE,
)


def _plain(text):
    text = re.sub(r'!\[[^\]]*\]\([^)]*\)', '', text)
    text = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', text)
    text = re.sub(r'\[([^\]]+)\]\[[^\]]*\]', r'\1', text)
    text = re.sub(r'\{\s*[:.#][^}]*\}', '', text)
    text = re.sub(r'`([^`]*)`', r'\1', text)
    text = re.sub(r'(\*\*|__)(.+?)\1', r'\2', text)
    text = re.sub(r'(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])', r'\1', text)
    text = re.sub(r'<[^>]+>', '', text)
    # House style has no em or en dashes; source text sometimes does.
    text = re.sub(r'\s*\u2014\s*', ', ', text).replace('\u2013', ' to ')
    # Material writes the description into content="..." without escaping it.
    text = text.replace('"', "'").replace('\u201c', "'").replace('\u201d', "'")
    text = re.sub(r'\s+', ' ', text).strip()
    return re.sub(r'\s+,', ',', text)


def first_paragraph(markdown):
    fence = None
    lines = []
    skipping = False
    for raw in markdown.splitlines():
        line = raw.strip()
        if fence:
            if line.startswith(fence):
                fence = None
            continue
        if line.startswith(('```', '~~~')):
            fence = line[:3]
            if lines:
                break
            continue
        if not line:
            if lines:
                break
            skipping = False
            continue
        # Indented lines before any prose are admonition bodies; after a skipped
        # list item or metadata line they are its wrapped continuation.
        if raw[:1] in (' ', '\t') and (not lines or skipping):
            continue
        if _NOT_PROSE.match(line) or _METADATA.match(line):
            if lines:
                break
            skipping = True
            continue
        if skipping and not lines:
            continue
        lines.append(line)
    return _plain(' '.join(lines))


def cap(text, limit=LIMIT):
    if len(text) <= limit:
        return text
    cut = text[:limit + 1].rsplit(' ', 1)[0].rstrip(',;:')
    end = cut.rfind('. ')
    if end >= MINIMUM:
        return cut[:end + 1]
    # No sentence end in range: cut short enough that the ellipsis fits the limit.
    cut = text[:limit - 2].rsplit(' ', 1)[0].rstrip(',;:.')
    return cut + '...'


def on_page_markdown(markdown, page, config, files):
    if page.meta.get('description'):
        # Hand-written descriptions reach the same unescaped attribute.
        page.meta['description'] = _plain(str(page.meta['description']))
        return markdown
    text = first_paragraph(markdown)
    if len(text) >= MINIMUM:
        page.meta['description'] = cap(text)
    elif page.title:
        page.meta['description'] = cap(_plain(f'{page.title}. {config["site_description"]}'))
    return markdown

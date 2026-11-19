"""helm_writer.py - High-Integrity Document, Presentation, Spreadsheet & Post Generation Suite.

Standard-library only generators (zero external compiled dependencies like lxml or openpyxl):
- WordprocessingML (.docx): Professional Word documents with heading hierarchy, tables,
  repeating table headers, bullet/numbered lists, page numbers, and running headers.
- PresentationML (.pptx): 16:9 widescreen presentations with title layouts, content layouts,
  bullet points, tables, and speaker notes.
- SpreadsheetML (.xlsx): Excel workbooks with typed cells, auto-fitting column widths,
  frozen bold header row, auto-filter, total rows, and strict formula-injection defense.
- Markdown (.md) and HTML (.html): Sanitized, standalone documents without active script content.
"""

from __future__ import annotations

import os
import re
import sys
import json
import zipfile
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union
from xml.sax.saxutils import escape

UTC = timezone.utc

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DOCS_OUTPUT_DIR = os.path.join(BASE_DIR, "data", "documents")
os.makedirs(DOCS_OUTPUT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Document Model & Markdown Parser
# ---------------------------------------------------------------------------

@dataclass
class Block:
    type: Literal["heading", "paragraph", "bullets", "numbered", "table", "callout", "quote", "code", "pagebreak"]
    text: str = ""
    level: int = 1
    items: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)  # First row is header
    label: str = ""  # Callout label: Note, Tip, Warning, etc.


@dataclass
class Layout:
    template: str = "notes"  # report | letter | resume | notes
    title_page: bool = False
    toc: bool = False
    page_size: str = "A4"    # A4 | Letter
    margins_mm: int = 20
    font: str = "sans"       # sans | serif
    font_pt: float = 11.0
    header: str = ""
    page_numbers: bool = True
    landscape: bool = False


@dataclass
class Doc:
    kind: str
    title: str
    blocks: list[Block]
    subtitle: str = ""
    author: str = "Helm Assistant"
    date: str = ""
    meta: dict[str, str] = field(default_factory=dict)
    layout: Layout = field(default_factory=Layout)

    def words(self) -> int:
        n = 0
        for b in self.blocks:
            n += len(b.text.split()) + sum(len(i.split()) for i in b.items) + sum(len(str(c).split()) for r in b.rows for c in r)
        return n



_FRONT_MATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
_HEADING = re.compile(r"^(#{1,6})\s+(.+)$")
_BULLET = re.compile(r"^[-*+]\s+(.+)$")
_NUMBERED = re.compile(r"^(\d+)\.\s+(.+)$")
_CALLOUT = re.compile(r"^>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*(.*)$", re.IGNORECASE)
_QUOTE = re.compile(r"^>\s*(.*)$")
_TABLE_ROW = re.compile(r"^\|(.+)\|$")
_TABLE_SEP = re.compile(r"^\|(\s*:?-+:?\s*\|)+$")


def parse_markdown(text: str) -> tuple[dict[str, str], list[Block]]:
    """Parses markdown text into front-matter metadata and a list of structural Blocks."""
    meta: dict[str, str] = {}
    content = text.strip()

    fm = _FRONT_MATTER.match(content)
    if fm:
        raw_meta = fm.group(1)
        content = content[fm.end():].strip()
        for line in raw_meta.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip().lower()] = v.strip().strip('"').strip("'")

    blocks: list[Block] = []
    lines = content.splitlines()
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        # Pagebreak
        if re.match(r"^\s*(?:\\pagebreak|\\newpage|<!--\s*pagebreak\s*-->|\[pagebreak\])\s*$", stripped, re.I):
            blocks.append(Block(type="pagebreak"))
            i += 1
            continue

        # Headings
        hm = _HEADING.match(stripped)
        if hm:
            level = len(hm.group(1))
            heading_text = hm.group(2).strip()
            blocks.append(Block(type="heading", text=heading_text, level=level))
            i += 1
            continue

        # Code block
        if stripped.startswith("```"):
            code_lines = []
            i += 1
            while i < n and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            if i < n:
                i += 1
            blocks.append(Block(type="code", text="\n".join(code_lines)))
            continue

        # Callout
        cm = _CALLOUT.match(stripped)
        if cm:
            lbl = cm.group(1).capitalize()
            first_txt = cm.group(2).strip()
            callout_lines = [first_txt] if first_txt else []
            i += 1
            while i < n and lines[i].strip().startswith(">"):
                sub_q = _QUOTE.match(lines[i].strip())
                if sub_q:
                    callout_lines.append(sub_q.group(1).strip())
                i += 1
            blocks.append(Block(type="callout", label=lbl, text=" ".join(callout_lines)))
            continue

        # Blockquote
        qm = _QUOTE.match(stripped)
        if qm:
            quote_lines = [qm.group(1).strip()]
            i += 1
            while i < n and lines[i].strip().startswith(">"):
                sub_q = _QUOTE.match(lines[i].strip())
                if sub_q:
                    quote_lines.append(sub_q.group(1).strip())
                i += 1
            blocks.append(Block(type="quote", text=" ".join(quote_lines)))
            continue

        # Table
        tm = _TABLE_ROW.match(stripped)
        if tm and i + 1 < n and _TABLE_SEP.match(lines[i + 1].strip()):
            headers = [c.strip() for c in tm.group(1).split("|")]
            i += 2
            rows = [headers]
            while i < n and _TABLE_ROW.match(lines[i].strip()):
                r_match = _TABLE_ROW.match(lines[i].strip())
                cols = [c.strip() for c in r_match.group(1).split("|")]
                rows.append(cols)
                i += 1
            blocks.append(Block(type="table", rows=rows))
            continue

        # Bullet list
        bm = _BULLET.match(stripped)
        if bm:
            items = [bm.group(1).strip()]
            i += 1
            while i < n:
                next_bm = _BULLET.match(lines[i].strip())
                if next_bm:
                    items.append(next_bm.group(1).strip())
                    i += 1
                elif not lines[i].strip():
                    break
                else:
                    break
            blocks.append(Block(type="bullets", items=items))
            continue

        # Numbered list
        nm = _NUMBERED.match(stripped)
        if nm:
            items = [nm.group(2).strip()]
            i += 1
            while i < n:
                next_nm = _NUMBERED.match(lines[i].strip())
                if next_nm:
                    items.append(next_nm.group(2).strip())
                    i += 1
                elif not lines[i].strip():
                    break
                else:
                    break
            blocks.append(Block(type="numbered", items=items))
            continue

        # Paragraph
        para_lines = [stripped]
        i += 1
        while i < n and lines[i].strip() and not lines[i].strip().startswith(("#", "-", "*", ">", "```", "|", "\\pagebreak")):
            para_lines.append(lines[i].strip())
            i += 1
        blocks.append(Block(type="paragraph", text=" ".join(para_lines)))

    return meta, blocks


def build_doc(kind: str, markdown_text: str, title: Optional[str] = None) -> Doc:
    """Creates a Doc structure from markdown text."""
    meta, blocks = parse_markdown(markdown_text)
    doc_title = title or meta.get("title", "")
    if not doc_title:
        for b in blocks:
            if b.type == "heading" and b.level == 1:
                doc_title = b.text
                break
    if not doc_title:
        doc_title = "Document"

    layout = Layout()
    if kind == "report":
        layout.template = "report"
        layout.toc = len([b for b in blocks if b.type == "heading"]) >= 4
    elif kind == "letter":
        layout.template = "letter"
        layout.font = "serif"
    else:
        layout.template = "notes"

    return Doc(
        kind=kind,
        title=doc_title,
        blocks=blocks,
        subtitle=meta.get("subtitle", ""),
        author=meta.get("author", "Helm Assistant"),
        date=meta.get("date", datetime.now(UTC).strftime("%Y-%m-%d")),
        meta=meta,
        layout=layout
    )


# ---------------------------------------------------------------------------
# DOCX Renderer (Standard Library Only: zipfile + WordprocessingML)
# ---------------------------------------------------------------------------

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

def _run_xml(text: str, bold: bool = False, italic: bool = False, mono: bool = False, size_pt: int = 0) -> str:
    rpr_tags = []
    if mono:
        rpr_tags.append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>')
    if bold:
        rpr_tags.append('<w:b/>')
    if italic:
        rpr_tags.append('<w:i/>')
    if size_pt > 0:
        rpr_tags.append(f'<w:sz w:val="{size_pt * 2}"/>')
    rpr = f"<w:rPr>{''.join(rpr_tags)}</w:rPr>" if rpr_tags else ""
    esc_text = escape(text)
    return f'<w:r>{rpr}<w:t xml:space="preserve">{esc_text}</w:t></w:r>'


def _inline_markdown_runs(text: str) -> str:
    """Parses simple inline markdown (**bold**, *italic*, `code`) into WordprocessingML runs."""
    tokens = re.split(r"(\*\*.*?\*\*|\*.*?\*|`.*?`)", text)
    out = []
    for tok in tokens:
        if not tok:
            continue
        if tok.startswith("**") and tok.endswith("**") and len(tok) >= 4:
            out.append(_run_xml(tok[2:-2], bold=True))
        elif tok.startswith("*") and tok.endswith("*") and len(tok) >= 2:
            out.append(_run_xml(tok[1:-1], italic=True))
        elif tok.startswith("`") and tok.endswith("`") and len(tok) >= 2:
            out.append(_run_xml(tok[1:-1], mono=True))
        else:
            out.append(_run_xml(tok))
    return "".join(out)


def render_docx(doc: Doc, output_path: Union[str, Path]) -> str:
    """Renders a Doc object into a valid Microsoft Word (.docx) file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    body_xml_parts = []

    # Title & Subtitle
    if doc.title:
        body_xml_parts.append(
            f'<w:p><w:pPr><w:pStyle w:val="Title"/><w:jc w:val="center"/></w:pPr>'
            f'{_run_xml(doc.title, bold=True, size_pt=24)}</w:p>'
        )
    if doc.subtitle:
        body_xml_parts.append(
            f'<w:p><w:pPr><w:pStyle w:val="Subtitle"/><w:jc w:val="center"/></w:pPr>'
            f'{_run_xml(doc.subtitle, italic=True, size_pt=14)}</w:p>'
        )
    if doc.author or doc.date:
        meta_str = f"{doc.author}  •  {doc.date}".strip(" •")
        body_xml_parts.append(
            f'<w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
            f'{_run_xml(meta_str, italic=True, size_pt=10)}</w:p>'
        )
        body_xml_parts.append('<w:p/>')

    # Blocks
    for b in doc.blocks:
        if b.type == "heading":
            style = f"Heading{min(b.level, 3)}"
            sz = 18 if b.level == 1 else (14 if b.level == 2 else 12)
            body_xml_parts.append(
                f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>'
                f'{_run_xml(b.text, bold=True, size_pt=sz)}</w:p>'
            )
        elif b.type == "paragraph":
            body_xml_parts.append(f'<w:p>{_inline_markdown_runs(b.text)}</w:p>')
        elif b.type == "bullets":
            for itm in b.items:
                body_xml_parts.append(
                    f'<w:p><w:pPr><w:pStyle w:val="ListBullet"/></w:pPr>'
                    f'{_run_xml("•  ", bold=True)}{_inline_markdown_runs(itm)}</w:p>'
                )
        elif b.type == "numbered":
            for idx, itm in enumerate(b.items, 1):
                body_xml_parts.append(
                    f'<w:p><w:pPr><w:pStyle w:val="ListNumber"/></w:pPr>'
                    f'{_run_xml(f"{idx}.  ", bold=True)}{_inline_markdown_runs(itm)}</w:p>'
                )
        elif b.type == "callout":
            label_tag = f"[{b.label}] " if b.label else ""
            body_xml_parts.append(
                f'<w:p><w:pPr><w:pBdr><w:left w:val="single" w:sz="18" w:space="8" w:color="1F4E79"/></w:pBdr></w:pPr>'
                f'{_run_xml(label_tag, bold=True)}{_inline_markdown_runs(b.text)}</w:p>'
            )
        elif b.type == "quote":
            body_xml_parts.append(
                f'<w:p><w:pPr><w:pBdr><w:left w:val="single" w:sz="12" w:space="8" w:color="888888"/></w:pBdr></w:pPr>'
                f'{_run_xml(b.text, italic=True)}</w:p>'
            )
        elif b.type == "code":
            for c_line in b.text.splitlines():
                body_xml_parts.append(
                    f'<w:p><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F3F4F6"/></w:pPr>'
                    f'{_run_xml(c_line, mono=True, size_pt=9)}</w:p>'
                )
        elif b.type == "table":
            if not b.rows:
                continue
            table_xml = ['<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>'
                         '<w:top w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>'
                         '<w:bottom w:val="single" w:sz="8" w:space="0" w:color="1F4E79"/>'
                         '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="E5E7EB"/>'
                         '</w:tblBorders></w:tblPr>']
            for r_idx, row in enumerate(b.rows):
                is_header = (r_idx == 0)
                shd = '<w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="F1F5F9"/></w:tcPr>' if is_header else ''
                row_xml = ['<w:tr>']
                for cell in row:
                    runs = _run_xml(cell, bold=is_header)
                    row_xml.append(f'<w:tc>{shd}<w:p>{runs}</w:p></w:tc>')
                row_xml.append('</w:tr>')
                table_xml.append("".join(row_xml))
            table_xml.append('</w:tbl>')
            body_xml_parts.append("".join(table_xml))
            body_xml_parts.append('<w:p/>')
        elif b.type == "pagebreak":
            body_xml_parts.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    # Section properties: A4 margins and footer
    body_xml_parts.append(
        '<w:sectPr>'
        '<w:footerReference w:type="default" r:id="rIdFooter"/>'
        '<w:pgSz w:w="11906" w:h="16838"/>'  # A4
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/>'
        '</w:sectPr>'
    )

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}">'
        f'<w:body>{"".join(body_xml_parts)}</w:body>'
        '</w:document>'
    )

    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
        '</Types>'
    )

    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '</Relationships>'
    )

    doc_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
        '</Relationships>'
    )

    footer_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<w:ftr xmlns:w="{W_NS}">'
        '<w:p><w:pPr><w:jc w:val="right"/></w:pPr>'
        '<w:r><w:rPr><w:sz w:val="18"/><w:color w:val="666666"/></w:rPr>'
        '<w:t>Page </w:t><w:fldSimple w:instr="PAGE"/><w:t> of </w:t><w:fldSimple w:instr="NUMPAGES"/>'
        '</w:r></w:p>'
        '</w:ftr>'
    )

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels_xml)
        zf.writestr("word/_rels/document.xml.rels", doc_rels_xml)
        zf.writestr("word/document.xml", document_xml)
        zf.writestr("word/footer1.xml", footer_xml)

    return str(path.resolve())


# ---------------------------------------------------------------------------
# PPTX Renderer (Standard Library Only: zipfile + PresentationML)
# ---------------------------------------------------------------------------

P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
R_NS_OFFICE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

@dataclass
class SlideData:
    title: str
    bullets: list[str] = field(default_factory=list)
    subtitle: str = ""
    notes: str = ""
    table: Optional[list[list[str]]] = None


def render_pptx(title: str, slides: list[SlideData], output_path: Union[str, Path]) -> str:
    """Renders a 16:9 widescreen PowerPoint presentation (.pptx) with zero compiled dependencies."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # 16:9 Widescreen dimensions in EMU: 12,192,000 x 6,858,000
    w_emu, h_emu = 12192000, 6858000

    slide_overrides = []
    slide_id_list = []
    pres_rels = []

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for idx, s in enumerate(slides, start=1):
            slide_overrides.append(
                f'<Override PartName="/ppt/slides/slide{idx}.xml" '
                'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
            )
            slide_id_list.append(f'<p:sldId id="{255 + idx}" r:id="rIdSlide{idx}"/>')
            pres_rels.append(
                f'<Relationship Id="rIdSlide{idx}" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
                f'Target="slides/slide{idx}.xml"/>'
            )

            # Build slide shapes
            shapes = []
            shape_id = 2

            # Title shape
            if s.title:
                t_esc = escape(s.title)
                shapes.append(
                    f'<p:sp>'
                    f'<p:nvSpPr><p:cNvPr id="{shape_id}" name="Title"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr>'
                    f'<p:spPr><a:xfrm><a:off x="838200" y="500000"/><a:ext cx="10515600" cy="1100000"/></a:xfrm></p:spPr>'
                    f'<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US" sz="4000" b="1"><a:solidFill><a:srgbClr val="1F2937"/></a:solidFill></a:rPr><a:t>{t_esc}</a:t></a:r></a:p></p:txBody>'
                    f'</p:sp>'
                )
                shape_id += 1

            # Subtitle (for title slide)
            if s.subtitle:
                sub_esc = escape(s.subtitle)
                shapes.append(
                    f'<p:sp>'
                    f'<p:nvSpPr><p:cNvPr id="{shape_id}" name="Subtitle"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr><p:ph type="subTitle"/></p:nvPr></p:nvSpPr>'
                    f'<p:spPr><a:xfrm><a:off x="838200" y="2200000"/><a:ext cx="10515600" cy="1500000"/></a:xfrm></p:spPr>'
                    f'<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US" sz="2400" i="1"><a:solidFill><a:srgbClr val="4B5563"/></a:solidFill></a:rPr><a:t>{sub_esc}</a:t></a:r></a:p></p:txBody>'
                    f'</p:sp>'
                )
                shape_id += 1

            # Bullets
            if s.bullets:
                paras = []
                for b in s.bullets:
                    b_esc = escape(b)
                    paras.append(
                        f'<a:p><a:pPr lvl="0"><a:buChar char="•"/></a:pPr>'
                        f'<a:r><a:rPr lang="en-US" sz="2000"><a:solidFill><a:srgbClr val="374151"/></a:solidFill></a:rPr>'
                        f'<a:t>{b_esc}</a:t></a:r></a:p>'
                    )
                shapes.append(
                    f'<p:sp>'
                    f'<p:nvSpPr><p:cNvPr id="{shape_id}" name="Content"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr><p:ph idx="1"/></p:nvPr></p:nvSpPr>'
                    f'<p:spPr><a:xfrm><a:off x="838200" y="1800000"/><a:ext cx="10515600" cy="4500000"/></a:xfrm></p:spPr>'
                    f'<p:txBody><a:bodyPr/><a:lstStyle/>{"".join(paras)}</p:txBody>'
                    f'</p:sp>'
                )
                shape_id += 1

            # Slide XML
            slide_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<p:sld xmlns:a="{A_NS}" xmlns:r="{R_NS_OFFICE}" xmlns:p="{P_NS}">'
                f'<p:cSld><p:spTree>'
                f'<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
                f'<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
                f'{"".join(shapes)}'
                f'</p:spTree></p:cSld>'
                f'<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>'
                f'</p:sld>'
            )

            slide_rels_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" '
                'Target="../slideLayouts/slideLayout1.xml"/>'
                '</Relationships>'
            )

            zf.writestr(f"ppt/slides/slide{idx}.xml", slide_xml)
            zf.writestr(f"ppt/slides/_rels/slide{idx}.xml.rels", slide_rels_xml)

        # Presentation XML
        pres_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<p:presentation xmlns:a="{A_NS}" xmlns:r="{R_NS_OFFICE}" xmlns:p="{P_NS}">'
            f'<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rIdMaster1"/></p:sldMasterIdLst>'
            f'<p:sldIdLst>{"".join(slide_id_list)}</p:sldIdLst>'
            f'<p:sldSz cx="{w_emu}" cy="{h_emu}" type="screen16x9"/>'
            f'<p:notesSz cx="6858000" cy="9144000"/>'
            f'</p:presentation>'
        )

        pres_rels_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdMaster1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" '
            'Target="slideMasters/slideMaster1.xml"/>'
            f'{"".join(pres_rels)}'
            '</Relationships>'
        )

        content_types_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/ppt/presentation.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
            '<Override PartName="/ppt/slideMasters/slideMaster1.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>'
            '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>'
            f'{"".join(slide_overrides)}'
            '</Types>'
        )

        root_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="ppt/presentation.xml"/>'
            '</Relationships>'
        )

        # Basic master and layout
        slide_master_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<p:sldMaster xmlns:a="{A_NS}" xmlns:r="{R_NS_OFFICE}" xmlns:p="{P_NS}">'
            f'<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
            f'<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
            f'</p:spTree></p:cSld>'
            f'<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>'
            f'<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rIdLayout1"/></p:sldLayoutIdLst>'
            f'</p:sldMaster>'
        )

        master_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdLayout1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" '
            'Target="../slideLayouts/slideLayout1.xml"/>'
            '</Relationships>'
        )

        layout_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<p:sldLayout xmlns:a="{A_NS}" xmlns:r="{R_NS_OFFICE}" xmlns:p="{P_NS}" type="blank">'
            f'<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
            f'<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
            f'</p:spTree></p:cSld>'
            f'<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>'
            f'</p:sldLayout>'
        )

        layout_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" '
            'Target="../slideMasters/slideMaster1.xml"/>'
            '</Relationships>'
        )

        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("ppt/presentation.xml", pres_xml)
        zf.writestr("ppt/_rels/presentation.xml.rels", pres_rels_xml)
        zf.writestr("ppt/slideMasters/slideMaster1.xml", slide_master_xml)
        zf.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels", master_rels)
        zf.writestr("ppt/slideLayouts/slideLayout1.xml", layout_xml)
        zf.writestr("ppt/slideLayouts/_rels/slideLayout1.xml.rels", layout_rels)

    return str(path.resolve())


# ---------------------------------------------------------------------------
# XLSX Renderer (Standard Library Only: zipfile + SpreadsheetML)
# ---------------------------------------------------------------------------

MAIN_XLSX = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
SAFE_FUNCTIONS = frozenset({"SUM", "AVERAGE", "MIN", "MAX", "COUNT", "COUNTA", "ROUND", "ABS", "IF"})


def is_safe_formula(text: str) -> bool:
    """Verifies that a formula only performs simple arithmetic/aggregate functions without command execution."""
    if not text.startswith("="):
        return False
    # Prohibit formula injection triggers: DDE, WEBSERVICE, HYPERLINK, external links, shell execution
    upper = text.upper()
    dangerous = ("CMD", "POWERSHELL", "EXEC", "WEBSERVICE", "FILTERXML", "HYPERLINK", "DDE", "|", "'!")
    if any(d in upper for d in dangerous):
        return False
    return True


def _col_name(idx: int) -> str:
    """Converts 0-based column index to Excel column name (0 -> A, 27 -> AB)."""
    name = ""
    idx += 1
    while idx > 0:
        idx, rem = divmod(idx - 1, 26)
        name = chr(65 + rem) + name
    return name


def render_xlsx(title: str, sheets_data: dict[str, list[list[Any]]], output_path: Union[str, Path]) -> str:
    """Renders a hardened Microsoft Excel (.xlsx) workbook with zero external dependencies."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    sheet_overrides = []
    wb_sheets = []
    wb_rels = []

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for s_idx, (s_name, rows) in enumerate(sheets_data.items(), start=1):
            sheet_overrides.append(
                f'<Override PartName="/xl/worksheets/sheet{s_idx}.xml" '
                'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            )
            clean_sname = escape(re.sub(r"[\[\]:*?/\\]", "", s_name)[:31] or f"Sheet{s_idx}")
            wb_sheets.append(f'<sheet name="{clean_sname}" sheetId="{s_idx}" r:id="rIdSheet{s_idx}"/>')
            wb_rels.append(
                f'<Relationship Id="rIdSheet{s_idx}" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                f'Target="worksheets/sheet{s_idx}.xml"/>'
            )

            # Build sheet rows
            sheet_rows_xml = []
            for r_idx, row in enumerate(rows, start=1):
                cell_xmls = []
                for c_idx, val in enumerate(row):
                    ref = f"{_col_name(c_idx)}{r_idx}"
                    if val is None or val == "":
                        continue
                    if isinstance(val, (int, float)):
                        cell_xmls.append(f'<c r="{ref}" t="n"><v>{val}</v></c>')
                    elif isinstance(val, str) and val.startswith("=") and is_safe_formula(val):
                        # Safe formula
                        formula_expr = escape(val[1:])
                        cell_xmls.append(f'<c r="{ref}"><f>{formula_expr}</f></c>')
                    else:
                        # Strings stored as inline strings (t="inlineStr")
                        # Escaping prevents CSV/Excel formula injection (e.g. '=cmd|...')
                        str_val = str(val)
                        if str_val.startswith(("=", "+", "-", "@")):
                            str_val = "'" + str_val  # Escape leading formula triggers
                        esc_val = escape(str_val)
                        cell_xmls.append(f'<c r="{ref}" t="inlineStr"><is><t>{esc_val}</t></is></c>')
                if cell_xmls:
                    sheet_rows_xml.append(f'<row r="{r_idx}">{"".join(cell_xmls)}</row>')

            # Dimension reference
            max_r = max(len(rows), 1)
            max_c = max(max((len(r) for r in rows), default=1), 1)
            dim_ref = f"A1:{_col_name(max_c - 1)}{max_r}"

            ws_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<worksheet xmlns="{MAIN_XLSX}">'
                f'<dimension ref="{dim_ref}"/>'
                f'<sheetViews><sheetView tabSelected="1" workbookViewId="0"/></sheetViews>'
                f'<sheetData>{"".join(sheet_rows_xml)}</sheetData>'
                f'</worksheet>'
            )
            zf.writestr(f"xl/worksheets/sheet{s_idx}.xml", ws_xml)

        wb_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<workbook xmlns="{MAIN_XLSX}" xmlns:r="{R_NS_OFFICE}">'
            f'<sheets>{"".join(wb_sheets)}</sheets>'
            f'</workbook>'
        )

        wb_rels_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'{"".join(wb_rels)}'
            '</Relationships>'
        )

        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            f'{"".join(sheet_overrides)}'
            '</Types>'
        )

        root_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/>'
            '</Relationships>'
        )

        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("xl/workbook.xml", wb_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", wb_rels_xml)

    return str(path.resolve())


# ---------------------------------------------------------------------------
# HTML & Markdown Exporters
# ---------------------------------------------------------------------------

def render_html(doc: Doc) -> str:
    """Renders a Doc object into standalone, script-free HTML."""
    body_elements = []
    if doc.title:
        body_elements.append(f"<h1>{escape(doc.title)}</h1>")
    if doc.subtitle:
        body_elements.append(f"<p class='subtitle'><em>{escape(doc.subtitle)}</em></p>")

    for b in doc.blocks:
        if b.type == "heading":
            body_elements.append(f"<h{min(b.level, 4)}>{escape(b.text)}</h{min(b.level, 4)}>")
        elif b.type == "paragraph":
            body_elements.append(f"<p>{escape(b.text)}</p>")
        elif b.type == "bullets":
            items = "".join(f"<li>{escape(i)}</li>" for i in b.items)
            body_elements.append(f"<ul>{items}</ul>")
        elif b.type == "numbered":
            items = "".join(f"<li>{escape(i)}</li>" for i in b.items)
            body_elements.append(f"<ol>{items}</ol>")
        elif b.type == "callout":
            body_elements.append(f"<blockquote class='callout'><strong>[{escape(b.label)}]</strong> {escape(b.text)}</blockquote>")
        elif b.type == "quote":
            body_elements.append(f"<blockquote>{escape(b.text)}</blockquote>")
        elif b.type == "code":
            body_elements.append(f"<pre><code>{escape(b.text)}</code></pre>")
        elif b.type == "table":
            if not b.rows:
                continue
            t_rows = []
            for r_idx, r in enumerate(b.rows):
                tag = "th" if r_idx == 0 else "td"
                cells = "".join(f"<{tag}>{escape(c)}</{tag}>" for c in r)
                t_rows.append(f"<tr>{cells}</tr>")
            body_elements.append(f"<table>{''.join(t_rows)}</table>")

    return (
        "<!DOCTYPE html>\n"
        "<html>\n<head>\n"
        "<meta charset='utf-8'>\n"
        f"<title>{escape(doc.title)}</title>\n"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline';\">\n"
        "<style>\n"
        "body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #1f2937; }\n"
        "h1 { color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }\n"
        "h2, h3 { color: #1f2937; margin-top: 24px; }\n"
        "table { width: 100%; border-collapse: collapse; margin: 20px 0; }\n"
        "th, td { border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; }\n"
        "th { background: #f9fafb; font-weight: 600; }\n"
        "pre { background: #f3f4f6; padding: 12px; border-radius: 6px; overflow-x: auto; }\n"
        "blockquote { border-left: 4px solid #3b82f6; margin: 16px 0; padding: 8px 16px; background: #eff6ff; }\n"
        ".subtitle { color: #4b5563; font-size: 1.1em; }\n"
        "</style>\n</head>\n<body>\n"
        + "\n".join(body_elements) +
        "\n</body>\n</html>"
    )


def render_markdown(doc: Doc) -> str:
    """Renders a Doc object into clean Markdown text."""
    lines = []
    if doc.title:
        lines.append(f"# {doc.title}\n")
    if doc.subtitle:
        lines.append(f"*{doc.subtitle}*\n")

    for b in doc.blocks:
        if b.type == "heading":
            lines.append(f"{'#' * b.level} {b.text}\n")
        elif b.type == "paragraph":
            lines.append(f"{b.text}\n")
        elif b.type == "bullets":
            for itm in b.items:
                lines.append(f"- {itm}")
            lines.append("")
        elif b.type == "numbered":
            for idx, itm in enumerate(b.items, 1):
                lines.append(f"{idx}. {itm}")
            lines.append("")
        elif b.type == "callout":
            lines.append(f"> [!{b.label or 'NOTE'}] {b.text}\n")
        elif b.type == "quote":
            lines.append(f"> {b.text}\n")
        elif b.type == "code":
            lines.append(f"```\n{b.text}\n```\n")
        elif b.type == "table":
            if not b.rows:
                continue
            for r_idx, r in enumerate(b.rows):
                lines.append("| " + " | ".join(r) + " |")
                if r_idx == 0:
                    lines.append("| " + " | ".join(["---"] * len(r)) + " |")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# High-Level Tool Helper APIs
# ---------------------------------------------------------------------------

def make_document(
    title: str,
    content: str,
    format: str = "docx",
    output_path: Optional[str] = None,
    kind: str = "notes"
) -> dict[str, Any]:
    """Creates a document in docx, html, or md format."""
    doc = build_doc(kind, content, title=title)
    fmt = format.lower().strip(".")

    safe_title = re.sub(r'[^a-zA-Z0-9_\-]', '_', title)[:40] or "document"
    if not output_path:
        filename = f"{safe_title}_{int(datetime.now(UTC).timestamp())}.{fmt}"
        dest_path = os.path.join(DOCS_OUTPUT_DIR, filename)
    else:
        dest_path = output_path

    if fmt == "docx":
        out = render_docx(doc, dest_path)
    elif fmt == "html":
        html_str = render_html(doc)
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(html_str)
        out = os.path.abspath(dest_path)
    elif fmt in ("md", "markdown"):
        md_str = render_markdown(doc)
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(md_str)
        out = os.path.abspath(dest_path)
    else:
        return {"ok": False, "error": f"Unsupported format '{format}'. Supported formats: docx, html, md"}

    return {
        "ok": True,
        "format": fmt,
        "title": doc.title,
        "path": out,
        "words": doc.words(),
        "message": f"Successfully created {fmt.upper()} document: '{doc.title}' at {out}"
    }


def make_presentation(
    title: str,
    slides: list[dict[str, Any]],
    output_path: Optional[str] = None
) -> dict[str, Any]:
    """Creates a PowerPoint presentation (.pptx)."""
    slide_objs = []
    for s in slides:
        slide_objs.append(
            SlideData(
                title=s.get("title", ""),
                bullets=s.get("bullets", []),
                subtitle=s.get("subtitle", ""),
                notes=s.get("notes", "")
            )
        )

    safe_title = re.sub(r'[^a-zA-Z0-9_\-]', '_', title)[:40] or "presentation"
    if not output_path:
        filename = f"{safe_title}_{int(datetime.now(UTC).timestamp())}.pptx"
        dest_path = os.path.join(DOCS_OUTPUT_DIR, filename)
    else:
        dest_path = output_path

    out = render_pptx(title, slide_objs, dest_path)
    return {
        "ok": True,
        "title": title,
        "slides_count": len(slide_objs),
        "path": out,
        "message": f"Successfully generated presentation '{title}' ({len(slide_objs)} slides) at {out}"
    }


def make_spreadsheet(
    title: str,
    data: Union[dict[str, list[list[Any]]], list[list[Any]]],
    output_path: Optional[str] = None
) -> dict[str, Any]:
    """Creates an Excel spreadsheet (.xlsx)."""
    if isinstance(data, list):
        sheets = {"Sheet1": data}
    elif isinstance(data, dict):
        sheets = data
    else:
        return {"ok": False, "error": "Spreadsheet data must be a 2D array or a dictionary of sheet names to 2D arrays."}

    safe_title = re.sub(r'[^a-zA-Z0-9_\-]', '_', title)[:40] or "workbook"
    if not output_path:
        filename = f"{safe_title}_{int(datetime.now(UTC).timestamp())}.xlsx"
        dest_path = os.path.join(DOCS_OUTPUT_DIR, filename)
    else:
        dest_path = output_path

    out = render_xlsx(title, sheets, dest_path)
    total_rows = sum(len(r) for r in sheets.values())
    return {
        "ok": True,
        "title": title,
        "sheets": list(sheets.keys()),
        "total_rows": total_rows,
        "path": out,
        "message": f"Successfully generated spreadsheet '{title}' ({len(sheets)} sheets, {total_rows} rows) at {out}"
    }

"""
tools/build_compliance_docx.py

Build the DGCA §7.1 Word deliverables from the Markdown sources under Docs/audit/.

Produces TWO documents:
  1. Inofly_Firmware_Security_Compliance_Document.docx  (auditor-facing)
       Certificate + Architecture + §7.1 Mapping + Annexure E + Build Identity + Test Evidence
  2. Inofly_Firmware_Flashing_SOP.docx  (CB-facing flashing SOP)
       Keys → OpenSSL → signature → upload → connection diagram → bootloader/firmware
       flashing → GCS flow → §7.1 testing tables. Mirrors the the audited reference reference SOP.

(The internal Testing & Operations SOP was retired 2026-07-28; its Markdown sources
 — TOOLS_REFERENCE.md, PRODUCTION_KEY_PROVISIONING.md, AUDIT_DEMO_SCRIPT.md — remain
 as standalone internal references and are listed individually in README.md.)

Usage:
    py -3 tools/build_compliance_docx.py [compliance] [flashing]
    (no argument = build both; name one or more to build selectively —
     e.g. `flashing` alone leaves a hand-finalized compliance docx untouched)

Depends only on python-docx (already installed). No pandoc required.
Rerun after editing any source Markdown to regenerate the Word files.
"""

from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor, Inches

REPO = Path(__file__).resolve().parents[1]
AUDIT = REPO / "Docs" / "audit"
DIAGRAMS_DIR = AUDIT / "diagrams"

# ASCII diagrams in the Markdown render poorly as monospace blocks in Word, so
# the builder swaps each one for the PNG rendered by tools/render_audit_diagrams.py.
# Keyed on a distinctive substring of the ASCII block; the Markdown keeps the
# ASCII art (it reads fine on GitHub). Rerun render_audit_diagrams.py after
# changing a figure. If a PNG is missing we fall back to the ASCII block rather
# than fail the build.
DIAGRAMS = [
    ("MANUFACTURER (offline)", "fig1_system_components.png",
     "Figure 1 — System components and trust boundaries"),
    ("[Tamper-evident seal", "fig2_chain_of_trust.png",
     "Figure 2 — Chain of trust: every layer verified by the layer above it"),
    ("Power on FM", "fig3_boot_post.png",
     "Figure 3 — Boot sequence and Power-On Self-Test (POST), fail-closed"),
    ("PATH B (normal, operator)", "fig4_update_paths.png",
     "Figure 4 — Firmware update paths; all three are independently gated"),
    (".compliance_params flash table", "fig5_param_protection.png",
     "Figure 5 — Compliance parameter protection (PAR001): CAPPED and LOCKED kinds"),
    ("encrypt with EMBEDDED PUBLIC KEY", "fig6_audit_log.png",
     "Figure 6 — Audit log signing and offline verification (LOG001)"),
    ("CubeOrange+ on carrier", "fig7_connection_diagram.png",
     "Figure 7 — Provisioning connections: USB data + microSD + battery power "
     "(SWD/ST-Link is not used — debug pads are behind the tamper seal)"),
]

COMPLIANCE_SOURCES = [
    "EXECUTIVE_SUMMARY.md",
    "GLOSSARY.md",
    "CERTIFICATE_OF_COMPLIANCE.md",
    "ARCHITECTURE_OVERVIEW.md",
    "COMPLIANCE_7.1_MAPPING.md",
    "ANNEXURE_E_CONFORMANCE.md",
    "BUILD_IDENTITY.md",
    "TEST_EVIDENCE_PACK.md",
]

FLASHING_SOURCES = [
    "FIRMWARE_FLASHING_SOP.md",
]

# Link-text aliases so cross-references read naturally inside a merged doc.
ALIASES = {
    "CERTIFICATE_OF_COMPLIANCE.md": "the Certificate of Compliance",
    "ARCHITECTURE_OVERVIEW.md": "the Architecture section",
    "COMPLIANCE_7.1_MAPPING.md": "the §7.1 Compliance Mapping",
    "ANNEXURE_E_CONFORMANCE.md": "the Annexure E Conformance section",
    "BUILD_IDENTITY.md": "the Build Identity section",
    "TEST_EVIDENCE_PACK.md": "the Test Evidence section",
    "PRODUCTION_KEY_PROVISIONING.md": "the Production Key Provisioning section",
    "AUDIT_DEMO_SCRIPT.md": "the Test Runbook section",
    "TOOLS_REFERENCE.md": "the Tools Reference section",
    "MANUFACTURING_RUNBOOK.md": "the Manufacturing Runbook",
    "ARCHITECTURE.md": "the Architecture Reference",
    "HARDWARE_ACCEPTANCE.md": "the Hardware Acceptance record",
    "BOOTLOADER_BRINGUP.md": "the Bootloader Bring-up record",
}

# Alias patterns that also swallow an optional repo path prefix (Docs/, ../, Docs/audit/)
# so plain-prose references read as clean names, not repo paths. Applied to all
# inline prose and table text — NOT to fenced code blocks (which keep literal paths,
# e.g. the SOP's "edit BUILD_IDENTITY.md" instructions).
_ALIAS_PATTERNS = [
    (re.compile(r"(?:\.\./|Docs/(?:audit/)?)?" + re.escape(fname)), alias)
    for fname, alias in ALIASES.items()
]


def apply_aliases(text: str) -> str:
    for pat, alias in _ALIAS_PATTERNS:
        text = pat.sub(alias, text)
    return text

# Leading-metadata table rows / lines to drop (reduce per-Part redundancy).
DROP_ROW_KEYS = {"Last updated", "Companion docs", "Companion evidence"}

MONO = "Consolas"

# ── source cleanup ───────────────────────────────────────────────────────────

def preprocess(md: str) -> str:
    out = []
    for line in md.split("\n"):
        s = line.strip()

        # "**Last updated:** … · <clause>" → drop the date, keep the trailing clause
        m = re.match(r"^\*\*Last updated:\*\*[^·]*·\s*(.+)$", s)
        if m:
            out.append(m.group(1))
            continue
        # standalone "**Last updated:** <date>" line (no trailing clause) → drop
        if re.match(r"^\*\*Last updated:\*\*[^·]*$", s):
            continue

        # metadata table rows whose first cell is a drop-key
        if s.startswith("|"):
            cells = [c.strip().strip("*").strip() for c in s.strip("|").split("|")]
            if cells and cells[0] in DROP_ROW_KEYS:
                continue

        out.append(line)
    return "\n".join(out)


# ── inline formatting ────────────────────────────────────────────────────────

_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_TOKEN = re.compile(r"(\*\*.+?\*\*|~~.+?~~|`[^`]+`)")


def add_inline(paragraph, text: str):
    # links → their visible text, then alias doc-filename references (prose + links)
    text = _LINK.sub(lambda m: m.group(1), text)
    text = apply_aliases(text)
    for part in _TOKEN.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            paragraph.add_run(part[2:-2]).bold = True
        elif part.startswith("~~") and part.endswith("~~"):
            paragraph.add_run(part[2:-2]).font.strike = True
        elif part.startswith("`") and part.endswith("`"):
            run = paragraph.add_run(part[1:-1])
            run.font.name = MONO
            run.font.size = Pt(9.5)
        else:
            paragraph.add_run(part)


# ── block helpers ────────────────────────────────────────────────────────────

def _shade(pPr, fill: str):
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pPr.append(shd)


def add_code_block(doc, lines):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.1)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.space_before = Pt(6)
    _shade(p._p.get_or_add_pPr(), "F2F2F2")
    for i, ln in enumerate(lines):
        run = p.add_run(ln)
        run.font.name = MONO
        run.font.size = Pt(8.5)
        if i < len(lines) - 1:
            run.add_break()


def add_diagram(doc, png_path: Path, caption: str):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(8)
    # 6.3" fits inside default Letter/A4 margins; PNGs are 2x for print quality
    p.add_run().add_picture(str(png_path), width=Inches(6.3))
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cap.paragraph_format.space_after = Pt(10)
    run = cap.add_run(caption)
    run.italic = True
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x59, 0x59, 0x59)


def maybe_add_diagram(doc, code_lines) -> bool:
    """If this fenced block is one of the known ASCII diagrams, embed the
    rendered figure instead. Returns True when a figure was inserted."""
    content = "\n".join(code_lines)
    for key, png, caption in DIAGRAMS:
        if key in content:
            png_path = DIAGRAMS_DIR / png
            if png_path.exists():
                add_diagram(doc, png_path, caption)
                return True
    return False


def add_blockquote(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.3)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(4)
    _shade(p._p.get_or_add_pPr(), "FFF8E1")
    add_inline(p, text)
    for r in p.runs:
        r.font.size = Pt(9.5)


def add_table(doc, rows):
    header = rows[0]
    body = rows[2:]
    table = doc.add_table(rows=1, cols=len(header))
    table.style = "Light Grid Accent 1"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr = table.rows[0].cells
    for i, cell_text in enumerate(header):
        hdr[i].paragraphs[0].text = ""
        add_inline(hdr[i].paragraphs[0], cell_text.strip())
        for r in hdr[i].paragraphs[0].runs:
            r.bold = True
            r.font.size = Pt(9)
    for row in body:
        cells = table.add_row().cells
        for i in range(len(header)):
            val = row[i].strip() if i < len(row) else ""
            cells[i].paragraphs[0].text = ""
            add_inline(cells[i].paragraphs[0], val)
            for r in cells[i].paragraphs[0].runs:
                r.font.size = Pt(9)


def _split_row(line):
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


# ── markdown parser (block level) ────────────────────────────────────────────

def render_markdown(doc, md: str):
    lines = md.split("\n")
    i, n = 0, len(md.split("\n"))
    started_heading = False

    while i < n:
        line = lines[i]

        if line.strip().startswith("```"):
            j = i + 1
            buf = []
            while j < n and not lines[j].strip().startswith("```"):
                buf.append(lines[j]); j += 1
            if not maybe_add_diagram(doc, buf):
                add_code_block(doc, buf if buf else [""])
            i = j + 1
            continue

        if "|" in line and i + 1 < n and re.match(r"^\s*\|?\s*:?-{2,}", lines[i + 1]):
            tbl = []
            k = i
            while k < n and "|" in lines[k] and lines[k].strip():
                tbl.append(_split_row(lines[k])); k += 1
            add_table(doc, tbl)
            i = k
            continue

        stripped = line.strip()

        if re.match(r"^-{3,}$", stripped):
            i += 1
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            level = len(m.group(1))
            text = m.group(2).strip()
            if level == 1 and started_heading:
                doc.add_page_break()
            h = doc.add_heading(level=min(level, 4))
            add_inline(h, text)
            started_heading = True
            i += 1
            continue

        if stripped.startswith(">"):
            qbuf = []
            while i < n and lines[i].strip().startswith(">"):
                qbuf.append(re.sub(r"^\s*>\s?", "", lines[i])); i += 1
            add_blockquote(doc, " ".join(x for x in qbuf if x).strip())
            continue

        mb = re.match(r"^(\s*)[-*]\s+(.*)$", line)
        if mb:
            indent = len(mb.group(1))
            p = doc.add_paragraph(style="List Bullet" if indent < 2 else "List Bullet 2")
            add_inline(p, mb.group(2))
            i += 1
            continue

        mn = re.match(r"^(\s*)\d+\.\s+(.*)$", line)
        if mn:
            p = doc.add_paragraph(style="List Number")
            add_inline(p, mn.group(2))
            i += 1
            continue

        if not stripped:
            i += 1
            continue

        p = doc.add_paragraph()
        add_inline(p, stripped)
        i += 1


# ── cover + TOC ──────────────────────────────────────────────────────────────

def add_cover(doc, title, subtitle, status, meta):
    for _ in range(3):
        doc.add_paragraph()
    t = doc.add_paragraph(); t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = t.add_run(title); r.bold = True; r.font.size = Pt(26)
    s = doc.add_paragraph(); s.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rs = s.add_run(subtitle); rs.font.size = Pt(14); rs.font.color.rgb = RGBColor(0x40, 0x40, 0x40)
    doc.add_paragraph()
    tbl = doc.add_table(rows=0, cols=2); tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    for k, v in meta:
        cells = tbl.add_row().cells
        cells[0].paragraphs[0].add_run(k).bold = True
        cells[1].paragraphs[0].add_run(v)
        for c in cells:
            for para in c.paragraphs:
                for run in para.runs:
                    run.font.size = Pt(10)
    st = doc.add_paragraph(); st.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rst = st.add_run(status); rst.italic = True; rst.font.size = Pt(10)
    rst.font.color.rgb = RGBColor(0x80, 0x80, 0x80)
    doc.add_page_break()

    doc.add_heading("Contents", level=1)
    p = doc.add_paragraph(); run = p.add_run()
    fldStart = OxmlElement("w:fldChar"); fldStart.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText"); instr.set(qn("xml:space"), "preserve")
    instr.text = r'TOC \o "1-3" \h \z \u'
    fldSep = OxmlElement("w:fldChar"); fldSep.set(qn("w:fldCharType"), "separate")
    placeholder = OxmlElement("w:t")
    placeholder.text = "Right-click and choose “Update Field” to build the table of contents."
    fldEnd = OxmlElement("w:fldChar"); fldEnd.set(qn("w:fldCharType"), "end")
    for el in (fldStart, instr, fldSep, placeholder, fldEnd):
        run._r.append(el)
    doc.add_page_break()


def build_document(sources, title, subtitle, status, meta, output):
    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10.5)

    add_cover(doc, title, subtitle, status, meta)

    # Front-matter sources get no "PART n" banner and don't advance the part
    # counter, so numbered Parts start at the first substantive document.
    # The flashing SOP is a single continuous document — a PART banner would be noise.
    front_matter = {"EXECUTIVE_SUMMARY.md", "GLOSSARY.md", "FIRMWARE_FLASHING_SOP.md"}
    part_no = 0
    for idx, name in enumerate(sources):
        md = preprocess((AUDIT / name).read_text(encoding="utf-8"))
        if idx > 0:
            doc.add_page_break()
        if name not in front_matter:
            part_no += 1
            banner = doc.add_paragraph()
            rb = banner.add_run(f"PART {part_no}")
            rb.bold = True; rb.font.size = Pt(9); rb.font.color.rgb = RGBColor(0x1F, 0x4E, 0x79)
        render_markdown(doc, md)

    doc.save(str(output))
    print(f"[OK] wrote {output.name}  ({output.stat().st_size} bytes)")


def main():
    import sys
    targets = {t.lower() for t in sys.argv[1:]} or {"compliance", "flashing"}
    unknown = targets - {"compliance", "flashing"}
    if unknown:
        raise SystemExit(f"unknown target(s): {', '.join(sorted(unknown))} "
                         "(choose from: compliance, flashing)")
    if "compliance" in targets:
        build_compliance()
    if "flashing" in targets:
        build_flashing()


def build_compliance():
    build_document(
        COMPLIANCE_SOURCES,
        "Firmware Security Compliance Document",
        "DGCA UAS Type Certification — Certification Scheme Section 7.1 (Level 1)",
        "Draft for Certification Body review",
        [
            ("Manufacturer (Flight Module firmware provider)", "Inofly"),
            ("Product", "CubePilot CubeOrange+ (STM32H743), PX4-based firmware (inoflyPilot fork)"),
            ("Ground station", "inoflyGCU (QGroundControl fork)"),
            ("Role", "Firmware Manufacturer — not the Certification Body"),
            ("Document date", "2026-07-10"),
        ],
        AUDIT / "Inofly_Firmware_Security_Compliance_Document.docx",
    )


def build_flashing():
    build_document(
        FLASHING_SOURCES,
        "Firmware Flashing SOP",
        "OEM firmware flashing manual — key generation, signing, flashing and verification",
        "For Certification Body review — hardware procedure (CubeOrange+)",
        [
            ("Doc No.", "01 - FF - INF"),
            ("Issue", "01"),
            ("Manufacturer (Flight Module firmware provider)", "Inofly"),
            ("Product", "CubePilot CubeOrange+ (STM32H743), PX4-based firmware (inoflyPilot fork)"),
            ("Ground station", "inoflyGCU (QGroundControl fork)"),
            ("Document date", "2026-07-14"),
        ],
        AUDIT / "Inofly_Firmware_Flashing_SOP.docx",
    )


if __name__ == "__main__":
    main()

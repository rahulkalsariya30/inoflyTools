"""
tools/generate_security_doc.py

Generates a non-technical Word document explaining the drone security
implementation for DGCA compliance review.

Usage:
    python tools/generate_security_doc.py
Output:
    Docs/Drone_Security_Overview.docx
"""

from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from pathlib import Path
import datetime

OUT_DIR = Path(__file__).resolve().parents[1] / "Docs"
OUT_DIR.mkdir(exist_ok=True)
OUT_FILE = OUT_DIR / "Drone_Security_Overview.docx"

# ── Colour palette ─────────────────────────────────────────────────────────────
NAVY       = RGBColor(0x1F, 0x39, 0x64)   # headings
TEAL       = RGBColor(0x00, 0x70, 0xC0)   # sub-headings
LIGHT_BLUE = RGBColor(0xBD, 0xD7, 0xEE)   # table header fill
GREEN      = RGBColor(0x37, 0x86, 0x40)   # Done
ORANGE     = RGBColor(0xC5, 0x5A, 0x11)   # TODO
GRAY       = RGBColor(0x75, 0x75, 0x75)   # body text accent
WHITE      = RGBColor(0xFF, 0xFF, 0xFF)

# ── Helpers ────────────────────────────────────────────────────────────────────

def set_cell_bg(cell, hex_color: str):
    """Set table cell background colour (e.g. '1F3964')."""
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement("w:shd")
    shd.set(qn("w:val"),   "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"),  hex_color)
    tcPr.append(shd)

def add_heading(doc, text, level=1):
    p = doc.add_heading(text, level=level)
    run = p.runs[0] if p.runs else p.add_run(text)
    run.font.color.rgb = NAVY if level == 1 else TEAL
    run.font.bold = True
    p.paragraph_format.space_before = Pt(14 if level == 1 else 8)
    p.paragraph_format.space_after  = Pt(4)
    return p

def add_body(doc, text, bold=False, color=None):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.font.size  = Pt(11)
    run.font.bold  = bold
    if color:
        run.font.color.rgb = color
    p.paragraph_format.space_after = Pt(4)
    return p

def add_bullet(doc, text, sub=False):
    style = "List Bullet 2" if sub else "List Bullet"
    p = doc.add_paragraph(style=style)
    run = p.add_run(text)
    run.font.size = Pt(11)
    p.paragraph_format.space_after = Pt(2)
    return p

def add_table_row(table, cells, bold=False, bg=None, fg=WHITE):
    row = table.add_row()
    for i, text in enumerate(cells):
        cell = row.cells[i]
        cell.text = text
        run = cell.paragraphs[0].runs[0]
        run.font.size  = Pt(10)
        run.font.bold  = bold
        if fg and bold:
            run.font.color.rgb = fg
        if bg:
            set_cell_bg(cell, bg)
    return row

def status_symbol(status: str) -> str:
    return {"done": "✅  Done", "todo": "⚠  Planned", "partial": "🔧  In Progress"}.get(status, status)


# ── Document ───────────────────────────────────────────────────────────────────

def build():
    doc = Document()

    # Page margins
    for section in doc.sections:
        section.top_margin    = Cm(2.0)
        section.bottom_margin = Cm(2.0)
        section.left_margin   = Cm(2.5)
        section.right_margin  = Cm(2.5)

    # ── Cover ──────────────────────────────────────────────────────────────────
    doc.add_paragraph()
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("Drone Firmware Security\nCompliance Overview")
    run.font.size  = Pt(26)
    run.font.bold  = True
    run.font.color.rgb = NAVY

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run2 = sub.add_run("DGCA UAS Type Certification — Level 1\nPrepared by: Inofly Technologies")
    run2.font.size  = Pt(13)
    run2.font.color.rgb = GRAY

    date_p = doc.add_paragraph()
    date_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    date_run = date_p.add_run(f"Date: {datetime.date.today().strftime('%d %B %Y')}")
    date_run.font.size  = Pt(11)
    date_run.font.color.rgb = GRAY

    doc.add_page_break()

    # ── 1. Purpose ─────────────────────────────────────────────────────────────
    add_heading(doc, "1. Purpose of This Document")
    add_body(doc,
        "This document explains, in plain language, the security measures we are building "
        "into our drone firmware and ground control software. It maps each security feature "
        "to the specific requirement it satisfies under the DGCA (Directorate General of "
        "Civil Aviation) UAS Type Certification rules for Level 1 drone manufacturers."
    )
    add_body(doc,
        "Our role is that of the Firmware Manufacturer — we build, sign, and protect the "
        "software that runs on the flight controller. We are not the Certification Body."
    )

    # ── 2. The Problem ─────────────────────────────────────────────────────────
    add_heading(doc, "2. What Problem Are We Solving?")
    add_body(doc,
        "A drone is only as trustworthy as the software running on it. Without security "
        "controls, anyone could:"
    )
    add_bullet(doc, "Flash a tampered or malicious firmware onto a drone undetected.")
    add_bullet(doc, "Change safety-critical settings (maximum altitude, geofence) without authorisation.")
    add_bullet(doc, "Operate the drone with no way to prove what software version is running.")
    add_bullet(doc, "Leave no tamper-evident trail if something goes wrong.")

    add_body(doc,
        "\nThe DGCA requires manufacturers to address all of these risks before a drone can "
        "receive type certification. We are implementing a layered security framework — "
        "from the moment the firmware is built, right through to the drone's boot process "
        "and the ground control software."
    )

    # ── 3. How It Works ────────────────────────────────────────────────────────
    add_heading(doc, "3. How Our Security Works — The Big Picture")
    add_body(doc,
        "Think of our security system like a chain of trust. Each link in the chain "
        "verifies the one before it:"
    )

    steps = [
        ("Step 1 — We sign the firmware before release",
         "When we build a firmware release, our build tools automatically calculate a "
         "unique fingerprint (SHA-256 checksum) for the software. A digital signature "
         "is then applied using our private cryptographic key — similar to a wax seal "
         "on an envelope. This signed bundle is what gets shipped."),
        ("Step 2 — The signed bundle is loaded onto the drone",
         "A provisioning tool writes a small 'manifest' file onto the drone's storage. "
         "This manifest contains the fingerprints and the digital signature. It is "
         "the drone's reference point for knowing what the legitimate firmware looks like."),
        ("Step 3 — Every time the drone boots, it checks itself (POST)",
         "On every power-on, before anything else happens, the flight controller "
         "runs a Power On Self Test (POST). It recalculates the firmware fingerprint "
         "and checks the digital signature. If anything has been tampered with, "
         "the check fails."),
        ("Step 4 — A failed check blocks the drone from flying",
         "If the POST fails for any reason, the arming system is blocked. The drone "
         "cannot take off. The pilot and ground control software are both notified "
         "immediately with a clear pre-flight failure message."),
        ("Step 5 — The ground control software monitors security in real time",
         "Our custom QGroundControl plugin displays the live security status of the "
         "drone. The operator can see whether the firmware integrity check passed, "
         "review the audit log, and upload signed firmware updates."),
        ("Step 6 — Each drone has its own hardware security identity",
         "Every flight module contains a TPM 2.0 hardware security chip. At manufacturing "
         "time, a unique device key is generated inside this chip — it never leaves the "
         "hardware. The manufacturer certifies this device key, creating a chain: "
         "manufacturer key → certifies → device key. All data the drone generates at "
         "runtime (audit logs, boot attestations) is signed by the device's own key, "
         "proving exactly which drone produced it."),
        ("Step 7 — Only signed firmware updates are accepted",
         "When a firmware update is needed, the drone itself verifies the manufacturer "
         "signature on the update bundle before accepting it. An unsigned or tampered "
         "update is rejected — even if someone tries to push it directly."),
    ]

    for title_text, detail in steps:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after  = Pt(2)
        run_title = p.add_run(f"\n{title_text}\n")
        run_title.font.bold  = True
        run_title.font.size  = Pt(11)
        run_title.font.color.rgb = TEAL
        run_detail = p.add_run(detail)
        run_detail.font.size = Pt(11)

    # ── 4. Cryptography ────────────────────────────────────────────────────────
    add_heading(doc, "4. The Cryptographic Foundation")
    add_body(doc,
        "All signing and verification in this system is built on industry-standard "
        "cryptographic algorithms approved by NIST and required by DGCA:"
    )
    add_bullet(doc, "Signing Algorithm: ECDSA P-256 (also called secp256r1) — the same algorithm used to secure HTTPS on the internet.")
    add_bullet(doc, "Hash / Fingerprint: SHA-256 — produces a unique 64-character fingerprint of any file. A single changed bit produces a completely different fingerprint.")
    add_body(doc, "\nTwo-layer key architecture (DGCA Level 1 requirement):", bold=True)
    add_bullet(doc, "Manufacturer Key (ROT001) — held on the build machine (TPM/HSM). Signs firmware releases, manifests, and update bundles. Proves a build is authentic.")
    add_bullet(doc, "Device Key (DEV001) — held inside each drone's TPM chip. Signs data the drone generates at runtime: audit logs, boot attestations. Proves which drone produced which data.")
    add_body(doc,
        "These are two different keys with two different purposes. The manufacturer key covers "
        "what we release; the device key covers what the drone does in the field. Without a "
        "device key, you cannot prove which drone generated which audit log entry — a requirement "
        "for DGCA Level 1 compliance."
    )

    # ── 5. Requirement table ───────────────────────────────────────────────────
    add_heading(doc, "5. DGCA Requirements and How We Meet Them")
    add_body(doc, "The table below maps each DGCA requirement to the feature we have built or are building:")
    doc.add_paragraph()

    cols = ("Req. ID", "Plain-English Requirement", "What We Built", "Status")
    table = doc.add_table(rows=1, cols=4)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER

    # column widths
    widths = [Cm(2.2), Cm(5.5), Cm(7.5), Cm(2.0)]
    for i, w in enumerate(widths):
        for cell in table.columns[i].cells:
            cell.width = w

    # header row
    hdr = table.rows[0]
    for i, col in enumerate(cols):
        hdr.cells[i].text = col
        run = hdr.cells[i].paragraphs[0].runs[0]
        run.font.bold  = True
        run.font.size  = Pt(10)
        run.font.color.rgb = WHITE
        set_cell_bg(hdr.cells[i], "1F3964")

    rows = [
        ("ROT001", "Manufacturer must have a cryptographic identity (private key)",
         "ECDSA P-256 keypair generated and stored securely. Private key never leaves the build environment. Phase 4 will move this into a TPM/HSM hardware chip.", "done"),
        ("ROT002", "Public key must be embedded inside the firmware",
         "Public key is compiled into the firmware as a C header file. The drone always has it available for verification.", "done"),
        ("DEV001", "Each flight module must have its own hardware-bound Root of Trust (TPM/TEE)",
         "Every drone needs a TPM 2.0 chip with a unique device key. The manufacturer certifies this key, creating a chain of trust. All runtime data (logs, attestations) is signed by the device key — not the manufacturer key.", "todo"),
        ("CHK001", "Firmware code and data must each have a separate fingerprint",
         "SHA-256 checksums are computed separately for the code section and data section of every firmware build.", "done"),
        ("SIG001", "The firmware manifest (fingerprints + metadata) must be digitally signed",
         "Our signing tool signs the manifest with the manufacturer private key. The signature is part of every release bundle.", "done"),
        ("PKG001", "Firmware must be packaged as a tamper-evident signed bundle",
         "Bundler tool produces a .fwbundle file containing firmware binary + signed manifest. Any tampering breaks the signature.", "done"),
        ("PRV001", "Signed manifest must be provisioned onto the drone",
         "Provisioning tool writes the binary manifest to drone storage. Verified locally before writing.", "done"),
        ("POST001", "Drone must verify firmware integrity on every boot (Power On Self Test)",
         "secure_boot module runs at boot, checks CRC32 integrity + ECDSA signature, publishes result via internal message bus.", "done"),
        ("POST002", "POST must verify actual firmware code in memory (hardware)",
         "To be implemented in Phase 4. Requires NuttX RTOS crypto support. SITL currently returns a pass stub.", "todo"),
        ("POST003", "POST must verify actual firmware data in memory (hardware)",
         "To be implemented in Phase 4. Requires knowing the exact data storage address on the target hardware.", "todo"),
        ("POST004", "POST must verify the board ID matches the expected hardware",
         "To be implemented in Phase 6. Board ID is available at compile time — small effort.", "todo"),
        ("ARM001", "Drone must block take-off if POST failed",
         "Arming check module reads the POST result. If the check did not pass, arming is blocked and a preflight failure is shown.", "done"),
        ("PAR001", "Safety-critical parameters can only be changed with a valid manufacturer signature",
         "To be designed and built in Phase 5. Affects parameters like max altitude, geofence radius, speed limits.", "todo"),
        ("LOG001", "All security events must be written to a signed, tamper-evident audit log",
         "Drone signs each log entry with its own device key (DEV001), proving which drone generated it. QGC viewer built in Phase 3. Drone-side signing requires DEV001 (Phase 4).", "todo"),
        ("UPD001", "The drone must reject any firmware update that is not signed by the manufacturer",
         "Drone-side rejection to be built in Phase 3. QGC already handles the signed bundle upload flow.", "todo"),
    ]

    STATUS_BG = {"done": "E2EFDA", "todo": "FCE4D6"}
    for row_data in rows:
        req_id, plain, built, status = row_data
        row = table.add_row()
        data = [req_id, plain, built, status_symbol(status)]
        for i, text in enumerate(data):
            row.cells[i].text = text
            run = row.cells[i].paragraphs[0].runs[0]
            run.font.size = Pt(10)
        set_cell_bg(row.cells[3], STATUS_BG.get(status, "FFFFFF"))

    # ── 6. Phase roadmap ───────────────────────────────────────────────────────
    doc.add_paragraph()
    add_heading(doc, "6. Implementation Roadmap")
    add_body(doc,
        "The work is organised into phases. Each phase builds on the previous one. "
        "The first two phases are complete. Phase 3 is the active work."
    )
    doc.add_paragraph()

    phases = [
        ("Phase 1 — Manufacturer Toolchain", "✅  Complete",
         "All tools needed to build and sign a secure firmware release: key generation, "
         "checksum calculation, manifest signing, public key embedding, and bundle packaging."),
        ("Phase 2 — Firmware Security Module", "✅  Complete",
         "The security code running inside the drone firmware: the POST module that checks "
         "firmware integrity on boot, the arming gate that blocks take-off on failure, and "
         "the SITL (simulation) integration test that proves the end-to-end flow works."),
        ("Phase 3 — Ground Control Software Plugin", "⏳  In Progress",
         "Custom plugin for QGroundControl that shows live security status, lets operators "
         "upload signed firmware bundles, view the audit log, and enforces signed-update "
         "rejection at the drone level."),
        ("Phase 4 — Hardware Root of Trust", "⏳  Planned (Level 1 Required)",
         "Two parts: (1) Move the manufacturer signing key into a TPM/HSM hardware chip on "
         "the build machine. (2) Provision each flight module with its own TPM-based device "
         "key, certified by the manufacturer. This is required for DGCA Level 1 — without a "
         "device key, the drone cannot sign its own runtime data (audit logs, attestations). "
         "Also implements real in-memory hash verification on NuttX hardware."),
        ("Phase 5 — Parameter Protection", "⏳  Planned",
         "Prevent unauthorised changes to safety-critical flight parameters. Any write to "
         "a protected parameter (altitude limit, geofence, speed cap) must be accompanied "
         "by a valid manufacturer signature."),
        ("Phase 6 — Compliance Test Suite & Report", "⏳  Planned",
         "Full automated test suite that exercises every requirement end-to-end. Output "
         "is a compliance report ready for DGCA submission."),
    ]

    for phase_title, phase_status, phase_desc in phases:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after  = Pt(2)
        run_t = p.add_run(phase_title)
        run_t.font.bold  = True
        run_t.font.size  = Pt(11)
        run_t.font.color.rgb = NAVY
        run_s = p.add_run(f"   {phase_status}")
        run_s.font.size  = Pt(10)
        run_s.font.color.rgb = GREEN if "Complete" in phase_status else ORANGE

        p2 = doc.add_paragraph()
        p2.paragraph_format.left_indent = Cm(0.5)
        p2.paragraph_format.space_after = Pt(4)
        r2 = p2.add_run(phase_desc)
        r2.font.size = Pt(11)

    # ── 7. What the Pilot Sees ─────────────────────────────────────────────────
    add_heading(doc, "7. What the Pilot and Operator See")
    add_body(doc,
        "Security should not be invisible to the people operating the drone. Our implementation "
        "surfaces security status at every important moment:"
    )

    scenarios = [
        ("Normal boot — firmware intact",
         "The drone boots, runs the POST, passes all checks. The QGC security panel shows "
         "a green 'Firmware Integrity: PASS' status. The pilot can proceed normally."),
        ("Tampered firmware detected",
         "The POST detects a hash or signature mismatch. The arming system is blocked. "
         "QGC shows a red 'Preflight Fail: Firmware integrity check failed' alert. "
         "The drone cannot take off until the firmware is re-provisioned with a valid signed build."),
        ("Secure firmware update",
         "The operator opens the firmware update panel in QGC, selects a .fwbundle file, "
         "and uploads it. QGC and the drone both verify the manufacturer signature before "
         "flashing. An unsigned bundle is rejected with a clear error message."),
        ("Unauthorised parameter change attempt",
         "Someone tries to change the maximum altitude via an unsigned MAVLink command. "
         "The drone rejects the write. The event is logged to the audit log with a timestamp. "
         "(Phase 5)"),
    ]

    for scen_title, scen_desc in scenarios:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(6)
        r1 = p.add_run(scen_title + "\n")
        r1.font.bold  = True
        r1.font.size  = Pt(11)
        r1.font.color.rgb = TEAL
        r2 = p.add_run(scen_desc)
        r2.font.size = Pt(11)

    # ── 8. Glossary ────────────────────────────────────────────────────────────
    add_heading(doc, "8. Glossary of Key Terms")

    terms = [
        ("ECDSA P-256",      "A digital signature algorithm. The same mathematics used to secure online banking. P-256 means the key is 256 bits long — considered very strong."),
        ("SHA-256",          "A fingerprinting algorithm. Given any file, it produces a unique 64-character code. If even one byte of the file changes, the fingerprint is completely different."),
        ("Manifest",         "A small file containing the firmware fingerprints, version number, and board ID — all signed by the manufacturer. The drone keeps this as its reference."),
        ("POST",             "Power On Self Test. A check the drone runs automatically on every boot before allowing any flight operations."),
        ("Manufacturer Root of Trust", "The manufacturer's private key — used to sign firmware releases and update bundles. Held on the build machine, never on the drone."),
        ("Device Root of Trust", "A unique key held inside each drone's TPM chip. Signs data the drone generates at runtime (audit logs, boot attestations). Proves which specific drone produced which data."),
        ("TPM 2.0",          "Trusted Platform Module. A dedicated hardware chip for storing cryptographic keys. Even if someone has physical access to the hardware, the key cannot be extracted."),
        ("Arming Gate",      "The pre-flight check system in PX4. We added a new check: if POST failed, the drone cannot arm (start motors)."),
        (".fwbundle",        "Our signed firmware update package. Contains the firmware binary and a signed manifest. Cannot be tampered with without breaking the signature."),
        ("uORB",             "PX4's internal message bus — like a notice board that different software modules post messages to. The POST result is published here so the arming gate can read it."),
        ("DGCA Level 1",     "The baseline type certification tier for drone manufacturers in India. Requires a documented chain of trust, firmware integrity checks, and secure update mechanisms."),
    ]

    table2 = doc.add_table(rows=1, cols=2)
    table2.style = "Table Grid"
    table2.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, w in enumerate([Cm(4.5), Cm(12.7)]):
        for cell in table2.columns[i].cells:
            cell.width = w

    hdr2 = table2.rows[0]
    for i, col in enumerate(("Term", "Meaning")):
        hdr2.cells[i].text = col
        run = hdr2.cells[i].paragraphs[0].runs[0]
        run.font.bold  = True
        run.font.size  = Pt(10)
        run.font.color.rgb = WHITE
        set_cell_bg(hdr2.cells[i], "1F3964")

    for term, meaning in terms:
        row = table2.add_row()
        row.cells[0].text = term
        row.cells[1].text = meaning
        for cell in row.cells:
            run = cell.paragraphs[0].runs[0]
            run.font.size = Pt(10)
        set_cell_bg(row.cells[0], "BDD7EE")

    # ── Footer note ────────────────────────────────────────────────────────────
    doc.add_paragraph()
    note = doc.add_paragraph()
    note.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = note.add_run(
        "This document is intended for internal review and regulatory discussion. "
        "It does not contain any private key material or sensitive cryptographic data."
    )
    r.font.size  = Pt(9)
    r.font.italic = True
    r.font.color.rgb = GRAY

    doc.save(str(OUT_FILE))
    print(f"[OK] Saved: {OUT_FILE}")


if __name__ == "__main__":
    build()

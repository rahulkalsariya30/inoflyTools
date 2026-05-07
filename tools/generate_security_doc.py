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
         "is then applied using our private cryptographic key (RSA-2048) — similar to a wax seal "
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
        ("Step 6 — Safety-critical parameters are locked",
         "Parameters like maximum altitude, geofence range, and maximum speed are "
         "statically compiled into the firmware and cannot be changed from any ground "
         "control station at runtime. Any attempt to modify them is blocked and logged "
         "to the audit trail."),
        ("Step 7 — Only signed firmware updates are accepted",
         "When a firmware update is needed, the drone itself verifies the manufacturer "
         "signature on the update bundle before accepting it. An unsigned or tampered "
         "update is rejected — even if someone tries to push it directly."),
        ("Step 8 — Only authorised ground control software can communicate",
         "Each drone is provisioned with a unique MAVLink signing key during manufacturing. "
         "Only a GCS with the matching key can send commands to the drone. Unauthorised "
         "ground control software (without the key) is rejected. The signing mode cannot "
         "be disabled at runtime."),
        ("Step 9 — All security events are logged with tamper-evident signing",
         "Every security event (boot check results, firmware update attempts, parameter "
         "change violations) is written to a binary audit log on the drone's storage. "
         "The entire log file is signed using the manufacturer's RSA key, creating a "
         "tamper-evident trail that can be verified offline."),
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
    add_bullet(doc, "Signing Algorithm: RSA-2048 with PSS padding — a widely trusted algorithm used in banking, aviation, and government systems. 2048-bit keys provide 112-bit security, accepted by NIST SP 800-57 R5 for new signatures through end of 2030.")
    add_bullet(doc, "Hash / Fingerprint: SHA-256 — produces a unique 64-character fingerprint of any file. A single changed bit produces a completely different fingerprint.")
    add_bullet(doc, "GCS-FC Pairing: MAVLink v2 message signing with 32-byte HMAC-SHA256 key — ensures only authorised ground control software can communicate with the drone.")
    add_body(doc, "\nSingle keypair architecture:", bold=True)
    add_bullet(doc, "Private key — held ONLY on the manufacturer's build machine. Signs firmware releases, manifests, and update bundles. Decrypts audit log signatures for offline verification. Never leaves the build environment.")
    add_bullet(doc, "Public key — embedded in every drone's firmware as a C header. Verifies signatures at boot (POST), encrypts audit log hashes for tamper-evident signing.")
    add_body(doc,
        "RSA enables both signing (firmware verification) and encryption (audit log signing) "
        "with the same keypair. This keeps the architecture simple: one keypair, two uses."
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
         "RSA-2048 keypair generated and stored securely. Private key never leaves the build environment.", "done"),
        ("ROT002", "Public key must be embedded inside the firmware",
         "Public key is compiled into the firmware as a C header file (DER format). The drone always has it available for verification.", "done"),
        ("CHK001", "Firmware code and data must each have a separate fingerprint",
         "SHA-256 checksums are computed separately for the code section and data section of every firmware build.", "done"),
        ("SIG001", "The firmware manifest (fingerprints + metadata) must be digitally signed",
         "Our signing tool signs the manifest with the manufacturer private key (RSA-PSS). The signature is part of every release bundle.", "done"),
        ("PKG001", "Firmware must be packaged as a tamper-evident signed bundle",
         "Bundler tool produces a .fwbundle file containing firmware binary + signed manifest. Any tampering breaks the signature.", "done"),
        ("PRV001", "Signed manifest must be provisioned onto the drone",
         "Provisioning tool writes the 501-byte binary manifest to drone storage. CRC32 + RSA-PSS verified locally before writing.", "done"),
        ("POST001", "Drone must verify firmware integrity on every boot (Power On Self Test)",
         "secure_boot module runs at boot: CRC32 integrity check, then RSA-PSS signature verification. Publishes result via uORB message bus.", "done"),
        ("POST002", "POST must verify actual firmware code in memory (hardware)",
         "Requires NuttX linker symbols for flash addresses. SITL returns pass stub. Target: OrangeCube/Pixhawk with libtomcrypt.", "todo"),
        ("POST003", "POST must verify actual firmware data in memory (hardware)",
         "Requires knowledge of PX4 parameter storage address on target hardware. SITL returns pass stub.", "todo"),
        ("POST004", "POST must verify the board ID matches the expected hardware",
         "Board ID available at compile time via CONFIG_BOARD_ID. Small effort — compare manifest vs hardware.", "todo"),
        ("ARM001", "Drone must block take-off if POST failed",
         "Arming check module subscribes to firmware_integrity_status. If check_passed is false, arming is blocked with preflight failure.", "done"),
        ("PAR001", "Safety-critical parameters must be protected from unauthorised changes",
         "Six parameters statically compiled and locked: max altitude, max speed, fence range, frame type, frame config, MAVLink signing mode. Any write attempt is blocked and logged.", "done"),
        ("LOG001", "All security events must be written to a signed, tamper-evident audit log",
         "132-byte binary entries with CRC32 integrity. Per-file RSA signing: SHA-256 of audit_log.bin encrypted with public key, verified offline with private key.", "done"),
        ("UPD001", "The drone must reject any firmware update that is not signed by the manufacturer",
         "FirmwareUpdateGatekeeper verifies staged manifest (CRC32 + RSA-PSS) before authorising bootloader reboot. QGC also verifies client-side.", "done"),
        ("PAIR001", "Only authorised GCS software can communicate with the drone",
         "MAVLink v2 message signing with 32-byte per-drone key. MAV_SIGN_CFG locked to 1 by PAR001. Provisioning tool generates unique key per drone.", "done"),
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
        "Phases 1 through 4 are complete. Phase 5 targets real hardware deployment. "
        "Phase 6 is the final compliance test suite."
    )
    doc.add_paragraph()

    phases = [
        ("Phase 1 — Manufacturer Toolchain", "✅  Complete",
         "All tools needed to build and sign a secure firmware release: key generation, "
         "checksum calculation, manifest signing, public key embedding, bundle packaging, "
         "and full release pipeline."),
        ("Phase 2 — Firmware Security Module", "✅  Complete",
         "The security code running inside the drone firmware: the POST module that checks "
         "firmware integrity on boot, the arming gate that blocks take-off on failure, "
         "firmware update gatekeeper, and the SITL integration test."),
        ("Phase 3 — Ground Control Software Plugin", "✅  Complete",
         "Custom plugin for QGroundControl: live security status panel, secure firmware "
         "update page (bundle verification + extraction), audit log viewer (real-time feed "
         "+ download), and drone-side firmware update signature rejection."),
        ("Phase 4 — Parameter Protection + Audit Logging + GCS Pairing", "✅  Complete",
         "Zero-window compliance parameter protection (6 locked parameters), per-file RSA "
         "audit logging (tamper-evident binary log with offline verification), and GCS-FC "
         "pairing via MAVLink signing (per-drone key provisioning)."),
        ("Phase 5 — Hardware Deployment", "⏳  Planned",
         "Deploy to OrangeCube/Pixhawk hardware: public key in CRP-protected flash, real "
         "code and data hash verification using libtomcrypt on NuttX, board ID verification, "
         "and hardware-specific testing."),
        ("Phase 6 — Compliance Test Suite & Report", "⏳  In Progress",
         "Full automated test suite with 260+ tests mapped to DGCA requirements. "
         "Compliance report generator produces machine-readable JSON and human-readable "
         "text reports for auditor submission."),
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
         "Someone tries to change the maximum altitude via a MAVLink command. "
         "The drone rejects the write immediately — the parameter is statically compiled "
         "and locked. The attempt is logged to the tamper-evident audit log with a timestamp."),
        ("Unauthorised GCS connection attempt",
         "An operator tries to connect with a GCS that does not have the drone's signing key. "
         "All commands are rejected because they lack valid MAVLink signatures. "
         "Only a GCS with the matching key (provisioned during manufacturing) can communicate."),
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
        ("RSA-2048 / RSA-PSS", "A digital signature and encryption algorithm. RSA-2048 provides 112-bit security (NIST SP 800-57 R5, accepted for new signatures through 2030). PSS padding is the modern, provably secure signature scheme. The same family of algorithms used to secure online banking and government systems."),
        ("SHA-256",          "A fingerprinting algorithm. Given any file, it produces a unique 64-character code. If even one byte of the file changes, the fingerprint is completely different."),
        ("Manifest",         "A small file containing the firmware fingerprints, version number, and board ID — all signed by the manufacturer. The drone keeps this as its reference. 501 bytes in binary format."),
        ("POST",             "Power On Self Test. A check the drone runs automatically on every boot before allowing any flight operations."),
        ("Root of Trust",    "The manufacturer's RSA-2048 keypair. Private key signs firmware releases and decrypts log signatures (never leaves the build machine). Public key is embedded in firmware for verification and log signing."),
        ("MAVLink Signing",  "MAVLink v2 protocol feature that authenticates every message using a shared 32-byte key (HMAC-SHA256). Ensures only authorised GCS software can control the drone."),
        ("Compliance Parameters", "Safety-critical flight parameters (max altitude, speed, geofence) that are statically compiled into the firmware and cannot be changed at runtime from any ground control station."),
        ("Arming Gate",      "The pre-flight check system in PX4. We added a new check: if POST failed, the drone cannot arm (start motors)."),
        (".fwbundle",        "Our signed firmware update package. Contains the firmware binary and a signed manifest. Cannot be tampered with without breaking the signature."),
        ("Audit Log",        "A tamper-evident binary log of all security events (boot checks, update attempts, parameter violations). Each log file is signed using RSA encryption for offline verification."),
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

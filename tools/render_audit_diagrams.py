"""
tools/render_audit_diagrams.py

Render the architecture diagrams (fig1–fig6 for the compliance document,
fig7 for the Firmware Flashing SOP) under Docs/audit/ as PNG images.

WHY this exists: the Markdown sources carry ASCII diagrams, which read fine
on GitHub but render as walls of monospace text inside the generated Word
deliverable. build_compliance_docx.py swaps each ASCII diagram for the PNG
produced here, so the CB gets real figures while the Markdown stays diff-able.

The diagrams are hand-laid-out SVG (deterministic, reviewable in git) and
rasterized with PyMuPDF at 2x for print quality. Content was verified against
the firmware sources on 2026-07-13 — notably:
  * POST check order matches FirmwareIntegrityChecker::run(): CRC/format ->
    signature -> code_hash -> data_hash -> board_id (board_id is LAST).
  * Audit entries are 316 bytes (AUDIT_ENTRY_SIZE in security_audit_entry.h).
  * Update reject reasons 2/3/4 match FirmwareUpdateAuthorization.msg.

Usage:
    py -3 tools/render_audit_diagrams.py
Output:
    Docs/audit/diagrams/*.png  (+ .svg sources for review)
"""

from __future__ import annotations

from pathlib import Path

import fitz  # PyMuPDF

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "Docs" / "audit" / "diagrams"

# ── design system ────────────────────────────────────────────────────────────
# One muted palette across all figures so the document reads as one system.
# Domains: blue = manufacturer/trusted, amber = ground/operator,
# green = flight module / pass, red = fail/reject, gray = artifacts/neutral.

PAL = {
    "blue":  {"stroke": "#1F4E79", "fill": "#DEEBF7", "title": "#1F4E79"},
    "green": {"stroke": "#2E6B34", "fill": "#E4F1E4", "title": "#2E6B34"},
    "amber": {"stroke": "#9A6A0B", "fill": "#FBF0D3", "title": "#7A5408"},
    "red":   {"stroke": "#B42318", "fill": "#FBEAE8", "title": "#B42318"},
    "gray":  {"stroke": "#565F6B", "fill": "#F2F4F7", "title": "#3B4148"},
    "white": {"stroke": "#565F6B", "fill": "#FFFFFF", "title": "#3B4148"},
}
INK = "#374151"      # arrows + labels
BODY = "#333333"     # body text
FONT = "Helvetica"


class SVG:
    """Tiny SVG builder: keeps the diagram code below declarative."""

    def __init__(self, width: int, height: int):
        self.w, self.h = width, height
        self.parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{height}" viewBox="0 0 {width} {height}">',
            f'<rect width="{width}" height="{height}" fill="white"/>',
        ]

    def raw(self, s: str):
        self.parts.append(s)

    def box(self, x, y, w, h, scheme="gray", dash=False, rx=8, sw=1.5):
        c = PAL[scheme]
        dash_attr = ' stroke-dasharray="6,4"' if dash else ""
        self.raw(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
            f'fill="{c["fill"]}" stroke="{c["stroke"]}" stroke-width="{sw}"{dash_attr}/>'
        )

    def text(self, x, y, s, size=12, color=BODY, bold=False, italic=False,
             anchor="middle", mono=False):
        fam = "Courier" if mono else FONT
        weight = ' font-weight="bold"' if bold else ""
        style = ' font-style="italic"' if italic else ""
        self.raw(
            f'<text x="{x}" y="{y}" font-family="{fam}" font-size="{size}"'
            f'{weight}{style} fill="{color}" text-anchor="{anchor}">{esc(s)}</text>'
        )

    def lines(self, cx, y, rows, size=12, color=BODY, lh=17, anchor="middle"):
        for i, row in enumerate(rows):
            self.text(cx, y + i * lh, row, size=size, color=color, anchor=anchor)

    def titled_box(self, x, y, w, h, title, rows=(), scheme="gray",
                   tsize=13.5, bsize=11.5, lh=16, dash=False, pad_top=22):
        self.box(x, y, w, h, scheme=scheme, dash=dash)
        self.text(x + w / 2, y + pad_top, title, size=tsize,
                  color=PAL[scheme]["title"], bold=True)
        if rows:
            self.lines(x + w / 2, y + pad_top + 20, rows, size=bsize, lh=lh)

    def _arrowhead(self, x, y, direction):
        d = 9
        pts = {
            "right": f"{x},{y} {x-d},{y-5} {x-d},{y+5}",
            "left":  f"{x},{y} {x+d},{y-5} {x+d},{y+5}",
            "down":  f"{x},{y} {x-5},{y-d} {x+5},{y-d}",
            "up":    f"{x},{y} {x-5},{y+d} {x+5},{y+d}",
        }[direction]
        self.raw(f'<polygon points="{pts}" fill="{INK}"/>')

    def arrow(self, x1, y1, x2, y2, label=None, label_dy=-7, dash=False,
              label_size=11):
        """Straight arrow (horizontal or vertical)."""
        dash_attr = ' stroke-dasharray="5,4"' if dash else ""
        self.raw(
            f'<path d="M {x1} {y1} L {x2} {y2}" stroke="{INK}" '
            f'stroke-width="1.5" fill="none"{dash_attr}/>'
        )
        if x1 == x2:
            self._arrowhead(x2, y2, "down" if y2 > y1 else "up")
        else:
            self._arrowhead(x2, y2, "right" if x2 > x1 else "left")
        if label:
            lx = (x1 + x2) / 2
            ly = (y1 + y2) / 2 + (label_dy if y1 == y2 else 0)
            if x1 == x2:  # vertical: put label to the right of the line
                self.text(x1 + 10, ly + 4, label, size=label_size, color=INK,
                          italic=True, anchor="start")
            else:
                self.text(lx, ly, label, size=label_size, color=INK, italic=True)

    def elbow(self, x1, y1, xm, x2, y2, label=None, dash=False, label_size=11):
        """Horizontal-vertical-horizontal elbow arrow ending pointing right/left."""
        dash_attr = ' stroke-dasharray="5,4"' if dash else ""
        self.raw(
            f'<path d="M {x1} {y1} L {xm} {y1} L {xm} {y2} L {x2} {y2}" '
            f'stroke="{INK}" stroke-width="1.5" fill="none"{dash_attr}/>'
        )
        self._arrowhead(x2, y2, "right" if x2 > xm else "left")
        if label:
            self.text(xm, (y1 + y2) / 2, label, size=label_size, color=INK,
                      italic=True)

    def svg(self) -> str:
        return "\n".join(self.parts + ["</svg>"])


def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def emit(name: str, s: SVG):
    OUT.mkdir(parents=True, exist_ok=True)
    svg_path = OUT / f"{name}.svg"
    svg_path.write_text(s.svg(), encoding="utf-8")
    doc = fitz.open(stream=s.svg().encode(), filetype="svg")
    pix = doc[0].get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
    png_path = OUT / f"{name}.png"
    pix.save(str(png_path))
    print(f"[OK] {png_path.relative_to(REPO)}  ({pix.width}x{pix.height})")


# ── figure 1: system components ──────────────────────────────────────────────

def fig1_system():
    s = SVG(1240, 620)

    # domain containers
    s.titled_box(20, 20, 370, 480, "MANUFACTURER  (offline)", scheme="blue",
                 dash=True, tsize=14)
    s.titled_box(440, 20, 300, 480, "GROUND  (operator)", scheme="amber",
                 dash=True, tsize=14)
    s.titled_box(790, 20, 430, 480, "AIRCRAFT  (Flight Module)", scheme="green",
                 dash=True, tsize=14)

    # manufacturer column
    s.titled_box(45, 60, 320, 78, "RSA-2048 private key", [
        "held offline (air-gapped) — never leaves",
        "the manufacturer, never on the aircraft",
    ], scheme="blue")
    s.titled_box(45, 158, 320, 96, "Release pipeline", [
        "checksum (code + data separately)",
        "→ sign (RSA-PSS)  → bundle  → export",
    ], scheme="white")
    s.titled_box(45, 274, 320, 96, "Signed outputs", [
        "manifest.bin (registered checksums)",
        "firmware .fwbundle",
        "signed bootloader artifact",
    ], scheme="gray")
    s.titled_box(45, 400, 320, 78, "RSA-2048 public key", [
        "PEM retained for the Certification Body;",
        "embedded in every Flight-Module binary",
    ], scheme="blue")

    # ground column
    s.titled_box(465, 90, 250, 150, "inoflyGCU (QGroundControl fork)", [
        "Secure Firmware Update UI",
        "Security status panel",
        "Audit Log panel",
    ], scheme="amber")
    s.titled_box(465, 280, 250, 70, "MAVLink v2 signing", [
        "HMAC-SHA256 on every message",
    ], scheme="white")

    # aircraft column
    s.titled_box(815, 66, 380, 64, "Verifying bootloader  (sector 0)", [
        "embedded public key — verifies app signature",
    ], scheme="green")
    s.arrow(1005, 130, 1005, 156)
    s.titled_box(815, 156, 380, 158, "App firmware — secure_boot module", [
        "POST: firmware integrity check on every boot",
        "Update gatekeeper (signed updates only)",
        "Compliance parameter guard",
        "Audit logger (RSA-bound entries)",
    ], scheme="green")
    s.titled_box(815, 340, 380, 92, "SD card", [
        "manifest.bin (signed registered checksums)",
        "audit_log.bin + audit_log.sig",
        "MAVLink signing key (provisioned)",
    ], scheme="gray")

    # flows between domains (kept below the columns so nothing crosses a box)
    s.arrow(390, 540, 810, 540, label="signed .fwbundle → QGroundControl verifies → uploads over signed MAVLink + FTP")
    s.arrow(810, 575, 390, 575, label="audit_log.bin + .sig downloaded for offline verification at the manufacturer / Certification Body")
    s.arrow(390, 612, 810, 612, dash=True,
            label="public key embedded in bootloader + app firmware at build time (no key ever provisioned in the field)")
    return s


# ── figure 2: chain of trust ─────────────────────────────────────────────────

def fig2_chain():
    s = SVG(1240, 540)
    x, w = 80, 560
    ax = x + w / 2

    s.titled_box(x, 30, w, 74, "Tamper-evident seal", [
        "airframe + Cube enclosure — visibly broken on intrusion",
        "compensating control for physical SWD/JTAG access (BOOT007)",
    ], scheme="amber")
    s.arrow(ax, 104, ax, 134)

    s.titled_box(x, 134, w, 74, "Verifying bootloader — flash sector 0", [
        "carries the manufacturer PUBLIC key",
        "sector 0 writable only via signed bl_update (BOOT006 / BOOT008)",
    ], scheme="blue")
    s.arrow(ax, 208, ax, 238, label="verifies the application-firmware signature every boot (BOOT001)")

    s.titled_box(x, 238, w, 74, "App firmware — signed by manufacturer", [
        "embeds the manufacturer PUBLIC key",
        "runs POST on every boot",
    ], scheme="blue")
    s.arrow(ax, 312, ax, 342, label="verifies manifest RSA-PSS signature (POST001)")

    s.titled_box(x, 342, w, 74, "manifest.bin — signed by manufacturer", [
        "registered checksums: code_hash, data_hash + board_id",
        "POST recomputes both hashes from LIVE flash and compares",
    ], scheme="blue")
    s.arrow(ax, 416, ax, 446, label="all integrity checks must pass")

    s.titled_box(x, 446, w, 64, "ARM gate", [
        "refuses to arm if any check failed — result audit-logged",
    ], scheme="green")

    # right-hand commentary
    cx = 720
    s.text(cx, 60, "Physical anchor", size=12.5, color=PAL["amber"]["title"], bold=True, anchor="start")
    s.lines(cx, 80, [
        "Reaching the debug port (SWD/JTAG) or USB",
        "requires visibly breaking the seal; a broken seal",
        "forces the return-to-manufacturer",
        "re-provisioning workflow.",
    ], size=11.5, anchor="start")

    s.text(cx, 170, "Cryptographic anchor", size=12.5, color=PAL["blue"]["title"], bold=True, anchor="start")
    s.lines(cx, 190, [
        "Every layer below the seal is RSA-PSS-verified",
        "(SHA-256, MGF1-SHA256, salt 32) against a public",
        "key vouched for by the layer above it.",
        "",
        "Producing any accepted artifact — bootloader,",
        "firmware, manifest — requires the private key,",
        "which never leaves the manufacturer.",
    ], size=11.5, anchor="start")

    s.text(cx, 330, "Why a “verifying” bootloader", size=12.5, color=PAL["gray"]["title"], bold=True, anchor="start")
    s.lines(cx, 350, [
        "The STM32H743 has no authenticating Boot ROM.",
        "The bootloader therefore verifies the firmware;",
        "its own integrity is anchored operationally",
        "(bootstrap-trust + signed bl_update + seal) —",
        "the same posture as the ArduPilot secure-boot",
        "pattern, appropriate for DGCA Level 1.",
    ], size=11.5, anchor="start")
    return s


# ── figure 3: boot sequence / POST ───────────────────────────────────────────

def fig3_post():
    s = SVG(1240, 700)

    s.titled_box(60, 24, 300, 44, "Power on Flight Module", scheme="gray", pad_top=28)
    s.arrow(210, 68, 210, 96)

    s.titled_box(60, 96, 300, 78, "Bootloader verifies app-firmware", [
        "RSA-PSS signature against its",
        "embedded public key (BOOT001)",
    ], scheme="blue")
    # invalid branch
    s.arrow(360, 135, 470, 135, label="signature invalid")
    s.titled_box(470, 100, 330, 70, "Refuse to launch (fail-closed)", [
        "stays in bootloader; unit only accepts",
        "a manufacturer-signed image",
    ], scheme="red")
    s.arrow(210, 174, 210, 202, label="signature valid")

    s.titled_box(60, 202, 300, 60, "App firmware boots;", [
        "secure_boot module autostarts",
    ], scheme="green", pad_top=24)
    s.arrow(210, 262, 210, 290)

    # POST ladder — order matches FirmwareIntegrityChecker::run()
    lx, lw = 60, 620
    s.box(lx, 290, lw, 240, scheme="white")
    s.text(lx + lw / 2, 316, "POST — checks run in this order, fail-closed at the first failure",
           size=13.5, color=PAL["gray"]["title"], bold=True)
    steps = [
        ("1", "Manifest present and readable on SD", "reason 1 — NO_MANIFEST"),
        ("2", "Manifest CRC32 + format check", "reason 2 — MANIFEST_CORRUPT"),
        ("3", "Manifest RSA-PSS signature (embedded public key)", "reason 3 — SIGNATURE_INVALID"),
        ("4", "code_hash — recomputed from LIVE flash, compared", "reason 4 — CODE_HASH_MISMATCH"),
        ("5", "data_hash — recomputed from LIVE flash, compared", "reason 5 — DATA_HASH_MISMATCH"),
        ("6", "board_id matches this hardware", "reason 6 — BOARD_ID_MISMATCH"),
    ]
    y = 336
    for num, txt, fail in steps:
        s.raw(f'<circle cx="{lx+30}" cy="{y+8}" r="11" fill="{PAL["blue"]["fill"]}" '
              f'stroke="{PAL["blue"]["stroke"]}" stroke-width="1.2"/>')
        s.text(lx + 30, y + 12, num, size=11.5, color=PAL["blue"]["title"], bold=True)
        s.text(lx + 52, y + 12, txt, size=12, anchor="start")
        s.text(lx + lw - 18, y + 12, "fail → " + fail, size=10.5,
               color=PAL["red"]["title"], anchor="end")
        y += 31

    # outcomes
    s.arrow(240, 530, 240, 566, label="all pass")
    s.titled_box(60, 566, 360, 104, "PASS", [
        "firmware_integrity_status = PASS",
        "POST_RESULT PASS written to audit log",
        "ARM gate allows arming",
    ], scheme="green")

    s.arrow(560, 530, 560, 566, label="any failure")
    s.titled_box(460, 566, 360, 104, "FAIL (fail-closed)", [
        "firmware_integrity_status = FAIL + reason code",
        "POST_RESULT FAILURE written to audit log",
        "ARM gate blocks arming · ground station shows the reason",
    ], scheme="red")

    # side note
    s.lines(860, 320, [
        "Registered checksums live in the signed",
        "manifest.bin: they cannot be altered",
        "without the private key — any edit fails",
        "the CRC or the signature check.",
        "",
        "Code and data are hashed separately",
        "(steps 4 and 5) so parameters can be",
        "revised by a future signed release",
        "without touching the code hash.",
        "",
        "Both outcomes — PASS and FAIL — are",
        "recorded in the RSA-bound audit log.",
    ], size=11.5, anchor="start")
    return s


# ── figure 4: update paths ───────────────────────────────────────────────────

def fig4_updates():
    s = SVG(1240, 680)

    # Path B lane — boxes first, arrows last, so no label is painted over
    s.titled_box(20, 20, 1200, 230, "PATH B — normal operator update: signed .fwbundle via QGroundControl",
                 scheme="green", dash=True, tsize=13)
    s.titled_box(45, 60, 235, 80, "QGroundControl verifies bundle", [
        "signature client-side;",
        "“Install” enabled only if valid",
    ], scheme="amber")
    s.titled_box(360, 60, 235, 80, "Flight Module stages", [
        "update_manifest.bin",
        "(+ staged image, UPDATE.BIN)",
    ], scheme="gray")
    s.titled_box(675, 60, 270, 80, "Flight Module verify_update gate", [
        "CRC32 → RSA-PSS sig → board_id",
        "against EMBEDDED public key",
    ], scheme="blue")
    s.titled_box(1005, 60, 190, 80, "Next boot", [
        "bootloader BOOT001",
        "+ full POST re-check",
    ], scheme="green")
    s.titled_box(675, 176, 270, 56, "Rejected — reason 2 / 3 / 4", [
        "UPDATE_ATTEMPT FAILURE audit-logged",
    ], scheme="red", pad_top=22)
    s.arrow(280, 100, 360, 100, label="MAVLink-FTP")
    s.arrow(595, 100, 675, 100)
    s.arrow(945, 100, 1005, 100, label="accept")
    s.arrow(810, 140, 810, 176, label="reject")
    s.text(45, 218, "The Flight Module never trusts the Ground Control Station — it re-verifies everything against its own embedded key.",
           size=11, color=INK, italic=True, anchor="start")

    # Path A lane
    s.titled_box(20, 270, 1200, 150, "PATH A — physical attack: raw image via USB/DFU",
                 scheme="red", dash=True, tsize=13)
    s.titled_box(45, 310, 250, 70, "Unsigned image written", [
        "(requires breaking the",
        "tamper seal to reach USB)",
    ], scheme="red")
    s.titled_box(375, 310, 300, 70, "Bootloader refuses to launch", [
        "signature check fails (BOOT001)",
        "— unit stays in bootloader",
    ], scheme="blue")
    s.arrow(295, 345, 375, 345, label="next boot")
    s.lines(710, 330, [
        "Defense in depth: the tamper-evident seal (BOOT007) gates physical",
        "access, BOOT001 blocks execution of anything unsigned, and POST",
        "remains the checksum backstop.",
    ], size=11.5, anchor="start")

    # bl_update lane
    s.titled_box(20, 440, 1200, 180, "BOOTLOADER UPDATE — signed bl_update (BOOT008)",
                 scheme="blue", dash=True, tsize=13)
    s.titled_box(45, 480, 280, 76, "Candidate bootloader on SD", [
        "must carry a manufacturer",
        "RSA-PSS signature",
    ], scheme="gray")
    s.titled_box(405, 480, 320, 76, "bl_update verifies signature", [
        "BEFORE erasing sector 0 —",
        "unsigned / tampered images refused",
    ], scheme="blue")
    s.titled_box(805, 480, 250, 76, "Sector 0 rewritten", [
        "new verifying bootloader",
        "installed (factory operation)",
    ], scheme="green")
    s.arrow(325, 518, 405, 518)
    s.arrow(725, 518, 805, 518, label="verified")
    s.text(45, 600, "Every path is fail-closed: nothing unsigned is staged, launched, or written to sector 0.",
           size=11, color=INK, italic=True, anchor="start")
    s.text(20, 650, "Three independent fail-closed layers protect every update: the ground-station client-side check, the Flight Module update gate, and boot-time verification (bootloader + POST).",
           size=11.5, color=INK, italic=True, anchor="start")
    return s


# ── figure 5: compliance parameter protection ────────────────────────────────

def fig5_params():
    s = SVG(1240, 480)

    # top row: how the registered values are anchored
    s.titled_box(30, 30, 300, 80, ".compliance_params flash table", [
        "registered values compiled into",
        "the firmware binary (PAR001)",
    ], scheme="blue")
    s.arrow(330, 70, 400, 70, label="covered by")
    s.titled_box(400, 30, 220, 80, "data_hash", [
        "SHA-256 of exactly",
        "that flash section",
    ], scheme="gray")
    s.arrow(620, 70, 690, 70, label="registered in")
    s.titled_box(690, 30, 240, 80, "Signed manifest.bin", [
        "cannot be altered without",
        "the private key",
    ], scheme="blue")
    s.arrow(930, 70, 1000, 70, label="checked by")
    s.titled_box(1000, 30, 210, 80, "POST, every boot", [
        "data_hash recomputed",
        "from live flash",
    ], scheme="green")

    s.text(30, 148, "Changing any registered value requires a new manufacturer-signed release — no ground-station or operator action can alter the certified table.",
           size=11.5, color=INK, italic=True, anchor="start")

    # runtime enforcement
    s.titled_box(30, 180, 380, 64, "param_set from Ground Control Station / operator", [
        "every write to a compliance parameter is intercepted",
    ], scheme="amber", pad_top=24)
    s.arrow(220, 244, 220, 282)

    s.titled_box(30, 282, 560, 116, "CAPPED — operator-tunable mission caps", [
        "GF_MAX_VER_DIST 120 m · GF_MAX_HOR_DIST 500 m · MPC_XY_VEL_MAX 15 m/s",
        "within (0, ceiling]: accepted, RAM-only, never persisted",
        "above ceiling: REJECTED + audit-logged (ceiling quoted)",
        "boot value 0 → arming blocked until the operator sets each cap",
    ], scheme="gray")

    s.titled_box(630, 282, 560, 116, "LOCKED — certificate-fixed configuration", [
        "SYS_AUTOSTART 4001 · CA_AIRFRAME 0 · MAV_SIGN_CFG 1",
        "always reads the registered value (survives power-cycle)",
        "write of the registered value: accepted as a no-op",
        "any other value: REJECTED + audit-logged (attempted vs registered)",
    ], scheme="gray")

    # LOCKED branch: leave the param_set box on the right, drop into the LOCKED box top
    s.raw(f'<path d="M 410 214 L 910 214 L 910 274" stroke="{INK}" '
          f'stroke-width="1.5" fill="none"/>')
    s._arrowhead(910, 282, "down")
    s.text(660, 208, "LOCKED rows", size=11, color=INK, italic=True)
    s.text(240, 262, "CAPPED rows", size=11, color=INK, italic=True, anchor="start")

    s.lines(30, 440, [
        "The protected property: the operator can fly more conservatively than the certificate allows, but can never move a",
        "certified value past its registered limit — and every attempt to do so is a signed audit event.",
    ], size=11.5, anchor="start")
    return s


# ── figure 6: audit log signing ──────────────────────────────────────────────

def fig6_audit():
    s = SVG(1240, 360)

    s.titled_box(30, 30, 310, 110, "Flight Module writes audit events", [
        "POST results (pass AND fail),",
        "update attempts, arming blocks,",
        "parameter violations — 316-byte",
        "CRC-protected entries → audit_log.bin",
    ], scheme="green")
    s.titled_box(425, 30, 330, 110, "Log hash bound to the root of trust", [
        "SHA-256(audit_log.bin) encrypted",
        "with the EMBEDDED PUBLIC key",
        "→ audit_log.sig (256 bytes)",
    ], scheme="blue")
    s.titled_box(840, 30, 370, 110, "Offline verification (manufacturer / Certification Body)", [
        "decrypt .sig with the PRIVATE key,",
        "recompute SHA-256, compare:",
        "match → authentic and untampered",
        "mismatch → edited or forged",
    ], scheme="gray")
    s.arrow(340, 85, 425, 85, label="every write")
    s.arrow(755, 85, 840, 85, label="FTP / SD")

    s.lines(30, 190, [
        "Why this proves origin and integrity: only the manufacturer's offline private key can open audit_log.sig. A log whose",
        "decrypted hash matches its content can only have been produced by a Flight Module carrying this root of trust, and",
        "cannot have been edited afterwards. The Flight Module itself holds no private key — a compromised drone cannot forge a valid log.",
    ], size=11.5, anchor="start")

    s.titled_box(30, 260, 560, 64, "Verification tools", [
        "verify_audit_log.py (authenticity) · decode_audit_log.py (readable entries)",
    ], scheme="white", pad_top=24)
    return s


# ── figure 7: provisioning connection diagram (Firmware Flashing SOP) ────────

def fig7_connection():
    """Physical hookup for flashing/provisioning a unit. Deliberately shows the
    three REAL paths only (USB data, microSD, battery power) and calls out that
    SWD/ST-Link is NOT part of the flow — on this architecture the debug pads
    are sealed (BOOT007), unlike the ST-Link-based reference SOP."""
    s = SVG(1240, 660)

    def dbl_arrow(x1, y1, x2, y2):
        # both-ends arrowhead: a connection, not a one-way flow
        s.raw(f'<path d="M {x1} {y1} L {x2} {y2}" stroke="{INK}" '
              f'stroke-width="1.5" fill="none"/>')
        if x1 == x2:
            s._arrowhead(x2, y2, "down" if y2 > y1 else "up")
            s._arrowhead(x1, y1, "up" if y2 > y1 else "down")
        else:
            s._arrowhead(x2, y2, "right" if x2 > x1 else "left")
            s._arrowhead(x1, y1, "left" if x2 > x1 else "right")

    # provisioning host (manufacturer domain → blue)
    s.titled_box(40, 90, 340, 160, "Provisioning host (Windows laptop)", [
        "QGroundControl: firmware load,",
        "MAVLink console, MAVLink-FTP",
        "nsh serial console over USB",
        "signed release artifacts staged locally",
    ], scheme="blue")

    # flight module (green) with its three physical ports as white boxes
    s.titled_box(700, 60, 500, 330,
                 "CubeOrange+ Flight Module (STM32H743, board-id 1063)", [
        "sector 0 — secure verifying bootloader (manufacturer public key embedded)",
        "application firmware — POST re-verifies checksums on every boot",
        "ports below are on the carrier board",
    ], scheme="green")
    s.titled_box(715, 170, 100, 36, "USB port", scheme="white", tsize=12, pad_top=23)
    s.titled_box(715, 320, 110, 36, "POWER1", scheme="white", tsize=12, pad_top=23)
    s.titled_box(1040, 320, 140, 36, "microSD slot", scheme="white", tsize=12, pad_top=23)

    # USB data connection (bidirectional)
    dbl_arrow(380, 188, 715, 188)
    s.text(547, 176, "USB (data)", size=11.5, color=INK, italic=True, bold=True)
    s.text(547, 208, "firmware load · nsh console · MAVLink-FTP", size=11, color=INK, italic=True)

    # power chain: LiPo -> power module -> POWER1 (mandatory)
    s.titled_box(40, 430, 160, 64, "LiPo battery", scheme="gray", pad_top=26)
    s.titled_box(260, 430, 190, 64, "Power module", scheme="gray", pad_top=26)
    s.arrow(200, 462, 260, 462)
    s.elbow(450, 462, 580, 715, 338, label="power")
    s.text(40, 528, "Battery power via POWER1 is mandatory — USB alone does not boot the Flight Module.",
           size=11.5, color=PAL["red"]["title"], bold=True, anchor="start")

    # microSD card and what lives on it
    s.titled_box(940, 440, 260, 110, "microSD card", [
        "inofly/manifest.bin (registered checksums)",
        "signed bootloader .bin (one-shot install)",
        "audit_log.bin + audit_log.sig",
        "MAVLink signing key",
    ], scheme="gray", bsize=10.5, lh=15)
    dbl_arrow(1110, 440, 1110, 356)
    # keep both label lines inside the 390..440 band (below the green box edge,
    # above the card box) so they don't straddle the container border
    s.text(1095, 412, "seated in slot — files via", size=10.5, color=INK, italic=True, anchor="end")
    s.text(1095, 427, "card reader or MAVLink-FTP", size=10.5, color=INK, italic=True, anchor="end")

    # what is deliberately absent from this diagram
    s.titled_box(40, 570, 1160, 64, "Not used: ST-Link / SWD-JTAG debugger", [
        "The debug pads sit inside the Cube enclosure behind the tamper-evident seal (BOOT007) — "
        "production flashing uses USB and the microSD card only; every flash path is gated by signature verification.",
    ], scheme="red", dash=True, bsize=11)
    return s


def main():
    emit("fig1_system_components", fig1_system())
    emit("fig2_chain_of_trust", fig2_chain())
    emit("fig3_boot_post", fig3_post())
    emit("fig4_update_paths", fig4_updates())
    emit("fig5_param_protection", fig5_params())
    emit("fig6_audit_log", fig6_audit())
    emit("fig7_connection_diagram", fig7_connection())


if __name__ == "__main__":
    main()

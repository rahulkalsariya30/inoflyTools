# RDP Burn Runbook

> # 🚫 RETIRED 2026-05-04 (ADR-013)
>
> **This runbook is retired before its first execution.** The Phase 5b
> step it was meant to govern — burning RDP Level 2 on production
> CubeOrange+ units — is not part of our manufacturing flow.
>
> **Forcing function:** the CubeOrange+ carriers we ship have no
> externally accessible BOOT0 button. Burning RDP Level 2 requires
> BOOT0 + SWD access during factory provisioning, which is not
> operationally possible without breaking Hex's factory seal — the
> same seal we are now relying on as a tamper-evident control.
>
> **Replacement:**
>
> - Manufacturing flow: see [MANUFACTURING_RUNBOOK.md](MANUFACTURING_RUNBOOK.md).
> - Architectural rationale: see [ARCHITECTURE.md §12 ADR-013](ARCHITECTURE.md).
> - Requirement-level remap: see [SECURITY_PLAN.md](../SECURITY_PLAN.md)
>   under BOOT001 / BOOT005 / BOOT006 / BOOT007 (the three-part
>   compensating control that replaces BOOT002 / BOOT003).
>
> **Why this file is kept rather than deleted.** The retired-runbook
> file exists so that any document, link, comment, or commit that
> references `Docs/RDP_BURN_RUNBOOK.md` continues to land on a page
> that explicitly states the retirement and points to the replacement.
> Outright deletion would leave broken links in the architecture and
> security-plan documents, and would lose the traceability that the
> retirement happened deliberately on 2026-05-04. The original
> contents were never written (this file would have been a Phase 5b
> deliverable); there is therefore no historical procedural content
> to preserve here.
>
> **Document history**
>
> | Version | Date | Change |
> |---|---|---|
> | 0.0 (retired stub) | 2026-05-04 | File created as a retired stub. The original RDP-burn procedure was never written — Phase 5b deliverable was overtaken by ADR-013 before drafting. |

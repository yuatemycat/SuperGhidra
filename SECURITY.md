# Security Policy

SuperGhidra is a reverse-engineering and binary analysis acceleration framework. Because binary analysis frequently inspects untrusted or obfuscated binaries, maintaining verified security boundaries is essential.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability or exploit vector within SuperGhidra (including parser overflows, shared-memory privilege escalation, or unauthorized emulator tampering):

1. **Do NOT open a public GitHub issue.**
2. Please submit your finding securely via **GitHub Private Vulnerability Reporting** on the repository page:
   `https://github.com/yuatemycat/SuperGhidra/security/advisories/new`
3. Include:
   - Description of the vulnerability and attack vector.
   - Minimal reproducing binary, script, or payload.
   - Potential impact on host or isolated emulator environments.

We will acknowledge receipt within 48 hours and coordinate a fix and advisory prior to public disclosure.

---

## Security Architectural Guarantees

SuperGhidra enforces defense-in-depth guarantees by design:

1. **Daemon Security Model (`ghidra_oracle.py`):**
   - **Loopback Binding Invariant:** Daemon binds strictly to loopback addresses (`127.0.0.1`, `::1`). Non-loopback addresses (e.g. `0.0.0.0`) are refused unless `--allow-remote` is explicitly provided.
   - **Session Token Verification:** Mutating and control commands (`stop`, `rename`, `comment`, `clear`, `register_struct`, `mode`, `hibernate`) require a valid session token (via `--token`, `SUPERGHIDRA_SESSION_TOKEN`, or local token file).
   - **Bounded Request Payloads:** Enforces a 2 MB maximum request size limit to prevent buffer exhaustion and memory denial-of-service.
2. **Read-Only Decompilation (`ghidra_oracle.py`):**
   - Analysis instances open programs with read-only flags (`readOnly=True`) to prevent project or binary contamination. Symbol renames and comments are recorded in non-destructive write overlays (`ghidra_overlay.json`) and transaction journals (`.ghidra-delta.jsonl`).
3. **Device Isolation (`EmulatorFleetGuard`):**
   - Dedicated protection mechanisms strictly prohibit memory injection, code mutation, or Frida hook attachment on production host devices or unlisted device serials.
4. **Shared Memory Boundaries (`shm_decompiler_bridge.py`):**
   - Shared memory segments use bounded ring buffers with explicit payload size validation and atomic store barriers to prevent out-of-bounds reads/writes.
5. **Obligation Ledger Gate (`evidence_ledger.py`):**
   - Automated struct commits and symbol renames must satisfy deterministic checks (`VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier`) before committing.

# Security Policy

SuperGhidra is an advanced reverse-engineering and binary analysis acceleration framework. Because binary analysis frequently inspects untrusted, hostile, or obfuscated payloads, maintaining robust security boundaries is paramount.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

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

1. **Read-Only Decompilation (`ghidra_oracle.py`):**
   - Analysis instances open programs with read-only flags to prevent binary contamination.
2. **Device Isolation (`EmulatorFleetGuard`):**
   - Dedicated protection mechanisms strictly prohibit memory injection, code mutation, or Frida hook attachment on production host devices or unlisted device serials.
3. **Shared Memory Boundaries (`shm_decompiler_bridge.py`):**
   - Shared memory segments use bounded ring buffers with explicit payload size validation and atomic store barriers to prevent out-of-bounds reads/writes.

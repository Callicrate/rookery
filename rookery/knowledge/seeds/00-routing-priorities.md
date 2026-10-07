# General CTF Routing Priorities

Prefer concrete technical surfaces first:

1. Web endpoints, source code, auth/session bugs, exposed files, APIs, client JS, SSRF, IDOR, injection.
2. Pwn binaries, remote services, libc/ld, heap/stack/format-string primitives, seccomp, sandbox escapes.
3. Rev artifacts, crackmes, bytecode, APKs, WASM, firmware, obfuscation, symbolic constraints.
4. Crypto with clear primitives: RSA, ECC, lattice, XOR/stream, padding, hashes, signatures, RNG, oracles.
5. Forensics/stego with files, pcaps, disks, images, archives, memory dumps, logs.
6. Misc/protocol/infra with deterministic local experiments.
7. OSINT/geosint only when there is a bounded source path or exact proof gap.

Parked means retry later with a different style. Never call a challenge unknowable. Dead routes are not dead challenges.

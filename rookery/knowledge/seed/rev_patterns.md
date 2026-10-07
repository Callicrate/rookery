# Rev CTF Pattern Seed

## First pass

- `file`, `strings`, `rabin2 -I`, `r2 -A`, `objdump`, `ltrace`, `strace`.
- Identify packing, VM, language/runtime, resources, config blobs.
- Run with controlled input and compare failure paths.

## Common lanes

- Static password checks: locate compare, backtrack transforms.
- Encoded tables: XOR, add/sub/rotate, base64/base85, custom alphabets.
- VM challenges: extract bytecode, implement interpreter/disassembler.
- Anti-debug: patch branches, fake time/env/files, skip ptrace checks.
- Go/Rust/.NET/Java: use runtime-aware tooling and decompilers.
- Mobile/APK: jadx/apktool resources, strings, network endpoints.

## Repro standard

- Leave a solver script that derives the answer from binary bytes, not manual guesses.

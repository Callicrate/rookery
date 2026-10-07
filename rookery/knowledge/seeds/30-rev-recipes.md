# Rev CTF Recipes

Fast triage:

```bash
file artifact
strings -a artifact | rg -i 'flag|ctf|key|license|wrong|correct|debug'
rabin2 -zz artifact | head
r2 -A -q -c 'afl; izz; pdf @ main' artifact
```

Common lanes:

- Static comparison against input, XOR/add/sub/rol encoders.
- Base encodings hidden in strings/resources.
- Anti-debug/time checks that can be patched.
- VM/bytecode interpreters: extract opcodes and write a small emulator.
- Constraint solving: z3 from branch conditions.
- Packed/obfuscated binaries: dynamic trace and memory dump.
- Android/APK: jadx, apktool, resources, native libs.
- WASM/JS: decompile, instrument, monkey-patch checks.

Prefer extracting the check and writing `solve.py` over manual guessing.

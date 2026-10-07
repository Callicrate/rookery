# Pwn CTF Recipes

Initial triage:

```bash
file chall
checksec --file=chall || pwn checksec chall
strings -a chall | head -200
readelf -a chall | head
./chall
```

Find primitive:

- Stack overflow: cyclic pattern, RIP/EIP offset, canary/no canary, ret2win, ret2libc, ROP chain.
- Format string: leak stack/libc/canary, write GOT/return address, `%n` if enabled.
- Heap: UAF, double free, tcache poisoning, unsorted leak, off-by-one, house-of-*.
- Integer/sign: negative sizes, truncation, allocation mismatch.
- Seccomp/sandbox: enumerate syscalls, ORW chain, mprotect + shellcode if possible.

Use `gdbq`, pwntools scripts, and bounded local/remote tests. Keep exploit scripts small and deterministic.

# Pwn CTF Pattern Seed

## First pass

- `file`, `checksec`, `strings`, `readelf -a`, `objdump -d`, `ldd`.
- Run locally with sample input; capture crash with cyclic pattern.
- Identify architecture, PIE, NX, canary, RELRO, libc version, seccomp.

## Common lanes

- Stack overflow: offset, ret2win, ROP, ret2libc, stack alignment.
- Format string: leak addresses, write GOT/return address if RELRO permits.
- Heap: tcache poisoning, double free, use-after-free, unsafe unlink, house patterns.
- Integer bugs: signedness, truncation, overflow into allocation sizes.
- Sandbox/seccomp: ORW chain, SROP, mprotect, mmap, permitted syscalls.
- Kernel/module: inspect ioctl handlers, copy_to/from_user, race, refcount, UAF.

## Repro standard

- Exploit script should connect locally/remotely via args.
- Preserve crash logs, offsets, leaks, and final interactive transcript.

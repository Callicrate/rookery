# Crypto CTF Pattern Seed

## First pass

- Identify primitive, parameters, key sizes, nonce/IV behavior, repeated values, oracle access.
- Search for exact constants and error messages in local corpus and SearXNG.
- Write scripts that parse the provided data exactly.

## Common lanes

- XOR/repeating key: known plaintext, crib drag, frequency, key length.
- RSA: small e, shared modulus, common factor, Wiener's, Fermat, broadcast, leaked dp/dq, oracle.
- AES modes: ECB block leaks, CBC bitflips, padding oracle, CTR nonce reuse, GCM nonce reuse.
- Hash/MAC: length extension, weak salts, custom hash differentials, HMAC confusion.
- LCG/PRNG: recover state from outputs, timestamp seeds, MT19937 clone.
- Elliptic curves: invalid curve, small subgroup, nonce reuse, weak curve parameters.
- Lattices: approximate common divisor, knapsack, partial nonce leakage.

## Repro standard

- Solver script should print the final candidate and intermediate checks.

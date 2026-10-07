# Crypto CTF Recipes

Classify first: exact primitive, parameters, oracle, samples, and what is known.

Common attacks:

- RSA: small e broadcast, common modulus, shared primes, low private exponent, partial key exposure, padding oracle, textbook malleability.
- ECC: nonce reuse, weak curves, invalid curve, small subgroup, biased nonce, hidden number problem.
- XOR/stream: key reuse, crib dragging, known plaintext, repeating key, LFSR reconstruction.
- Block ciphers: ECB cut/paste, CBC bit flipping, padding oracle, IV/key reuse, CTR nonce reuse.
- Hash/signature: length extension, hash collision challenge, HMAC confusion, JWT none/HS-RS confusion.
- RNG: seed time, MT19937 clone, LCG recovery, modulo bias.
- Lattice: approximate common divisor, knapsack, partial nonce, Coppersmith hints.

Keep equations in a script. Verify by decrypting or reproducing the exact flag.

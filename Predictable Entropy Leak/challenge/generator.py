# Token server nonce emitter (public mechanism; seed is secret, not included).
#
# The server uses a standard Mersenne-Twister (MT19937) PRNG, exactly the one
# behind Python's `random` module. Each operational nonce is one 32-bit output:
#
#     rng = random.Random(SECRET_SEED)          # MT19937
#     nonces = [rng.getrandbits(32) for _ in range(624)]   # -> prng_stream.txt
#
# Immediately after those 624 nonces, the server seals its admin vault with a
# keystream drawn from the *same* generator (big-endian, 4 bytes per 32-bit
# word), XORed over the vault bytes:
#
#     ks = b""
#     while len(ks) < len(vault):
#         ks += rng.getrandbits(32).to_bytes(4, "big")
#     sealed = bytes(a ^ b for a, b in zip(vault, ks))      # -> sealed_vault.hex
#
# Only `prng_stream.txt` (the 624 nonces) and `sealed_vault.hex` are published.
import random

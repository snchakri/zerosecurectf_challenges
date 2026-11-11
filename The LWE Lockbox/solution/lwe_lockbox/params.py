"""Global constants and frozen challenge contract."""

N = 60
M = 140
Q = 10007
NOISE_MIN = -8
NOISE_MAX = 8

TRUE_FLAG = "ZeroSecure_CTF{z3r0_s3cur3_m4st3r_4rch1t3ct_pr0v3n}"

# SHA-256 of canonical master string built from six true fragments in slot order S1..S6.
TRUE_FRAGMENT_DIGEST = "905dd1b1f779b5714d363cf238b141bb548d1f4980500fab32f42a41f4eb3c39"

CORPUS_TEXT = (
    "Alice was beginning to get very tired of sitting by her sister on the bank, "
    "and of having nothing to do: once or twice she had peeped into the book her "
    "sister was reading, but it had no pictures or conversations in it. So she was "
    "considering in her own mind whether the pleasure of making a daisy-chain would "
    "be worth the trouble of getting up and picking the daisies."
)

CORE_SLOTS = ("S1", "S2", "S3", "S4", "S5", "S6")
RECOVERY_SLOT = "R"

DECOY_FLAGS = (
    "ZeroSecure_CTF{lattice_shadow_checkpoint}",
    "ZeroSecure_CTF{almost_noisefree_but_not_quite}",
    "ZeroSecure_CTF{crawler_bait_false_positive}",
    "ZeroSecure_CTF{rank_mirage_vector_mismatch}",
)

BOT_HINT_KEYWORDS = (
    "ai",
    "bot",
    "crawler",
    "autonomous",
    "agent",
    "policy",
    "llm",
    "chatgpt",
)

# Osint Event Trace — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Read `challenge/question.txt` and identify the indicated artifact.
2. Use the decoding or inspection method in the preserved pack notes.
3. Recover the flag from the supplied artifact. This older pack has no separate author solver.

**Verification:** original beginner artifacts retained; independent solution documented during archive review. Original event-only links may no longer respond.

## Archived solve

1. Open the event website named in the player question.
2. Find its LOCATION VECTOR/venue section and read the city.
3. Use the city in lowercase with the prescribed `part5_` prefix.

The local event-site source `zerosecure2_hero/content/samples/venue.json` identifies the venue as Nadergul, Hyderabad. That produces `ZeroSecure_CTF{part5_hyderabad}` for the preserved event context. This is a local archival inference; the old page was not revalidated live.

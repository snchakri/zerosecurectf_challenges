# Seccomp BPF Sandbox Policy Audit

**Category:** Miscellaneous

The sentries of Castle Doom run every petitioner's request through a gatekeeping
filter carved into the kernel itself: a classic Berkeley Packet Filter attached
as a seccomp policy. When a courier of CICADA3301 bribed a palace engineer, all
they could smuggle out was the raw filter image the kernel actually loads -- a
flat little array of eight-byte instruction words, no comments, no symbols.

Doom's quartermasters were careless about one thing. Instead of merely allowing
or killing each syscall, this policy answers *back*: for each request it recognises
it returns an "errno" value, and those returned values are not random. The filter
is a tiny machine that, probed in order, dribbles out a secret one byte at a time
-- but only after mangling each byte through arithmetic it recomputes on the fly.

**Download the attached file** and recover the flag.

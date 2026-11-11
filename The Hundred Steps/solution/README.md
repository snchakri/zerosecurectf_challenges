# The Hundred Steps — solution

1. Read `kernel.c`: task `i` waits on task `next[i]`.
2. Follow pointers from task zero until a task repeats. Rotate the resulting cycle to its smallest task: `0, 3, 12, 5, 10`.
3. The brief says that this ordered cycle determines the location and encoding of the hidden bytes in `boot.img`.

## Archive limitation

The archive preserves the kernel and image, but no sector layout, key derivation, or extraction implementation. The cycle is reproducible; decoding the image to the accepted answer was not verified.

`accepted_flags.txt` is the event scoring record, not a substitute for cryptographic recovery.

# Palimpsest

**Category:** Digital Forensics

A benign ZIP "hand-off" archive lists only four innocuous files, but its body holds extra local file headers the central directory never references; the flag is a DEFLATE-compressed frame split across those orphaned, unindexed records and reassembled via a residual CRC index.

**Download the attached file** and recover the flag.

# UART Hardware Logic Analyzer Trace

**Category:** Miscellaneous

Deep in the citadel's maintenance crawlspace, a CICADA3301 operative clipped a
logic-analyzer probe onto an unmarked debug header on one of Doom's service
boards. For a few hundred microseconds the single data line chattered, and the
probe faithfully dumped every rising and falling edge into a Value Change Dump.

No one labelled the line. No one wrote down the speed. But the pin never lies:
the edges carry an ordinary asynchronous serial transmission, and whatever the
board whispered to itself is sitting there in the timing, waiting for someone
patient enough to clock it out.

**Download the attached files** and recover the flag.

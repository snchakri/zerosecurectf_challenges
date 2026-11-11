# Dunderdome

**Category:** Miscellaneous

A Python expression sandbox screens your source for the literal sequence "__" and a deny-list of builtins, then eval's it under a restricted builtins table; escape by constructing the dunder names at runtime (chr + getattr), walking object.__subclasses__() to a class that still carries the real os globals, and reading the flag out of os.environ.

**Connect:** `nc <challenge-host> 30040`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.

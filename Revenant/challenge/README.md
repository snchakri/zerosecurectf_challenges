# Revenant

**Category:** Binary Exploitation

A toy in-memory "record manager" frees a record's heap chunk but keeps using the slot (use-after-free). Reclaim the freed chunk with a same-size-class raw note, overwrite the dangling record's handler function pointer with the address of win(), and invoke the record to disclose the env flag. No info leak (binary is -no-pie), no allocator-metadata corruption.

**Connect:** `nc <challenge-host> 30051`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.

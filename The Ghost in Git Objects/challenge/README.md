# The Ghost in Git Objects

**Category:** Digital Forensics

A developer committed a production private key to a repository, realized the mistake, executed `git reset --hard HEAD~1`, and force pushed. However, the raw object was not garbage collected from the local `.git` directory.

**Download the attached file** and recover the flag.

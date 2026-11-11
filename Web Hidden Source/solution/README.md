# Web Hidden Source — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Read `challenge/question.txt` and identify the indicated artifact.
2. Use the decoding or inspection method in the preserved pack notes.
3. Recover the flag from the supplied artifact. This older pack has no separate author solver.

**Verification:** original beginner artifacts retained; independent solution documented during archive review. Original event-only links may no longer respond.

## Concrete solve

1. Inspect the HTML source and referenced JavaScript files.
2. Search those files for the flag prefix; the hidden content is delivered to the browser with the public site.

```bash
python solution/solve.py
```

The JavaScript comment contains a Base64 token. Decode `WmVyb1NlY3VyZV9DVEZ7cGFydDJfc291cmNlX3NlY3JldH0=` to recover the real answer; literal `{...}` strings in the question are format examples.

#!/usr/bin/env python3
"""
Real solver for misc_07_regex_crossword_hexagonal.

Reads ONLY dist/crossword_patterns.json : a hexagonal (three-axis) regular-
expression crossword. Every cell lies on three lines -- a row, a column and a
'\'-diagonal -- and each line is constrained by a regex that the whole line
string must fully match. Exactly one grid satisfies all constraints; its rows,
read top-to-bottom, spell the flag.

Approach:
  * a small regex engine compiles each pattern to a Thompson NFA over the
    puzzle alphabet (supports char classes with ranges and negation, '.',
    concatenation, alternation, grouping and *,+,?,{m},{m,n} quantifiers;
    leading ^ / trailing $ are treated as a full-match anchor);
  * the crossword is solved as a constraint-satisfaction problem with
    backtracking + forward checking. For a line with some cells fixed and the
    rest free, an NFA reachability pass decides whether any completion still
    matches, which prunes the search immediately.

Does not contain the flag and never reads the ./flag file.
"""
import argparse
import json
import os
import sys


# --------------------------------------------------------------------------- #
#  regex -> NFA
# --------------------------------------------------------------------------- #
class Node:
    pass


class Parser:
    def __init__(self, pattern, alphabet):
        # strip full-match anchors
        if pattern.startswith("^"):
            pattern = pattern[1:]
        if pattern.endswith("$"):
            pattern = pattern[:-1]
        self.s = pattern
        self.i = 0
        self.alphabet = set(alphabet)

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else None

    def next(self):
        c = self.s[self.i]
        self.i += 1
        return c

    def parse(self):
        node = self.parse_alt()
        assert self.i == len(self.s), f"trailing input at {self.i}: {self.s!r}"
        return node

    def parse_alt(self):
        branches = [self.parse_concat()]
        while self.peek() == "|":
            self.next()
            branches.append(self.parse_concat())
        if len(branches) == 1:
            return branches[0]
        return ("alt", branches)

    def parse_concat(self):
        items = []
        while self.peek() is not None and self.peek() not in "|)":
            items.append(self.parse_repeat())
        if len(items) == 1:
            return items[0]
        return ("concat", items)

    def parse_repeat(self):
        atom = self.parse_atom()
        c = self.peek()
        if c == "*":
            self.next(); return ("star", atom)
        if c == "+":
            self.next(); return ("plus", atom)
        if c == "?":
            self.next(); return ("opt", atom)
        if c == "{":
            self.next()
            num = ""
            while self.peek() is not None and self.peek() != "}" and self.peek() != ",":
                num += self.next()
            m = int(num)
            n = m
            if self.peek() == ",":
                self.next()
                num2 = ""
                while self.peek() is not None and self.peek() != "}":
                    num2 += self.next()
                n = int(num2) if num2 else None
            assert self.next() == "}"
            return ("rep", atom, m, n)
        return atom

    def parse_atom(self):
        c = self.peek()
        if c == "(":
            self.next()
            node = self.parse_alt()
            assert self.next() == ")"
            return node
        if c == "[":
            return self.parse_class()
        if c == ".":
            self.next()
            return ("set", frozenset(self.alphabet))
        if c == "\\":
            self.next()
            lit = self.next()
            return ("set", frozenset([lit]))
        # literal
        lit = self.next()
        return ("set", frozenset([lit]))

    def parse_class(self):
        assert self.next() == "["
        negate = False
        if self.peek() == "^":
            self.next()
            negate = True
        chars = set()
        first = True
        while self.peek() != "]" or first:
            first = False
            ch = self.next()
            if ch == "\\":
                ch = self.next()
                chars.add(ch)
                continue
            # range a-b (not when '-' is last before ])
            if self.peek() == "-" and self.i + 1 < len(self.s) and self.s[self.i + 1] != "]":
                self.next()  # consume '-'
                end = self.next()
                for o in range(ord(ch), ord(end) + 1):
                    chars.add(chr(o))
            else:
                chars.add(ch)
        assert self.next() == "]"
        if negate:
            chars = set(self.alphabet) - chars
        return ("set", frozenset(chars))


# NFA as list of states; each state: dict with 'eps':[idx], 'trans':[(frozenset,idx)]
class NFA:
    def __init__(self):
        self.states = []

    def new(self):
        self.states.append({"eps": [], "trans": []})
        return len(self.states) - 1


def build_nfa(node, alphabet):
    nfa = NFA()

    def build(n):
        """Return (start, accept) state indices for sub-expression n."""
        typ = n[0]
        if typ == "set":
            s = nfa.new(); a = nfa.new()
            nfa.states[s]["trans"].append((n[1], a))
            return s, a
        if typ == "concat":
            parts = n[1]
            s = nfa.new()
            cur = s
            for p in parts:
                ps, pa = build(p)
                nfa.states[cur]["eps"].append(ps)
                cur = pa
            return s, cur
        if typ == "alt":
            s = nfa.new(); a = nfa.new()
            for b in n[1]:
                bs, ba = build(b)
                nfa.states[s]["eps"].append(bs)
                nfa.states[ba]["eps"].append(a)
            return s, a
        if typ == "star":
            s = nfa.new(); a = nfa.new()
            bs, ba = build(n[1])
            nfa.states[s]["eps"] += [bs, a]
            nfa.states[ba]["eps"] += [bs, a]
            return s, a
        if typ == "plus":
            bs, ba = build(n[1])
            a = nfa.new()
            nfa.states[ba]["eps"] += [bs, a]
            return bs, a
        if typ == "opt":
            s = nfa.new(); a = nfa.new()
            bs, ba = build(n[1])
            nfa.states[s]["eps"] += [bs, a]
            nfa.states[ba]["eps"].append(a)
            return s, a
        if typ == "rep":
            _, m, n2 = n[1], n[2], n[3]
            atom = n[1]
            s = nfa.new()
            cur = s
            for _ in range(m):
                bs, ba = build(atom)
                nfa.states[cur]["eps"].append(bs)
                cur = ba
            if n2 is None:  # {m,} -> m copies then star
                bs, ba = build(atom)
                nfa.states[cur]["eps"].append(bs)
                nfa.states[ba]["eps"].append(bs)
                a = nfa.new()
                nfa.states[cur]["eps"].append(a)
                nfa.states[ba]["eps"].append(a)
                return s, a
            a = nfa.new()
            nfa.states[cur]["eps"].append(a)
            for _ in range(n2 - m):
                bs, ba = build(atom)
                nfa.states[cur]["eps"].append(bs)
                nfa.states[ba]["eps"].append(a)
                cur = ba
            return s, a
        raise ValueError(typ)

    start, accept = build(node)
    return nfa, start, accept


def eps_closure(nfa, states):
    stack = list(states)
    seen = set(states)
    while stack:
        s = stack.pop()
        for e in nfa.states[s]["eps"]:
            if e not in seen:
                seen.add(e)
                stack.append(e)
    return seen


class Line:
    def __init__(self, pattern, cells, alphabet):
        node = Parser(pattern, alphabet).parse()
        self.nfa, self.start, self.accept = build_nfa(node, alphabet)
        self.cells = cells      # list of global cell ids, in order

    def feasible(self, assign, domains):
        """True if some completion of this line matches the regex."""
        cur = eps_closure(self.nfa, {self.start})
        for cell in self.cells:
            allowed = {assign[cell]} if cell in assign else domains[cell]
            nxt = set()
            for s in cur:
                for (symset, t) in self.nfa.states[s]["trans"]:
                    if symset & allowed:
                        nxt.add(t)
            if not nxt:
                return False
            cur = eps_closure(self.nfa, nxt)
        return self.accept in cur


# --------------------------------------------------------------------------- #
#  crossword solver
# --------------------------------------------------------------------------- #
def solve_obj(obj, max_solutions=2):
    rows = obj["grid"]["rows"]
    cols = obj["grid"]["cols"]
    alphabet = list(obj["alphabet"])

    def cid(r, c):
        return r * cols + c

    lines = []
    cell_lines = {}
    for ln in obj["lines"]:
        cells = [cid(r, c) for (r, c) in ln["cells"]]
        line = Line(ln["pattern"], cells, alphabet)
        lines.append(line)
        for cell in cells:
            cell_lines.setdefault(cell, []).append(line)

    ncells = rows * cols
    domains = {i: set(alphabet) for i in range(ncells)}
    order = list(range(ncells))
    assign = {}
    solutions = []

    def backtrack(idx):
        if len(solutions) >= max_solutions:
            return
        if idx == len(order):
            solutions.append(dict(assign))
            return
        cell = order[idx]
        for ch in sorted(domains[cell]):
            assign[cell] = ch
            ok = True
            for line in cell_lines.get(cell, []):
                if not line.feasible(assign, domains):
                    ok = False
                    break
            if ok:
                backtrack(idx + 1)
            del assign[cell]
            if len(solutions) >= max_solutions:
                return

    backtrack(0)

    results = []
    for sol in solutions:
        grid = [[sol[cid(r, c)] for c in range(cols)] for r in range(rows)]
        flag = "".join("".join(row) for row in grid)
        results.append(flag)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    with open(os.path.join(args.dist, "crossword_patterns.json"), "r", encoding="utf-8") as f:
        obj = json.load(f)
    results = solve_obj(obj, max_solutions=2)
    if len(results) != 1:
        sys.stderr.write(f"expected a unique solution, found {len(results)}\n")
        sys.exit(2)
    print(results[0])


if __name__ == "__main__":
    main()

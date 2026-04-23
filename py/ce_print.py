#!/usr/bin/env python3
import re
import sys
from pathlib import Path


def split_outputs(s: str):
    s = s.strip()
    if not s:
        return []
    return s.split()


def parse_refinement_blocks(text: str):
    lines = text.splitlines()
    i = 0
    blocks = []

    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("Refinement CE:"):
            ce = line[len("Refinement CE:"):].strip()

            i += 1
            sul = ""
            hyp = ""

            # Parse SUL Response (can span multiple lines)
            if i < len(lines) and lines[i].strip().startswith("SUL Response:"):
                sul = lines[i].strip()[len("SUL Response:"):].strip()
                i += 1
                while i < len(lines):
                    cur = lines[i].strip()
                    if cur.startswith("HYP Response:"):
                        break
                    if cur.startswith("(") and "New State:" in cur:
                        break
                    if cur.startswith("Refinement CE:"):
                        break
                    sul += (" " if sul else "") + cur
                    i += 1

            # Parse HYP Response (can span multiple lines)
            if i < len(lines) and lines[i].strip().startswith("HYP Response:"):
                hyp = lines[i].strip()[len("HYP Response:"):].strip()
                i += 1
                while i < len(lines):
                    cur = lines[i].strip()
                    if cur.startswith("(") and "New State:" in cur:
                        break
                    if cur.startswith("Refinement CE:"):
                        break
                    hyp += (" " if hyp else "") + cur
                    i += 1

            blocks.append((ce, sul, hyp))
            continue

        i += 1

    return blocks


def print_block_table(idx, ce, sul, hyp):
    inputs = ce.split()
    sul_out = split_outputs(sul)
    hyp_out = split_outputs(hyp)

    n = max(len(inputs), len(sul_out), len(hyp_out))

    # pad
    inputs += [""] * (n - len(inputs))
    sul_out += [""] * (n - len(sul_out))
    hyp_out += [""] * (n - len(hyp_out))

    rows = []
    mismatches = 0
    for k in range(n):
        ok = sul_out[k] == hyp_out[k]
        if not ok:
            mismatches += 1
        rows.append((
            str(k + 1),
            inputs[k],
            sul_out[k],
            hyp_out[k],
            "OK" if ok else "DIFF",
        ))

    widths = [
        max(len(r[c]) for r in ([("Step", "Input", "SUL", "HYP", "Cmp")] + rows))
        for c in range(5)
    ]

    def fmt_row(r):
        return " | ".join(r[c].ljust(widths[c]) for c in range(5))

    print("=" * 120)
    print(f"Refinement block #{idx}")
    print(f"Inputs: {len(ce.split())}, SUL outputs: {len(split_outputs(sul))}, HYP outputs: {len(split_outputs(hyp))}, mismatches: {mismatches}")
    print("-" * 120)
    print(fmt_row(("Step", "Input", "SUL", "HYP", "Cmp")))
    print("-" * 120)
    for r in rows:
        print(fmt_row(r))
    print()


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <logfile>")
        sys.exit(1)

    path = Path(sys.argv[1])
    text = path.read_text(encoding="utf-8", errors="replace")

    blocks = parse_refinement_blocks(text)
    if not blocks:
        print("No refinement blocks found.")
        sys.exit(0)

    for idx, (ce, sul, hyp) in enumerate(blocks, 1):
        print_block_table(idx, ce, sul, hyp)


if __name__ == "__main__":
    main()

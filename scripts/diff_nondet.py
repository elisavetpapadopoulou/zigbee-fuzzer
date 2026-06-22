#!/usr/bin/env python3
from pathlib import Path
import sys


def parse_nondet_log(path: Path):
    text = path.read_text(errors="replace").splitlines()

    test_inputs = None
    output_runs = []

    for line in text:
        line = line.strip()

        if line.startswith("Test:"):
            test_inputs = line.removeprefix("Test:").strip().split()

        elif "times outputs:" in line:
            # Example:
            # 1 times outputs: EMPTYRESPONSE EMPTYRESPONSE ...
            outputs_part = line.split("times outputs:", 1)[1].strip()
            output_runs.append(outputs_part.split())

    if not test_inputs:
        raise ValueError("Could not find 'Test:' line in nondet log.")

    if not output_runs:
        raise ValueError("Could not find any 'times outputs:' lines in nondet log.")

    return test_inputs, output_runs


def mark_diff(values):
    unique = set(values)
    if len(unique) <= 1:
        return " "
    return "*"


def print_table(inputs, runs):
    max_rows = len(inputs)

    for i, run in enumerate(runs, start=1):
        if len(run) != max_rows:
            print(
                f"[WARN] Run {i} has {len(run)} outputs, "
                f"but test has {max_rows} inputs."
            )

    headers = ["#", "Input"] + [f"Run {i}" for i in range(1, len(runs) + 1)] + ["Diff?"]

    rows = []
    for idx, inp in enumerate(inputs):
        values = []
        for run in runs:
            values.append(run[idx] if idx < len(run) else "<MISSING>")

        rows.append([str(idx + 1), inp] + values + [mark_diff(values)])

    widths = [
        max(len(str(row[col])) for row in [headers] + rows)
        for col in range(len(headers))
    ]

    def fmt(row):
        return " | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))

    print(fmt(headers))
    print("-+-".join("-" * w for w in widths))

    for row in rows:
        print(fmt(row))


def print_diff_summary(inputs, runs):
    print("\nDifferent steps:")
    found = False

    for idx, inp in enumerate(inputs):
        values = [run[idx] if idx < len(run) else "<MISSING>" for run in runs]
        unique = sorted(set(values))

        if len(unique) > 1:
            found = True
            print(f"\nStep {idx + 1}: {inp}")
            for i, value in enumerate(values, start=1):
                print(f"  Run {i}: {value}")

    if not found:
        print("  None. All runs match.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python compare_nondet.py experiments/results/hardware_trial/nondet.log")
        sys.exit(1)

    path = Path(sys.argv[1])
    inputs, runs = parse_nondet_log(path)

    print_table(inputs, runs)
    print_diff_summary(inputs, runs)


if __name__ == "__main__":
    main()

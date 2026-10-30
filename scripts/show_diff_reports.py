#!/usr/bin/env python3

import argparse
import difflib
import sys
from pathlib import Path

SIMULATION_REPORT_MARKER = "** Simulation Report **"
REVENUE_REPORT_MARKER = "** Revenue Report **"


class Color:
    RED = "\033[31m"
    GREEN = "\033[32m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"{code}{text}{self.RESET}"

    def red(self, text):
        return self.wrap(self.RED, text)

    def green(self, text):
        return self.wrap(self.GREEN, text)

    def bold(self, text):
        return self.wrap(self.BOLD, text)


def extract_section(text: str, start_marker: str, end_marker: str = None):
    """Returns the text from start_marker to end_marker (or to the end of text if end_marker
    is None or not found after start_marker), or None if start_marker itself isn't present."""
    idx = text.find(start_marker)
    if idx == -1:
        return None
    section = text[idx:]
    if end_marker:
        end_idx = section.find(end_marker)
        if end_idx != -1:
            section = section[:end_idx]
    return section


def unified_section_diff(attempt_section, baseline_section, label, c: Color):
    lines = list(
        difflib.unified_diff(
            attempt_section.splitlines(),
            baseline_section.splitlines(),
            fromfile=f"attempt ({label})",
            tofile=f"baseline ({label})",
            lineterm="",
        )
    )
    out = []
    for line in lines:
        if line.startswith("+"):
            out.append(c.green(line))
        elif line.startswith("-"):
            out.append(c.red(line))
        else:
            out.append(line)
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt")
    parser.add_argument("baseline")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    c = Color(enabled=not args.no_color and sys.stdout.isatty())

    attempt_text = Path(args.attempt).read_text()
    baseline_text = Path(args.baseline).read_text()

    attempt_sim = extract_section(attempt_text, SIMULATION_REPORT_MARKER, REVENUE_REPORT_MARKER)
    baseline_sim = extract_section(baseline_text, SIMULATION_REPORT_MARKER, REVENUE_REPORT_MARKER)

    print()
    print(c.bold("=== Simulation Report diff ==="))
    if attempt_sim is None or baseline_sim is None:
        missing = [name for name, sim in (("attempt", attempt_sim), ("baseline", baseline_sim)) if sim is None]
        print(f"No {SIMULATION_REPORT_MARKER!r} section found in: {', '.join(missing)} - skipping this diff.\n")
    elif attempt_sim == baseline_sim:
        print(c.green("Simulation Report sections are identical.\n"))
    else:
        print(unified_section_diff(attempt_sim, baseline_sim, "Simulation Report", c))

    attempt_rev = extract_section(attempt_text, REVENUE_REPORT_MARKER)
    baseline_rev = extract_section(baseline_text, REVENUE_REPORT_MARKER)

    print(c.bold("=== Revenue Report diff ==="))
    if attempt_rev is None or baseline_rev is None:
        missing = [name for name, rev in (("attempt", attempt_rev), ("baseline", baseline_rev)) if rev is None]
        print(f"No {REVENUE_REPORT_MARKER!r} section found in: {', '.join(missing)} - skipping this diff.")
    elif attempt_rev == baseline_rev:
        print(c.green("Revenue Report sections are identical."))
    else:
        print(unified_section_diff(attempt_rev, baseline_rev, "Revenue Report", c))
    print()


if __name__ == "__main__":
    main()

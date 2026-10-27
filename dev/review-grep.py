#!/usr/bin/env python3
"""review-grep — the manual-review grep sweep as a standalone script.

The patterns and the sweep live in `squawk.checklist` (so the `squawk greps`
subcommand and the Checklist page share them); this is a thin wrapper for
running it straight from a checkout. Prefer `squawk greps DIR [AREA]`.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from squawk.checklist import grep_sweep


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write("usage: review-grep.py DIR [AREA]\n")
        return 2
    target, area = argv[0], (" ".join(argv[1:]) or None)
    if not os.path.isdir(target):
        sys.stderr.write("not a directory: %s\n" % target)
        return 2
    total = 0
    for name, hits in grep_sweep(target, area):
        total += len(hits)
        print("\n=== %s ===" % name)
        if not hits:
            print("  (no hits — read the code anyway)")
            continue
        last = None
        for label, rel, line_no, text in hits:
            if label != last:
                print("  * %s" % label)
                last = label
            print("    %s:%d: %s" % (rel, line_no, text))
    print("\n%d line(s) to look at. A hit is a place to LOOK, not a finding." % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())

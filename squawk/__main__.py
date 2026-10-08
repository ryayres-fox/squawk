"""`python3 -m squawk`, and `python3 squawk` from the directory above.

Running the package directory by path (`python3 squawk`) puts that directory
itself on sys.path, not its parent, so `from squawk.cli import main` failed with
`ModuleNotFoundError: No module named 'squawk'`. A dropped `.py` is an easy
thing to type and the traceback named nothing useful, so the parent goes on the
path first and both spellings work.
"""

import os
import sys

_PKG = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_PKG)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from squawk.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

"""Make the squawk package importable under pytest from any working
directory, so the tests import the package the app runs as.

The suites sit in `tests/` and the package sits beside that directory, at the
root of the checkout, which is what goes on the path."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

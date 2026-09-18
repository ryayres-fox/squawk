#!/usr/bin/env python3
"""Squawk's entry point. The code lives in the squawk/ package beside this file;
this keeps `python3 squawk.py ...` working exactly as it always has, and re-exports
the package for anything that imports this file."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from squawk import *  # noqa: F403
from squawk import __version__, main  # noqa: F401

if __name__ == "__main__":
    sys.exit(main())

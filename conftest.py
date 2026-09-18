"""Make the squawk package beside this file importable under pytest from any
working directory, so the tests import the package the app runs as."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

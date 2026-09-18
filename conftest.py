"""
Pytest configuration — makes the repo root importable as `leo_sentinel` so
tests/ doesn't need a packaging layer just to reach the script.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

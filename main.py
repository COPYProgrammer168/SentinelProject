"""Convenience entry point for Sentinel from project root."""

from __future__ import annotations
import sys
from pathlib import Path

# Ensure workspace root is in sys.path
root_dir = str(Path(__file__).resolve().parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from sentinel.main import main

if __name__ == "__main__":
    main()

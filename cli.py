#!/usr/bin/env python3
"""Compatibility wrapper for local development.

Prefer: python -m auditor ... or supply-chain-auditor ...
"""

from auditor.cli import main

if __name__ == "__main__":
    main()

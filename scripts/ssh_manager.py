# -*- coding: utf-8 -*-
"""Compatibility shim.

The implementation lives in the ``ssh_manager`` package next to this file.
The historical invocation keeps working unchanged:

    python scripts/ssh_manager.py <command> ...

``python -m ssh_manager`` (run from ``scripts/``) works too.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssh_manager.cli import main  # noqa: E402

if __name__ == "__main__":
    main()

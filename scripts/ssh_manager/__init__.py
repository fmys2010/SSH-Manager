# -*- coding: utf-8 -*-
"""Persistent SSH session manager (daemon + CLI).

This package holds the implementation; ``scripts/ssh_manager.py`` is a thin
compatibility shim so the historical command line keeps working:

    python scripts/ssh_manager.py <command> ...
"""

from .config import VERSION

__all__ = ["VERSION"]

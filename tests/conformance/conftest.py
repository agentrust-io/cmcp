"""
Conformance test conftest.

Ensures the worktree's src/ directory takes precedence over any installed
editable package, so tests exercise the code in this branch.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Insert worktree src/ at the front of sys.path so imports resolve to this
# branch's code rather than the installed editable package.
_src = str(Path(__file__).parent.parent.parent / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

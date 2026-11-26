"""Pytest configuration.

The application module exposes ``app = create_app()`` for uvicorn. Point that
import-time app at a temporary database so test runs do not create ./data.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TEST_RUNTIME = Path(tempfile.mkdtemp(prefix="signing-backend-pytest-"))
os.environ.setdefault("SIGNING_DB_PATH", str(_TEST_RUNTIME / "import-time-app.db"))

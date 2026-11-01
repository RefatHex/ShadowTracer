"""Phase 5.6 Item 4: shadowtracer/VERSION was unused anywhere until now
(docs/design/VERSIONING.md) - read once at import time, "unknown" if
missing rather than failing startup over a display string. Its own module
so both main.py (FastAPI app version) and routers/health.py (the
/health response) can import it without main.py<->health.py importing
each other.
"""

import os

_VERSION_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "..", "VERSION")
try:
    with open(_VERSION_FILE) as _f:
        VERSION = _f.read().strip()
except OSError:
    VERSION = "unknown"

from __future__ import annotations

import sys
from pathlib import Path

# Allow the backend package to import cloud-level modules such as Decoder.
CLOUD_ROOT = Path(__file__).resolve().parents[2]
if str(CLOUD_ROOT) not in sys.path:
    sys.path.insert(0, str(CLOUD_ROOT))
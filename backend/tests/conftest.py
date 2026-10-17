"""
PraHari test configuration.

Also isolates the suite from the operational database. The default database
path now resolves to the project root, which is where real collected
telemetry lives; without this override, importing the app during tests would
open — and run schema migrations against — the operator's live data.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# Point every test at a throwaway database BEFORE app.core.config is imported,
# since the config object is cached for the process lifetime.
_TEST_DB_DIR = tempfile.mkdtemp(prefix="prahari_tests_")
os.environ.setdefault(
    "PRAHARI_DATABASE_URL",
    f"sqlite:///{Path(_TEST_DB_DIR) / 'prahari_test_session.db'}",
)
# Experiment manifests likewise: the default is <repo>/experiments, which
# holds real manifests. Tests that capture one used to write it there
# (ADR-074).
os.environ.setdefault(
    "PRAHARI_EXPERIMENTS_DIR",
    str(Path(_TEST_DB_DIR) / "experiments"),
)


def pytest_sessionfinish(session, exitstatus):
    """Remove the throwaway database directory after the run."""
    import shutil

    shutil.rmtree(_TEST_DB_DIR, ignore_errors=True)

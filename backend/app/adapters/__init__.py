"""
PraHari Adapters Package

Pluggable telemetry adapters mapping heterogeneous sources into canonical NormalizedEvents.
"""

from app.adapters.base import BaseTelemetryAdapter, AdapterHealth
from app.adapters.csv_import import (
    CsvImportAdapter,
    import_csv_file,
    import_csv_string,
    validate_and_normalize_row,
)
from app.adapters.json_stream import JsonStreamAdapter
from app.adapters.synthetic_replay import SyntheticFlowGenerator

__all__ = [
    "BaseTelemetryAdapter",
    "AdapterHealth",
    "CsvImportAdapter",
    "import_csv_file",
    "import_csv_string",
    "validate_and_normalize_row",
    "JsonStreamAdapter",
    "SyntheticFlowGenerator",
]

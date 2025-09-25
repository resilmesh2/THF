"""
DEPRECATED: Use functions._shared.time_parser instead
This module has been moved to functions._shared.time_parser for system-wide use
"""
# Import from the new shared location for backward compatibility
from .._shared.time_parser import (
    parse_time_to_opensearch,
    build_time_range_filter,
    build_single_time_range_filter
)
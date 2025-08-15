"""
Anomaly detection functions for Wazuh SIEM data
"""

from .detect_threshold import execute as execute_threshold
from old.detect_pattern import execute as execute_pattern
from .detect_behavioral import execute as execute_behavioral
from .detect_trend import execute as execute_trend

__all__ = [
    "execute_threshold",
    "execute_pattern", 
    "execute_behavioral",
    "execute_trend"
]
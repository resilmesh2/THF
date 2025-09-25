"""
Comprehensive time parsing utilities for all Wazuh functions - System-wide temporal parsing
"""
import re
from datetime import datetime, date, timedelta
from typing import Dict, Any


def parse_time_to_opensearch(time_str: str) -> str:
    """Convert natural language time strings to OpenSearch-compatible format

    Supports comprehensive temporal patterns including:
    - Numeric: "3 hours ago", "2 days ago"
    - Text numbers: "three hours ago", "two days ago"
    - Natural: "yesterday", "an hour ago", "half an hour ago"
    - Relative: "12h", "3d", "1w"
    - Common phrases: "last night", "this morning", "today"
    """

    if not time_str:
        return "now"

    # Normalize input
    time_str = time_str.lower().strip()

    # Text number to digit mapping
    text_numbers = {
        'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4', 'five': '5',
        'six': '6', 'seven': '7', 'eight': '8', 'nine': '9', 'ten': '10',
        'eleven': '11', 'twelve': '12', 'thirteen': '13', 'fourteen': '14', 'fifteen': '15',
        'sixteen': '16', 'seventeen': '17', 'eighteen': '18', 'nineteen': '19', 'twenty': '20',
        'thirty': '30', 'forty': '40', 'fifty': '50', 'sixty': '60',
        'a': '1', 'an': '1', 'half': '0.5'
    }

    # Replace text numbers with digits
    for word, digit in text_numbers.items():
        time_str = re.sub(rf'\b{word}\b', digit, time_str)

    # Handle special cases first
    special_cases = {
        'now': 'now',
        'yesterday': 'now-1d',
        'last night': 'now-12h',
        'this morning': 'now-6h',
        'today': 'now-1h',
        'an hour ago': 'now-1h',
        'half an hour ago': 'now-30m',
        'a minute ago': 'now-1m',
        'just now': 'now-1m'
    }

    if time_str in special_cases:
        return special_cases[time_str]

    # Enhanced relative time patterns with comprehensive coverage
    patterns = [
        # Numeric + unit + ago patterns
        (r'^(\d+(?:\.\d+)?)h ago$', lambda m: f"now-{int(float(m.group(1)))}h"),
        (r'^(\d+(?:\.\d+)?) hours? ago$', lambda m: f"now-{int(float(m.group(1)))}h"),
        (r'^(\d+(?:\.\d+)?)m ago$', lambda m: f"now-{int(float(m.group(1)))}m"),
        (r'^(\d+(?:\.\d+)?) minutes? ago$', lambda m: f"now-{int(float(m.group(1)))}m"),
        (r'^(\d+(?:\.\d+)?)d ago$', lambda m: f"now-{int(float(m.group(1)))}d"),
        (r'^(\d+(?:\.\d+)?) days? ago$', lambda m: f"now-{int(float(m.group(1)))}d"),
        (r'^(\d+(?:\.\d+)?)w ago$', lambda m: f"now-{int(float(m.group(1)))}w"),
        (r'^(\d+(?:\.\d+)?) weeks? ago$', lambda m: f"now-{int(float(m.group(1)))}w"),
        (r'^(\d+(?:\.\d+)?)s ago$', lambda m: f"now-{int(float(m.group(1)))}s"),
        (r'^(\d+(?:\.\d+)?) seconds? ago$', lambda m: f"now-{int(float(m.group(1)))}s"),

        # Short format without "ago"
        (r'^(\d+(?:\.\d+)?)h$', lambda m: f"now-{int(float(m.group(1)))}h"),
        (r'^(\d+(?:\.\d+)?)m$', lambda m: f"now-{int(float(m.group(1)))}m"),
        (r'^(\d+(?:\.\d+)?)d$', lambda m: f"now-{int(float(m.group(1)))}d"),
        (r'^(\d+(?:\.\d+)?)w$', lambda m: f"now-{int(float(m.group(1)))}w"),
        (r'^(\d+(?:\.\d+)?)s$', lambda m: f"now-{int(float(m.group(1)))}s"),

        # "Past X" patterns
        (r'^past (\d+(?:\.\d+)?) hours?$', lambda m: f"now-{int(float(m.group(1)))}h"),
        (r'^past (\d+(?:\.\d+)?) days?$', lambda m: f"now-{int(float(m.group(1)))}d"),
        (r'^past (\d+(?:\.\d+)?) weeks?$', lambda m: f"now-{int(float(m.group(1)))}w"),

        # "Last X" patterns
        (r'^last (\d+(?:\.\d+)?) hours?$', lambda m: f"now-{int(float(m.group(1)))}h"),
        (r'^last (\d+(?:\.\d+)?) days?$', lambda m: f"now-{int(float(m.group(1)))}d"),
        (r'^last (\d+(?:\.\d+)?) weeks?$', lambda m: f"now-{int(float(m.group(1)))}w"),

        # "Previous X" patterns
        (r'^previous (\d+(?:\.\d+)?) hours?$', lambda m: f"now-{int(float(m.group(1)))}h"),
        (r'^previous (\d+(?:\.\d+)?) days?$', lambda m: f"now-{int(float(m.group(1)))}d"),
    ]

    # Try each pattern
    for pattern, converter in patterns:
        match = re.match(pattern, time_str)
        if match:
            return converter(match)

    # Handle ISO datetime formats
    if 'T' in time_str or re.match(r'^\d{4}-\d{2}-\d{2}', time_str):
        return time_str

    # Handle simple date formats
    if re.match(r'^\d{4}-\d{2}-\d{2}$', time_str):
        return f"{time_str}T00:00:00"

    # Default fallback with warning
    import structlog
    logger = structlog.get_logger()
    logger.warning("Unrecognized time format, using default", time_str=time_str, default="now-1h")
    return "now-1h"


def build_time_range_filter(start_time: str, end_time: str) -> Dict[str, Any]:
    """Build time range filter for OpenSearch queries using enhanced parsing"""
    # Convert time-only formats to OpenSearch-compatible format
    parsed_start = parse_time_to_opensearch(start_time)
    parsed_end = parse_time_to_opensearch(end_time)

    return {
        "range": {
            "@timestamp": {
                "gte": parsed_start,
                "lte": parsed_end
            }
        }
    }


def build_single_time_range_filter(time_range: str) -> Dict[str, Any]:
    """Build single time range filter (e.g., 'past 3 hours') for OpenSearch queries"""
    parsed_time = parse_time_to_opensearch(time_range)

    return {
        "range": {
            "@timestamp": {
                "gte": parsed_time,
                "lte": "now"
            }
        }
    }
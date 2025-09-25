"""
Shared time parsing utilities for trace_timeline functions
"""
import re
from datetime import datetime, date, timedelta
from typing import Dict, Any


def parse_time_to_opensearch(time_str: str) -> str:
    """Convert time string to OpenSearch-compatible format"""

    if not time_str:
        return "now"

    # Handle relative time formats (preferred for OpenSearch)
    # Handle "12h ago", "6h ago", etc.
    hours_ago_pattern = r'^(\d+)h ago$'
    match = re.match(hours_ago_pattern, time_str)
    if match:
        hours = match.group(1)
        return f"now-{hours}h"

    # Handle "12 hours ago", "6 hours ago", etc.
    hours_ago_full_pattern = r'^(\d+) hours? ago$'
    match = re.match(hours_ago_full_pattern, time_str)
    if match:
        hours = match.group(1)
        return f"now-{hours}h"

    # Handle "2d ago", "3d ago", etc.
    days_ago_short_pattern = r'^(\d+)d ago$'
    match = re.match(days_ago_short_pattern, time_str)
    if match:
        days = match.group(1)
        return f"now-{days}d"

    # Handle "2 days ago", "3 days ago", etc.
    days_ago_full_pattern = r'^(\d+) days? ago$'
    match = re.match(days_ago_full_pattern, time_str)
    if match:
        days = match.group(1)
        return f"now-{days}d"

    # Handle "1w ago", "2w ago", etc.
    weeks_ago_short_pattern = r'^(\d+)w ago$'
    match = re.match(weeks_ago_short_pattern, time_str)
    if match:
        weeks = match.group(1)
        return f"now-{weeks}w"

    # Handle "a week ago", "2 weeks ago", etc.
    weeks_ago_full_pattern = r'^(?:a|(\d+)) weeks? ago$'
    match = re.match(weeks_ago_full_pattern, time_str)
    if match:
        weeks = match.group(1) if match.group(1) else "1"
        return f"now-{weeks}w"

    # If it's already a full datetime, return as-is
    if 'T' in time_str or re.match(r'^\d{4}-\d{2}-\d{2}', time_str):
        return time_str

    # Default to "now" for unrecognized formats
    return "now"


def build_time_range_filter(start_time: str, end_time: str) -> Dict[str, Any]:
    """Build time range filter for OpenSearch queries"""
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
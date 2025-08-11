"""
Generate stacked visualization data for Wazuh alerts
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate multi-dimensional stacked data structures optimized for dashboard visualizations
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Stacking parameters including stack_dimension, time_interval, etc.
        
    Returns:
        Stacked data structure optimized for dashboard visualization
    """
    try:
        # Extract parameters
        stack_dimension = params.get("stack_dimension", "severity")
        time_interval = params.get("time_interval", "1h")
        time_range = params.get("time_range", "24h")
        stack_limit = params.get("stack_limit", 10)
        cumulative = params.get("cumulative", False)
        secondary_dimension = params.get("secondary_dimension")
        
        logger.info("Executing stack alerts analysis", 
                   stack_dimension=stack_dimension,
                   time_interval=time_interval,
                   time_range=time_range,
                   stack_limit=stack_limit,
                   cumulative=cumulative)
        
        # Build PPL query based on stacking requirements
        ppl_query = build_stacking_ppl_query(
            stack_dimension, time_interval, time_range, stack_limit, secondary_dimension
        )
        
        # Execute PPL query
        response = await opensearch_client.execute_ppl_query(ppl_query)
        
        # Process and format results for dashboard consumption
        formatted_results = format_stacked_data(
            response, stack_dimension, time_interval, time_range, cumulative
        )
        
        logger.info("Stack alerts analysis completed",
                   total_time_buckets=len(formatted_results.get("stacked_data", [])),
                   stack_categories=len(formatted_results.get("stack_analysis", {}).get("stack_categories", [])))
        
        return formatted_results
        
    except Exception as e:
        logger.error("Stack alerts analysis failed", error=str(e))
        raise Exception(f"Failed to execute stack alerts analysis: {str(e)}")


def build_stacking_ppl_query(stack_dimension: str, time_interval: str, time_range: str, stack_limit: int, secondary_dimension: str = None) -> str:
    """Build PPL query for stacking based on dimension"""
    
    # Map dimensions to fields
    dimension_fields = {
        "severity": "rule.level",
        "hosts": "agent.name", 
        "rules": "rule.groups",
        "users": "data.win.eventdata.targetUserName",
        "ips": "data.srcip"
    }
    
    primary_field = dimension_fields.get(stack_dimension, "rule.level")
    
    # Convert time_range to PPL compatible format
    ppl_time_range = convert_to_ppl_timerange(time_range)
    
    if secondary_dimension:
        secondary_field = dimension_fields.get(secondary_dimension)
        ppl_query = f"""
        source = wazuh-alerts-*
        | where @timestamp >= {ppl_time_range}
        | stats count({primary_field}) BY {primary_field}, {secondary_field}
        | head {stack_limit}
        """.strip()
    else:
        ppl_query = f"""
        source = wazuh-alerts-*
        | where @timestamp >= {ppl_time_range}
        | stats count({primary_field}) BY {primary_field}
        | head {stack_limit}
        """.strip()
    
    return ppl_query


def convert_to_ppl_timerange(time_range: str) -> str:
    """Convert time range string to PPL compatible format"""
    from datetime import datetime, timedelta
    
    # Remove any whitespace
    time_range = time_range.strip()
    
    # Calculate the actual datetime instead of using interval syntax
    now = datetime.utcnow()
    
    if time_range.endswith('h'):
        hours = int(time_range[:-1])
        target_time = now - timedelta(hours=hours)
    elif time_range.endswith('d'):
        days = int(time_range[:-1])
        target_time = now - timedelta(days=days)
    elif time_range.endswith('m') and not time_range.endswith('min'):
        minutes = int(time_range[:-1])
        target_time = now - timedelta(minutes=minutes)
    elif time_range.endswith('min'):
        minutes = int(time_range[:-3])
        target_time = now - timedelta(minutes=minutes)
    elif time_range.endswith('w'):
        weeks = int(time_range[:-1])
        target_time = now - timedelta(weeks=weeks)
    else:
        # Default to 24 hours if format not recognized
        target_time = now - timedelta(hours=24)
    
    # Format as ISO timestamp for PPL
    return f"'{target_time.isoformat()}'"


def format_stacked_data(ppl_response: Dict[str, Any], stack_dimension: str, time_interval: str, time_range: str, cumulative: bool) -> Dict[str, Any]:
    """Format PPL response into dashboard-ready stacked structure"""
    
    # Process PPL grouped response
    schema = ppl_response.get('schema', [])
    datarows = ppl_response.get('datarows', [])
    
    if not schema or not datarows:
        return build_empty_stack_response(stack_dimension, time_interval, time_range)
    
    # For simple grouping: first column is the dimension, last column is count
    dimension_col = 0
    count_col = -1  # Last column is count
    
    stacked_data = []
    category_totals = {}
    total_alerts = 0
    
    # Process grouped data
    for row in datarows:
        category = row[dimension_col]
        count = row[count_col] if len(row) > abs(count_col) else 0
        
        if isinstance(count, (int, float)):
            count = int(count)
        else:
            count = 0
        
        # Map category name for better display
        display_name = map_category_name(category, stack_dimension)
        category_totals[display_name] = count
        total_alerts += count
    
    # Create a single time bucket since we don't have time-series data
    current_time = datetime.now().isoformat()
    
    stacked_data.append({
        "timestamp": current_time,
        "time_bucket": "Current Period",
        "stack_breakdown": category_totals,
        "total_alerts": total_alerts,
        "cumulative_total": total_alerts
    })
    
    # Stack categories are the mapped category names
    stack_categories = list(category_totals.keys())
    
    # Build complete response
    return build_complete_stack_response(
        stacked_data, stack_categories, stack_dimension, time_interval, time_range, category_totals
    )


def map_category_name(category: str, stack_dimension: str) -> str:
    """Map raw category values to display-friendly names"""
    
    if stack_dimension == "severity":
        severity_map = {
            "0": "Informational", "1": "Informational", "2": "Informational", "3": "Low",
            "4": "Low", "5": "Low", "6": "Medium", "7": "Medium", "8": "Medium",
            "9": "High", "10": "High", "11": "High", "12": "Critical",
            "13": "Critical", "14": "Critical", "15": "Critical"
        }
        return severity_map.get(str(category), f"Level-{category}")
    
    # For other dimensions, return as-is but truncated if too long
    if isinstance(category, str) and len(category) > 30:
        return category[:27] + "..."
    
    return str(category) if category is not None else "Unknown"


def format_time_bucket(timestamp: str, time_interval: str) -> str:
    """Format timestamp into readable time bucket"""
    try:
        if isinstance(timestamp, str):
            # Parse timestamp and create bucket label
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            if time_interval.endswith('h'):
                return dt.strftime("%H:%M")
            elif time_interval.endswith('d'):
                return dt.strftime("%m-%d")
            else:
                return dt.strftime("%H:%M")
    except:
        return str(timestamp)


def build_complete_stack_response(stacked_data: List[Dict], stack_categories: List[str], stack_dimension: str, time_interval: str, time_range: str, category_totals: Dict[str, int]) -> Dict[str, Any]:
    """Build the complete stacked response structure"""
    
    # Calculate summary statistics
    total_alerts = sum(bucket.get("total_alerts", 0) for bucket in stacked_data)
    peak_bucket = max(stacked_data, key=lambda x: x.get("total_alerts", 0)) if stacked_data else {}
    
    # Calculate category percentages
    category_percentages = {}
    if total_alerts > 0:
        for category, count in category_totals.items():
            category_percentages[category] = round((count / total_alerts) * 100, 1)
    
    # Determine dominant category
    dominant_category = max(category_totals.items(), key=lambda x: x[1])[0] if category_totals else "Unknown"
    
    # Map stack categories for display
    display_categories = [map_category_name(cat, stack_dimension) for cat in stack_categories]
    
    # Build visualization config
    visualization_config = build_visualization_config(display_categories, stack_dimension)
    
    return {
        "stack_analysis": {
            "stack_dimension": stack_dimension,
            "time_interval": time_interval,
            "analysis_period": time_range,
            "total_time_buckets": len(stacked_data),
            "stack_categories": display_categories,
            "total_alerts_analyzed": total_alerts
        },
        "stacked_data": stacked_data,
        "visualization_config": visualization_config,
        "stack_summary": {
            "peak_activity_time": peak_bucket.get("timestamp"),
            "peak_total": peak_bucket.get("total_alerts", 0),
            "dominant_category": dominant_category,
            "category_percentages": category_percentages,
            "temporal_distribution": "even" if len(set(b.get("total_alerts", 0) for b in stacked_data)) > len(stacked_data) * 0.7 else "clustered"
        }
    }


def build_visualization_config(stack_categories: List[str], stack_dimension: str) -> Dict[str, Any]:
    """Build visualization configuration for dashboard consumption"""
    
    # Define color palettes for different dimensions
    color_palettes = {
        "severity": ["#FF4444", "#FF8800", "#FFCC00", "#00CC00", "#00AAFF"],
        "hosts": ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf"],
        "rules": ["#3498db", "#e74c3c", "#2ecc71", "#f39c12", "#9b59b6", "#1abc9c", "#34495e", "#e67e22", "#95a5a6", "#f1c40f"],
        "users": ["#ff6b6b", "#4ecdc4", "#45b7d1", "#96ceb4", "#feca57", "#ff9ff3", "#54a0ff", "#5f27cd", "#00d2d3", "#ff9f43"],
        "ips": ["#6c5ce7", "#a29bfe", "#fd79a8", "#fdcb6e", "#6c5ce7", "#a29bfe", "#fd79a8", "#fdcb6e", "#00b894", "#00cec9"]
    }
    
    colors = color_palettes.get(stack_dimension, color_palettes["severity"])
    
    return {
        "chart_type": "stacked_bar",
        "x_axis": "timestamp",
        "y_axis": "alert_count",
        "stack_layers": stack_categories,
        "color_palette": colors[:len(stack_categories)],
        "dashboard_compatible": True,
        "opensearch_visualization": {
            "type": "histogram",
            "aggregation": "count",
            "interval": "auto"
        }
    }


def build_empty_stack_response(stack_dimension: str, time_interval: str, time_range: str) -> Dict[str, Any]:
    """Build empty response when no data is found"""
    
    return {
        "stack_analysis": {
            "stack_dimension": stack_dimension,
            "time_interval": time_interval,
            "analysis_period": time_range,
            "total_time_buckets": 0,
            "stack_categories": [],
            "total_alerts_analyzed": 0
        },
        "stacked_data": [],
        "visualization_config": {
            "chart_type": "stacked_bar",
            "x_axis": "timestamp",
            "y_axis": "alert_count",
            "stack_layers": [],
            "color_palette": []
        },
        "stack_summary": {
            "peak_activity_time": None,
            "peak_total": 0,
            "dominant_category": None,
            "category_percentages": {},
            "temporal_distribution": "no_data"
        }
    }
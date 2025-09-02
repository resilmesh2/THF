"""
OpenSearch client for Wazuh SIEM integration
"""
from opensearchpy import OpenSearch, AsyncOpenSearch, RequestsHttpConnection
from typing import Dict, Any, Optional, List
import structlog
from datetime import datetime, timedelta
import re
import asyncio

logger = structlog.get_logger()

class WazuhOpenSearchClient:
    """OpenSearch client specifically configured for Wazuh SIEM"""
    
    def __init__(self, host: str, port: int = 9200, auth: tuple = None, use_ssl: bool = True, verify_certs: bool = False):
        """
        Initialize OpenSearch client for Wazuh
        
        Args:
            host: OpenSearch host
            port: OpenSearch port (default: 9200)
            auth: Authentication tuple (username, password)
            use_ssl: Use SSL connection
            verify_certs: Verify SSL certificates
        """
        self.host = host
        self.port = port
        self.auth = auth
        
        # Configure async client
        self.client = AsyncOpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_auth=auth,
            use_ssl=use_ssl,
            verify_certs=verify_certs,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
            timeout=30,
            max_retries=3,
            retry_on_timeout=True
        )
        
        # Wazuh index patterns
        self.alerts_index = "wazuh-alerts-*"
        self.monitoring_index = "wazuh-monitoring-*"
        self.archives_index = "wazuh-archives-*"
        
        logger.info("OpenSearch client initialized", 
                   host=host, port=port, ssl=use_ssl)
        
    async def search(self, index: str, query: Dict[str, Any], size: int = 100) -> Dict[str, Any]:
        """
        Execute search query against OpenSearch
        
        Args:
            index: Index pattern to search
            query: OpenSearch query
            size: Maximum number of results
            
        Returns:
            Search results
        """
        try:
            query['size'] = size
            
            logger.debug("Executing search query",
                         index=index,
                         query_type=query.get('query', {}).get('bool', {}).get('must', []))
            
            response = await self.client.search(
                index=index,
                body=query
            )
            
            hits_total = response.get('hits', {}).get('total', {})
            if isinstance(hits_total, dict):
                total_count = hits_total.get('value', 0)
            else:
                total_count = hits_total
                
            logger.info("Search query executed successfully",
                        index=index,
                        hits=total_count,
                        returned=len(response.get('hits', {}).get('hits', [])))
            
            return response
            
        except Exception as e:
            logger.error("Search query failed",
                         error=str(e),
                         index=index,
                         query=query)
            raise

    async def count(self, index: str, query: Dict[str, Any]) -> Dict[str, Any]:
        """
        Count documents matching query
        
        Args:
            index: Index pattern
            query: OpenSearch query
            
        Returns:
            Count result
        """
        try:
            response = await self.client.count(
                index=index,
                body=query
            )
            
            logger.info("Count query executed",
                        index=index,
                        count=response.get('count', 0))
            
            return response
            
        except Exception as e:
            logger.error("Count query failed",
                         error=str(e),
                         index=index)
            raise

    async def get_indices(self) -> List[str]:
        """
        Get list of available Wazuh indices
        
        Returns:
            List of index names
        """
        try:
            response = await self.client.cat.indices(format='json')
            indices = [idx['index'] for idx in response if idx['index'].startswith('wazuh')]
            
            logger.info("Retrieved indices", count=len(indices))
            return indices
            
        except Exception as e:
            logger.error("Failed to get indices", error=str(e))
            raise

    def build_time_range_filter(self, time_range: str) -> Dict[str, Any]:
        """
        Convert time range string to OpenSearch query filter
        
        Args:
            time_range: Time range string (e.g., "7d", "24h", "30m", "2025-07-24T06:00:00 to 2025-07-24T09:00:00")
            
        Returns:
            OpenSearch time range filter
        """
        try:
            # Handle absolute time ranges with various formats
            if any(sep in time_range.lower() for sep in [" to ", " until ", "-"]):
                from datetime import datetime, date
                today = date.today().strftime("%Y-%m-%d")
                
                # Handle format: "today 06:00-09:00"
                if "today" in time_range.lower() and "-" in time_range:
                    # Extract the time part after "today"
                    time_part = time_range.lower().replace("today", "").strip()
                    if "-" in time_part:
                        parts = time_part.split("-")
                        if len(parts) == 2:
                            start_time = self._parse_time_expression(parts[0].strip(), today)
                            end_time = self._parse_time_expression(parts[1].strip(), today)
                            
                            logger.info("Parsed today time range with dash", 
                                       original_range=time_range,
                                       start_time=start_time, 
                                       end_time=end_time)
                            
                            return {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_time,
                                        "lte": end_time
                                    }
                                }
                            }
                
                # Handle format: "time to time" or "time until time"
                elif " to " in time_range.lower() or " until " in time_range.lower():
                    separator = " to " if " to " in time_range.lower() else " until "
                    parts = time_range.split(separator)
                    if len(parts) == 2:
                        start_time = parts[0].strip()
                        end_time = parts[1].strip()
                        
                        # Convert time expressions to ISO format
                        start_time = self._parse_time_expression(start_time, today)
                        end_time = self._parse_time_expression(end_time, today)
                        
                        logger.info("Parsed absolute time range", 
                                   original_range=time_range,
                                   start_time=start_time, 
                                   end_time=end_time)
                        
                        return {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time,
                                    "lte": end_time
                                }
                            }
                        }
            
            # Handle relative time ranges
            elif time_range.endswith('d'):
                days = int(time_range[:-1])
                gte = f"now-{days}d"
            elif time_range.endswith('h'):
                hours = int(time_range[:-1])
                gte = f"now-{hours}h"
            elif time_range.endswith('m'):
                minutes = int(time_range[:-1])
                gte = f"now-{minutes}m"
            elif time_range.endswith('s'):
                seconds = int(time_range[:-1])
                gte = f"now-{seconds}s"
            else:
                # Default to 24 hours if format not recognized
                gte = "now-24h"
                logger.warning("Unrecognized time range format, using default", 
                             time_range=time_range, default="24h")
                
            return {
                "range": {
                    "@timestamp": {
                        "gte": gte,
                        "lte": "now"
                    }
                }
            }
            
        except ValueError as e:
            logger.error("Invalid time range format", 
                        time_range=time_range, 
                        error=str(e))
            # Return default 24h range
            return {
                "range": {
                    "@timestamp": {
                        "gte": "now-24h",
                        "lte": "now"
                    }
                }
            }
    
    def _parse_time_expression(self, time_expr: str, date_str: str) -> str:
        """
        Convert time expression to ISO format
        
        Args:
            time_expr: Time expression like "6 am", "9 am", "06:00:00", etc.
            date_str: Date string in YYYY-MM-DD format
            
        Returns:
            ISO timestamp string
        """
        import re
        
        # Remove "today" and other date references
        time_expr = re.sub(r'\b(today|yesterday|tomorrow)\b', '', time_expr).strip()
        
        # Handle 24-hour format like "06:00:00"
        if re.match(r'^\d{2}:\d{2}:\d{2}$', time_expr):
            return f"{date_str}T{time_expr}"
        
        # Handle shorter 24-hour format like "06:00"
        if re.match(r'^\d{1,2}:\d{2}$', time_expr):
            return f"{date_str}T{time_expr}:00"
        
        # Parse time expressions like "6 am", "9 am", "2:30 pm"
        am_pm_pattern = r'(\d{1,2})(?::(\d{2}))?\s*(am|pm)'
        match = re.search(am_pm_pattern, time_expr.lower())
        
        if match:
            hour = int(match.group(1))
            minute = int(match.group(2)) if match.group(2) else 0
            am_pm = match.group(3)
            
            # Convert to 24-hour format
            if am_pm == 'pm' and hour != 12:
                hour += 12
            elif am_pm == 'am' and hour == 12:
                hour = 0
                
            return f"{date_str}T{hour:02d}:{minute:02d}:00"
        
        # If parsing fails, try to construct a basic timestamp
        logger.warning("Could not parse time expression, attempting basic format", 
                      time_expr=time_expr)
        return f"{date_str}T{time_expr}"

    def build_filters_query(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert filters dict to OpenSearch query filters with intelligent field detection
        
        Args:
            filters: Dictionary of field:value filters
            
        Returns:
            List of OpenSearch query filters
        """
        query_filters = []
        
        for field, value in filters.items():
            # Handle special process filtering with intelligent field detection
            if field in ["process", "process_name", "executable", "image", "command", "cmd", "binary"] and isinstance(value, str):
                # Use the same logic as build_entity_query for process names
                if ('\\' in value or '/' in value):
                    # Likely executable path
                    query_filters.append({
                        "wildcard": {"data.win.eventdata.image": f"*{value}*"}
                    })
                else:
                    # Process name - search across multiple Windows event fields
                    query_filters.append({
                        "bool": {
                            "should": [
                                {"wildcard": {"data.win.eventdata.image": f"*{value}*"}},
                                {"wildcard": {"data.win.eventdata.originalFileName": f"*{value}*"}},
                                {"wildcard": {"data.win.eventdata.commandLine": f"*{value}*"}},
                                {"wildcard": {"rule.description": f"*{value}*"}}
                            ],
                            "minimum_should_match": 1
                        }
                    })
            # Handle host filtering with intelligent field detection
            elif field in ["host", "host_id", "agent", "agent_id", "hostname", "agent_name"] and isinstance(value, str):
                import re
                # Check if value looks like an IP address
                ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                if re.match(ip_pattern, value):
                    query_filters.append({"term": {"agent.ip": value}})
                # Check if value looks like an agent ID (numbers only)
                elif value.isdigit():
                    query_filters.append({"term": {"agent.id": value}})
                else:
                    # Search across multiple hostname fields
                    query_filters.append({
                        "bool": {
                            "should": [
                                {"term": {"agent.name": value}},
                                {"term": {"data.os.hostname": value}}
                            ],
                            "minimum_should_match": 1
                        }
                    })
            # Handle OS-specific filtering
            elif field in ["os", "os_name", "operating_system"] and isinstance(value, str):
                query_filters.append({"term": {"data.os.name": value}})
            elif field in ["os_version", "version"] and isinstance(value, str):
                query_filters.append({"term": {"data.os.version": value}})
            elif field in ["fqdn", "fully_qualified_domain_name"] and isinstance(value, str):
                query_filters.append({"term": {"data.os.hostname": value}})
            # Handle file filtering with intelligent field detection
            elif field in ["file", "file_name", "file_path", "filename", "filepath"] and isinstance(value, str):
                import re
                # Check if value contains path separators (likely full file path)
                if ('\\' in value or '/' in value):
                    query_filters.append({
                        "bool": {
                            "should": [
                                {"wildcard": {"data.win.eventdata.targetFilename": f"*{value}*"}},
                                {"wildcard": {"syscheck.path": f"*{value}*"}},
                                {"wildcard": {"data.file.path": f"*{value}*"}}
                            ],
                            "minimum_should_match": 1
                        }
                    })
                # Check if it looks like a hash
                elif re.match(r'^[a-fA-F0-9]{32}$', value):
                    # MD5 hash
                    query_filters.append({"term": {"syscheck.md5_after": value.lower()}})
                elif re.match(r'^[a-fA-F0-9]{40}$', value):
                    # SHA1 hash
                    query_filters.append({"term": {"syscheck.sha1_after": value.lower()}})
                elif re.match(r'^[a-fA-F0-9]{64}$', value):
                    # SHA256 hash
                    query_filters.append({"term": {"syscheck.sha256_after": value.lower()}})
                else:
                    # For file names, search across multiple file name fields
                    query_filters.append({
                        "bool": {
                            "should": [
                                {"wildcard": {"data.file.name": f"*{value}*"}},
                                {"wildcard": {"syscheck.path": f"*{value}*"}},
                                {"wildcard": {"data.win.eventdata.targetFilename": f"*{value}*"}}
                            ],
                            "minimum_should_match": 1
                        }
                    })
                # Handle rule filtering
            elif field in ["rule_id", "rule", "ruleid"] and isinstance(value, str):
                query_filters.append({"term": {"rule.id": value}})
            elif field in ["rule_level", "severity", "level"] and isinstance(value, (str, int)):
                # Convert severity names to numeric levels
                if isinstance(value, str):
                    severity_mapping = {
                        "critical": 12,
                        "high": 8, 
                        "medium": 5,
                        "low": 3,
                        "informational": 1,
                        "info": 1
                    }
                    if value.lower() in severity_mapping:
                        level_value = severity_mapping[value.lower()]
                    else:
                        try:
                            level_value = int(value)
                        except ValueError:
                            # Skip invalid severity values
                            continue
                else:
                    level_value = int(value)
                
                # For named severities, use range queries to include all levels at or above the threshold
                if isinstance(value, str) and value.lower() in ["critical", "high", "medium", "low"]:
                    query_filters.append({"range": {"rule.level": {"gte": level_value}}})
                else:
                    query_filters.append({"term": {"rule.level": level_value}})
            elif field in ["rule_group", "rule_groups", "group", "groups"] and isinstance(value, str):
                query_filters.append({"term": {"rule.groups": value}})
            # Standard filtering logic for other fields
            elif isinstance(value, list):
                # Multiple values - use terms query
                query_filters.append({
                    "terms": {field: value}
                })
            elif isinstance(value, str):
                if '*' in value or '?' in value:
                    # Wildcard query
                    query_filters.append({
                        "wildcard": {field: value}
                    })
                else:
                    # Exact match
                    query_filters.append({
                        "term": {field: value}
                    })
            elif isinstance(value, dict):
                # Range or other complex query
                query_filters.append({
                    "range": {field: value}
                })
            else:
                # Simple term query
                query_filters.append({
                    "term": {field: value}
                })
        
        return query_filters

    def build_aggregation_query(self, agg_type: str, field: str, size: int = 10) -> Dict[str, Any]:
        """
        Build aggregation query for common patterns
        
        Args:
            agg_type: Type of aggregation (terms, date_histogram, etc.)
            field: Field to aggregate on
            size: Number of buckets
            
        Returns:
            Aggregation query
        """
        if agg_type == "terms":
            return {
                "terms": {
                    "field": field,
                    "size": size,
                    "order": {"_count": "desc"}
                }
            }
        elif agg_type == "date_histogram":
            return {
                "date_histogram": {
                    "field": field,
                    "interval": "1h",
                    "format": "yyyy-MM-dd HH:mm:ss"
                }
            }
        elif agg_type == "avg":
            return {
                "avg": {
                    "field": field
                }
            }
        elif agg_type == "max":
            return {
                "max": {
                    "field": field
                }
            }
        elif agg_type == "min":
            return {
                "min": {
                    "field": field
                }
            }
        else:
            logger.warning("Unknown aggregation type", agg_type=agg_type)
            return {
                "terms": {
                    "field": field,
                    "size": size
                }
            }

    async def test_connection(self) -> bool:
        """
        Test connection to OpenSearch cluster
        
        Returns:
            True if connection successful
        """
        try:
            response = await self.client.cluster.health()
            status = response.get('status', 'unknown')
            
            logger.info("OpenSearch connection test", 
                       status=status, 
                       cluster_name=response.get('cluster_name'))
            
            return status in ['green', 'yellow']
            
        except Exception as e:
            logger.error("OpenSearch connection test failed", error=str(e))
            return False

    async def close(self):
        """Close the OpenSearch client connection"""
        try:
            await self.client.close()
            logger.info("OpenSearch client connection closed")
        except Exception as e:
            logger.error("Error closing OpenSearch client", error=str(e))

    def get_field_mappings(self) -> Dict[str, str]:
        """
        Get common Wazuh field mappings for different entity types
        
        Returns:
            Dictionary mapping entity types to field names
        """
        return {
            "host": "agent.name",
            "user": "data.win.eventdata.targetUserName",
            "process": "data.win.eventdata.image",
            "file": "data.win.eventdata.targetFilename",
            "ip": "agent.ip",
            "source_port": "data.win.eventdata.sourcePort",
            "destination_port": "data.win.eventdata.destinationPort",
            "rule_id": "rule.id",
            "rule_level": "rule.level",
            "rule_description": "rule.description",
            "rule_groups": "rule.groups",
            "timestamp": "@timestamp",
            "alert_id": "_id"
        }
    
    def get_detailed_field_mappings(self) -> Dict[str, Dict[str, str]]:
        """
        Get detailed field mappings for comprehensive entity attributes
        
        Returns:
            Dictionary mapping entity types to their detailed field mappings
        """
        return {
            "process": {
                "pid": "data.win.eventdata.processId",
                "ppid": "data.win.eventdata.parentProcessId",
                "command_line": "data.win.eventdata.commandLine",
                "exe": "data.win.eventdata.image",
                "image_path": "data.win.eventdata.image",
                "uid": "data.win.eventdata.subjectUserSid",
                "parent_command_line": "data.win.eventdata.parentCommandLine",
                "guid": "data.win.eventdata.processGuid",
                "login_id": "data.win.eventdata.logonId",
                "integrity_level": "data.win.eventdata.integrityLevel",
                "current_working_path": "data.win.eventdata.currentDirectory",
                "md5_hash": "syscheck.md5_after",
                "sha1_hash": "syscheck.sha1_after",
                "signature_valid": "data.win.eventdata.status"
            },
            "user": {
                "name": "data.win.eventdata.targetUserName",
                "subject_name": "data.win.eventdata.subjectUserName",
                "domain": "data.win.eventdata.targetDomainName",
                "subject_domain": "data.win.eventdata.subjectDomainName",
                "sid": "data.win.eventdata.targetUserSid",
                "subject_sid": "data.win.eventdata.subjectUserSid",
                "logon_id": "data.win.eventdata.targetLogonId",
                "logon_type": "data.win.eventdata.logonType"
            },
            "host": {
                "name": "agent.name",
                "ip": "agent.ip",
                "id": "agent.id",
                "manager": "manager.name",
                # Additional OS fields from mapping file
                "hostname": "data.os.hostname",
                "os_name": "data.os.name",
                "os_version": "data.os.version",
                "fqdn": "data.os.hostname"
            },
            "file": {
                "name": "data.file.name",
                "path": "data.file.path",
                "size": "data.file.size",
                "hash": "data.file.hash",
                # Additional fields from mapping file
                "file_name": "syscheck.path",
                "file_path": "data.win.eventdata.targetFilename",
                "size_after": "syscheck.size_after",
                "creation": "syscheck.mtime_after",
                "owner": "syscheck.uname_after",
                "mode": "syscheck.perm_after",
                "content": "syscheck.diff",
                "signature_valid": "data.win.eventdata.status"
            }
        }

    def build_entity_query(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        """
        Build query for specific entity with intelligent field detection
        
        Args:
            entity_type: Type of entity (host, user, process, service, file)
            entity_id: ID of the entity
            
        Returns:
            OpenSearch query for the entity
        """
        import re
        
        # Smart field detection based on entity_id format and type
        if entity_type == "host":
            # Check if entity_id looks like an IP address
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, entity_id):
                field = "agent.ip"
            # Check if entity_id looks like an agent ID (numbers only)
            elif entity_id.isdigit():
                field = "agent.id"
            else:
                # Search across multiple hostname fields including OS hostname
                return {
                    "bool": {
                        "should": [
                            {"term": {"agent.name": entity_id}},
                            {"term": {"data.os.hostname": entity_id}}
                        ],
                        "minimum_should_match": 1
                    }
                }
                
        elif entity_type == "process":
            # Check if entity_id looks like a PID (numbers only)
            if entity_id.isdigit():
                return {"term": {"data.win.eventdata.processId": entity_id}}
            # Check if it looks like a GUID pattern
            elif re.match(r'^{[0-9a-fA-F-]+}$', entity_id):
                return {"term": {"data.win.eventdata.processGuid": entity_id}}
            # Check if it contains path separators (likely executable path)
            elif ('\\' in entity_id or '/' in entity_id):
                return {"wildcard": {"data.win.eventdata.image": f"*{entity_id}*"}}
            else:
                # For process names, search across multiple Windows event fields
                return {
                    "bool": {
                        "should": [
                            {"wildcard": {"data.win.eventdata.image": f"*{entity_id}*"}},
                            {"wildcard": {"data.win.eventdata.originalFileName": f"*{entity_id}*"}},
                            {"wildcard": {"data.win.eventdata.commandLine": f"*{entity_id}*"}},
                            {"wildcard": {"rule.description": f"*{entity_id}*"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
                
        elif entity_type == "service":
            # Check if entity_id looks like a PID (numbers only)
            if entity_id.isdigit():
                return {"term": {"data.win.eventdata.processId": entity_id}}
            # Check if it contains path separators (likely executable path)
            elif ('\\' in entity_id or '/' in entity_id):
                return {"wildcard": {"data.win.eventdata.image": f"*{entity_id}*"}}
            else:
                # For service names, search across multiple Windows event fields
                return {
                    "bool": {
                        "should": [
                            {"wildcard": {"data.win.eventdata.image": f"*{entity_id}*"}},
                            {"wildcard": {"data.win.eventdata.originalFileName": f"*{entity_id}*"}},
                            {"wildcard": {"data.win.eventdata.commandLine": f"*{entity_id}*"}},
                            {"wildcard": {"rule.description": f"*{entity_id}*"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
                
        elif entity_type == "user":
            # Check if entity_id looks like a SID
            if entity_id.startswith('S-1-'):
                field = "data.win.eventdata.targetUserSid"
            # Check if it looks like a logon ID
            elif re.match(r'^0x[0-9a-fA-F]+$', entity_id):
                field = "data.win.eventdata.targetLogonId"
            else:
                # Default to username
                field = "data.win.eventdata.targetUserName"
                
        elif entity_type == "file":
            # Check if entity_id contains path separators (likely full file path)
            if ('\\' in entity_id or '/' in entity_id):
                # Search across multiple file path fields
                return {
                    "bool": {
                        "should": [
                            {"wildcard": {"data.win.eventdata.targetFilename": f"*{entity_id}*"}},
                            {"wildcard": {"syscheck.path": f"*{entity_id}*"}},
                            {"wildcard": {"data.file.path": f"*{entity_id}*"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            # Check if it looks like a hash (MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars)
            elif re.match(r'^[a-fA-F0-9]{32}$', entity_id):
                # MD5 hash
                return {"term": {"syscheck.md5_after": entity_id.lower()}}
            elif re.match(r'^[a-fA-F0-9]{40}$', entity_id):
                # SHA1 hash
                return {"term": {"syscheck.sha1_after": entity_id.lower()}}
            elif re.match(r'^[a-fA-F0-9]{64}$', entity_id):
                # SHA256 hash (if available)
                return {"term": {"syscheck.sha256_after": entity_id.lower()}}
            else:
                # For file names, search across multiple file name fields
                return {
                    "bool": {
                        "should": [
                            {"wildcard": {"data.file.name": f"*{entity_id}*"}},
                            {"wildcard": {"syscheck.path": f"*{entity_id}*"}},
                            {"wildcard": {"data.win.eventdata.targetFilename": f"*{entity_id}*"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
                
        else:
            # Use regular field mappings for other entity types
            field_mappings = self.get_field_mappings()
            field = field_mappings.get(entity_type, "agent.name")
        
        return {
            "term": {field: entity_id}
        }
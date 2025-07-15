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
            connection_class=RequestsHttpConnection,
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
            time_range: Time range string (e.g., "7d", "24h", "30m")
            
        Returns:
            OpenSearch time range filter
        """
        try:
            if time_range.endswith('d'):
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
                    "timestamp": {
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
                    "timestamp": {
                        "gte": "now-24h",
                        "lte": "now"
                    }
                }
            }

    def build_filters_query(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert filters dict to OpenSearch query filters
        
        Args:
            filters: Dictionary of field:value filters
            
        Returns:
            List of OpenSearch query filters
        """
        query_filters = []
        
        for field, value in filters.items():
            if isinstance(value, list):
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
                    "calendar_interval": "1h",
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
            "user": "data.srcuser",
            "process": "data.process.name",
            "file": "data.file.name",
            "ip": "data.srcip",
            "port": "data.srcport",
            "rule_id": "rule.id",
            "rule_level": "rule.level",
            "rule_description": "rule.description",
            "rule_groups": "rule.groups",
            "timestamp": "timestamp",
            "alert_id": "_id"
        }

    def build_entity_query(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        """
        Build query for specific entity
        
        Args:
            entity_type: Type of entity (host, user, process, file)
            entity_id: ID of the entity
            
        Returns:
            OpenSearch query for the entity
        """
        field_mappings = self.get_field_mappings()
        field = field_mappings.get(entity_type, "agent.name")
        
        return {
            "term": {field: entity_id}
        }
"""
Context Preprocessing for Wazuh Security Agent

Handles conversation context analysis and parameter enrichment
separate from the LLM system prompt to prevent bias and pollution.
"""
import re
import structlog
from typing import Dict, Any, List, Optional

logger = structlog.get_logger()


class ConversationContextProcessor:
    """
    Processes conversation context and enriches user queries with
    contextual parameters without polluting the LLM system prompt.
    """

    def __init__(self):
        self.contextual_keywords = [
            "those", "these", "that", "this", "the critical ones", "the high priority",
            "from there", "on that host", "for that user", "more details", "more information",
            "same host", "same user", "same timeframe", "same period", "those alerts",
            "critical alerts", "high severity", "from before", "previously mentioned",
            "the ones", "earlier", "above", "mentioned", "said alerts", "said events",
            "these alerts", "these events", "those processes", "these processes"
        ]

    def process_query_with_context(self, user_input: str, chat_history: List) -> Dict[str, Any]:
        """
        Process user query and return enriched parameters based on context.

        Args:
            user_input: User's natural language query
            chat_history: Previous conversation messages

        Returns:
            Dictionary with:
            - original_query: Original user input
            - has_contextual_reference: Boolean if query references previous context
            - explicit_new_params: Boolean if user specified new parameters
            - suggested_filters: Dict of suggested filters from context
            - context_applied: Boolean if context should be applied
            - reasoning: String explaining the decision
        """
        result = {
            "original_query": user_input,
            "has_contextual_reference": False,
            "explicit_new_params": False,
            "suggested_filters": {},
            "context_applied": False,
            "reasoning": ""
        }

        # Step 1: Check for contextual references
        has_contextual_reference = any(
            keyword in user_input.lower() for keyword in self.contextual_keywords
        )
        result["has_contextual_reference"] = has_contextual_reference

        # Step 2: Check for explicit new parameters
        new_time_specified = bool(re.search(r'\b(\d+)\s*(hour|day|minute)', user_input.lower()))
        new_host_specified = any(word in user_input.lower() for word in ["host", "agent", "server"])
        result["explicit_new_params"] = new_time_specified or new_host_specified

        # Step 3: Extract previous context
        previous_context = self._extract_previous_context(chat_history) if chat_history else {}

        # Step 4: Decision logic
        if result["explicit_new_params"]:
            result["reasoning"] = f"User specified new parameters (time: {new_time_specified}, host: {new_host_specified}). Skipping context preservation."
            logger.info("Skipping context preservation - explicit new parameters",
                       new_time=new_time_specified, new_host=new_host_specified)
            return result

        if not has_contextual_reference:
            result["reasoning"] = "No contextual keywords found. Treating as independent query."
            return result

        if not previous_context:
            result["reasoning"] = "Contextual keywords found but no previous context available."
            return result

        # Step 5: Build suggested filters from context
        suggested_filters = {}
        suggested_time_range = None

        if previous_context.get("hosts"):
            # Use 'host' for intelligent field detection (OpenSearch client will auto-detect agent.id vs agent.name)
            suggested_filters["host"] = previous_context["hosts"][0]

        if previous_context.get("timeframes"):
            # Convert timeframe to standardized format
            suggested_time_range = self._extract_timeframe(previous_context["timeframes"])

        if previous_context.get("alert_types"):
            if "critical" in previous_context["alert_types"]:
                suggested_filters["rule.level"] = {"gte": 12}
            elif "high" in previous_context["alert_types"]:
                suggested_filters["rule.level"] = {"gte": 8, "lte": 11}

        if previous_context.get("processes"):
            suggested_filters["process.name"] = previous_context["processes"][0]

        if previous_context.get("rule_groups"):
            suggested_filters["rule.groups"] = previous_context["rule_groups"]

        if previous_context.get("ip_addresses"):
            suggested_filters["ip.src"] = previous_context["ip_addresses"][0]

        result["suggested_filters"] = suggested_filters
        result["suggested_time_range"] = suggested_time_range
        result["context_applied"] = bool(suggested_filters) or bool(suggested_time_range)

        context_parts = []
        if suggested_filters:
            context_parts.append(f"filters: {list(suggested_filters.keys())}")
        if suggested_time_range:
            context_parts.append(f"time_range: {suggested_time_range}")

        result["reasoning"] = f"Applied context from previous query. {', '.join(context_parts) if context_parts else 'No context applied'}"

        logger.info("Context processing completed",
                   has_contextual_ref=has_contextual_reference,
                   previous_context=previous_context,
                   suggested_filters=suggested_filters,
                   suggested_time_range=suggested_time_range,
                   reasoning=result["reasoning"])

        return result

    def _extract_timeframe(self, timeframes: List[str]) -> Optional[str]:
        """Extract and normalize timeframe from context"""
        if not timeframes:
            return None

        for tf in timeframes:
            tf_lower = tf.lower()
            if "12 hour" in tf_lower:
                return "12h"
            elif "10 hour" in tf_lower:
                return "10h"
            elif "6 hour" in tf_lower:
                return "6h"
            elif "24 hour" in tf_lower:
                return "24h"
            elif any(x in tf_lower for x in ["1 hour", "1h"]):
                return "1h"

            # Extract any number + hours pattern
            hour_match = re.search(r'(\d+)\s*hour', tf_lower)
            if hour_match:
                return f"{hour_match.group(1)}h"

        return "24h"  # default

    def _extract_previous_context(self, chat_history: List) -> Dict[str, List]:
        """
        Extract relevant context from previous conversation messages

        Args:
            chat_history: List of previous conversation messages

        Returns:
            Dictionary containing extracted context
        """
        context = {
            "hosts": [],
            "users": [],
            "timeframes": [],
            "alert_types": [],
            "ip_addresses": [],
            "processes": [],
            "rule_groups": [],
            "rule_descriptions": [],
            "query_actions": [],
            "severity_levels": [],
        }

        # Look at recent messages (last 4-6 messages)
        recent_messages = chat_history[-6:] if len(chat_history) > 6 else chat_history

        for message in recent_messages:
            if hasattr(message, 'content'):
                content = message.content.lower()

                # Extract hosts
                host_patterns = [
                    r'\bhost\s+(\d+)\b',
                    r'\bon\s+host\s+(\d+)\b',
                    r'\bfor\s+host\s+(\d+)\b',
                    r'\bfrom\s+host\s+(\d+)\b',
                    r'\bthat\s+host\b.*?\b(\d{3})\b',
                ]
                for pattern in host_patterns:
                    matches = re.findall(pattern, content)
                    context["hosts"].extend(matches)

                # Extract IP addresses
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ip_matches = re.findall(ip_pattern, content)
                context["ip_addresses"].extend(ip_matches)

                # Extract users
                user_patterns = [
                    r'\buser\s+([a-zA-Z][a-zA-Z0-9_.-]+)\b',
                    r'\busername\s+([a-zA-Z][a-zA-Z0-9_.-]+)\b',
                    r'\baccount\s+([a-zA-Z][a-zA-Z0-9_.-]+)\b'
                ]
                for pattern in user_patterns:
                    matches = re.findall(pattern, content)
                    context["users"].extend(matches)

                # Extract timeframes
                time_patterns = [
                    r'(last \d+ \w+)',
                    r'(past \d+ \w+)',
                    r'(over the (?:past|last) \d+ \w+)',
                    r'(\d+ hours?)',
                    r'(\d+ days?)',
                    r'(this week)',
                    r'(today)',
                    r'(yesterday)',
                    r'(\d+h)',
                    r'(\d+d)',
                ]
                for pattern in time_patterns:
                    matches = re.findall(pattern, content)
                    context["timeframes"].extend(matches)

                # Extract alert types and severity levels
                if "critical" in content:
                    context["alert_types"].append("critical")
                    context["severity_levels"].append("12")
                if "high" in content:
                    context["alert_types"].append("high")
                    context["severity_levels"].extend(["8", "9"])
                if "medium" in content:
                    context["alert_types"].append("medium")
                    context["severity_levels"].extend(["5", "6"])
                if "low" in content:
                    context["alert_types"].append("low")
                    context["severity_levels"].extend(["3", "4"])

                # Extract processes
                process_patterns = [
                    r'\bprocess\s+([a-zA-Z0-9_.-]+\.exe)\b',
                    r'\b([a-zA-Z0-9_.-]+\.exe)\s+process\b',
                ]
                for pattern in process_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    context["processes"].extend(matches)

                # Extract rule groups
                rule_group_patterns = [
                    r'rule\.groups["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)\b',
                    r'\brule\s+group[s]?\s+["\']?([a-zA-Z0-9_-]+)\b'
                ]
                for pattern in rule_group_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    context["rule_groups"].extend(matches)

                # Extract query actions
                if "action" in content and "filtering" in content:
                    context["query_actions"].append("filtering")
                if "action" in content and "ranking" in content:
                    context["query_actions"].append("ranking")
                if "action" in content and "counting" in content:
                    context["query_actions"].append("counting")

        # Remove duplicates and clean up
        for key in context:
            if isinstance(context[key], list):
                context[key] = list(set(context[key]))

        # Prioritize numeric hosts
        if context["hosts"]:
            numeric_hosts = [h for h in context["hosts"] if h.isdigit()]
            if numeric_hosts:
                context["hosts"] = numeric_hosts + [h for h in context["hosts"] if not h.isdigit()]

        return context

    def enhance_tool_parameters(self, tool_params: Dict[str, Any], suggested_filters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance tool parameters with contextual filters.

        Args:
            tool_params: Original tool parameters from LLM
            suggested_filters: Suggested filters from context

        Returns:
            Enhanced parameters with contextual filters merged
        """
        if not suggested_filters:
            return tool_params

        enhanced_params = tool_params.copy()

        # Merge filters
        if "filters" not in enhanced_params:
            enhanced_params["filters"] = {}

        for key, value in suggested_filters.items():
            if key == "time_range":
                # Only apply time_range if not already specified
                if "time_range" not in enhanced_params:
                    enhanced_params["time_range"] = value
            else:
                # Add to filters
                enhanced_params["filters"][key] = value

        logger.info("Enhanced tool parameters with context",
                   original_keys=list(tool_params.keys()),
                   added_filters=list(suggested_filters.keys()))

        return enhanced_params
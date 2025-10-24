"""
Infer relationship types between network entities (host, user, process, file) based on Wazuh event data
"""
from typing import Dict, Any, Optional

# Sysmon Event ID to relationship type mappings
SYSMON_EVENT_RELATIONSHIPS = {
    "1": "spawned",           # Process Create
    "2": "modified",          # File Creation Time Changed
    "3": "connected_to",      # Network Connection
    "5": "terminated",        # Process Terminated
    "6": "loaded",            # Driver Loaded
    "7": "loaded",            # Image/DLL Loaded
    "8": "accessed",          # CreateRemoteThread
    "10": "accessed",         # Process Access
    "11": "creates",          # File Create
    "12": "creates",          # Registry Create/Delete
    "13": "writes",           # Registry Set Value
    "15": "creates",          # File Create Stream
    "17": "creates",          # Pipe Created
    "18": "connected_to",     # Pipe Connected
    "22": "queried",          # DNS Query
    "23": "deletes",          # File Delete
    "26": "deletes",          # File Delete Detected
}

# Windows Security Event ID to relationship type mappings
WINDOWS_EVENT_RELATIONSHIPS = {
    "4624": "authenticated_as",   # Logon Success
    "4625": "failed_auth_as",     # Logon Failed
    "4648": "authenticated_as",   # Logon with Explicit Credentials
    "4672": "elevated_to",        # Special Privileges Assigned
    "4688": "spawned",            # Process Creation
    "4689": "terminated",         # Process Termination
    "4698": "created",            # Scheduled Task Created
    "4699": "deleted",            # Scheduled Task Deleted
    "4720": "created",            # User Account Created
    "4726": "deleted",            # User Account Deleted
    "5140": "accessed",           # Network Share Access
    "5145": "accessed",           # Network Share Detailed Access
    "5156": "connected_to",       # Network Connection Allowed
    "5157": "blocked_connection_to", # Network Connection Blocked
}


def _validate_relationship_for_target(relationship: str, target_type: str) -> bool:
    """
    Validate if a relationship type makes sense for the target entity type

    Args:
        relationship: Relationship type label (e.g., 'spawned', 'creates')
        target_type: Target entity type (process, host, user, file)

    Returns:
        True if the relationship is valid for this target type, False otherwise
    """
    if not target_type:
        # If target_type is None (all relationships), accept the relationship
        return True

    target = target_type.lower()

    # Define which relationships are valid for which target types
    valid_mappings = {
        "spawned": ["process"],              # Only Process → Process
        "terminated": ["process"],           # Only Process → Process
        "injected_into": ["process"],        # Only Process → Process
        "creates": ["file"],                 # Only Process → File (for file creation)
        "deletes": ["file"],                 # Only Process → File
        "writes": ["file"],                  # Only Process → File
        "reads": ["file"],                   # Only Process → File
        "modifies": ["file"],                # Only Process → File
        "modified": ["file"],                # Only Process → File
        "accesses": ["file", "process"],     # Process → File or Process → Process
        "accessed": ["file", "process", "host", "user"],  # Generic access
        "loads": ["file"],                   # Process loads DLL/module (file)
        "loaded": ["file"],                  # Process loaded file
        "authenticated_as": ["user"],        # Process → User
        "failed_auth_as": ["user"],          # Process → User
        "elevated_to": ["user"],             # Process → User
        "elevated_by": ["user"],             # Process → User
        "executed_by": ["user"],             # Process → User
        "logged_into": ["host"],             # User → Host
        "runs_on": ["host"],                 # Process → Host
        "connected_to": ["host", "process", "user", "file"],  # Generic connection
        "queried": ["host", "file"],         # DNS queries, file queries
        "created": ["file", "user"],         # Generic creation
        "deleted": ["file", "user"],         # Generic deletion
    }

    # Check if this relationship is valid for the target type
    valid_targets = valid_mappings.get(relationship)

    # If relationship not in mapping, accept it (unknown relationship types pass through)
    if valid_targets is None:
        return True

    # Check if target type is in the list of valid targets
    return target in valid_targets


def infer_relationship_type(
    source_type: str,
    target_type: str,
    event_data: Dict[str, Any]
) -> str:
    """
    Infer the relationship type based on entity types and Wazuh event data

    Args:
        source_type: Source entity type (process, host, user, file)
        target_type: Target entity type (process, host, user, file)
        event_data: Wazuh alert event data containing rule groups, event IDs, etc.

    Returns:
        Relationship label (e.g., 'creates', 'executes', 'runs_on', 'executed_by')
    """
    # Extract event metadata
    win_system = event_data.get("data", {}).get("win", {}).get("system", {})
    event_id = win_system.get("eventID")
    rule_groups = event_data.get("rule", {}).get("groups", [])
    rule_description = event_data.get("rule", {}).get("description", "").lower()

    # Priority 1: Check Sysmon Event ID first (most specific)
    # BUT: Verify the relationship makes sense for the target entity type
    if event_id and event_id in SYSMON_EVENT_RELATIONSHIPS:
        relationship = SYSMON_EVENT_RELATIONSHIPS[event_id]

        # Validate relationship against target entity type
        if _validate_relationship_for_target(relationship, target_type):
            return relationship
        # If invalid, fall through to next priority

    # Priority 2: Check Windows Security Event ID
    if event_id and event_id in WINDOWS_EVENT_RELATIONSHIPS:
        relationship = WINDOWS_EVENT_RELATIONSHIPS[event_id]

        # Validate relationship against target entity type
        if _validate_relationship_for_target(relationship, target_type):
            return relationship
        # If invalid, fall through to next priority

    # Priority 3: Infer from rule description keywords
    keyword_relationship = _infer_from_keywords(source_type, target_type, rule_description, rule_groups)
    if keyword_relationship:
        return keyword_relationship

    # Priority 4: Fallback to entity-type based inference
    return _infer_by_entity_types(source_type, target_type, rule_groups, rule_description)


def _infer_from_keywords(
    source_type: str,
    target_type: str,
    rule_description: str,
    rule_groups: list
) -> Optional[str]:
    """
    Infer relationship from rule description keywords

    Args:
        source_type: Source entity type
        target_type: Target entity type
        rule_description: Lowercase rule description
        rule_groups: Rule group classifications

    Returns:
        Relationship type or None if no clear match
    """
    # File operations
    if any(kw in rule_description for kw in ["file created", "file dropped", "dropped"]):
        return "creates"
    elif any(kw in rule_description for kw in ["file deleted", "removed"]):
        return "deletes"
    elif any(kw in rule_description for kw in ["file modified", "modified", "changed"]):
        return "modifies"
    elif any(kw in rule_description for kw in ["file read", "accessed", "opened"]):
        return "reads"
    elif "wrote" in rule_description or "written" in rule_description:
        return "writes"

    # Process operations
    elif any(kw in rule_description for kw in ["process created", "new process", "spawned", "launched"]):
        return "spawned"
    elif any(kw in rule_description for kw in ["process terminated", "killed", "ended"]):
        return "terminated"
    elif "executed" in rule_description or "execution" in rule_description:
        return "executes"

    # DLL/Module operations
    elif "loaded" in rule_description or "dll" in rule_description:
        return "loads"

    # Authentication operations
    elif any(kw in rule_description for kw in ["logon success", "login success", "authenticated"]):
        return "authenticated_as"
    elif any(kw in rule_description for kw in ["logon fail", "login fail", "authentication fail"]):
        return "failed_auth_as"
    elif "privilege" in rule_description or "elevation" in rule_description:
        return "elevated_to"

    # Network operations
    elif "connection" in rule_description or "connected" in rule_description:
        return "connected_to"

    return None


def _infer_by_entity_types(
    source_type: str,
    target_type: str,
    rule_groups: list,
    rule_description: str
) -> str:
    """
    Infer relationship based on entity type combinations

    Args:
        source_type: Source entity type
        target_type: Target entity type
        rule_groups: Rule group classifications
        rule_description: Lowercase rule description

    Returns:
        Relationship type label
    """
    source = source_type.lower()
    target = target_type.lower()

    # Process → Host
    if source == "process" and target == "host":
        return "runs_on"

    # Process → User
    elif source == "process" and target == "user":
        if any(g in rule_groups for g in ["authentication", "authentication_success"]):
            return "authenticated_as"
        elif any(g in rule_groups for g in ["authentication_failed", "authentication_failures"]):
            return "failed_auth_as"
        elif "privilege" in rule_description or "elevation" in rule_description:
            return "elevated_by"
        else:
            return "executed_by"

    # Process → Process
    elif source == "process" and target == "process":
        if "inject" in rule_description or "remote" in rule_description:
            return "injected_into"
        elif "terminate" in rule_description or "kill" in rule_description:
            return "terminated"
        else:
            return "spawned"

    # Process → File
    elif source == "process" and target == "file":
        # Check for specific file operations in rule groups
        if any("file" in g for g in rule_groups):
            if "delete" in rule_description:
                return "deletes"
            elif "modify" in rule_description or "write" in rule_description:
                return "writes"
            elif "read" in rule_description or "access" in rule_description:
                return "reads"
            elif "create" in rule_description or "drop" in rule_description:
                return "creates"
        # Default for process-file
        return "accesses"

    # Host → User
    elif source == "host" and target == "user":
        return "hosts"

    # Host → Process
    elif source == "host" and target == "process":
        return "executes"

    # Host → File
    elif source == "host" and target == "file":
        return "contains"

    # User → Host
    elif source == "user" and target == "host":
        if any(g in rule_groups for g in ["authentication", "logon", "login"]):
            return "logged_into"
        return "accessed"

    # User → Process
    elif source == "user" and target == "process":
        return "launched"

    # User → File
    elif source == "user" and target == "file":
        if "access" in rule_description:
            return "accessed"
        return "owns"

    # File → Process
    elif source == "file" and target == "process":
        return "executed_by"

    # File → Host
    elif source == "file" and target == "host":
        return "stored_on"

    # File → User
    elif source == "file" and target == "user":
        return "owned_by"

    # Default fallback
    else:
        return "connected_to"


def get_relationship_description(relationship_type: str) -> str:
    """
    Get human-readable description of relationship type

    Args:
        relationship_type: Relationship type label

    Returns:
        Human-readable description
    """
    descriptions = {
        # Process relationships
        "runs_on": "Process executes on host",
        "executed_by": "Process executed by user",
        "spawned": "Process created another process",
        "terminated": "Process terminated another process",
        "injected_into": "Process injected code into another process",
        "creates": "Process created file",
        "deletes": "Process deleted file",
        "writes": "Process wrote to file",
        "reads": "Process read from file",
        "modifies": "Process modified file",
        "loads": "Process loaded library/module",
        "accesses": "Process accessed file",

        # Authentication relationships
        "authenticated_as": "Successful authentication as user",
        "failed_auth_as": "Failed authentication attempt as user",
        "elevated_to": "Privilege elevation to user context",

        # Host relationships
        "hosts": "Host contains user account",
        "executes": "Host executes process",
        "contains": "Host stores file",

        # User relationships
        "logged_into": "User logged into host",
        "launched": "User launched process",
        "owns": "User owns file",

        # Network relationships
        "connected_to": "Network connection established",
        "blocked_connection_to": "Network connection blocked",

        # File relationships
        "stored_on": "File stored on host",
        "owned_by": "File owned by user",

        # Generic
        "accessed": "Entity accessed another entity",
    }

    return descriptions.get(relationship_type, f"Related via {relationship_type}")


def get_relationship_directionality(relationship_type: str) -> str:
    """
    Determine if relationship is directional or bidirectional

    Args:
        relationship_type: Relationship type label

    Returns:
        'directional' or 'bidirectional'
    """
    # Most relationships are directional (A → B is different from B → A)
    bidirectional = ["connected_to", "interacts_with"]

    if relationship_type in bidirectional:
        return "bidirectional"
    return "directional"

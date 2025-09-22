"""
Debug what's actually being passed to the agent
"""

# Mock message class that better represents the real conversation
class MockMessage:
    def __init__(self, content):
        self.content = content

# Real conversation from your scenario
test_messages = [
    MockMessage("Show me all alerts on host 012 over the past 10 hours."),
    MockMessage("Over the past 10 hours, host 012 (agent name: U209-PC-BLEE) has generated 170 alerts. Here's a security analysis of the findings:\n\nKey Statistics:\n\n    Total Alerts: 170\n    Severity Breakdown:\n        Low (Level 3): 152 alerts\n        Medium (Level 5-6): 14 alerts\n        High (Level 8-9): 4 alerts\n\nNotable Security Events:\n\n    High Severity Alerts:\n        2 instances of 'A new external device was recognized by the system' (Level 8)\n        2 instances of 'Powershell process created an executable file in Windows root folder' (Level 9)"),
]

import sys
import os
sys.path.append(os.path.dirname(__file__))

from agent.wazuh_agent import WazuhSecurityAgent
from dotenv import load_dotenv

load_dotenv()

try:
    agent = WazuhSecurityAgent(
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", "dummy"),
        opensearch_config={
            "host": "localhost",
            "port": 9200,
            "auth": ("admin", "admin"),
            "use_ssl": False,
            "verify_certs": False
        }
    )

    # Test context extraction
    print("=== CONTEXT EXTRACTION TEST ===")
    context = agent._extract_previous_context(test_messages)
    print("Extracted Context:")
    for key, value in context.items():
        print(f"  {key}: {value}")

    # Test the exact query that's failing
    test_query = "Show me details of which PowerShell processes created executable files on that host."

    print(f"\n=== PROMPT ENHANCEMENT TEST ===")
    print(f"Input query: {test_query}")

    enhanced_prompt = agent._enhance_prompt_with_context(test_query, test_messages)

    print(f"\n=== FULL ENHANCED PROMPT ===")
    print(enhanced_prompt)

    print(f"\n=== POWERSHELL GUIDANCE SECTION ===")
    lines = enhanced_prompt.split('\n')
    for i, line in enumerate(lines):
        if 'POWERSHELL' in line or ('analyze_alerts' in line and 'agent.id' in line):
            print(f"Line {i}: {line}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
"""
Test context extraction for host 012 scenario
"""

# Mock message class
class MockMessage:
    def __init__(self, content):
        self.content = content

# Test messages similar to your conversation
test_messages = [
    MockMessage("Show me all alerts on host 012 over the past 10 hours."),
    MockMessage("Over the past 10 hours, host 012 (agent name: U209-PC-BLEE) has generated 170 alerts..."),
    MockMessage("Show me details of which PowerShell processes created executable files on that host.")
]

# Import the context extraction logic
import sys
import os
sys.path.append(os.path.dirname(__file__))

from agent.wazuh_agent import WazuhSecurityAgent
import os
from dotenv import load_dotenv

load_dotenv()

# Create a minimal agent just to test context extraction
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
    context = agent._extract_previous_context(test_messages)

    print("Extracted Context:")
    for key, value in context.items():
        print(f"  {key}: {value}")

    # Test prompt enhancement for PowerShell query
    enhanced_prompt = agent._enhance_prompt_with_context(
        "Show me details of which PowerShell processes created executable files on that host.",
        test_messages
    )

    print("\nEnhanced Prompt Preview:")
    # Look for the PowerShell guidance section
    lines = enhanced_prompt.split('\n')
    powershell_section = [line for line in lines if 'POWERSHELL' in line or 'analyze_alerts' in line]

    if powershell_section:
        print("PowerShell-specific guidance found:")
        for line in powershell_section:
            print(f"  {line}")
    else:
        print("No PowerShell-specific guidance found!")

    print(f"\nTotal prompt length: {len(enhanced_prompt)} characters")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
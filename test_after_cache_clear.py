"""
Test after cache clear to verify fix
"""
import os
from dotenv import load_dotenv

# Clear any cached imports
import sys
modules_to_clear = [m for m in sys.modules.keys() if m.startswith('agent') or m.startswith('tools')]
for module in modules_to_clear:
    if module in sys.modules:
        del sys.modules[module]

# Now import fresh
from agent.wazuh_agent import WazuhSecurityAgent

load_dotenv()

def test_method_availability():
    """Test that methods are available"""
    print("Testing method availability...")

    # Check class has methods
    cls = WazuhSecurityAgent
    print(f"Class has _enhance_prompt_with_context: {hasattr(cls, '_enhance_prompt_with_context')}")
    print(f"Class has _extract_previous_context: {hasattr(cls, '_extract_previous_context')}")

    # Create instance
    try:
        agent = WazuhSecurityAgent(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", "dummy_key"),
            opensearch_config={
                "host": os.getenv("OPENSEARCH_HOST", "localhost"),
                "port": int(os.getenv("OPENSEARCH_PORT", "9200")),
                "auth": ("admin", "admin"),
                "use_ssl": False,
                "verify_certs": False
            }
        )

        print(f"Instance has _enhance_prompt_with_context: {hasattr(agent, '_enhance_prompt_with_context')}")
        print(f"Instance has _extract_previous_context: {hasattr(agent, '_extract_previous_context')}")

        # Test calling the method
        result = agent._enhance_prompt_with_context("test query", [])
        print(f"Method call successful! Result length: {len(result)}")

        return True

    except Exception as e:
        print(f"Error creating agent: {e}")
        return False

if __name__ == "__main__":
    success = test_method_availability()
    print(f"Test {'PASSED' if success else 'FAILED'}")
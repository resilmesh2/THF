"""
Custom LangChain callback handler for detailed timing measurements
"""
from langchain.callbacks.base import BaseCallbackHandler
from typing import Any, Dict, List
import structlog
import time

logger = structlog.get_logger()

# Per-model pricing (USD per 1M tokens)
MODEL_PRICING = {
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
}
DEFAULT_PRICING = {"input": 3.00, "output": 15.00}  # Fallback to Sonnet rates


def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate USD cost for a given model and token counts."""
    pricing = MODEL_PRICING.get(model, DEFAULT_PRICING)
    return (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000

class TimingCallbackHandler(BaseCallbackHandler):
    """
    Custom callback handler to track timing of different agent execution phases
    """

    def __init__(self):
        super().__init__()
        self.timings = {
            "total_start": None,
            "total_end": None,
            "llm_calls": [],
            "tool_calls": [],
            "chain_calls": [],
            "agent_actions": []
        }
        self.current_llm_start = None
        self.current_tool_start = None
        self.current_tool_name = None
        self.current_chain_start = None
        self.iteration_count = 0
        # Token usage tracking
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.model_name = None

    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        """Run when LLM starts running."""
        self.current_llm_start = time.time()
        # Removed logging to improve performance

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Run when LLM ends running."""
        if self.current_llm_start:
            duration = time.time() - self.current_llm_start
            input_tokens = 0
            output_tokens = 0

            # Extract token usage from LLMResult
            try:
                llm_output = getattr(response, "llm_output", None) or {}
                # langchain-anthropic stores usage in llm_output["usage"]
                usage = llm_output.get("usage", {})
                input_tokens = usage.get("input_tokens", 0)
                output_tokens = usage.get("output_tokens", 0)

                # Capture model name for cost calculation
                if not self.model_name and llm_output.get("model"):
                    self.model_name = llm_output["model"]

                # Fallback: check generations[].message.usage_metadata (newer langchain-core)
                if input_tokens == 0 and output_tokens == 0:
                    try:
                        for gen_list in getattr(response, "generations", []):
                            for gen in (gen_list if isinstance(gen_list, list) else [gen_list]):
                                msg = getattr(gen, "message", None)
                                if msg:
                                    meta = getattr(msg, "usage_metadata", None) or {}
                                    input_tokens += meta.get("input_tokens", 0)
                                    output_tokens += meta.get("output_tokens", 0)
                                    if not self.model_name:
                                        resp_meta = getattr(msg, "response_metadata", None) or {}
                                        self.model_name = resp_meta.get("model")
                    except Exception:
                        pass

                self.total_input_tokens += input_tokens
                self.total_output_tokens += output_tokens
            except Exception:
                pass

            self.timings["llm_calls"].append({
                "start": self.current_llm_start,
                "duration": duration,
                "iteration": self.iteration_count,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens
            })
            self.current_llm_start = None

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Run when LLM errors."""
        if self.current_llm_start:
            duration = time.time() - self.current_llm_start
            logger.error("❌ LLM error",
                        error=str(error),
                        duration_seconds=round(duration, 3),
                        iteration=self.iteration_count)
            self.current_llm_start = None

    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        """Run when tool starts running."""
        self.current_tool_start = time.time()
        tool_name = serialized.get("name", "unknown") if serialized else "unknown"
        # Store the tool name so we can use it in on_tool_end
        self.current_tool_name = tool_name
        # Removed logging to improve performance

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Run when tool ends running."""
        if self.current_tool_start:
            duration = time.time() - self.current_tool_start
            # Use the stored tool name from on_tool_start
            tool_name = getattr(self, 'current_tool_name', 'unknown')

            self.timings["tool_calls"].append({
                "start": self.current_tool_start,
                "duration": duration,
                "tool_name": tool_name,
                "iteration": self.iteration_count
            })
            # Removed logging to improve performance
            self.current_tool_start = None
            self.current_tool_name = None

    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        """Run when tool errors."""
        if self.current_tool_start:
            duration = time.time() - self.current_tool_start
            logger.error("❌ Tool error",
                        error=str(error),
                        duration_seconds=round(duration, 3),
                        iteration=self.iteration_count)
            self.current_tool_start = None

    def on_chain_start(
        self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any
    ) -> None:
        """Run when chain starts running."""
        try:
            self.current_chain_start = time.time()
            # Iteration tracking happens in on_agent_action instead
        except Exception:
            # Silently fail to avoid slowing down execution
            pass

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        """Run when chain ends running."""
        try:
            if self.current_chain_start:
                duration = time.time() - self.current_chain_start
                # We don't really need chain timing details, skip it to improve performance
                self.current_chain_start = None
        except Exception:
            # Silently fail to avoid slowing down execution
            pass

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:
        """Run on agent action."""
        # Track iterations without logging to avoid performance impact
        self.iteration_count += 1

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        """Run on agent finish."""
        # Minimal tracking to avoid performance impact
        pass

    def start_timing(self):
        """Start overall timing"""
        self.timings["total_start"] = time.time()
        # Removed logging to improve performance

    def end_timing(self):
        """End overall timing and log summary"""
        self.timings["total_end"] = time.time()
        total_duration = self.timings["total_end"] - self.timings["total_start"]

        # Calculate breakdown
        total_llm_time = sum(call["duration"] for call in self.timings["llm_calls"])
        total_tool_time = sum(call["duration"] for call in self.timings["tool_calls"])

        # Print detailed timing summary to terminal
        print("\n" + "="*80)
        print("⏱️  QUERY EXECUTION TIMING SUMMARY")
        print("="*80)
        print(f"🕐 Total Time: {total_duration:.3f} seconds")
        print(f"🔄 Agent Iterations: {self.iteration_count}")
        print("-"*80)

        print(f"\n📊 Time Breakdown:")
        print(f"  🤖 LLM Processing:     {total_llm_time:.3f}s ({self._percentage(total_llm_time, total_duration)}%)")
        print(f"  🔧 Tool Execution:     {total_tool_time:.3f}s ({self._percentage(total_tool_time, total_duration)}%)")
        print(f"  ⚙️  Other (orchestration): {(total_duration - total_llm_time - total_tool_time):.3f}s ({self._percentage(total_duration - total_llm_time - total_tool_time, total_duration)}%)")

        # Detailed LLM calls
        if self.timings["llm_calls"]:
            print(f"\n🤖 LLM Calls Detail ({len(self.timings['llm_calls'])} calls):")
            for i, call in enumerate(self.timings["llm_calls"], 1):
                print(f"  Call {i} (Iteration {call['iteration']}): {call['duration']:.3f}s")

        # Detailed tool calls
        if self.timings["tool_calls"]:
            print(f"\n🔧 Tool Calls Detail ({len(self.timings['tool_calls'])} calls):")
            for i, call in enumerate(self.timings["tool_calls"], 1):
                print(f"  {i}. {call['tool_name']}: {call['duration']:.3f}s (Iteration {call['iteration']})")

        # Token usage & cost summary
        total_tokens = self.total_input_tokens + self.total_output_tokens
        model = self.model_name or "claude-sonnet-4-20250514"
        cost = calculate_cost(model, self.total_input_tokens, self.total_output_tokens)
        print(f"\n💰 Token Usage & Cost (model: {model}):")
        print(f"  Input Tokens:  {self.total_input_tokens:,}")
        print(f"  Output Tokens: {self.total_output_tokens:,}")
        print(f"  Total Tokens:  {total_tokens:,}")
        print(f"  Estimated Cost: ${cost:.6f}")

        print("="*80 + "\n")

        # Also log structured data
        logger.info("Query execution completed",
                   total_duration=round(total_duration, 3),
                   total_llm_time=round(total_llm_time, 3),
                   total_tool_time=round(total_tool_time, 3),
                   llm_calls=len(self.timings["llm_calls"]),
                   tool_calls=len(self.timings["tool_calls"]),
                   iterations=self.iteration_count,
                   input_tokens=self.total_input_tokens,
                   output_tokens=self.total_output_tokens,
                   total_tokens=total_tokens,
                   cost_usd=round(cost, 6),
                   model=model)

    def _percentage(self, part: float, total: float) -> str:
        """Calculate percentage and return as formatted string"""
        if total == 0:
            return "0.0"
        return f"{(part / total * 100):.1f}"

    def get_summary(self) -> Dict[str, Any]:
        """Get timing summary as dictionary"""
        if not self.timings["total_start"] or not self.timings["total_end"]:
            return {}

        total_duration = self.timings["total_end"] - self.timings["total_start"]
        total_llm_time = sum(call["duration"] for call in self.timings["llm_calls"])
        total_tool_time = sum(call["duration"] for call in self.timings["tool_calls"])

        total_tokens = self.total_input_tokens + self.total_output_tokens
        model = self.model_name or "claude-sonnet-4-20250514"
        cost = calculate_cost(model, self.total_input_tokens, self.total_output_tokens)

        return {
            "total_duration": round(total_duration, 3),
            "total_llm_time": round(total_llm_time, 3),
            "total_tool_time": round(total_tool_time, 3),
            "orchestration_time": round(total_duration - total_llm_time - total_tool_time, 3),
            "llm_calls_count": len(self.timings["llm_calls"]),
            "tool_calls_count": len(self.timings["tool_calls"]),
            "iterations": self.iteration_count,
            "llm_calls": self.timings["llm_calls"],
            "tool_calls": self.timings["tool_calls"],
            "token_summary": {
                "model": model,
                "totals": {
                    "input_tokens": self.total_input_tokens,
                    "output_tokens": self.total_output_tokens,
                    "total_tokens": total_tokens,
                    "cost_usd": round(cost, 6)
                },
                "per_call": [
                    {
                        "call": i + 1,
                        "input_tokens": call.get("input_tokens", 0),
                        "output_tokens": call.get("output_tokens", 0),
                    }
                    for i, call in enumerate(self.timings["llm_calls"])
                ]
            }
        }

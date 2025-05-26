import os
import re
import json
import requests
from typing import Dict, List, Any, Optional, Union
from google import genai
import dotenv

# Load environment variables
dotenv.load_dotenv()


class TokenCounter:
    """
    Token counting utility for various LLM providers.
    Supports Google Gemini (with native count_tokens API) and Fireworks AI models.
    """
    
    def __init__(self):
        # Initialize Gemini client for token counting
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        if self.gemini_api_key:
            self.gemini_client = genai.Client(api_key=self.gemini_api_key)
        else:
            self.gemini_client = None
        
        # Fireworks AI models and their approximate token ratios
        # Based on research: most models use similar tokenization to GPT models
        # 1 token ≈ 4 characters for most models
        self.fireworks_token_ratios = {
            "deepseek-v3": 4,      # characters per token
            "deepseek-r1": 4,
            "qwen3-30b": 4,
            "qwen3-235b": 4
        }
    
    def count_gemini_tokens(self, prompt: str, model: str = "gemini-2.0-flash") -> Dict[str, int]:
        """
        Count tokens for Gemini models using the native count_tokens API.
        
        Args:
            prompt (str): Text to count tokens for
            model (str): Gemini model name
            
        Returns:
            Dict[str, int]: Token count information including total_tokens and total_billable_characters
        """
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        try:
            from google.genai.types import HttpOptions
            
            # Use the new Gen AI SDK count_tokens method
            response = self.gemini_client.models.count_tokens(
                model=model,
                contents=prompt
            )
            
            return {
                "total_tokens": response.total_tokens,
                "total_billable_characters": getattr(response, 'total_billable_characters', None),
                "cached_content_token_count": getattr(response, 'cached_content_token_count', None)
            }
            
        except Exception as e:
            # Fallback to estimation if API fails
            estimated_tokens = self._estimate_tokens_chars(prompt)
            print(f"Warning: Gemini token counting failed ({str(e)}), using estimation")
            return {
                "total_tokens": estimated_tokens,
                "total_billable_characters": len(prompt),
                "cached_content_token_count": None,
                "estimated": True
            }
    
    def count_fireworks_tokens(self, prompt: str, model_key: str) -> Dict[str, int]:
        """
        Estimate token count for Fireworks AI models.
        Since Fireworks doesn't provide a native token counting API, we use character-based estimation.
        
        Args:
            prompt (str): Text to count tokens for
            model_key (str): Model key (e.g., 'deepseek-v3', 'qwen3-235b')
            
        Returns:
            Dict[str, int]: Estimated token count information
        """
        if model_key not in self.fireworks_token_ratios:
            print(f"Warning: Unknown model {model_key}, using default ratio")
            chars_per_token = 4
        else:
            chars_per_token = self.fireworks_token_ratios[model_key]
        
        char_count = len(prompt)
        estimated_tokens = max(1, char_count // chars_per_token)
        
        # For DeepSeek R1, add extra tokens for reasoning overhead
        if "deepseek-r1" in model_key.lower():
            # R1 models use reasoning tokens, add 10-20% overhead
            estimated_tokens = int(estimated_tokens * 1.15)
        
        return {
            "total_tokens": estimated_tokens,
            "total_characters": char_count,
            "chars_per_token_ratio": chars_per_token,
            "estimated": True,
            "model": model_key
        }
    
    def _estimate_tokens_chars(self, text: str) -> int:
        """
        General token estimation based on character count.
        Uses the common approximation of 1 token ≈ 4 characters.
        """
        return max(1, len(text) // 4)
    
    def count_tokens_for_messages(self, messages: List[Dict], provider: str, model: str) -> Dict[str, int]:
        """
        Count tokens for a list of chat messages.
        
        Args:
            messages (List[Dict]): List of message dictionaries with 'role' and 'content'
            provider (str): 'gemini' or 'fireworks'
            model (str): Model name/key
            
        Returns:
            Dict[str, int]: Token count information
        """
        # Combine all message content
        combined_text = ""
        for message in messages:
            role = message.get("role", "")
            content = message.get("content", "")
            # Add role formatting that's typically used in chat
            combined_text += f"{role}: {content}\n"
        
        if provider.lower() == "gemini":
            return self.count_gemini_tokens(combined_text, model)
        elif provider.lower() == "fireworks":
            return self.count_fireworks_tokens(combined_text, model)
        else:
            raise ValueError(f"Unsupported provider: {provider}")
    
    def estimate_output_tokens(self, input_tokens: int, task_type: str = "general") -> Dict[str, int]:
        """
        Estimate output tokens based on input and task type.
        
        Args:
            input_tokens (int): Number of input tokens
            task_type (str): Type of task - 'general', 'reasoning', 'code', 'summary'
            
        Returns:
            Dict[str, int]: Estimated output token ranges
        """
        ratios = {
            "general": (0.2, 1.0),      # 20% to 100% of input
            "reasoning": (1.0, 3.0),    # 100% to 300% of input (for reasoning models)
            "code": (0.5, 2.0),         # 50% to 200% of input
            "summary": (0.1, 0.3),      # 10% to 30% of input
            "translation": (0.8, 1.2),  # 80% to 120% of input
        }
        
        min_ratio, max_ratio = ratios.get(task_type, ratios["general"])
        
        return {
            "estimated_min_output_tokens": int(input_tokens * min_ratio),
            "estimated_max_output_tokens": int(input_tokens * max_ratio),
            "task_type": task_type
        }
    
    def calculate_cost_estimate(self, input_tokens: int, output_tokens: int, 
                              provider: str, model: str) -> Dict[str, float]:
        """
        Calculate estimated cost based on token counts.
        
        Args:
            input_tokens (int): Number of input tokens
            output_tokens (int): Number of output tokens
            provider (str): 'gemini' or 'fireworks'
            model (str): Model name/key
            
        Returns:
            Dict[str, float]: Cost breakdown
        """
        # Pricing per 1M tokens (approximate, as of 2025)
        pricing = {
            "gemini": {
                "gemini-2.0-flash": {"input": 0.075, "output": 0.30},
                "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
                "gemini-1.5-pro": {"input": 1.25, "output": 5.00}
            },
            "fireworks": {
                "deepseek-v3": {"input": 0.27, "output": 1.10},
                "deepseek-r1": {"input": 8.00, "output": 8.00},  # Fireworks pricing
                "qwen3-30b": {"input": 0.90, "output": 0.90},
                "qwen3-235b": {"input": 9.00, "output": 9.00}
            }
        }
        
        if provider not in pricing or model not in pricing[provider]:
            return {"error": f"Pricing not available for {provider}/{model}"}
        
        rates = pricing[provider][model]
        
        input_cost = (input_tokens / 1_000_000) * rates["input"]
        output_cost = (output_tokens / 1_000_000) * rates["output"]
        total_cost = input_cost + output_cost
        
        return {
            "input_cost_usd": round(input_cost, 6),
            "output_cost_usd": round(output_cost, 6),
            "total_cost_usd": round(total_cost, 6),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "provider": provider,
            "model": model
        }


def create_token_counter() -> TokenCounter:
    """
    Factory function to create a TokenCounter instance.
    """
    return TokenCounter()


# ========== STANDALONE RESPONSE ANALYSIS FUNCTIONS ==========

def analyze_response(prompt: str, response: str, provider: str, model: str, 
                    task_type: str = "general") -> Dict[str, Any]:
    """
    Comprehensive analysis of an LLM response including token counts and cost estimation.
    
    Args:
        prompt (str): The original prompt sent to the LLM
        response (str): The LLM's response
        provider (str): 'gemini' or 'fireworks'
        model (str): Model name/key
        task_type (str): Type of task for better analysis
        
    Returns:
        Dict[str, Any]: Complete analysis including tokens, cost, and metrics
    """
    counter = TokenCounter()
    
    # Count input tokens
    if provider.lower() == "gemini":
        input_tokens = counter.count_gemini_tokens(prompt, model)
        output_tokens = counter.count_gemini_tokens(response, model)
    elif provider.lower() == "fireworks":
        input_tokens = counter.count_fireworks_tokens(prompt, model)
        output_tokens = counter.count_fireworks_tokens(response, model)
    else:
        raise ValueError(f"Unsupported provider: {provider}")
    
    # Calculate cost
    cost_info = counter.calculate_cost_estimate(
        input_tokens.get("total_tokens", 0),
        output_tokens.get("total_tokens", 0),
        provider,
        model
    )
    
    # Calculate basic metrics
    response_length = len(response)
    words_generated = len(response.split())
    
    # Efficiency metrics
    chars_per_token = response_length / max(1, output_tokens.get("total_tokens", 1))
    cost_per_word = cost_info.get("total_cost_usd", 0) / max(1, words_generated)
    
    return {
        "input_analysis": input_tokens,
        "output_analysis": output_tokens,
        "cost_breakdown": cost_info,
        "response_metrics": {
            "character_count": response_length,
            "word_count": words_generated,
            "chars_per_output_token": round(chars_per_token, 2),
            "cost_per_word_usd": round(cost_per_word, 6)
        },
        "metadata": {
            "provider": provider,
            "model": model,
            "task_type": task_type
        }
    }


def count_tokens(text: str, provider: str, model: str) -> Dict[str, int]:
    """
    Simple token counting function for any text.
    
    Args:
        text (str): Text to count tokens for
        provider (str): 'gemini' or 'fireworks'
        model (str): Model name/key
        
    Returns:
        Dict[str, int]: Token count information
    """
    counter = TokenCounter()
    
    if provider.lower() == "gemini":
        return counter.count_gemini_tokens(text, model)
    elif provider.lower() == "fireworks":
        return counter.count_fireworks_tokens(text, model)
    else:
        raise ValueError(f"Unsupported provider: {provider}")


def estimate_cost(input_text: str, output_text: str, provider: str, model: str) -> Dict[str, float]:
    """
    Estimate cost for a complete request/response pair.
    
    Args:
        input_text (str): The prompt/input text
        output_text (str): The response text
        provider (str): 'gemini' or 'fireworks'
        model (str): Model name/key
        
    Returns:
        Dict[str, float]: Cost breakdown
    """
    counter = TokenCounter()
    
    # Count tokens for both input and output
    input_tokens = count_tokens(input_text, provider, model)
    output_tokens = count_tokens(output_text, provider, model)
    
    return counter.calculate_cost_estimate(
        input_tokens.get("total_tokens", 0),
        output_tokens.get("total_tokens", 0),
        provider,
        model
    )


def compare_model_efficiency(prompt: str, responses: Dict[str, Dict]) -> Dict[str, Any]:
    """
    Compare efficiency across multiple model responses.
    
    Args:
        prompt (str): The original prompt
        responses (Dict[str, Dict]): Dict with model names as keys and response info as values
                                   Format: {"model_name": {"response": "text", "provider": "gemini/fireworks", "model": "model_key"}}
    
    Returns:
        Dict[str, Any]: Comparison metrics
    """
    results = {}
    
    for model_name, info in responses.items():
        response_text = info["response"]
        provider = info["provider"]
        model = info["model"]
        
        analysis = analyze_response(prompt, response_text, provider, model)
        
        results[model_name] = {
            "total_cost": analysis["cost_breakdown"].get("total_cost_usd", 0),
            "output_tokens": analysis["output_analysis"].get("total_tokens", 0),
            "word_count": analysis["response_metrics"]["word_count"],
            "cost_per_word": analysis["response_metrics"]["cost_per_word_usd"],
            "response_length": analysis["response_metrics"]["character_count"]
        }
    
    # Find best performers
    if results:
        best_cost = min(results.values(), key=lambda x: x["total_cost"])
        best_value = min(results.values(), key=lambda x: x["cost_per_word"])
        
        comparison = {
            "model_results": results,
            "best_cost_model": next(k for k, v in results.items() if v["total_cost"] == best_cost["total_cost"]),
            "best_value_model": next(k for k, v in results.items() if v["cost_per_word"] == best_value["cost_per_word"]),
            "cost_range": {
                "min_cost": best_cost["total_cost"],
                "max_cost": max(v["total_cost"] for v in results.values())
            }
        }
        
        return comparison
    
    return {"error": "No valid responses provided"}


def batch_analyze_responses(conversations: List[Dict]) -> Dict[str, Any]:
    """
    Analyze multiple conversations for token usage patterns.
    
    Args:
        conversations (List[Dict]): List of conversation dicts
                                  Format: [{"prompt": "text", "response": "text", "provider": "gemini/fireworks", "model": "model_key"}]
    
    Returns:
        Dict[str, Any]: Aggregate analysis
    """
    total_cost = 0
    total_input_tokens = 0
    total_output_tokens = 0
    total_words = 0
    provider_stats = {}
    
    for conv in conversations:
        analysis = analyze_response(
            conv["prompt"], 
            conv["response"], 
            conv["provider"], 
            conv["model"]
        )
        
        cost = analysis["cost_breakdown"].get("total_cost_usd", 0)
        input_tokens = analysis["input_analysis"].get("total_tokens", 0)
        output_tokens = analysis["output_analysis"].get("total_tokens", 0)
        words = analysis["response_metrics"]["word_count"]
        
        total_cost += cost
        total_input_tokens += input_tokens
        total_output_tokens += output_tokens
        total_words += words
        
        # Track by provider
        provider = conv["provider"]
        if provider not in provider_stats:
            provider_stats[provider] = {"cost": 0, "requests": 0, "tokens": 0}
        
        provider_stats[provider]["cost"] += cost
        provider_stats[provider]["requests"] += 1
        provider_stats[provider]["tokens"] += (input_tokens + output_tokens)
    
    return {
        "totals": {
            "total_cost_usd": round(total_cost, 6),
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "total_words_generated": total_words,
            "total_conversations": len(conversations)
        },
        "averages": {
            "avg_cost_per_conversation": round(total_cost / max(1, len(conversations)), 6),
            "avg_words_per_response": round(total_words / max(1, len(conversations)), 1),
            "avg_tokens_per_conversation": round((total_input_tokens + total_output_tokens) / max(1, len(conversations)), 1)
        },
        "provider_breakdown": provider_stats
    }


# ========== QUICK USAGE EXAMPLES ==========

def demo_token_analysis():
    """Demo function showing how to use the response analysis tools."""
    
    print("=== Token Analysis Demo ===\n")
    
    # Example prompt and response
    prompt = "Explain machine learning in simple terms"
    response = "Machine learning is a subset of artificial intelligence that enables computers to learn and make decisions from data without being explicitly programmed for every task."
    
    # Analyze a single response
    analysis = analyze_response(prompt, response, "fireworks", "deepseek-v3")
    print("Single Response Analysis:")
    print(f"- Input tokens: {analysis['input_analysis']['total_tokens']}")
    print(f"- Output tokens: {analysis['output_analysis']['total_tokens']}")
    print(f"- Total cost: ${analysis['cost_breakdown']['total_cost_usd']}")
    print(f"- Cost per word: ${analysis['response_metrics']['cost_per_word_usd']}")
    print()
    
    # Count tokens for planning
    token_count = count_tokens("Write a detailed analysis of AI trends in 2025", "gemini", "gemini-2.0-flash")
    print(f"Token count for planning: {token_count['total_tokens']} tokens")
    print()
    
    # Compare multiple responses (example)
    responses = {
        "DeepSeek-V3": {
            "response": response,
            "provider": "fireworks", 
            "model": "deepseek-v3"
        },
        "Gemini-Flash": {
            "response": response,
            "provider": "gemini",
            "model": "gemini-2.0-flash"
        }
    }
    
    comparison = compare_model_efficiency(prompt, responses)
    print("Model Comparison:")
    print(f"- Best cost model: {comparison['best_cost_model']}")
    print(f"- Best value model: {comparison['best_value_model']}")
    print(f"- Cost range: ${comparison['cost_range']['min_cost']:.6f} - ${comparison['cost_range']['max_cost']:.6f}")


if __name__ == "__main__":
    # Run original tests
    counter = TokenCounter()
    
    # Test text
    test_prompt = "Explain quantum computing in simple terms. What are the key principles?"
    
    print("=== Token Counting Examples ===")
    
    # Test Gemini token counting
    try:
        print("\n--- Gemini Token Count ---")
        gemini_result = counter.count_gemini_tokens(test_prompt)
        print(f"Gemini result: {gemini_result}")
    except Exception as e:
        print(f"Gemini test failed: {e}")
    
    # Test Fireworks token counting
    print("\n--- Fireworks Token Count ---")
    fireworks_result = counter.count_fireworks_tokens(test_prompt, "deepseek-v3")
    print(f"Fireworks result: {fireworks_result}")
    
    # Test message counting
    print("\n--- Message Token Count ---")
    messages = [
        {"role": "user", "content": "What is machine learning?"},
        {"role": "assistant", "content": "Machine learning is a subset of AI..."},
        {"role": "user", "content": "Can you give me an example?"}
    ]
    message_result = counter.count_tokens_for_messages(messages, "fireworks", "deepseek-v3")
    print(f"Message tokens: {message_result}")
    
    # Test output estimation
    print("\n--- Output Estimation ---")
    input_tokens = fireworks_result["total_tokens"]
    output_est = counter.estimate_output_tokens(input_tokens, "reasoning")
    print(f"Output estimation: {output_est}")
    
    # Test cost calculation
    print("\n--- Cost Estimation ---")
    cost_est = counter.calculate_cost_estimate(
        input_tokens, 
        output_est["estimated_max_output_tokens"], 
        "fireworks", 
        "deepseek-v3"
    )
    print(f"Cost estimation: {cost_est}")
    
    print("\n" + "="*50)
    # Demo the new response analysis functions
    demo_token_analysis()

import os
import json
import requests
import dotenv
from typing import Dict, List, Any, Optional, Union
from google import genai
from google.genai import types
import re

# Load environment variables
dotenv.load_dotenv()

class LLM:
    """
    Comprehensive LLM Helper class supporting multiple providers:
    - Google Gemini (basic, tool use, grounding)
    - Fireworks AI (DeepSeek, Qwen models)
    """
    
    def __init__(self, desc: str):
        # Initialize Gemini client
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        if self.gemini_api_key:
            self.gemini_client = genai.Client(api_key=self.gemini_api_key)
        else:
            self.gemini_client = None
            print("Warning: GEMINI_API_KEY not found in environment variables")
        
        # Fireworks AI configuration
        self.fireworks_api_key = os.getenv("FIREWORKS_API_KEY")
        self.fireworks_endpoint = "https://api.fireworks.ai/inference/v1/chat/completions"
        self.fireworks_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.fireworks_api_key}"
        }
        
        # Fireworks model mapping
        self.fireworks_models = {
            "deepseek-v3": "accounts/fireworks/models/deepseek-v3",
            "deepseek-r1": "accounts/fireworks/models/deepseek-r1-0528",
            "qwen3-30b-a3b": "accounts/fireworks/models/qwen3-30b-a3b",
            "qwen2.5-72b-instruct": "accounts/fireworks/models/qwen2p5-72b-instruct"
        }

    # ========== GEMINI FUNCTIONS ==========
    
    def gemini_basic_call(self, prompt: str, model: str = "gemini-2.0-flash") -> str:
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        try:
            response = self.gemini_client.models.generate_content(
                model=model,
                contents=prompt
            )
            return response.text
        except Exception as e:
            raise Exception(f"[gemini_basic_call] Gemini basic call failed: {str(e)}")

    def gemini_tool_use(self, prompt: str, tools: Dict[str, str], model: str = "gemini-2.0-flash") -> Dict:
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        try:         
            # Convert tools to proper format
            tool_objects = []
            
            # Process each function and its description
            for name, description in tools.items():
                # Extract parameters if specified in description
                params = []
                param_match = re.search(r"params=\((.*?)\)", description)
                if param_match:
                    # Extract and clean parameters
                    params = [p.strip() for p in param_match.group(1).split(',')]
                    # Remove the params=(...) from description
                    description = description.replace(param_match.group(0), "").strip()
                
                # Create parameter properties
                properties = {}
                for param in params:
                    properties[param] = {
                        "type": "string",  # Default to string type
                        "description": f"Parameter {param} for the {name} function"
                    }
                
                # Create function declaration
                function_declaration = {
                    "name": name,
                    "description": description,
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": params  # All extracted params are required
                    }
                }
                tool_objects.append(types.Tool(function_declarations=[function_declaration]))
            
            # Create config with tools
            config = types.GenerateContentConfig(tools=tool_objects)
            
            # Create contents
            contents = [types.Content(role="user", parts=[types.Part(text=prompt)])]
            
            response = self.gemini_client.models.generate_content(
                model=model,
                contents=contents,
                config=config
            )
            
            # Extract function calls if any
            function_calls = []
            if response.candidates and len(response.candidates) > 0:
                candidate = response.candidates[0]
                if candidate.content and candidate.content.parts:
                    for part in candidate.content.parts:
                        if hasattr(part, 'function_call') and part.function_call:
                            function_calls.append(part.function_call)
            
            return {
                "text": getattr(response, 'text', ''),
                "function_calls": function_calls,
                "full_response": response
            }
        except Exception as e:
            raise Exception(f"[gemini_tool_use] Gemini tool use failed: {str(e)}")

    def gemini_with_search(self, prompt: str, model: str = "gemini-1.5-flash", dynamic_threshold: float = 0.3) -> str:
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        try:            
            # For Gemini 2.0, use Search as a tool
            if "2.0" in model:
                # Create search tool for Gemini 2.0
                search_tool = {"google_search": {}}
                if dynamic_threshold != 0.3:  # Only add config if non-default
                    search_tool["google_search"]["dynamic_retrieval_config"] = {
                        "mode": "MODE_DYNAMIC",
                        "dynamic_threshold": dynamic_threshold
                    }
                
                tool_objects = [types.Tool(function_declarations=[], **search_tool)]
                config = types.GenerateContentConfig(tools=tool_objects)
                contents = [types.Content(role="user", parts=[types.Part(text=prompt)])]
                
                response = self.gemini_client.models.generate_content(
                    model=model,
                    contents=contents,
                    config=config
                )
                
                return getattr(response, 'text', '')
            
            # For Gemini 1.5, use grounding with Google Search
            else:
                # Create grounding tool for Gemini 1.5
                grounding_tool = types.Tool(
                    google_search_retrieval={
                        "dynamic_retrieval_config": {
                            "mode": "MODE_DYNAMIC",
                            "dynamic_threshold": dynamic_threshold
                        }
                    }
                )
                
                config = types.GenerateContentConfig(tools=[grounding_tool])
                contents = [types.Content(role="user", parts=[types.Part(text=prompt)])]
                
                response = self.gemini_client.models.generate_content(
                    model=model,
                    contents=contents,
                    config=config
                )
                
                return getattr(response, 'text', '')
                
        except Exception as e:
            raise Exception(f"[gemini_with_search] Gemini grounding call failed: {str(e)}")

    def gemini_reasoning_call(self, prompt: str, model: str = "gemini-2.5-pro-preview-05-06", 
                             include_thoughts: bool = True, thinking_budget: Optional[int] = None,
                             temperature: float = 0.3) -> str:
       
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        # Validate model supports thinking
        if "2.5" not in model:
            raise ValueError("Thinking is only supported on Gemini 2.5 series models")
        
        try:
            # Create thinking config
            thinking_config = types.ThinkingConfig(include_thoughts=include_thoughts)
            
            # Add thinking budget if specified and model supports it
            if thinking_budget is not None:
                if "flash" in model.lower():
                    thinking_config.thinking_budget = thinking_budget
                else:
                    print("Warning: thinking_budget is only supported for Flash models, ignoring parameter")
            
            # Create generation config with thinking and temperature
            config = types.GenerateContentConfig(
                thinking_config=thinking_config,
                temperature=temperature
            )
            
            # Generate content
            response = self.gemini_client.models.generate_content(
                model=model,
                contents=prompt,
                config=config
            )
            
            # Extract thought summary and main response
            thought_summary = ""
            main_response = ""
            
            if response.candidates and len(response.candidates) > 0:
                candidate = response.candidates[0]
                if candidate.content and candidate.content.parts:
                    for part in candidate.content.parts:
                        if hasattr(part, 'text') and part.text:
                            if hasattr(part, 'thought') and part.thought:
                                thought_summary = part.text
                            else:
                                main_response = part.text
            
            return main_response
                
        except Exception as e:
            raise Exception(f"[gemini_reasoning_call] Gemini reasoning call failed: {str(e)}")

    # ========== FIREWORKS AI FUNCTIONS ==========
    
    def fireworks_call(self, prompt: str, model_key: str, max_tokens: int = 4096, 
                      temperature: float = 0.5, system_prompt: Optional[str] = None, reasoning: bool = False) -> str:
        
        if model_key not in self.fireworks_models:
            raise ValueError(f"Unknown model key: {model_key}. Available: {list(self.fireworks_models.keys())}")
        
        model = self.fireworks_models[model_key]
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages
        }
        
        # Only add reasoning_effort: "none" when reasoning is False
        if not reasoning:
            payload["reasoning_effort"] = "none"
        if reasoning:
            payload["reasoning_effort"] = "low"
        
        try:
            response = requests.post(
                self.fireworks_endpoint,
                headers=self.fireworks_headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            response_json = response.json()
            content = response_json["choices"][0]["message"]["content"]
            
            # If reasoning is enabled, extract thinking content
            if reasoning:
                thinking_content = ""
                main_content = content
                
                # Extract content within <think></think> tags
                think_match = re.search(r'<think>(.*?)</think>', content, re.DOTALL)
                if think_match:
                    thinking_content = think_match.group(1).strip()
                    # Remove the <think></think> section from main content
                    main_content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
                    print(f"THINKING CONTENT: {thinking_content}")
                
                return content
            else:
                return content

        except requests.exceptions.RequestException as e:
            raise Exception(f"[fireworks_call] Fireworks API call failed: {str(e)}")
        except json.JSONDecodeError as e:
            raise Exception(f"[fireworks_call] Failed to parse Fireworks API response: {str(e)}")
        except (KeyError, IndexError) as e:
            raise Exception(f"[fireworks_call] Failed to extract content from Fireworks response: {str(e)}")


    def fireworks_tool_use(self, prompt: str, tools: Dict[str, str], 
                                model_key: str = "qwen3-235b", max_tokens: int = 4096,
                                temperature: float = 0.3, system_prompt: Optional[str] = None) -> Dict:
        
        if model_key not in self.fireworks_models:
            raise ValueError(f"Unknown model key: {model_key}. Available: {list(self.fireworks_models.keys())}")
        
        model = self.fireworks_models[model_key]
        
        # Convert tools dict to Fireworks format
        formatted_tools = []
        for name, description in tools.items():
            # Extract parameters if specified in description
            params = []
            param_match = re.search(r"params=\((.*?)\)", description)
            if param_match:
                # Extract and clean parameters
                params = [p.strip() for p in param_match.group(1).split(',')]
                # Remove the params=(...) from description
                description = description.replace(param_match.group(0), "").strip()
            
            # Create parameter properties
            properties = {}
            for param in params:
                properties[param] = {
                    "type": "string",  # Default to string type
                    "description": f"Parameter {param} for the {name} function"
                }
            
            # Create function declaration in Fireworks format
            formatted_tools.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": params  # All extracted params are required
                    }
                }
            })
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
            "tools": formatted_tools,
            "tool_choice": "auto"
        }
        
        try:
            response = requests.post(
                self.fireworks_endpoint,
                headers=self.fireworks_headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            response_json = response.json()
            message = response_json["choices"][0]["message"]
            
            return {
                "content": message.get("content", ""),
                "tool_calls": message.get("tool_calls", None)
            }
        
        #exception handling
        except requests.exceptions.RequestException as e:
            raise Exception(f"[fireworks_tool_use] Fireworks function calling failed: {str(e)}")
        except json.JSONDecodeError as e:
            raise Exception(f"[fireworks_tool_use] Failed to parse Fireworks API response: {str(e)}")
        except (KeyError, IndexError) as e:
            raise Exception(f"[fireworks_tool_use] Failed to extract data from Fireworks response: {str(e)}")


    def list_available_models(self) -> Dict[str, List[str]]:
        return {
            "gemini": ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"],
            "fireworks": list(self.fireworks_models.keys())
        }


# Example usage and testing
if __name__ == "__main__":
    llm = LLM()
    
    # Test basic Gemini call
    try:
        print("=== Testing Basic Gemini Call ===")
        response = llm.gemini_basic_call("Explain AI in one sentence.")
        print(f"Response: {response}")
        print()
    except Exception as e:
        print(f"Gemini test failed: {e}")
        print()
    
    #Test grounding
    try:
        print("=== Testing Grounding Gemini Call ===")
        response = llm.gemini_with_search("Explain AI in one sentence.")
        print(f"Response: {response}")
        print()
    except Exception as e:
        print(f"Gemini test failed: {e}")
        print()

    # Test reasoning call
    try:
        print("=== Testing Gemini Reasoning Call ===")
        response = llm.gemini_reasoning_call("What is the sum of the first 10 prime numbers? Show your reasoning step by step.")
        print(f"Main Response: {response}")
        print()
    except Exception as e:
        print(f"Gemini reasoning test failed: {e}")
        print()

    #Test function calling
    try:
        print("=== Testing Function Calling ===")
        response = llm.gemini_tool_use("What is machine learning?", [{"name": "get_current_weather", "description": "Get the current weather in a given location", "parameters": {"type": "object", "properties": {"location": {"type": "string", "description": "The city and country to get the weather for, e.g. San Francisco, CA"}}}}])
        print(f"Response: {response}")
        print()
    except Exception as e:
        print(f"Function calling test failed: {e}")
        print()

    # Test Fireworks AI call
    try:
        print("=== Testing Fireworks AI Call ===")
        content = llm.fireworks_call("What is machine learning?", "deepseek-v3")
        print(f"Response: {content}")
        print()
    except Exception as e:
        print(f"Fireworks test failed: {e}")
        print()
    
    # Test Fireworks AI call with reasoning
    try:
        print("=== Testing Fireworks AI Call with Reasoning ===")
        response = llm.fireworks_call("What is the sum of the first 5 prime numbers? Show your reasoning.", "deepseek-r1", reasoning=True)
        print(f"Response: {response}")
        print()
    except Exception as e:
        print(f"Fireworks reasoning test failed: {e}")
        print()
    
    # Show available models
    print("=== Available Models ===")
    models = llm.list_available_models()
    for provider, model_list in models.items():
        print(f"{provider.upper()}: {', '.join(model_list)}")
import os
import json
import requests
import dotenv
from typing import Dict, List, Any, Optional, Union
from google import genai

# Load environment variables
dotenv.load_dotenv()


class LLM:
    """
    Comprehensive LLM Helper class supporting multiple providers:
    - Google Gemini (basic, tool use, grounding)
    - Fireworks AI (DeepSeek, Qwen models)
    """
    
    def __init__(self):
        # Initialize Gemini client
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        if self.gemini_api_key:
            self.gemini_client = genai.Client(api_key=self.gemini_api_key)
        else:
            self.gemini_client = None
            print("Warning: GEMINI_API_KEY not found in environment variables")
        
        # Fireworks AI configuration
        self.fireworks_api_key = "fw_3ZjrbsMd3JtQ2Nn4djdCMbxJ"
        self.fireworks_endpoint = "https://api.fireworks.ai/inference/v1/chat/completions"
        self.fireworks_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.fireworks_api_key}"
        }
        
        # Fireworks model mapping
        self.fireworks_models = {
            "deepseek-v3": "accounts/fireworks/models/deepseek-v3",
            "deepseek-r1": "accounts/fireworks/models/deepseek-r1",
            "qwen3-30b": "accounts/fireworks/models/qwen3-30b-a3b",
            "qwen3-235b": "accounts/fireworks/models/qwen2p5-72b-instruct"
        }

    # ========== GEMINI FUNCTIONS ==========
    
    def gemini_basic_call(self, prompt: str, model: str = "gemini-2.0-flash") -> str:
        """
        Basic Gemini API call
        
        Args:
            prompt (str): The prompt to send to Gemini
            model (str): The Gemini model to use
            
        Returns:
            str: The generated response text
        """
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        try:
            response = self.gemini_client.models.generate_content(
                model=model,
                contents=prompt
            )
            return response.text
        except Exception as e:
            raise Exception(f"Gemini basic call failed: {str(e)}")

    def gemini_tool_use(self, prompt: str, tools: List[Dict], model: str = "gemini-2.0-flash") -> Dict:
        """
        Gemini API call with tool use functionality
        
        Args:
            prompt (str): The prompt to send to Gemini
            tools (List[Dict]): List of tool definitions (function declarations)
            model (str): The Gemini model to use
            
        Returns:
            Dict: The complete response including tool calls
        """
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        try:
            from google.genai import types
            
            # Convert tools to proper format
            tool_objects = []
            for tool in tools:
                if isinstance(tool, dict):
                    # If it's a function declaration dict, wrap it in Tool
                    tool_objects.append(types.Tool(function_declarations=[tool]))
                else:
                    # If it's already a Tool object, use as is
                    tool_objects.append(tool)
            
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
            raise Exception(f"Gemini tool use failed: {str(e)}")

    def gemini_with_search(self, prompt: str, model: str = "gemini-1.5-flash", 
                            dynamic_threshold: float = 0.3) -> Dict:
        """
        Gemini API call with Google Search grounding
        
        Args:
            prompt (str): The prompt to send to Gemini
            model (str): The Gemini model to use (gemini-1.5-* for grounding)
            dynamic_threshold (float): Dynamic retrieval threshold (0-1)
            
        Returns:
            Dict: Response with grounding metadata and search suggestions
        """
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        try:
            from google.genai import types
            
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
                
                return {
                    "text": getattr(response, 'text', ''),
                    "grounding_metadata": getattr(response, 'grounding_metadata', None),
                    "search_suggestions": getattr(response, 'search_suggestions', None),
                    "full_response": response
                }
            
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
                
                return {
                    "text": getattr(response, 'text', ''),
                    "grounding_metadata": getattr(response, 'grounding_metadata', None),
                    "search_suggestions": getattr(response, 'search_suggestions', None),
                    "full_response": response
                }
                
        except Exception as e:
            raise Exception(f"Gemini grounding call failed: {str(e)}")

    # ========== FIREWORKS AI FUNCTIONS ==========
    
    def fireworks_call(self, prompt: str, model_key: str, max_tokens: int = 4096, 
                      temperature: float = 0.3, system_prompt: Optional[str] = None) -> str:
        """
        Call Fireworks AI models
        
        Args:
            prompt (str): User prompt
            model_key (str): Model key from fireworks_models dict
            max_tokens (int): Maximum tokens to generate
            temperature (float): Temperature for generation
            system_prompt (str, optional): System prompt
            
        Returns:
            str: Generated content
        """
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
        
        try:
            response = requests.post(
                self.fireworks_endpoint,
                headers=self.fireworks_headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            response_json = response.json()
            return response_json["choices"][0]["message"]["content"]
        except requests.exceptions.RequestException as e:
            raise Exception(f"Fireworks API call failed: {str(e)}")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse Fireworks API response: {str(e)}")
        except (KeyError, IndexError) as e:
            raise Exception(f"Failed to extract content from Fireworks response: {str(e)}")

    def fireworks_tool_use(self, prompt: str, functions: List[Dict], 
                                model_key: str = "qwen3-235b", max_tokens: int = 4096,
                                temperature: float = 0.3, system_prompt: Optional[str] = None) -> Dict:
        """
        Call Fireworks AI with function calling (mainly for qwen3-235b)
        
        Args:
            prompt (str): User prompt
            functions (List[Dict]): Function definitions
            model_key (str): Model key (preferably qwen3-235b for function calling)
            max_tokens (int): Maximum tokens to generate
            temperature (float): Temperature for generation
            system_prompt (str, optional): System prompt
            
        Returns:
            Dict: Contains 'content' (str) and 'tool_calls' (Optional[List[Dict]])
        """
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
            "messages": messages,
            "tools": functions,
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
        except requests.exceptions.RequestException as e:
            raise Exception(f"Fireworks function calling failed: {str(e)}")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse Fireworks API response: {str(e)}")
        except (KeyError, IndexError) as e:
            raise Exception(f"Failed to extract data from Fireworks response: {str(e)}")

    def list_available_models(self) -> Dict[str, List[str]]:
        """
        List all available models by provider
        
        Returns:
            Dict: Available models grouped by provider
        """
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
    
    # Show available models
    print("=== Available Models ===")
    models = llm.list_available_models()
    for provider, model_list in models.items():
        print(f"{provider.upper()}: {', '.join(model_list)}")
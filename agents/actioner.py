import re
from typing import Dict, List, Any, Optional, Union
from tools.llms import LLM

ACTIONER_SYSTEM_PROMPT = """
You are a security testing agent with specific tools at your disposal. You MUST use these tools to actively test the website for security vulnerabilities.

ALWAYS format your response using EXACTLY this structure:

* DISCUSSION
[Your analysis of the security situation and testing strategy. Be specific about what vulnerabilities you're looking for.]

* ACTION
[Exactly ONE tool command with proper syntax and all required parameters]

VALID TOOL COMMANDS - USE THESE EXACT FORMATS:
- goto(page, "https://example.com") - Navigate to a URL
- click(page, "a.nav-link") - Click an element using CSS selector
- fill(page, "#input-field", "test value") - Fill a form field with value
- submit(page, "form#login") - Submit a form
- execute_js(page, "() => { return document.cookie }") - Execute JavaScript code
- auth_needed() - Signal that authentication is required
- refresh(page) - Refresh the current page
- complete() - Mark the current test plan as complete
- python_interpreter("print('test')") - Execute Python code
- get_user_input("Enter value:") - Request user input
- presskey(page, "Enter") - Press a keyboard key

CRITICAL RULES:
1. ALWAYS include the 'page' parameter as the FIRST parameter for all page interactions
2. NEVER use natural language in the ACTION section - only use valid tool commands
3. NEVER try to combine multiple actions - use only ONE command per response
4. ALWAYS use properly formatted and balanced quotes in selectors
5. Do not include explanations or notes in the ACTION section
6. You must perform at least 3 meaningful security testing actions before using complete()

CRITICAL URL FORMATTING:
- NEVER use plain text like "documentation" for URLs
- ALWAYS use proper URL paths starting with "/" like "/docs/"
- Documentation pages should be referenced as "/docs/" not as "documentation"

EXAMPLES OF CORRECT URL NAVIGATION:
✅ goto(page, "/docs/")
✅ goto(page, "/api/v1/users")
✅ goto(page, "https://example.com/docs") 

EXAMPLES OF INCORRECT URL NAVIGATION:
❌ goto(page, "documentation")
❌ goto(page, "docs page")
❌ goto("documentation")

SECURITY TESTING FOCUS:
- SQL Injection: Test forms with payloads like "admin' OR '1'='1", "'; DROP TABLE users; --"
- XSS: Test inputs with "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"
- Authentication Bypass: Test login forms with various bypass techniques
- Authorization: Test access to admin panels, API endpoints with different privileges
- Information Disclosure: Look for error messages, debug info, sensitive data exposure
- Session Management: Test session tokens, cookies, CSRF protection
- File Upload: Test malicious file uploads if upload functionality exists
- Directory Traversal: Test for "../" path traversal vulnerabilities

JAVASCRIPT EXECUTION EXAMPLES:
✅ execute_js(page, "() => { return document.title }")
✅ execute_js(page, "() => { return document.cookie }")
✅ execute_js(page, "() => { return localStorage.getItem('token') }")
✅ execute_js(page, "() => { return document.querySelector('input[name=\"csrf\"]').value }")

INCORRECT (WILL CAUSE ERRORS):
* ACTION
Let's navigate to the documentation page

CORRECT:
* ACTION
goto(page, "/docs/")

Remember: Each response must contain exactly ONE tool command in the ACTION section.
"""


class ActionerAgent:
    """
    Security test execution agent that takes test plans and generates
    specific tool commands for security testing using LLM analysis.
    """
    
    def __init__(self, desc: str, 
                 llm_type: str = "gemini_basic",
                 model: str = "gemini-2.0-flash",
                 fireworks_model_key: str = "deepseek-v3",
                 temperature: float = 0.3,
                 reasoning_config: Optional[Dict] = None):
        self.llm = LLM(desc="gemini-2.0-flash for security testing execution")
        self.conversation_history = []
        self.actions_performed = 0
        self.min_actions_required = 3
        
        # LLM configuration
        self.llm_type = llm_type  # "gemini_basic", "gemini_reasoning", "fireworks"
        self.model = model
        self.fireworks_model_key = fireworks_model_key
        self.temperature = temperature
        self.reasoning_config = reasoning_config or {
            "include_thoughts": True,
            "thinking_budget": None
        }
        
    def generate_action_of_plan_step(self, 
                         plan: Dict[str, str], 
                         page_data: str = "", 
                         tool_output: str = "",
                         conversation_history: Optional[List[str]] = None) -> Dict[str, str]:
        try:
            # Update conversation history
            if conversation_history:
                self.conversation_history = conversation_history
            
            # Build the prompt for the LLM
            prompt = self._build_execution_prompt(plan, page_data, tool_output)
            
            # Call LLM to get the response
            llm_response = self._call_llm(prompt)
            
            # Parse the response to extract discussion and action
            parsed_response = self._parse_actioner_response(llm_response)
            
            # Validate the action command
            validated_response = self._validate_action(parsed_response)
            
            # Update conversation history
            self._update_conversation_history(plan, parsed_response, tool_output)
            
            return validated_response
            
        except Exception as e:
            print(f"Error in plan execution: {str(e)}")
            return self._get_fallback_action(plan)
    
    def _build_execution_prompt(self, plan: Dict[str, str], page_data: str, tool_output: str) -> Union[str, Dict[str, str]]:
        # Extract plan details
        plan_title = plan.get('title', 'Security Test')
        plan_description = plan.get('description', 'Perform security testing')
        
        # Build conversation context
        context_section = ""
        if self.conversation_history:
            context_section = "\n\nPREVIOUS CONVERSATION CONTEXT:\n"
            for entry in self.conversation_history[-5:]:  # Last 5 entries for context
                context_section += f"{entry}\n"
        
        # Build page data section
        page_section = ""
        if page_data:
            page_section = f"\n\nCURRENT PAGE DATA:\n{page_data[:2000]}..."  # Limit to 2000 chars
        
        # Build tool output section
        tool_section = ""
        if tool_output:
            tool_section = f"\n\nPREVIOUS TOOL OUTPUT:\n{tool_output[:1000]}..."  # Limit to 1000 chars
        
        # Build actions performed section
        actions_section = f"\n\nACTIONS PERFORMED SO FAR: {self.actions_performed}"
        if self.actions_performed < self.min_actions_required:
            actions_section += f" (Need at least {self.min_actions_required} actions before completion)"
        
        # Construct the base prompt
        base_prompt = f"""
            {ACTIONER_SYSTEM_PROMPT}

            CURRENT TEST PLAN:
            Title: {plan_title}
            Description: {plan_description}
            {context_section}
            {page_section}
            {tool_section}
            {actions_section}

            Based on the test plan and current context, provide your next security testing action.
            Remember to follow the exact format with * DISCUSSION and * ACTION sections.
        """
        
        # Return the appropriate prompt format based on LLM type
        if self.llm_type == "fireworks":
            # For Fireworks, we need to separate system and user prompts
            return {
                "system_prompt": ACTIONER_SYSTEM_PROMPT,
                "user_prompt": f"""
                    CURRENT TEST PLAN:
                    Title: {plan_title}
                    Description: {plan_description}
                    {context_section}
                    {page_section}
                    {tool_section}
                    {actions_section}

                    Based on the test plan and current context, provide your next security testing action.
                    Remember to follow the exact format with * DISCUSSION and * ACTION sections.
                """
            }
        else:
            # For Gemini models, use combined prompt
            return base_prompt
    
    def _call_llm(self, prompt: Union[str, Dict[str, str]]) -> str:
        try:
            if self.llm_type == "gemini_basic":
                # Standard Gemini call
                if isinstance(prompt, dict):
                    # If we got a dict (shouldn't happen for gemini_basic), use combined prompt
                    combined_prompt = f"{prompt['system_prompt']}\n\n{prompt['user_prompt']}"
                    response = self.llm.gemini_basic_call(combined_prompt, model=self.model)
                else:
                    response = self.llm.gemini_basic_call(prompt, model=self.model)
                return response
                
            elif self.llm_type == "gemini_reasoning":
                # Gemini reasoning call with thinking
                if isinstance(prompt, dict):
                    # If we got a dict, use combined prompt
                    combined_prompt = f"{prompt['system_prompt']}\n\n{prompt['user_prompt']}"
                else:
                    combined_prompt = prompt
                
                response = self.llm.gemini_reasoning_call(
                    combined_prompt, 
                    model=self.model,
                    include_thoughts=self.reasoning_config.get("include_thoughts", True),
                    thinking_budget=self.reasoning_config.get("thinking_budget")
                )
                
                # For reasoning calls, we get a dict with 'text' and optional 'thought_summary'
                main_response = response.get('text', '')
                thought_summary = response.get('thought_summary', '')
                
                # Optionally include thought summary in response for debugging
                if thought_summary and self.reasoning_config.get("include_thoughts", True):
                    return f"THINKING: {thought_summary}\n\nRESPONSE: {main_response}"
                else:
                    return main_response
                
            elif self.llm_type == "fireworks":
                # Fireworks API call
                if isinstance(prompt, dict):
                    system_prompt = prompt.get('system_prompt', '')
                    user_prompt = prompt.get('user_prompt', '')
                else:
                    # If single string, treat as user prompt with no system prompt
                    system_prompt = ACTIONER_SYSTEM_PROMPT
                    user_prompt = prompt
                
                response = self.llm.fireworks_call(
                    user_prompt,
                    model_key=self.fireworks_model_key,
                    temperature=self.temperature,
                    system_prompt=system_prompt
                )
                return response
                
            else:
                raise ValueError(f"Unsupported LLM type: {self.llm_type}")
                
        except Exception as e:
            print(f"LLM call failed: {str(e)}")
            raise
    
    def _parse_actioner_response(self, response: str) -> Dict[str, str]:
        try:
            # Initialize result
            result = {
                'discussion': '',
                'action': ''
            }
            
            # Clean up the response
            response = response.strip()
            
            # Handle reasoning response format if present
            if "THINKING:" in response and "RESPONSE:" in response:
                # Extract just the response part for parsing
                response_match = re.search(r'RESPONSE:\s*(.*)', response, re.DOTALL)
                if response_match:
                    response = response_match.group(1).strip()
            
            # Extract DISCUSSION section
            discussion_pattern = r'\*\s*DISCUSSION\s*\n(.*?)(?=\*\s*ACTION|\Z)'
            discussion_match = re.search(discussion_pattern, response, re.DOTALL | re.IGNORECASE)
            
            if discussion_match:
                result['discussion'] = discussion_match.group(1).strip()
            
            # Extract ACTION section
            action_pattern = r'\*\s*ACTION\s*\n(.*?)(?=\*\s*\w+|\Z)'
            action_match = re.search(action_pattern, response, re.DOTALL | re.IGNORECASE)
            
            if action_match:
                result['action'] = action_match.group(1).strip()
            
            # If no structured format found, try to extract any tool command
            if not result['action']:
                result['action'] = self._extract_tool_command_fallback(response)
            
            # If no discussion found, provide a default
            if not result['discussion']:
                result['discussion'] = "Continuing security testing based on the current plan."
            
            return result
            
        except Exception as e:
            print(f"Response parsing error: {str(e)}")
            return {
                'discussion': 'Error parsing response, proceeding with fallback action.',
                'action': 'goto(page, "/docs/")'
            }
    
    def _extract_tool_command_fallback(self, response: str) -> str:        
        # List of valid tool commands
        valid_commands = [
            'goto', 'click', 'fill', 'submit', 'execute_js', 
            'auth_needed', 'refresh', 'complete', 'python_interpreter', 
            'get_user_input', 'presskey'
        ]
        
        # Try to find any valid tool command
        for command in valid_commands:
            pattern = rf'{command}\s*\([^)]*\)'
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                return match.group(0)
        
        # If no tool command found, return a safe default
        return 'goto(page, "/docs/")'
    
    def _validate_action(self, response: Dict[str, str]) -> Dict[str, str]:        
        action = response.get('action', '').strip()
        
        # List of valid tool commands with their expected patterns
        valid_patterns = {
            'goto': r'goto\s*\(\s*page\s*,\s*["\'][^"\']*["\']\s*\)',
            'click': r'click\s*\(\s*page\s*,\s*["\'][^"\']*["\']\s*\)',
            'fill': r'fill\s*\(\s*page\s*,\s*["\'][^"\']*["\']\s*,\s*["\'][^"\']*["\']\s*\)',
            'submit': r'submit\s*\(\s*page\s*,\s*["\'][^"\']*["\']\s*\)',
            'execute_js': r'execute_js\s*\(\s*page\s*,\s*["\'][^"\']*["\']\s*\)',
            'auth_needed': r'auth_needed\s*\(\s*\)',
            'refresh': r'refresh\s*\(\s*page\s*\)',
            'complete': r'complete\s*\(\s*\)',
            'python_interpreter': r'python_interpreter\s*\(\s*["\'][^"\']*["\']\s*\)',
            'get_user_input': r'get_user_input\s*\(\s*["\'][^"\']*["\']\s*\)',
            'presskey': r'presskey\s*\(\s*page\s*,\s*["\'][^"\']*["\']\s*\)'
        }
        
        # Check if action matches any valid pattern
        is_valid = False
        for command, pattern in valid_patterns.items():
            if re.match(pattern, action, re.IGNORECASE):
                is_valid = True
                break
        
        # If action is not valid, try to fix common issues
        if not is_valid:
            action = self._fix_action_command(action)
        
        # Update actions performed count (except for complete)
        if not action.startswith('complete'):
            self.actions_performed += 1
        
        # Ensure we don't complete too early
        if action.startswith('complete') and self.actions_performed < self.min_actions_required:
            action = 'goto(page, "/docs/")'  # Force more testing
            response['discussion'] += f" (Need {self.min_actions_required - self.actions_performed} more actions before completion)"
        
        response['action'] = action
        return response
    
    def _fix_action_command(self, action: str) -> str:        
        # Remove any extra text after the command
        action = re.sub(r'\).*$', ')', action)
        
        # Fix missing page parameter for page-interactive commands
        page_commands = ['goto', 'click', 'fill', 'submit', 'execute_js', 'refresh', 'presskey']
        for cmd in page_commands:
            if action.startswith(cmd) and 'page' not in action:
                # Insert page parameter
                action = re.sub(rf'^{cmd}\s*\(', f'{cmd}(page, ', action)
        
        # Fix unbalanced quotes
        if action.count('"') % 2 != 0:
            action += '"'
        if action.count("'") % 2 != 0:
            action += "'"
        
        # Fix missing closing parenthesis
        if action.count('(') > action.count(')'):
            action += ')'
        
        # If still invalid, return a safe default
        if not any(cmd in action for cmd in ['goto', 'click', 'fill', 'submit', 'execute_js', 'auth_needed', 'refresh', 'complete']):
            return 'goto(page, "/docs/")'
        
        return action
    
    def _update_conversation_history(self, plan: Dict[str, str], response: Dict[str, str], tool_output: str):        
        plan_title = plan.get('title', 'Security Test')
        discussion = response.get('discussion', '')
        action = response.get('action', '')
        
        # Add the interaction to history
        history_entry = f"Plan: {plan_title}\nDiscussion: {discussion}\nAction: {action}"
        if tool_output:
            history_entry += f"\nResult: {tool_output[:500]}..."
        
        self.conversation_history.append(history_entry)
        
        # Keep only the last 10 entries to manage memory
        if len(self.conversation_history) > 10:
            self.conversation_history = self.conversation_history[-10:]
    
    def _get_fallback_action(self, plan: Dict[str, str]) -> Dict[str, str]:        
        plan_title = plan.get('title', '').lower()
        plan_description = plan.get('description', '').lower()
        
        # Determine appropriate fallback based on plan content
        if any(term in plan_title or term in plan_description for term in ['sql', 'injection', 'login']):
            action = 'goto(page, "/login/")'
            discussion = "Navigating to login page to begin SQL injection testing."
        elif any(term in plan_title or term in plan_description for term in ['xss', 'cross-site', 'script']):
            action = 'goto(page, "/search/")'
            discussion = "Navigating to search functionality to test for XSS vulnerabilities."
        elif any(term in plan_title or term in plan_description for term in ['api', 'authorization', 'idor']):
            action = 'goto(page, "/api/")'
            discussion = "Navigating to API endpoints to test authorization mechanisms."
        elif any(term in plan_title or term in plan_description for term in ['admin', 'privilege']):
            action = 'goto(page, "/admin/")'
            discussion = "Navigating to admin panel to test access controls."
        else:
            action = 'goto(page, "/docs/")'
            discussion = "Starting security assessment by examining the application documentation."
        
        return {
            'discussion': discussion,
            'action': action
        }
    
    def reset_session(self):
        self.conversation_history = []
        self.actions_performed = 0
    
    def get_conversation_history(self) -> List[str]:
        return self.conversation_history.copy()
    
    def set_min_actions(self, min_actions: int):
        self.min_actions_required = max(1, min_actions)
    
    def configure_llm(self, llm_type: str, **kwargs):
        """Configure the LLM type and parameters"""
        self.llm_type = llm_type
        
        if 'model' in kwargs:
            self.model = kwargs['model']
        if 'fireworks_model_key' in kwargs:
            self.fireworks_model_key = kwargs['fireworks_model_key']
        if 'temperature' in kwargs:
            self.temperature = kwargs['temperature']
        if 'reasoning_config' in kwargs:
            self.reasoning_config.update(kwargs['reasoning_config'])
    
    def get_llm_config(self) -> Dict[str, Any]:
        """Get current LLM configuration"""
        return {
            'llm_type': self.llm_type,
            'model': self.model,
            'fireworks_model_key': self.fireworks_model_key,
            'temperature': self.temperature,
            'reasoning_config': self.reasoning_config
        }

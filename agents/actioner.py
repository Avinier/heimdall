import re
from typing import Dict, List, Any, Optional, Union
from tools.llms import LLM

ACTIONER_SYSTEM_PROMPT = """
You are an elite security testing agent specializing in Advanced Persistent Threat (APT) simulation and Dynamic Application Security Testing (DAST). You have access to specific tools and must use them to actively test websites for security vulnerabilities with strategic business context awareness.

## Enhanced Security Testing Framework
You will receive comprehensive test plans with strategic business intelligence including:
- **Business Impact**: Financial risk assessment and regulatory compliance implications
- **Attack Complexity**: Required skill level and sophisticated techniques needed
- **Compliance Risk**: Specific regulatory standards and frameworks affected

## Strategic Testing Prioritization
Adjust your testing approach based on business impact levels:
- **CRITICAL/CATASTROPHIC**: Focus on advanced persistent threat techniques, financial system compromise, and regulatory compliance violations
- **HIGH**: Implement sophisticated exploitation chains and enterprise-level attack simulation
- **MEDIUM**: Standard penetration testing with business logic focus
- **LOW**: Configuration and best practice validation

## Attack Complexity Awareness
Tailor your testing techniques based on complexity requirements:
- **EXPERT/VERY HIGH**: Use advanced evasion techniques, sophisticated payload crafting, and multi-vector attack chains
- **HIGH**: Implement business logic exploitation and advanced authorization bypass techniques
- **MEDIUM-HIGH**: Use standard injection techniques with WAF bypass methods
- **MEDIUM**: Apply conventional penetration testing methodologies
- **LOW-MEDIUM**: Focus on reconnaissance and basic vulnerability identification

ALWAYS format your response using EXACTLY this structure:

* DISCUSSION
[Your strategic analysis incorporating business impact, attack complexity, and compliance considerations. 
Reference specific plan details including business_impact, attack_complexity, and compliance_risk when available. Explain your testing approach and expected outcomes.]

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
7. Reference plan's business_impact and attack_complexity in your discussion when available

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

## Advanced Security Testing Methodologies

**CRITICAL/CATASTROPHIC Business Impact Testing:**
- SQL Injection with business logic bypass: "admin' UNION SELECT balance, account_id FROM accounts WHERE '1'='1"
- Advanced XSS with session hijacking: "<script>fetch('/api/transfer',{method:'POST',body:'amount=10000&to=attacker'})</script>"
- JWT manipulation for privilege escalation: Algorithm confusion attacks (HS256 to RS256)
- Financial transaction manipulation through race conditions
- Advanced persistent threat simulation with stealth techniques

**HIGH Business Impact Testing:**
- OAuth 2.0/SAML flow manipulation and federation bypass
- Business logic workflow exploitation and approval process bypass
- Advanced authorization testing with RBAC circumvention
- API security assessment with microservices exploitation
- Session management exploitation with concurrent abuse

**STANDARD Security Testing Focus:**
- SQL Injection: Test forms with payloads like "admin' OR '1'='1", "'; DROP TABLE users; --"
- XSS: Test inputs with "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"
- Authentication Bypass: Test login forms with various bypass techniques
- Authorization: Test access to admin panels, API endpoints with different privileges
- Information Disclosure: Look for error messages, debug info, sensitive data exposure
- Session Management: Test session tokens, cookies, CSRF protection
- File Upload: Test malicious file uploads if upload functionality exists
- Directory Traversal: Test for "../" path traversal vulnerabilities

**Enterprise Compliance Testing:**
- PCI DSS: Focus on payment processing security and cardholder data protection
- GDPR: Test data privacy controls and consent mechanisms
- SOX: Validate financial reporting controls and audit trail integrity
- HIPAA: Assess health information protection and access controls
- ISO 27001: Evaluate information security management controls

JAVASCRIPT EXECUTION EXAMPLES:
✅ execute_js(page, "() => { return document.title }")
✅ execute_js(page, "() => { return document.cookie }")
✅ execute_js(page, "() => { return localStorage.getItem('token') }")
✅ execute_js(page, "() => { return document.querySelector('input[name=\"csrf\"]').value }")
✅ execute_js(page, "() => { fetch('/api/admin/users').then(r=>r.text()).then(console.log) }")

INCORRECT (WILL CAUSE ERRORS):
* ACTION
Let's navigate to the documentation page

CORRECT:
* ACTION
goto(page, "/docs/")

Remember: Each response must contain exactly ONE tool command in the ACTION section. Always reference the plan's strategic context (business_impact, attack_complexity, compliance_risk) in your discussion to demonstrate elite-level security assessment capabilities.
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
        self.min_actions_required = 3
        
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
                         page_data: str = "", 
                         tool_output: str = "",
                         conversation_history: Optional[List[str]] = None) -> Dict[str, str]:
        try:
            # Build the prompt for the LLM using passed conversation history
            prompt = self._build_execution_prompt(plan, page_data, tool_output, conversation_history)
            
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
    
    def _build_execution_prompt(self, plan: Dict[str, str], page_data: str, tool_output: str, conversation_history: Optional[List[str]] = None) -> Union[str, Dict[str, str]]:
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
        
        # Add enhanced fields if available
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
        if page_data:
            page_section = f"\n\nCURRENT PAGE DATA:\n{page_data[:2000]}..."  # Limit to 2000 chars
        
        # Build tool output section
        tool_section = ""
        if tool_output:
            tool_section = f"\n\nPREVIOUS TOOL OUTPUT:\n{tool_output[:1000]}..."  # Limit to 1000 chars
        
        # Build actions performed section with strategic guidance
        actions_section = f"\n\nACTIONS PERFORMED SO FAR: {self.actions_performed}"
        if self.actions_performed < self.min_actions_required:
            actions_section += f" (Need at least {self.min_actions_required} actions before completion)"
        
        # Add strategic testing guidance based on plan context
        strategic_guidance = self._get_strategic_guidance(business_impact, attack_complexity, compliance_risk)
        
        # Construct the base prompt
        base_prompt = f"""
            {ACTIONER_SYSTEM_PROMPT}

            {plan_section}
            {strategic_guidance}
            {context_section}
            {page_section}
            {tool_section}
            {actions_section}

            Based on the enhanced test plan with strategic business context, provide your next security testing action.
            Remember to reference the business impact, attack complexity, and compliance risk in your discussion.
            Follow the exact format with * DISCUSSION and * ACTION sections.
        """
        
        # Return the appropriate prompt format based on api_type
        if self.api_type == "fireworks":
            # For Fireworks, we need to separate system and user prompts
            return {
                "system_prompt": ACTIONER_SYSTEM_PROMPT,
                "user_prompt": f"""
                    {plan_section}
                    {strategic_guidance}
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
    
    def _get_fallback_action(self, plan: Dict[str, str]) -> Dict[str, str]:        
        plan_title = plan.get('title', '').lower()
        plan_description = plan.get('description', '').lower()
        business_impact = plan.get('business_impact', '').lower()
        attack_complexity = plan.get('attack_complexity', '').lower()
        compliance_risk = plan.get('compliance_risk', '').lower()
        
        # Combine all plan text for analysis
        plan_text = f"{plan_title} {plan_description} {business_impact} {attack_complexity} {compliance_risk}"
        
        # Enhanced fallback logic based on plan context
        if any(term in plan_text for term in ['critical', 'catastrophic', 'financial', 'payment', 'transaction']):
            action = 'goto(page, "/api/v1/transactions")'
            discussion = f"Starting CRITICAL business impact assessment by examining financial transaction APIs. Plan indicates {plan.get('business_impact', 'high-risk financial impact')} requiring sophisticated testing approach."
        
        elif any(term in plan_text for term in ['sql', 'injection', 'login', 'authentication']):
            action = 'goto(page, "/login/")'
            discussion = f"Initiating authentication security assessment. Attack complexity: {plan.get('attack_complexity', 'standard')}. Focusing on SQL injection and authentication bypass techniques."
        
        elif any(term in plan_text for term in ['xss', 'cross-site', 'script', 'input', 'validation']):
            action = 'goto(page, "/search/")'
            discussion = f"Beginning input validation testing for XSS vulnerabilities. Business impact: {plan.get('business_impact', 'data compromise risk')}. Implementing systematic payload testing approach."
        
        elif any(term in plan_text for term in ['api', 'authorization', 'idor', 'privilege', 'escalation']):
            action = 'goto(page, "/api/")'
            discussion = f"Commencing API authorization testing. Attack complexity: {plan.get('attack_complexity', 'medium-high')}. Focusing on privilege escalation and IDOR vulnerabilities."
        
        elif any(term in plan_text for term in ['admin', 'administrative', 'access control', 'rbac']):
            action = 'goto(page, "/admin/")'
            discussion = f"Accessing administrative interfaces for access control testing. Compliance risk: {plan.get('compliance_risk', 'access control violations')}. Testing role-based access control mechanisms."
        
        elif any(term in plan_text for term in ['session', 'token', 'jwt', 'oauth', 'saml']):
            action = 'goto(page, "/dashboard/")'
            discussion = f"Initiating session management security assessment. Attack complexity: {plan.get('attack_complexity', 'high')}. Focusing on token manipulation and session hijacking techniques."
        
        elif any(term in plan_text for term in ['information', 'disclosure', 'reconnaissance', 'intelligence']):
            action = 'goto(page, "/docs/")'
            discussion = f"Beginning information disclosure assessment. Business impact: {plan.get('business_impact', 'competitive intelligence exposure')}. Systematic reconnaissance of exposed information."
        
        elif any(term in plan_text for term in ['cloud', 'infrastructure', 'devops', 'container']):
            action = 'goto(page, "/api/health/")'
            discussion = f"Starting infrastructure security assessment. Compliance risk: {plan.get('compliance_risk', 'infrastructure controls')}. Testing cloud and DevOps security posture."
        
        elif any(term in plan_text for term in ['pci dss', 'gdpr', 'sox', 'hipaa', 'iso 27001']):
            action = 'goto(page, "/api/v1/users")'
            discussion = f"Initiating compliance-focused testing. Compliance risk: {plan.get('compliance_risk', 'regulatory violations')}. Validating regulatory security controls."
        
        else:
            action = 'goto(page, "/docs/")'
            discussion = f"Starting comprehensive security assessment. Business impact: {plan.get('business_impact', 'standard risk assessment')}. Beginning with application documentation review."
        
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

    def _get_strategic_guidance(self, business_impact: str, attack_complexity: str, compliance_risk: str) -> str:
        """Generate strategic testing guidance based on plan context."""
        guidance_sections = []
        
        # Business Impact Guidance
        if business_impact:
            impact_level = ""
            if any(term in business_impact.upper() for term in ['CRITICAL', 'CATASTROPHIC']):
                impact_level = "CRITICAL/CATASTROPHIC"
                guidance_sections.append("""
STRATEGIC PRIORITY: CRITICAL/CATASTROPHIC Business Impact
- Focus on financial system compromise and data breach vectors
- Implement advanced persistent threat simulation techniques
- Test for regulatory compliance violations (PCI DSS, GDPR, SOX)
- Use sophisticated evasion and stealth techniques
- Prioritize payment processing and sensitive data access testing""")
            
            elif 'HIGH' in business_impact.upper():
                impact_level = "HIGH"
                guidance_sections.append("""
STRATEGIC PRIORITY: HIGH Business Impact
- Implement enterprise-level attack simulation
- Focus on business continuity threats and administrative access
- Test advanced authorization and session management
- Assess supply chain and third-party integration security
- Evaluate competitive intelligence exposure risks""")
            
            elif 'MEDIUM' in business_impact.upper():
                impact_level = "MEDIUM"
                guidance_sections.append("""
STRATEGIC PRIORITY: MEDIUM Business Impact
- Standard penetration testing with business logic focus
- Test for information disclosure and operational disruption
- Assess internal user compromise vectors
- Validate security best practices implementation""")
            
            elif 'LOW' in business_impact.upper():
                impact_level = "LOW"
                guidance_sections.append("""
STRATEGIC PRIORITY: LOW Business Impact
- Configuration validation and security best practice review
- Focus on technical debt and missing security headers
- Test for verbose error messages and information leakage""")
        
        # Attack Complexity Guidance
        if attack_complexity:
            complexity_guidance = ""
            if any(term in attack_complexity.upper() for term in ['EXPERT', 'VERY HIGH']):
                complexity_guidance = """
ATTACK COMPLEXITY: EXPERT/VERY HIGH
- Use advanced evasion techniques and sophisticated payloads
- Implement multi-vector attack chains and timing attacks
- Apply APT-level stealth and anti-forensics techniques
- Craft custom exploits and zero-day simulation approaches"""
            
            elif 'HIGH' in attack_complexity.upper():
                complexity_guidance = """
ATTACK COMPLEXITY: HIGH
- Implement business logic exploitation techniques
- Use advanced authorization bypass and privilege escalation
- Apply sophisticated session manipulation and CSRF techniques
- Test complex business workflow vulnerabilities"""
            
            elif 'MEDIUM' in attack_complexity.upper():
                complexity_guidance = """
ATTACK COMPLEXITY: MEDIUM-HIGH
- Use standard injection techniques with WAF bypass methods
- Implement conventional authentication and session testing
- Apply systematic input validation testing approaches"""
            
            elif 'LOW' in attack_complexity.upper():
                complexity_guidance = """
ATTACK COMPLEXITY: LOW-MEDIUM
- Focus on reconnaissance and basic vulnerability identification
- Use standard security scanning and validation techniques
- Apply conventional penetration testing methodologies"""
            
            if complexity_guidance:
                guidance_sections.append(complexity_guidance)
        
        # Compliance Risk Guidance
        if compliance_risk:
            compliance_guidance = "\nCOMPLIANCE FOCUS:"
            if 'PCI DSS' in compliance_risk.upper():
                compliance_guidance += "\n- Test payment card data protection and processing security"
                compliance_guidance += "\n- Validate cardholder data encryption and access controls"
            if 'GDPR' in compliance_risk.upper():
                compliance_guidance += "\n- Test personal data protection and consent mechanisms"
                compliance_guidance += "\n- Validate data subject rights and privacy controls"
            if 'SOX' in compliance_risk.upper():
                compliance_guidance += "\n- Test financial reporting controls and audit trail integrity"
                compliance_guidance += "\n- Validate executive certification and internal controls"
            if 'HIPAA' in compliance_risk.upper():
                compliance_guidance += "\n- Test health information protection and access controls"
                compliance_guidance += "\n- Validate patient data privacy and security safeguards"
            if 'ISO 27001' in compliance_risk.upper():
                compliance_guidance += "\n- Test information security management controls"
                compliance_guidance += "\n- Validate risk management and security framework implementation"
            
            if len(compliance_guidance) > len("\nCOMPLIANCE FOCUS:"):
                guidance_sections.append(compliance_guidance)
        
        # Combine all guidance sections
        if guidance_sections:
            return "\n\nSTRATEGIC TESTING GUIDANCE:" + "".join(guidance_sections)
        else:
            return "\n\nSTRATEGIC TESTING GUIDANCE:\n- Apply standard security testing methodologies"

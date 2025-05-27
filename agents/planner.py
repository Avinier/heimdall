import yaml
import re
from typing import List, Dict, Any, Optional
from llms import LLM

PLANNER_SYSTEM_PROMPT = """
You are an expert bug bounty hunter with years of experience finding critical vulnerabilities in web applications. Your job is to carefully analyze a website, think like an attacker, and identify potential security issues that could lead to high-impact exploits.

## Input Format
You will receive data in the following format:

Summarized HTML:
<html>...</html>

Page Data:
- Links: [list of discovered links]
- Forms: [list of forms found on the page] 
- Sensitive Strings: [any sensitive data found]

Request and Response Data:
- Request: [HTTP request details]
- Response: [HTTP response details]
- API calls: [any API requests and responses captured]

## Analysis Guidelines
- Examine authentication mechanisms for weaknesses
- Identify potential injection points (SQL, XSS, CSRF)
- Look for insecure direct object references
- Analyze API endpoints for security flaws
- Check for information disclosure
- Evaluate access controls
- Test input validation and sanitization
- Assess session management
- Look for client-side control bypasses

## Authentication Strategy
If you believe authentication would help find more vulnerabilities, start your plan by indicating that login is needed first. When you talk about login, mention that we should call the auth_needed() function so that the user can help us login. However, before asking for authentication, include at least 1-2 plans that test authentication implementation safety. Not everything must start with authentication - if there are clear vulnerabilities to explore first, prioritize those.

## Critical Requirements
- **MUST generate MULTIPLE security test plans (at least 3-5 different tests)**
- Each test plan must address a distinct security concern
- Avoid overly broad or generic plans
- Focus on high-impact vulnerabilities
- Base analysis only on provided data
- Use precise technical language
- Be specific about endpoints, parameters, and attack vectors
- If no security issues are apparent, return an empty list

## Output Format
Your response MUST be in YAML format. Each item should have a 'title' and 'description' field. Start directly with the YAML - no code blocks or additional text.

Each title and description should focus on a single kind of security issue. Be very specific in descriptions - if discussing endpoints, mention their URLs. Keep language professional but not overly direct (e.g., instead of "bruteforce", say "test with several values").

## Example Output Structure
```yaml
- title: Authentication Bypass Testing
  description: Examine the login form at /login for potential weaknesses by testing various input combinations and observing responses for authentication bypass opportunities.

- title: API Parameter Manipulation
  description: The /api/user endpoint accepts a 'userId' parameter that should be tested with different values to check for authorization issues and insecure direct object references.

- title: Cross-Site Scripting in Search Function
  description: The search functionality at /search appears to reflect user input in the response. Test with various XSS payloads to determine if input is properly sanitized.

- title: Information Disclosure in Error Messages
  description: Trigger error conditions across different endpoints to examine how the application handles exceptions and whether sensitive information is leaked in error messages.

- title: Input Validation Testing
  description: Test all input fields and parameters for proper validation against injection attacks, including SQL injection, command injection, and malformed input handling.
```

Remember: Generate multiple distinct test plans, each focusing on a specific vulnerability class or component. Your analysis should be thorough and based solely on the provided data.
"""


class Planner:
    """
    Security test planner that analyzes web application data and generates
    structured security testing plans using LLM analysis.
    """
    
    def __init__(self, desc: str):
        self.llm = LLM(desc="gemini-2.0-flash for now")
        
    def plan(self, input_pagedata: str) -> List[Dict[str, str]]:
        
        try:
            # Call LLM with the page data and system prompt
            llm_response = self._call_llm(input_pagedata)

            # Parse the LLM response to extract plans
            plans = self._parse_planner_response(llm_response)

            # Validate and clean the plans
            validated_plans = self._validate_plans(plans)
            
            return validated_plans
            
        except Exception as e:
            print(f"Error in plan generation: {str(e)}")
            # Return fallback plans if everything fails
            return self._get_fallback_plans()
    
    def _call_llm(self, input_pagedata: str) -> str:

        try:
            # Use Gemini basic call with the system prompt and page data
            full_prompt = f"{PLANNER_SYSTEM_PROMPT}\n\n{input_pagedata}"
            response = self.llm.gemini_basic_call(full_prompt, model="gemini-2.0-flash")
            return response
            
        except Exception as e:
            print(f"LLM call failed: {str(e)}")
            raise
    
    def _parse_planner_response(self, response: str) -> List[Dict[str, str]]:
        try:
            # First, try to extract YAML from the response
            yaml_content = self._extract_yaml_content(response)
            
            if yaml_content:
                # Parse the YAML content
                plans = yaml.safe_load(yaml_content)
                
                # Ensure it's a list
                if isinstance(plans, list):
                    return plans
                elif isinstance(plans, dict):
                    # If it's a single plan as dict, wrap in list
                    return [plans]
            
            # If YAML parsing fails, try regex-based extraction
            return self._extract_plans_with_regex(response)
            
        except yaml.YAMLError as e:
            print(f"YAML parsing error: {str(e)}")
            # Fallback to regex extraction
            return self._extract_plans_with_regex(response)
        except Exception as e:
            print(f"Response parsing error: {str(e)}")
            return []
    
    def _extract_yaml_content(self, response: str) -> Optional[str]:
        # Remove any markdown code blocks
        yaml_patterns = [
            r'```yaml\s*\n(.*?)\n```',  # ```yaml ... ```
            r'```\s*\n(.*?)\n```',     # ``` ... ```
            r'```yaml(.*?)```',         # ```yaml...``` (no newlines)
            r'```(.*?)```'              # ```...``` (no newlines)
        ]
        
        for pattern in yaml_patterns:
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # If no code blocks found, check if the entire response is YAML
        if response.strip().startswith('-') or response.strip().startswith('title:'):
            return response.strip()
        
        # Look for YAML-like content starting with '-'
        lines = response.split('\n')
        yaml_start = -1
        yaml_end = -1
        
        for i, line in enumerate(lines):
            if line.strip().startswith('- title:') or line.strip().startswith('-'):
                if yaml_start == -1:
                    yaml_start = i
                yaml_end = i
        
        if yaml_start != -1:
            return '\n'.join(lines[yaml_start:yaml_end + 1])
        
        return None
    
    def _extract_plans_with_regex(self, response: str) -> List[Dict[str, str]]:
        plans = []
        
        # Pattern to match title and description pairs
        patterns = [
            # YAML-style patterns
            r'- title:\s*([^\n]+)\s*description:\s*([^\n-]+)',
            r'title:\s*([^\n]+)\s*description:\s*([^\n]+)',
            # Numbered list patterns
            r'\d+\.\s*([^\n:]+):\s*([^\n]+)',
            # Bullet point patterns
            r'[•\-\*]\s*([^\n:]+):\s*([^\n]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if len(match) == 2:
                    title = match[0].strip().rstrip(':')
                    description = match[1].strip()
                    if title and description:
                        plans.append({
                            'title': title,
                            'description': description
                        })
        
        # Remove duplicates while preserving order
        seen = set()
        unique_plans = []
        for plan in plans:
            plan_key = (plan['title'].lower(), plan['description'].lower())
            if plan_key not in seen:
                seen.add(plan_key)
                unique_plans.append(plan)
        
        return unique_plans
    
    def _validate_plans(self, plans: List[Dict[str, str]]) -> List[Dict[str, str]]:
        validated_plans = []
        
        for plan in plans:
            if not isinstance(plan, dict):
                continue
                
            # Ensure required keys exist
            title = plan.get('title', '').strip()
            description = plan.get('description', '').strip()
            
            # Skip empty or invalid plans
            if not title or not description:
                continue
            
            # Clean up the content
            title = self._clean_text(title)
            description = self._clean_text(description)
            
            # Skip if still empty after cleaning
            if not title or not description:
                continue
            
            # Ensure minimum length for quality
            if len(title) < 5 or len(description) < 20:
                continue
            
            validated_plans.append({
                'title': title,
                'description': description
            })
        
        # If no valid plans found, return fallback
        if not validated_plans:
            return self._get_fallback_plans()
        
        return validated_plans
    
    def _clean_text(self, text: str) -> str:

        if not text:
            return ""
        
        # Remove extra whitespace and newlines
        text = re.sub(r'\s+', ' ', text.strip())
        
        # Remove common prefixes/suffixes
        text = re.sub(r'^[-•\*\d+\.\s]+', '', text)
        text = re.sub(r'[:\-]+$', '', text)
        
        # Remove quotes if they wrap the entire text
        if (text.startswith('"') and text.endswith('"')) or \
           (text.startswith("'") and text.endswith("'")):
            text = text[1:-1]
        
        return text.strip()
    
    def _get_fallback_plans(self) -> List[Dict[str, str]]:

        return [
            {
                'title': 'Authentication Mechanism Analysis',
                'description': 'Examine the authentication implementation for potential bypass vulnerabilities, weak session management, and credential handling issues.'
            },
            {
                'title': 'Input Validation Testing',
                'description': 'Test all input fields and parameters for proper validation against injection attacks including SQL injection, XSS, and command injection.'
            },
            {
                'title': 'Authorization and Access Control Review',
                'description': 'Analyze access control mechanisms to identify potential privilege escalation and insecure direct object reference vulnerabilities.'
            },
            {
                'title': 'Information Disclosure Assessment',
                'description': 'Check for sensitive information leakage in error messages, response headers, source code comments, and application behavior.'
            },
            {
                'title': 'Session Management Security Review',
                'description': 'Evaluate session handling mechanisms including token generation, validation, expiration, and protection against session-based attacks.'
            }
        ]


# Example usage and testing
if __name__ == "__main__":
    planner = Planner(desc="testing the planner")
    
    # Test with sample page data
    sample_data = """
Summarized HTML:
<html>
<head><title>Login Page</title></head>
<body>
<form action="/login" method="POST">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<input type="submit" value="Login">
</form>
</body>
</html>

Page Data:
- Links: ['/dashboard', '/admin', '/api/users']
- Forms: [{'action': '/login', 'method': 'POST', 'fields': ['username', 'password']}]
- Sensitive Strings: ['admin', 'password', 'token']

Request and Response Data:
- Request: POST /login HTTP/1.1
- Response: HTTP/1.1 200 OK, Set-Cookie: session=abc123
- API calls: ['/api/login', '/api/validate']
"""
    
    try:
        plans = planner.plan(sample_data)
        print("Generated Security Test Plans:")
        print("=" * 50)
        for i, plan in enumerate(plans, 1):
            print(f"{i}. {plan['title']}")
            print(f"   {plan['description']}")
            print()
    except Exception as e:
        print(f"Test failed: {e}")
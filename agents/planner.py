import yaml
import re
from typing import List, Dict, Any, Optional
from llms_test import LLM

PLANNER_SYSTEM_PROMPT = """
You are an expert bug bounty hunter with years of experience finding critical vulnerabilities in web applications. Your job is to carefully analyze a website, think like an attacker, and identify potential security issues that could lead to high-impact exploits.

## Input Format
You will receive data in the following format:

Summarized HTML:
<html>...</html>
<!-- This contains a security-focused summary with:
- Forms in condensed format: <form action="/login" method="POST" [CSRF]>text:username,password:password</form>
- Auth-related links: <a href="/admin">admin panel</a>
- API endpoints as comments: <!-- APIs: /api/users, /api/login -->
- Security headers in <head> section
- Error messages and security-relevant comments -->

Page Data:
- Links: ['url1', 'url2', ...]
- Forms: [{'action': '/login', 'method': 'POST', 'fields': ['username', 'password']}, ...]
- Sensitive Strings: [list of sensitive keywords/patterns found]

Request and Response Data:
- Request: GET/POST {url}
- Response: Status: {code}, Title: '{title}', Content-Type: {type}
- API calls: ['/api/endpoint1', '/api/endpoint2', ...]

Reconnaissance Data:
- Subdomains Found: [list of discovered subdomains]
- Technologies Detected: [frameworks, libraries, servers detected]
- Security Headers Present: [HSTS, CSP, X-Frame-Options, etc.]

Path Analysis:
- Accessible Paths: [list of accessible files/directories]
- Redirects Found: [redirect chains discovered]
- Additional APIs: [additional API endpoints found]

## Analysis Guidelines
Focus on these high-impact vulnerability classes:

**Authentication & Authorization:**
- Authentication bypass techniques
- Session management flaws
- Insecure direct object references (IDOR)

**Injection Attacks:**
- SQL injection in forms and parameters
- Cross-site scripting (XSS) in input fields

**API Security:**
- API endpoint enumeration and testing
- Parameter manipulation and fuzzing
- Rate limiting bypass
- API versioning vulnerabilities

**Information Disclosure:**
- Error message analysis for sensitive data leaks
- Technology fingerprinting for known vulnerabilities
- Comment analysis for developer secrets
- Subdomain enumeration for expanded attack surface

**Client-Side Security:**
- CSRF token validation
- Content Security Policy bypass
- DOM-based vulnerabilities
- Client-side control bypass

## Authentication Strategy
If authentication would help discover more vulnerabilities, mention calling auth_needed() function for user assistance with login. However, prioritize unauthenticated testing first - many critical vulnerabilities exist without authentication.

## Data Analysis Instructions

HTML Summary: Extract form actions/methods from condensed format, API endpoints from comments, CSRF indicators, security headers
Forms: Test for injection, CSRF implementation, input validation, hidden fields
APIs: Test authorization bypass, parameter manipulation, rate limiting
Tech Stack: Research known vulnerabilities for detected versions
Reconnaissance: Test subdomains, accessible paths, missing security headers

## Critical Requirements
- **MUST generate 3-5 specific security test plans**
- Reference actual endpoints, forms, APIs from provided data
- Focus on high-impact vulnerabilities based on discovered attack surface
- Use concrete, actionable testing steps
- Return empty list if no clear vulnerabilities found

## Output Format
Your response MUST be in YAML format. Each item should have a 'title' and 'description' field. Start directly with the YAML - no code blocks or additional text.

Be specific in descriptions - reference actual endpoints, form actions, and parameters found in the data. Use professional language (e.g., "test with various payloads" instead of "attack").

## Example Output Structure
```yaml
- title: SQL Injection Testing in Login Form
  description: The login form at /auth/login accepts username and password parameters. Test these inputs with SQL injection payloads to check for database query manipulation vulnerabilities, particularly focusing on authentication bypass.

- title: API Authorization Bypass Testing
  description: The discovered API endpoints /api/users and /api/admin should be tested for authorization bypass by manipulating user IDs, removing authentication headers, and testing different HTTP methods to access unauthorized data.

- title: Cross-Site Scripting in Search Functionality
  description: The search form with action /search reflects user input. Test with XSS payloads including script tags, event handlers, and encoded variants to determine if input sanitization is properly implemented.

- title: Information Disclosure via Error Messages
  description: Based on the detected technology stack (Apache/2.4.41, PHP/7.4), trigger error conditions across forms and API endpoints to check for sensitive information leakage in error responses.

- title: CSRF Token Validation Testing
  description: The forms show [CSRF] indicators but this needs verification. Test CSRF protection by removing tokens, using tokens from different sessions, and checking if the application properly validates token authenticity.
```

Remember: Base your analysis on the actual data provided. Reference specific URLs, endpoints, technologies, and security indicators found in the reconnaissance data. Generate targeted, actionable test plans that leverage the discovered attack surface.
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
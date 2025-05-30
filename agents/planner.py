import yaml
import re
from typing import List, Dict, Any, Optional
from llms_test import LLM

PLANNER_SYSTEM_PROMPT = """
You are an expert Vulnerability Assessment and Penetration Testing (VAPT) specialist with extensive experience in Dynamic Application Security Testing (DAST). Your role is to systematically analyze web applications using industry-standard VAPT methodologies and generate comprehensive security test plans that follow OWASP testing guidelines and NIST penetration testing frameworks.

## VAPT Methodology Overview
Your analysis follows a structured VAPT approach:
1. **Vulnerability Identification** - Systematic vulnerability discovery using DAST techniques
2. **Exploitation Planning** - Risk-based test case prioritization
3. **Impact Assessment** - Business risk evaluation for discovered vulnerabilities

## Input Format
You will receive comprehensive reconnaissance data in the following format:

**Summarized HTML:**
<html>...</html>
<!-- Security-focused analysis containing:
- Forms with security annotations: <form action="/login" method="POST" [CSRF]>text:username,password:password</form>
- Authentication mechanisms: <a href="/admin">admin panel</a>
- API endpoints: <!-- APIs: /api/users, /api/login -->
- Security headers analysis in <head> section
- Error messages and developer comments with security implications -->

**Application Fingerprinting:**
- Links: ['url1', 'url2', ...] (Attack surface enumeration)
- Forms: [{'action': '/login', 'method': 'POST', 'fields': ['username', 'password']}] (Input vectors)
- Sensitive Strings: [sensitive keywords/patterns] (Information disclosure indicators)

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

## DAST-Specific Testing Approaches

**Dynamic Input Validation Testing:**
- Boundary value analysis on all input fields
- Malformed data injection (oversized inputs, special characters)
- Type confusion attacks (string vs integer manipulation)
- Encoding bypass testing (URL, HTML, Unicode encoding)

**Session Management DAST:**
- Session token entropy analysis
- Session fixation and hijacking tests
- Concurrent session handling
- Session timeout validation
- Cross-site request forgery (CSRF) testing

**API Security DAST:**
- REST/GraphQL endpoint enumeration and fuzzing
- HTTP method tampering (PUT, DELETE, PATCH testing)
- Content-type manipulation attacks
- Rate limiting and DoS testing
- API versioning security gaps

**Client-Side Security DAST:**
- DOM manipulation and client-side bypass
- JavaScript security analysis
- WebSocket security testing
- Local storage security assessment

## Risk-Based Test Prioritization
Prioritize tests based on:
1. **Critical** - Authentication bypass, SQL injection, RCE
2. **High** - XSS, IDOR, sensitive data exposure
3. **Medium** - CSRF, information disclosure, security misconfigurations
4. **Low** - Missing security headers, verbose error messages

## Authentication Strategy for VAPT
If authentication is required for comprehensive testing, recommend calling auth_needed() function. However, prioritize unauthenticated attack surface first as per VAPT best practices - many critical vulnerabilities exist in public-facing components.

## DAST Analysis Instructions

**HTML Analysis:** Extract security-relevant elements, identify input vectors, analyze client-side controls
**Form Security:** Test input validation, CSRF protection, hidden field manipulation, file upload security
**API Testing:** Enumerate endpoints, test authorization, parameter manipulation, rate limiting
**Technology Stack:** Research CVEs for detected versions, test for known exploits
**Infrastructure:** Test subdomain takeover, missing security headers, service enumeration

## Critical VAPT Requirements
- **MUST generate ONLY 3-5 specific, actionable security test plans**
- Reference actual endpoints, forms, APIs from reconnaissance data
- Focus on high-impact vulnerabilities with clear exploitation paths
- Use industry-standard testing methodologies (OWASP, NIST, PTES)
- Provide concrete testing steps with expected outcomes
- Return empty list only if no testable attack surface exists

## Output Format
Your response MUST be in YAML format with 'title' and 'description' fields. Start directly with YAML - no code blocks or additional text.

Use professional VAPT terminology and reference specific testing techniques. Include payload examples where appropriate.

## VAPT Test Plan Examples
```yaml
- title: SQL Injection Vulnerability Assessment - Authentication Bypass
  description: Conduct systematic SQL injection testing on the login form at /auth/login using time-based and boolean-based payloads. Test username and password parameters with UNION-based queries, error-based injection, and authentication bypass techniques including ' OR '1'='1' variants. Verify database interaction through response timing analysis and error message enumeration.

- title: API Authorization Testing - IDOR and Privilege Escalation
  description: Perform comprehensive authorization testing on discovered API endpoints /api/users and /api/admin. Test for Insecure Direct Object References by manipulating user IDs (1, 2, 3, ../admin, etc.), test HTTP method tampering (GET to POST/PUT/DELETE), remove/modify authorization headers, and attempt horizontal/vertical privilege escalation through parameter manipulation.

- title: Cross-Site Scripting (XSS) Vulnerability Assessment
  description: Execute systematic XSS testing on all identified input vectors including search forms and user input fields. Test reflected XSS with payloads like <script>alert('XSS')</script>, stored XSS through persistent data submission, and DOM-based XSS via URL fragments. Include encoding bypass techniques (HTML entities, URL encoding, JavaScript encoding) and CSP bypass attempts.

- title: Session Management Security Assessment
  description: Analyze session handling mechanisms through session token entropy testing, session fixation attempts, and concurrent session validation. Test CSRF protection by removing/modifying tokens, attempt session hijacking through XSS, and validate session timeout enforcement. Include testing for secure cookie attributes and session invalidation on logout.

- title: Information Disclosure and Error Handling Assessment
  description: Systematically trigger error conditions across all application endpoints to identify information leakage. Test with malformed requests, invalid parameters, and boundary conditions. Analyze technology stack (Apache/2.4.41, PHP/7.4) for known CVEs and test for path disclosure, database errors, and stack trace exposure that could aid further exploitation.
```

Remember: Generate targeted, risk-based test plans that follow VAPT methodologies. Reference specific reconnaissance data and provide actionable testing steps that can be executed as part of a comprehensive DAST assessment. Focus on vulnerabilities that pose real business risk and can be validated through dynamic testing.
"""


class PlannerAgent:
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
            full_prompt = f"{PLANNER_SYSTEM_PROMPT}\n\n The actual page data is: {input_pagedata}"
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
    planner = PlannerAgent(desc="testing the planner")
    
    # Test with comprehensive VAPT sample data
    sample_data = """
Summarized HTML:
<html>
<head>
    <title>SecureBank - Online Banking Portal</title>
    <meta name="generator" content="WordPress 5.8.2">
    <!-- Security Headers Analysis -->
    <!-- Missing: Content-Security-Policy, X-Frame-Options -->
    <script src="/js/jquery-3.4.1.min.js"></script>
    <script src="/js/admin-panel.js"></script>
</head>
<body>
    <!-- Login Form with potential CSRF vulnerability -->
    <form action="/auth/login" method="POST" id="loginForm">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <input type="hidden" name="csrf_token" value="abc123def456">
        <input type="submit" value="Login">
    </form>
    
    <!-- Search functionality - potential XSS vector -->
    <form action="/search" method="GET">
        <input type="text" name="q" placeholder="Search transactions...">
        <input type="submit" value="Search">
    </form>
    
    <!-- File upload form - potential RCE vector -->
    <form action="/upload/statement" method="POST" enctype="multipart/form-data">
        <input type="file" name="document" accept=".pdf,.doc,.docx">
        <input type="submit" value="Upload Statement">
    </form>
    
    <!-- Admin panel link -->
    <a href="/admin/dashboard">Admin Panel</a>
    <a href="/api/docs">API Documentation</a>
    
    <!-- API endpoints discovered in comments -->
    <!-- APIs: /api/v1/users, /api/v1/accounts, /api/v2/transactions, /api/admin/users -->
    <!-- Internal APIs: /internal/backup, /internal/logs -->
    
    <!-- Error message with stack trace -->
    <!-- DEBUG: Database connection failed - MySQL server at localhost:3306 -->
    <!-- TODO: Remove debug info before production -->
</body>
</html>

Application Fingerprinting:
- Links: ['/dashboard', '/admin/dashboard', '/profile', '/transactions', '/api/docs', '/logout', '/forgot-password', '/register']
- Forms: [
    {'action': '/auth/login', 'method': 'POST', 'fields': ['username', 'password', 'csrf_token']},
    {'action': '/search', 'method': 'GET', 'fields': ['q']},
    {'action': '/upload/statement', 'method': 'POST', 'fields': ['document'], 'enctype': 'multipart/form-data'},
    {'action': '/profile/update', 'method': 'POST', 'fields': ['email', 'phone', 'address']},
    {'action': '/transfer', 'method': 'POST', 'fields': ['to_account', 'amount', 'description']}
]
- Sensitive Strings: ['admin', 'password', 'token', 'api_key', 'secret', 'database', 'mysql', 'localhost', 'debug', 'backup', 'internal']

Request and Response Data:
- Request: GET / HTTP/1.1
- Response: HTTP/1.1 200 OK, Server: Apache/2.4.41, X-Powered-By: PHP/7.4.3, Set-Cookie: PHPSESSID=abc123def456; path=/
- Request: POST /auth/login HTTP/1.1
- Response: HTTP/1.1 302 Found, Location: /dashboard, Set-Cookie: session_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
- API calls: ['/api/v1/users', '/api/v1/accounts/{id}', '/api/v2/transactions', '/api/admin/users', '/internal/backup']

Reconnaissance Data:
- Subdomains Found: ['admin.securebank.com', 'api.securebank.com', 'dev.securebank.com', 'staging.securebank.com', 'mail.securebank.com']
- Technologies Detected: [
    'Apache/2.4.41 (Ubuntu)',
    'PHP/7.4.3',
    'WordPress 5.8.2',
    'MySQL 5.7',
    'jQuery 3.4.1',
    'Bootstrap 4.5.2',
    'JWT Authentication',
    'Cloudflare CDN'
]
- Security Headers Present: ['Strict-Transport-Security: max-age=31536000']
- Security Headers Missing: ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']

Path Analysis:
- Accessible Paths: [
    '/admin/',
    '/api/',
    '/backup/',
    '/config/',
    '/logs/',
    '/phpinfo.php',
    '/wp-admin/',
    '/wp-content/uploads/',
    '/.git/',
    '/robots.txt',
    '/sitemap.xml',
    '/.env'
]
- Redirects Found: [
    '/admin -> /admin/login',
    '/dashboard -> /auth/login (if not authenticated)',
    '/api -> /api/v1/',
    '/old-api -> /api/v2/'
]
- Additional APIs: [
    '/api/v1/auth/login',
    '/api/v1/auth/refresh',
    '/api/v1/users/{id}',
    '/api/v1/accounts/{id}/balance',
    '/api/v1/transactions/{id}',
    '/api/v2/graphql',
    '/api/admin/users',
    '/api/admin/logs',
    '/internal/health',
    '/internal/metrics'
]

Additional Security Findings:
- Exposed Configuration: /.env file accessible containing database credentials
- Information Disclosure: /phpinfo.php reveals server configuration
- Version Control Exposure: /.git/ directory accessible
- Default Credentials: WordPress admin panel accessible with weak credentials
- Insecure File Permissions: /backup/ directory allows directory listing
- JWT Token Issues: Weak signing algorithm detected (HS256 with short secret)
- Database Errors: SQL error messages visible in application responses
- CORS Misconfiguration: Wildcard (*) origin allowed on API endpoints
- Rate Limiting: No rate limiting detected on authentication endpoints
- Session Management: Session tokens don't expire properly
"""
    
    try:
        plans = planner.plan(sample_data)
        print("Generated VAPT Security Test Plans:")
        print("=" * 60)
        print(plans)
    except Exception as e:
        print(f"Test failed: {e}")
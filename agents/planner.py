import yaml
import re
from typing import List, Dict, Any, Optional
from tools.llms import LLM

PLANNER_SYSTEM_PROMPT = """
You are an elite Vulnerability Assessment and Penetration Testing (VAPT) specialist with deep expertise in Advanced Persistent Threat (APT) simulation, Dynamic Application Security Testing (DAST), and enterprise security architecture analysis. 
Your role is to conduct world-class security assessments that provide actionable business intelligence and strategic security insights to C-level executives and technical teams.

## VAPT Methodology Framework
You operate as a **Gray Box Elite Penetration Tester** with reconnaissance data but limited internal knowledge, simulating sophisticated threat actors with initial foothold capabilities.

1. **Threat Intelligence Integration** - APT technique mapping and real-world attack simulation
2. **Business-Critical Asset Identification** - Crown jewel analysis and high-value target assessment  
3. **Advanced Exploitation Chaining** - Multi-vector attack path development
4. **Strategic Impact Assessment** - Board-level business risk quantification
5. **Regulatory Compliance Validation** - Industry-specific security standard verification

## Advanced Security Testing Arsenal Available

Your assessment methodology is supported by sophisticated automation and testing capabilities spanning the complete attack surface:

**Database Security & Injection Testing:** Advanced SQL injection capabilities with intelligent payload generation, database fingerprinting, and automated exploitation chains supporting all major database platforms.

**Cross-Site Scripting & Client-Side Security:** Comprehensive XSS testing with CSP bypass techniques, DOM manipulation analysis, and framework-specific payload optimization for modern web applications.

**Network Infrastructure Assessment:** Intelligent reconnaissance and port scanning capabilities with service enumeration, vulnerability detection, and stealth testing for comprehensive infrastructure mapping.

**API Security & Authentication Analysis:** Advanced API endpoint discovery, JWT token security analysis, OAuth flow testing, and authentication mechanism evaluation with business logic awareness.

**Authorization & Access Control Testing:** IDOR vulnerability detection, privilege escalation testing, and business logic bypass identification through systematic access control validation.

**Interactive Application Security Testing:** Browser automation capabilities enabling dynamic form manipulation, traffic interception, real-time security control testing, and advanced evasion technique deployment.

**Information Disclosure & Intelligence Operations:** Systematic sensitive data exposure analysis, technology stack enumeration, and strategic intelligence collection capabilities for comprehensive organizational assessment.

**Advanced Evasion & Bypass Capabilities:** WAF circumvention, CSP bypass techniques, and sophisticated payload encoding methods for testing against hardened security controls.

These capabilities enable execution of sophisticated attack chains, business logic exploitation, and advanced persistent threat simulation aligned with nation-state level methodologies.

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
- Technologies Detected: [frameworks, libraries, servers detected]
- Security Headers Present: [HSTS, CSP, X-Frame-Options, etc.]

Path Analysis:
- Accessible Paths: [list of accessible files/directories]
- Redirects Found: [redirect chains discovered]
- Additional APIs: [additional API endpoints found]

## Elite DAST Testing Methodologies

**Advanced Persistent Threat Simulation:**
- Multi-stage attack chain development (Initial Access → Persistence → Privilege Escalation → Lateral Movement → Data Exfiltration)
- Advanced evasion techniques (WAF bypass, IDS evasion, behavioral analysis avoidance)
- Business logic exploitation through workflow manipulation
- Supply chain attack vector assessment

**Executive-Level Business Logic Testing:**
- Financial transaction integrity bypass
- User privilege escalation through business workflow exploitation  
- Data access control circumvention via application logic flaws
- Regulatory compliance control bypass (PCI DSS, GDPR, HIPAA)

**Advanced API Security Assessment:**
- GraphQL introspection and query complexity attacks
- REST API business logic bypass through HTTP method manipulation
- Microservices inter-communication security testing
- API gateway security control validation

**Next-Generation Session Management Analysis:**
- JWT token manipulation and algorithm confusion attacks
- OAuth 2.0/OpenID Connect flow exploitation
- SAML assertion manipulation and relay attacks
- Advanced session fixation through race conditions

**Enterprise Infrastructure Penetration:**
- Cloud security posture assessment (AWS/Azure/GCP misconfigurations)
- Container security testing (Docker/Kubernetes escape scenarios)
- DevOps pipeline security assessment (CI/CD injection points)
- Enterprise SSO and identity federation bypass

## Strategic Risk-Based Test Prioritization

**CRITICAL (Board-Level Impact):**
- Financial system compromise (payment processing, accounting systems)
- Customer data breach vectors (PII, payment card data, health records)
- Administrative access compromise (domain admin, root access)
- Regulatory compliance violations (audit failures, legal liability)

**HIGH (Executive-Level Impact):**
- Business continuity threats (system availability, operational disruption)
- Competitive intelligence exposure (trade secrets, strategic plans)
- Supply chain compromise vectors (vendor access, partner integrations)
- Advanced persistent threat establishment (long-term access, stealth operations)

**MEDIUM (Operational Impact):**
- Internal user compromise (lateral movement enablers)
- Information disclosure (technical details, system architecture)
- Denial of service vulnerabilities (resource exhaustion, application crashes)

**LOW (Technical Debt):**
- Security best practice violations (missing headers, verbose errors)
- Configuration weaknesses (default credentials, unnecessary services)

## Elite Authentication Strategy
For comprehensive enterprise testing, prioritize unauthenticated attack surface first (external threat simulation), then escalate to authenticated testing (insider threat simulation). Recommend auth_needed() function when business-critical authenticated functionality requires assessment for complete risk evaluation.

## Advanced DAST Analysis Framework

**Intelligent HTML Security Parsing:**
- Automated business context extraction from application workflows
- Hidden functionality discovery through client-side code analysis
- Advanced DOM manipulation and client-side security bypass testing
- Progressive Web App (PWA) and Single Page Application (SPA) security assessment

**Enterprise Form Security Assessment:**
- Advanced input validation bypass (encoding variations, parser confusion)
- File upload security with polyglot payload testing
- CSRF token entropy analysis and prediction attempts
- Business workflow manipulation through form parameter abuse

**Strategic API Exploitation:**
- Business logic API abuse (transaction manipulation, workflow bypass)
- Advanced authorization testing (RBAC bypass, privilege escalation chains)
- API rate limiting bypass and business continuity impact assessment
- Microservices communication interception and manipulation

**Technology Stack Threat Intelligence:**
- Zero-day vulnerability research for detected versions
- Advanced configuration exploitation (cloud misconfigurations, container escapes)
- Supply chain vulnerability assessment for third-party components

## Elite VAPT Requirements
- **Generate EXACTLY 5-7 strategic, high-impact security test plans**
- Focus on business-critical vulnerabilities with quantifiable financial impact
- Provide executive-level risk communication alongside technical exploitation details
- Reference specific reconnaissance data with strategic business context
- Include advanced evasion techniques and sophisticated attack methodologies
- Incorporate threat intelligence and APT technique mapping (MITRE ATT&CK framework)
- Deliver actionable insights for both technical teams and executive leadership

## Professional Output Format
Response MUST be in YAML format with enhanced fields for strategic context. Start directly with YAML - no code blocks or explanatory text.

Required fields: title, description, business_impact, attack_complexity, compliance_risk

## Elite VAPT Test Plan Framework

```yaml
- title: Advanced SQL Injection with Business Logic Bypass - Financial Transaction Manipulation
  description: Execute sophisticated SQL injection campaigns against authentication and transaction processing endpoints (/auth/login, /api/transfer) using advanced techniques including blind boolean-based injection with time delays, UNION-based data exfiltration, and second-order injection through stored procedures. Implement WAF evasion through encoding variations (hex, unicode, double-encoding) and test transaction integrity through SQL injection-based business logic manipulation. Target database privilege escalation through stacked queries and operating system command execution via xp_cmdshell or similar vectors.
  business_impact: "CRITICAL - Potential unauthorized financial transfers, customer data breach affecting 10,000+ records, regulatory compliance violations (PCI DSS), estimated financial impact $2-5M including fines and remediation costs"
  attack_complexity: "HIGH - Requires advanced SQL injection techniques, WAF bypass capabilities, and business logic understanding"
  compliance_risk: "PCI DSS Requirement 6.5.1, SOX Section 302/404 - Financial reporting integrity compromise"

- title: Advanced API Authorization Exploitation - Privilege Escalation and Data Exfiltration Chain  
  description: Conduct comprehensive authorization testing across discovered API ecosystem (/api/users, /api/admin, /api/reports) implementing advanced IDOR techniques with business context manipulation, HTTP method override attacks (X-HTTP-Method-Override header), and JWT token manipulation including algorithm confusion attacks (HS256 to RS256). Execute horizontal privilege escalation through user enumeration and vertical escalation through role-based access control (RBAC) bypass. Chain multiple API vulnerabilities for complete administrative access and implement automated data exfiltration scripts targeting customer PII and financial records.
  business_impact: "CRITICAL - Complete customer database compromise, administrative account takeover, potential insider trading implications, estimated breach cost $3-7M based on 50,000+ customer records"
  attack_complexity: "VERY HIGH - Requires API security expertise, JWT manipulation skills, and advanced automation scripting"
  compliance_risk: "GDPR Article 32/33 - Personal data breach, PCI DSS Requirement 7 - Access control violations"

- title: Advanced Persistent Threat (APT) Simulation - Multi-Vector Attack Chain Development
  description: Simulate sophisticated nation-state level attack through coordinated exploit chaining starting with XSS-based credential harvesting, escalating through session hijacking with advanced JavaScript payloads, and establishing persistence through DOM manipulation and service worker abuse. Implement stealth techniques including traffic obfuscation, anti-forensics measures, and behavioral evasion. Execute lateral movement simulation through discovered administrative interfaces and test long-term persistence mechanisms including backup system compromise and configuration manipulation for sustained access.
  business_impact: "CATASTROPHIC - Complete organizational compromise, intellectual property theft, long-term espionage capability, potential nation-state level threat simulation, estimated impact $10-50M including business disruption"
  attack_complexity: "EXPERT - Requires advanced persistent threat simulation expertise, stealth techniques, and sophisticated evasion capabilities"
  compliance_risk: "ISO 27001 A.12.2 - Incident management failure, SOX Section 404 - Internal controls compromise"

- title: Enterprise Session Management Exploitation - Authentication Architecture Compromise
  description: Execute comprehensive session security assessment targeting enterprise authentication mechanisms including OAuth 2.0 flow manipulation, SAML assertion replay attacks, and advanced session fixation through race condition exploitation. Test session token entropy using statistical analysis, implement concurrent session abuse for privilege escalation, and execute advanced CSRF attacks with SameSite cookie bypass techniques. Target SSO infrastructure through token manipulation and federation trust relationship abuse, testing for authentication bypass through protocol-level vulnerabilities.
  business_impact: "HIGH - Enterprise-wide authentication compromise, potential access to all integrated systems, administrative account takeover affecting entire organization, estimated impact $1-3M"
  attack_complexity: "HIGH - Requires enterprise authentication protocol expertise, advanced session manipulation techniques"
  compliance_risk: "NIST Cybersecurity Framework - Identity and Access Management failures, SOX Section 302 - CEO/CFO certification compromise"

- title: Advanced Business Logic Exploitation - Financial Workflow Manipulation
  description: Conduct sophisticated business logic vulnerability assessment targeting critical financial workflows including payment processing, account balance manipulation, and transaction approval bypasses. Test race condition vulnerabilities in financial transactions, implement time-of-check-time-of-use (TOCTOU) attacks, and execute workflow sequence bypass through parameter manipulation. Target multi-step financial processes for logic flaws including discount abuse, currency conversion manipulation, and transaction reversal exploitation. Include advanced techniques for bypassing business rules through concurrent request processing and state manipulation.
  business_impact: "CRITICAL - Direct financial loss through transaction manipulation, potential fraud enabling worth millions, regulatory audit failures, customer trust destruction, estimated impact $5-15M"
  attack_complexity: "VERY HIGH - Requires deep understanding of financial systems, advanced timing attack capabilities, business process expertise"
  compliance_risk: "PCI DSS Requirement 2/6 - Secure payment processing, SOX Section 404 - Financial controls integrity, Anti-Money Laundering (AML) compliance violations"

- title: Advanced Information Warfare - Strategic Intelligence Gathering and Disclosure Exploitation
  description: Execute systematic information disclosure exploitation targeting strategic business intelligence including technology stack enumeration for zero-day targeting, administrative interface discovery through forced browsing with business context analysis, and advanced error manipulation for system architecture disclosure. Implement automated reconnaissance for sensitive file discovery (backup files, configuration dumps, source code repositories) and execute social engineering intelligence gathering through application-disclosed information. Target intellectual property exposure through development artifacts and implement competitive intelligence gathering through publicly accessible business logic disclosure.
  business_impact: "HIGH - Competitive advantage loss, intellectual property exposure, detailed attack surface mapping enabling future sophisticated attacks, estimated impact $2-8M in competitive disadvantage"
  attack_complexity: "MEDIUM-HIGH - Requires advanced reconnaissance techniques, business intelligence analysis capabilities"
  compliance_risk: "Trade secret protection failures, potential SEC disclosure requirements for material cybersecurity incidents"

- title: Cloud Infrastructure and DevOps Security Assessment - Supply Chain Attack Vector Analysis
  description: Conduct comprehensive cloud security posture assessment targeting discovered infrastructure indicators including container security testing, CI/CD pipeline security analysis, and cloud service misconfiguration exploitation. Test for privilege escalation through cloud IAM policy abuse, implement container escape techniques, and assess microservices inter-communication security. Target DevOps infrastructure through discovered deployment artifacts, test infrastructure-as-code security controls, and execute supply chain attack simulation through dependency confusion and package repository manipulation where applicable.
  business_impact: "CRITICAL - Complete infrastructure compromise, supply chain attack enablement, potential customer environment compromise through shared infrastructure, estimated impact $5-20M including customer liability"
  attack_complexity: "EXPERT - Requires advanced cloud security expertise, container technology knowledge, DevOps security understanding"
  compliance_risk: "SOC 2 Type II compliance failures, ISO 27001 A.13.2 - Information transfer security, customer contractual SLA violations"
```

## Strategic VAPT Excellence Standards

Your test plans must demonstrate world-class penetration testing expertise by:
- **Incorporating Threat Intelligence**: Reference current APT techniques and real-world attack patterns
- **Providing Strategic Context**: Translate technical findings into business risk and executive decision-making intelligence
- **Demonstrating Advanced Techniques**: Show expertise beyond basic vulnerability scanning through sophisticated exploitation methods
- **Quantifying Business Impact**: Provide specific financial impact estimates and regulatory compliance implications
- **Enabling Executive Communication**: Structure findings for board-level presentation and strategic security investment decisions

Remember: You are the world's elite VAPT specialist with access to advanced automation capabilities. Your assessments should provide strategic security insights that transform organizational security posture and deliver competitive advantage through comprehensive security intelligence. 

Focus on developing test strategies that leverage sophisticated testing capabilities to uncover vulnerabilities with existential business impact. Your plans should naturally incorporate advanced testing methodologies including automated injection testing, intelligent reconnaissance, API security analysis, browser automation, and evasion techniques.

Each test plan should demonstrate strategic thinking that guides technical teams toward the most impactful security validation approaches, enabling organizations to achieve security leadership positions within their industries through comprehensive threat simulation and business logic exploitation.
"""

class PlannerAgent:
    """
    Security test planner that analyzes web application data and generates
    structured security testing plans using LLM analysis.
    """
    
    def __init__(self, desc: str, api_type: str = "gemini", model_key: str = "qwen3-30b-a3b", 
                 reasoning: bool = True, temperature: float = 0.3):
        self.llm = LLM(desc="testing with qwen3 reasoning")
        self.api_type = api_type
        self.model_key = model_key
        self.reasoning = reasoning
        self.temperature = temperature
        
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
            print("Returning fallback plans")
            return self._get_fallback_plans()
    
    def _call_llm(self, input_pagedata: str) -> str:

        try:
            # Use appropriate API based on api_type
            full_prompt = f"{PLANNER_SYSTEM_PROMPT}\n\n The actual page data is: {input_pagedata}"
            
            if self.api_type == "gemini":
                response = self.llm.gemini_reasoning_call(
                    full_prompt, 
                    model=self.model_key, 
                    temperature=self.temperature, 
                    include_thoughts=self.reasoning
                )
                # Handle potential dict response from reasoning call
                if isinstance(response, dict):
                    return response.get('text', str(response))
                return response
            elif self.api_type == "fireworks":
                response = self.llm.fireworks_call(
                    full_prompt, 
                    model_key=self.model_key, 
                    reasoning=self.reasoning, 
                    temperature=self.temperature
                )
                return response
            else:
                raise ValueError(f"Unsupported api_type: {self.api_type}. Use 'gemini' or 'fireworks'")
            
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
        
        # Enhanced patterns to match the new YAML format with additional fields
        patterns = [
            # YAML-style patterns with multiple fields
            r'- title:\s*([^\n]+)\s*description:\s*([^\n-]+)(?:\s*business_impact:\s*([^\n-]+))?(?:\s*attack_complexity:\s*([^\n-]+))?(?:\s*compliance_risk:\s*([^\n-]+))?',
            r'title:\s*([^\n]+)\s*description:\s*([^\n]+)(?:\s*business_impact:\s*([^\n]+))?(?:\s*attack_complexity:\s*([^\n]+))?(?:\s*compliance_risk:\s*([^\n]+))?',
            # Numbered list patterns
            r'\d+\.\s*([^\n:]+):\s*([^\n]+)',
            # Bullet point patterns
            r'[•\-\*]\s*([^\n:]+):\s*([^\n]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for match in matches:
                if len(match) >= 2:
                    title = match[0].strip().rstrip(':')
                    description = match[1].strip()
                    
                    # Initialize plan with required fields
                    plan = {
                        'title': title,
                        'description': description
                    }
                    
                    # Add optional fields if they exist in the match
                    if len(match) > 2 and match[2]:
                        plan['business_impact'] = match[2].strip()
                    if len(match) > 3 and match[3]:
                        plan['attack_complexity'] = match[3].strip()
                    if len(match) > 4 and match[4]:
                        plan['compliance_risk'] = match[4].strip()
                    
                    if title and description:
                        plans.append(plan)
        
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
            
            # Clean up the content for all fields
            validated_plan = {
                'title': self._clean_text(title),
                'description': self._clean_text(description)
            }
            
            # Add optional fields if they exist and are valid
            optional_fields = ['business_impact', 'attack_complexity', 'compliance_risk']
            for field in optional_fields:
                if field in plan:
                    field_value = self._clean_text(plan[field])
                    if field_value:  # Only add if not empty after cleaning
                        validated_plan[field] = field_value
            
            # Skip if still empty after cleaning
            if not validated_plan['title'] or not validated_plan['description']:
                continue
            
            # Ensure minimum length for quality
            if len(validated_plan['title']) < 5 or len(validated_plan['description']) < 20:
                continue
            
            validated_plans.append(validated_plan)
        
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
        """Return fallback plans with the new enhanced format including business impact, attack complexity, and compliance risk."""
        return [
            {
                'title': 'Authentication Mechanism Analysis',
                'description': 'Examine the authentication implementation for potential bypass vulnerabilities, weak session management, and credential handling issues including JWT token manipulation, session fixation, and multi-factor authentication bypass techniques.',
                'business_impact': 'HIGH - Unauthorized access to user accounts, potential administrative compromise, estimated impact $500K-2M including incident response and customer trust loss',
                'attack_complexity': 'MEDIUM - Requires authentication protocol knowledge and session manipulation techniques',
                'compliance_risk': 'NIST Cybersecurity Framework - Identity and Access Management failures, potential GDPR Article 32 violations'
            },
            {
                'title': 'Input Validation Testing',
                'description': 'Test all input fields and parameters for proper validation against injection attacks including SQL injection, XSS, command injection, and advanced payload encoding techniques with WAF bypass methods.',
                'business_impact': 'CRITICAL - Data breach potential, system compromise, estimated impact $1-5M including regulatory fines and data breach notification costs',
                'attack_complexity': 'MEDIUM-HIGH - Requires injection technique expertise and advanced payload crafting',
                'compliance_risk': 'PCI DSS Requirement 6.5.1, SOX Section 302 - Data integrity compromise, OWASP Top 10 compliance violations'
            },
            {
                'title': 'Authorization and Access Control Review',
                'description': 'Analyze access control mechanisms to identify potential privilege escalation, insecure direct object references, and business logic bypass vulnerabilities affecting critical business functions.',
                'business_impact': 'HIGH - Unauthorized access to sensitive data and administrative functions, potential financial manipulation, estimated impact $800K-3M',
                'attack_complexity': 'HIGH - Requires business logic understanding and advanced authorization bypass techniques',
                'compliance_risk': 'SOX Section 404 - Internal controls failure, GDPR Article 25 - Data protection by design violations'
            },
            {
                'title': 'Information Disclosure Assessment',
                'description': 'Check for sensitive information leakage in error messages, response headers, source code comments, and application behavior that could enable advanced attack planning and reconnaissance.',
                'business_impact': 'MEDIUM - Competitive intelligence exposure, attack surface mapping enablement, estimated impact $200K-1M in competitive disadvantage',
                'attack_complexity': 'LOW-MEDIUM - Requires systematic reconnaissance and information analysis capabilities',
                'compliance_risk': 'Trade secret protection failures, ISO 27001 A.13.2 - Information transfer security violations'
            },
            {
                'title': 'Session Management Security Review',
                'description': 'Evaluate session handling mechanisms including token generation, validation, expiration, and protection against session-based attacks including advanced session hijacking and concurrent session abuse.',
                'business_impact': 'HIGH - Account takeover potential, session hijacking enabling unauthorized transactions, estimated impact $600K-2.5M',
                'attack_complexity': 'MEDIUM-HIGH - Requires session security expertise and advanced timing attack capabilities',
                'compliance_risk': 'PCI DSS Requirement 8 - Session management requirements, NIST SP 800-63B - Authentication and session management standards'
            }
        ]


# Example usage and testing
if __name__ == "__main__":
    planner = PlannerAgent(
        desc="testing the planner", 
        api_type="fireworks",
        model_key="qwen3-30b-a3b", 
        reasoning=True, 
        temperature=0.3
    )
    
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
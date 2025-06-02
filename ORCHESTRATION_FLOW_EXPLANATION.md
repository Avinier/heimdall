# Security Analysis Orchestration Flow - Developer Guide

## Overview

This orchestration system performs automated security testing of web applications using a three-tiered agent architecture with nested loops for comprehensive vulnerability assessment.

## Architecture Components

### 1. Core Agents

- **PlannerAgent**: Generates security test plans from page analysis
- **ActionerAgent**: Executes specific security testing actions
- **ContextManagerAgent**: Manages conversation history and content summarization

### 2. Supporting Tools

- **WebProxy**: Browser automation with Playwright
- **PageDataExtractor**: Extracts structured data from web pages

---

## Flow Structure: Three Nested Loops

```
OUTER LOOP: URL Processing
├── MIDDLE LOOP: Plan Execution
│   └── INNER LOOP: Action Iteration
```

---

## Detailed Flow with Sample Data

### Phase 1: Initialization

```python
base_url = "https://dev.quantumsenses.com"
urls_to_parse = ["https://dev.quantumsenses.com"]
visited_urls = set()
all_findings = []
```

**Agent Initialization:**

```
✓ WebProxy: Browser automation ready
✓ PlannerAgent: Gemini-2.5-flash-preview (reasoning=True, temp=0.3)
✓ ActionerAgent: Gemini-2.5-flash-preview (reasoning=True, temp=0.3)
✓ ContextManagerAgent: Qwen3-30B (reasoning=False, temp=0.2)
```

---

## OUTER LOOP: URL Processing

### Sample Iteration 1: Homepage Analysis

**Input:**

```
Current URL: https://dev.quantumsenses.com
URLs in queue: ["https://dev.quantumsenses.com"]
Visited URLs: []
```

**Step 1: Page Navigation & Data Extraction**

```python
# Browser navigates to URL
page.goto("https://dev.quantumsenses.com")
print(f"✓ Page title: {page.title()}")  # "QuantumSenses - AI Platform"

# Extract page data
extractor = PageDataExtractor(page)
raw_page_data = extractor.extract_page_data()
```

**Sample Raw Page Data (truncated):**

```
URL: https://dev.quantumsenses.com
Title: QuantumSenses - AI Platform
Forms: [
  {
    "action": "/api/auth/login",
    "method": "POST",
    "inputs": [
      {"name": "email", "type": "email", "required": true},
      {"name": "password", "type": "password", "required": true},
      {"name": "csrf_token", "type": "hidden", "value": "abc123xyz"}
    ]
  },
  {
    "action": "/api/search",
    "method": "GET",
    "inputs": [
      {"name": "q", "type": "text", "placeholder": "Search..."}
    ]
  }
]
Links: [
  {"url": "/dashboard", "text": "Dashboard"},
  {"url": "/api/docs", "text": "API Documentation"},
  {"url": "/admin", "text": "Admin Panel"},
  {"url": "/user/profile", "text": "Profile"}
]
JavaScript: ["jquery-3.6.0.min.js", "app.bundle.js", "analytics.js"]
Cookies: ["session_id=sess_abc123", "csrf_token=abc123xyz"]
Headers: {"X-Frame-Options": "DENY", "Content-Security-Policy": "..."}
Content-Length: 15247 characters
```

**Step 2: Link Discovery & Queue Management**

```python
new_links_count = 0
for link_info in extractor.links:
    link_url = "https://dev.quantumsenses.com/dashboard"
    if _is_same_domain(base_url, link_url):
        urls_to_parse.append(link_url)
        new_links_count += 1

print(f"✓ Added 4 new links to scan queue")
# Updated queue: ["/dashboard", "/api/docs", "/admin", "/user/profile"]
```

**Step 3: Content Summarization**

```python
# ContextManager summarizes raw data to reduce tokens
summarized_page_data = context_manager.summarize_page_source(raw_page_data, url)
context_stats = context_manager.get_context_stats(page_data_context)
print(f"✓ Page data summarized (Tokens: ~{context_stats['estimated_tokens']})")
```

**Sample Summarized Page Data:**

```
SECURITY-FOCUSED PAGE ANALYSIS - https://dev.quantumsenses.com

**Page Security Overview:**
Landing page for AI platform with authentication system and user dashboard access.
Attack surface includes login forms, search functionality, and administrative interfaces.

**Authentication & Authorization:**
- Login form: /api/auth/login (POST) with email/password fields and CSRF protection
- Hidden csrf_token field present: "abc123xyz"
- Session management via session_id cookie
- Admin panel accessible at /admin endpoint

**Input Attack Vectors:**
- Email field: email validation, potential for user enumeration
- Password field: no visible complexity requirements
- Search box: /api/search endpoint, GET method, XSS testing opportunity

**High-Priority Security Tests:**
- SQL Injection: /api/auth/login POST parameters
- XSS: /api/search?q= parameter
- Authentication Bypass: login form validation
- IDOR: /user/profile and /dashboard endpoints
- Privilege Escalation: /admin access controls

**Technology Stack:**
- jQuery 3.6.0, custom JavaScript bundle
- CSRF protection implemented
- X-Frame-Options: DENY header present
```

---

## MIDDLE LOOP: Plan Execution

**Step 4: Security Plan Generation**

```python
plans = planner.plan(raw_page_data)
print(f"✓ Generated {len(plans)} security test plans")
```

**Sample Generated Plans:**

```yaml
Plan 1:
  title: "Authentication Bypass Testing"
  description: "Test login form for SQL injection, credential bypass, and session management vulnerabilities using various authentication bypass techniques."

Plan 2:
  title: "Cross-Site Scripting (XSS) Assessment"
  description: "Evaluate search functionality and input fields for reflected and stored XSS vulnerabilities through payload injection and response analysis."

Plan 3:
  title: "Authorization and Access Control Review"
  description: "Test admin panel access, user privilege escalation, and insecure direct object references across dashboard and profile endpoints."

Plan 4:
  title: "Information Disclosure Analysis"
  description: "Examine error handling, debug information exposure, and technology fingerprinting opportunities through various reconnaissance techniques."

Plan 5:
  title: "CSRF and Session Management Testing"
  description: "Validate CSRF token implementation, session fixation resistance, and secure cookie configuration across authenticated operations."
```

### Sample Plan Execution: Plan 1 - Authentication Bypass Testing

**Initial Conversation History:**

```python
conversation_history = [
    {
        "role": "user",
        "content": "URL: https://dev.quantumsenses.com\n\nSUMMARIZED PAGE ANALYSIS:\n[summarized_page_data]"
    },
    {
        "role": "user",
        "content": "SECURITY TEST PLAN:\nTitle: Authentication Bypass Testing\nDescription: Test login form for SQL injection, credential bypass, and session management vulnerabilities using various authentication bypass techniques.\n\nExecute this plan using the available security testing tools."
    }
]
```

---

## INNER LOOP: Action Iteration

### Iteration 1: Initial Reconnaissance

**ActionerAgent Input:**

```python
actioner_response = actioner.generate_action_of_plan_step(
    plan={
        "title": "Authentication Bypass Testing",
        "description": "Test login form for SQL injection, credential bypass..."
    },
    page_data=page_data_context,
    tool_output="",
    conversation_history=[msg["content"] for msg in conversation_history]
)
```

**ActionerAgent Output:**

```python
{
    "discussion": "Beginning authentication bypass testing by navigating to the login form. I'll examine the form structure, CSRF implementation, and prepare for injection testing. The presence of csrf_token suggests some protection, but I need to verify its effectiveness.",
    "action": "goto(page, \"/api/auth/login\")"
}
```

**Action Execution:**

```python
action_output = _execute_action_command("goto(page, \"/api/auth/login\")", page)
# Result: "Successfully navigated to /api/auth/login. Page title: Login - QuantumSenses"
```

**Context Summarization:**

```python
summarized_action_result = context_manager.summarize(
    llm_response="Beginning authentication bypass testing by navigating to...",
    tool_use="goto(page, \"/api/auth/login\")",
    tool_output="Successfully navigated to /api/auth/login. Page title: Login - QuantumSenses"
)
```

**Sample Summarized Result:**

```
• **Navigation Action**: Successfully accessed login endpoint /api/auth/login
• **Page Analysis**: Login form confirmed present with email/password fields
• **Security Testing Setup**: Ready for authentication bypass testing including SQL injection and credential validation bypass attempts
• **CSRF Token**: Token present in form, validation testing required
```

**Updated Conversation History:**

```python
conversation_history.append({"role": "assistant", "content": discussion})
conversation_history.append({"role": "user", "content": f"Action Result: {summarized_action_result}"})
```

### Iteration 2: SQL Injection Testing

**ActionerAgent Input (with updated history):**

```python
# conversation_history now contains previous action and result
```

**ActionerAgent Output:**

```python
{
    "discussion": "Now I'll test for SQL injection vulnerabilities in the login form. I'll start with basic SQL injection payloads in the email field to check for database errors or authentication bypass. Testing with payload: admin' OR '1'='1",
    "action": "fill(page, \"input[name='email']\", \"admin' OR '1'='1\")"
}
```

**Action Execution:**

```python
action_output = _execute_action_command("fill(page, \"input[name='email']\", \"admin' OR '1'='1\")", page)
# Result: "Successfully filled email field with: admin' OR '1'='1"
```

### Iteration 3: Submit and Analyze Response

**ActionerAgent Output:**

```python
{
    "discussion": "Submitting the SQL injection payload to observe the application's response. Looking for database errors, authentication bypass, or unusual behavior that might indicate SQL injection vulnerability.",
    "action": "click(page, \"button[type='submit']\")"
}
```

**Action Execution:**

```python
action_output = _execute_action_command("click(page, \"button[type='submit']\")", page)
# Result: "Form submitted. Response: HTTP 400 - Invalid email format. Error message: Please enter a valid email address."
```

### Iteration 4: Alternative Injection Vector

**ActionerAgent Output:**

```python
{
    "discussion": "The application rejected the SQL injection payload due to client-side email validation. I'll try a different approach by testing the password field and using a valid email format with SQL injection in the password field.",
    "action": "fill(page, \"input[name='password']\", \"password' OR '1'='1' --\")"
}
```

### Final Iteration: Plan Completion

**ActionerAgent Output:**

```python
{
    "discussion": "Completed comprehensive authentication bypass testing. Tested SQL injection in both email and password fields, examined CSRF token validation, and attempted various authentication bypass techniques. The application appears to have basic input validation and CSRF protection, but deeper testing of password handling and backend validation is recommended.",
    "action": "complete()"
}
```

**Security Findings Analysis:**

```python
findings = _analyze_conversation_for_findings(conversation_history)
# Sample findings:
[
    "Information Disclosure: Client-side validation error messages revealed input processing logic",
    "Authentication Bypass: Basic SQL injection attempts blocked by input validation",
    "CSRF Vulnerability: CSRF token implementation requires further validation testing"
]
```

---

## Context Management Throughout the Flow

### Token Management

```python
# Before each iteration
if len(conversation_history) > keep_messages:  # keep_messages = 12
    # Preserve critical messages
    critical_messages = conversation_history[:2]  # Page context + plan
    recent_messages = conversation_history[-10:]   # Last 10 messages

    # Summarize middle portion
    middle_portion = conversation_history[2:-10]
    summarized_middle = context_manager.summarize_conversation(middle_portion)

    # Reconstruct history
    conversation_history = critical_messages + summarized_middle + recent_messages
```

### Sample Conversation Summary

```
To reduce context size, here is a VAPT summary of the previous security testing conversation:

**Authentication Testing Progress:**
• **SQL Injection Testing**: Attempted injection payloads in login form fields, encountered client-side validation blocking
• **Form Analysis**: Identified email format validation and CSRF token implementation
• **Error Response Analysis**: Application returns structured error messages revealing validation logic
• **Security Controls**: Basic input sanitization present, server-side validation effectiveness requires further testing
• **Attack Surface**: Login endpoint exhibits defensive measures but may have backend vulnerabilities
```

---

## Complete Flow Example: Plan Completion

After all iterations complete:

```python
# Plan 1 completed with findings
plan_findings = [
    "Information Disclosure: Client-side validation error messages revealed input processing logic",
    "Authentication Bypass: Basic SQL injection attempts blocked by input validation",
    "CSRF Vulnerability: CSRF token implementation requires further validation testing"
]
all_findings.extend(plan_findings)

print(f"Plan 1 completed with {len(plan_findings)} findings")
```

This process repeats for all 5 plans, then moves to the next URL in the queue.

---

## Final Output

```
===============================================================================
ORCHESTRATION COMPLETE - FINAL SUMMARY
===============================================================================
Total URLs analyzed: 5
Remaining URLs in queue: 0
Total tokens used: ~45,230
Total security findings: 23

🔍 SECURITY FINDINGS SUMMARY:
----------------------------------------
1. SQL Injection: Basic injection attempts blocked by input validation
2. XSS Vulnerability: Reflected XSS found in search parameter
3. Information Disclosure: Debug info exposed in error messages
4. Authorization Flaw: IDOR vulnerability in user profile endpoints
5. CSRF Vulnerability: Missing CSRF protection on password change
6. Authentication Bypass: Session fixation possible
... (17 more findings)
```

---

## Key Design Patterns

### 1. Nested Loop Architecture

- **Outer Loop**: Ensures comprehensive coverage of discovered URLs
- **Middle Loop**: Systematic execution of different security test categories
- **Inner Loop**: Iterative testing with adaptive responses

### 2. Context-Aware Summarization

- Preserves critical security context while managing token limits
- Focuses summaries on security-relevant information
- Maintains conversation continuity across iterations

### 3. Agent Specialization

- **Planner**: High-level security strategy
- **Actioner**: Tactical execution with reasoning
- **Context Manager**: Efficient information compression

### 4. Adaptive Action Generation

- LLM-driven decision making based on current context
- Validation and error correction for tool commands
- Fallback mechanisms for robust execution

This architecture enables comprehensive, automated security testing while maintaining efficiency and context awareness throughout the assessment process.

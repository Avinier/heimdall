from typing import List, Dict, Any, Optional
from tools.llms import LLM

SUMMARIZATION_SYSTEM_PROMPT = """
            You are a VAPT (Vulnerability Assessment and Penetration Testing) summarizer agent. Your role is to analyze and summarize security testing interactions with focus on vulnerability discovery and exploitation attempts.

            SECURITY TESTING INTERACTION ANALYSIS:

            1. Agent Security Action: What the security testing agent was attempting to accomplish
            {llm_response}

            2. Tool Command Executed: The actual security testing command that was run
            {tool_use}

            3. Tool Execution Result: The output from the security testing tool
            {limited_tool_output}

            SUMMARIZATION REQUIREMENTS:

            Your summary must explain:
            - What specific security vulnerability or attack vector was being tested
            - What security testing technique/tool was actually executed
            - What the security testing results indicate and if any vulnerabilities were discovered
            - Any security findings, error messages, or potential attack surface discovered

            FOCUS AREAS FOR SECURITY TESTING:
            - Authentication bypass attempts and results
            - SQL injection testing and database interaction
            - XSS (Cross-Site Scripting) vulnerability testing
            - Authorization and access control testing
            - Information disclosure and error message analysis
            - Session management and CSRF testing
            - API endpoint security assessment
            - File upload and directory traversal testing

            OUTPUT FORMAT:
            If the tool output is less than 200 words, return it as-is for full technical detail preservation.
            If longer than 200 words, provide a technical summary preserving:
            - Specific payloads used and their results
            - HTTP status codes and error messages
            - Security headers and authentication tokens
            - Database errors or system information disclosure
            - Any indicators of successful exploitation

            Keep the summary between 2-4 sentences. Maintain technical specificity and security relevance. Be succinct but preserve critical security details that could indicate vulnerabilities.
"""

SUMMARIZE_CONVERSATION_SYSTEM_PROMPT = """
            You are a VAPT (Vulnerability Assessment and Penetration Testing) conversation summarizer. Your role is to summarize security testing conversations focusing on vulnerability discovery and exploitation attempts.

            SECURITY TESTING CONVERSATION TO SUMMARIZE:
            {conversation_str}

            SUMMARIZATION REQUIREMENTS:

            Create a structured bullet-point summary covering:

            • **Vulnerability Testing Attempted**: What specific security vulnerabilities were tested (SQL injection, XSS, authentication bypass, authorization flaws, etc.)

            • **Security Testing Commands/Payloads**: Specific tool commands, payloads, or techniques used in the testing (fill(), click(), goto(), execute_js(), etc. with actual payloads)

            • **Security Test Results**: What happened when each security test was executed - HTTP responses, error messages, successful bypasses, access gained, etc.

            • **Security Findings Discovered**: Any confirmed vulnerabilities, security misconfigurations, information disclosure, or potential attack vectors identified

            • **Attack Surface Analysis**: Additional endpoints, forms, APIs, or functionality discovered during testing

            FOCUS ON SECURITY-RELEVANT DETAILS:
            - Authentication mechanisms tested and their results
            - Input validation bypass attempts
            - Authorization testing outcomes  
            - Session management testing
            - Error handling and information disclosure
            - API security assessment results
            - File upload and directory traversal testing
            - Any successful exploitation or proof-of-concept demonstrations

            Each bullet point should be 1-2 sentences maximum. Preserve technical details like URLs, payloads, status codes, and error messages. Keep the overall summary concise while maintaining security testing context.
"""

SUMMARIZE_PAGE_SOURCE_SYSTEM_PROMPT = """
        You are a VAPT (Vulnerability Assessment and Penetration Testing) web page analyzer. Your role is to analyze HTML content for security testing opportunities and vulnerability assessment.

        TARGET URL: {url}

        HTML CONTENT FOR SECURITY ANALYSIS:
        {page_source}

        SECURITY-FOCUSED ANALYSIS REQUIREMENTS:

        1. **Page Security Overview**
        - Brief description of the page's purpose and security-relevant functionality
        - Attack surface identification and security posture assessment

        2. **Security-Critical Interactive Elements**

        **Authentication & Authorization:**
        - Login forms: action URLs, methods, field names, CSRF protection, hidden fields
        - Registration/signup forms: validation requirements, user enumeration potential
        - Password reset functionality: security mechanisms, information disclosure
        - Administrative interfaces: access control, privilege escalation opportunities

        **Input Attack Vectors:**
        - All form inputs: names, types, validation patterns, injection testing opportunities
        - Search functionality: XSS and injection test points
        - File upload forms: allowed file types, path traversal potential, unrestricted upload risks
        - Text areas and rich text editors: stored XSS opportunities

        **Session & State Management:**
        - Session tokens visible in HTML: cookies, hidden fields, localStorage references
        - CSRF tokens: implementation patterns, bypass opportunities
        - Authentication state indicators: logged-in user info, privilege levels

        3. **Dynamic Security Elements**

        **Client-Side Security:**
        - JavaScript authentication: token handling, client-side validation bypasses
        - AJAX endpoints: API calls, authentication headers, parameter manipulation opportunities
        - WebSocket connections: real-time communication security
        - Local storage usage: sensitive data storage, token management

        **API & Backend Integration:**
        - REST endpoints: HTTP methods, parameter structures, authorization testing points
        - GraphQL endpoints: query structures, authorization bypass potential
        - Hidden API endpoints: embedded in JavaScript, HTML comments, or data attributes

        4. **Vulnerability Assessment Opportunities**

        **High-Priority Security Tests:**
        - SQL Injection: form parameters, URL parameters, hidden fields
        - Cross-Site Scripting (XSS): input fields, URL parameters, stored content areas
        - Authentication Bypass: login forms, session management, remember-me functionality
        - Authorization Flaws: IDOR potential in URLs, API endpoints, file access
        - CSRF Vulnerabilities: state-changing operations without proper token protection

        **Information Disclosure:**
        - Error messages: stack traces, database errors, path disclosure
        - Debug information: developer comments, TODO items, test credentials
        - Technology fingerprinting: framework versions, server information
        - Sensitive data exposure: emails, phone numbers, internal URLs

        **Security Misconfigurations:**
        - Missing security headers: CSP, X-Frame-Options, HSTS indicators
        - Insecure cookie settings: HttpOnly, Secure, SameSite attributes
        - Directory listing: accessible directories, backup files
        - Default credentials: common admin/admin, test accounts

        Provide specific CSS selectors, URLs, and parameter names for security testing. Focus on elements that represent real attack vectors for penetration testing. Prioritize findings by potential security impact.
"""

class ContextManagerAgent:
    """
    Context management agent that provides summarization capabilities for:
    - LLM responses and tool usage
    - Conversation histories
    - Page source content for security analysis
    
    Optimized for VAPT (Vulnerability Assessment and Penetration Testing) workflows.
    """
    
    def __init__(self, desc: str, debug: bool = False):
        self.llm = LLM(desc=desc)
        self.debug = debug
        
    def summarize(self, llm_response: str, tool_use: str, tool_output: str) -> str:
        # Limit tool output to prevent context overflow
        limited_tool_output = tool_output[:100000] if tool_output else ""
        
        prompt = SUMMARIZATION_SYSTEM_PROMPT.format(llm_response=llm_response, tool_use=tool_use, limited_tool_output=limited_tool_output)
        
        try:
            return self.llm.gemini_basic_call(prompt)
        except Exception as e:
            print(f"Error in summarize: {str(e)}")
            # Fallback summary with security focus
            return f"Security test attempted: {llm_response[:100]}... Tool executed: {tool_use}. Security result: {tool_output[:200] if tool_output else 'No output detected'}..."
        

    def summarize_conversation(self, conversation: List[Dict[str, str]]) -> List[Dict[str, str]]:
        # Convert conversation list to string format
        conversation_str = "\n".join([f"{msg['role']}: {msg['content']}" for msg in conversation])
        
        prompt = SUMMARIZE_CONVERSATION_SYSTEM_PROMPT.format(conversation_str=conversation_str)

        try:
            output = self.llm.gemini_basic_call(prompt)
            output = "To reduce context size, here is a VAPT summary of the previous security testing conversation:\n" + output
            return [{"role": "user", "content": output}]
        except Exception as e:
            print(f"Error in summarize_conversation: {str(e)}")
            # Fallback summary with security focus
            fallback_summary = f"Security testing conversation summary: {len(conversation)} messages covering vulnerability assessment and penetration testing activities."
            return [{"role": "user", "content": fallback_summary}]
        

    def summarize_page_source(self, page_source: str, url: str) -> str:
        # Process the entire page content directly without chunking
        prompt = SUMMARIZE_PAGE_SOURCE_SYSTEM_PROMPT.format(page_source=page_source, url=url)
        
        try:
            return self.llm.gemini_basic_call(prompt)
        except Exception as e:
            print(f"Error in summarize_page_source: {str(e)}")
            # Fallback summary with security focus
            return f"Security analysis of page from {url}: HTML content processed for vulnerability assessment. Length: {len(page_source)} characters. Manual security review recommended."

    def get_context_stats(self, text: str) -> Dict[str, Any]:
        char_count = len(text)
        # Rough estimation: 1 token ≈ 4 characters
        estimated_tokens = char_count // 4
        
        # Provide recommendations based on size for security testing workflows
        if estimated_tokens < 1000:
            recommendation = "Small context - suitable for detailed security analysis without summarization"
        elif estimated_tokens < 5000:
            recommendation = "Medium context - consider summarization to focus on security-critical elements"
        elif estimated_tokens < 20000:
            recommendation = "Large context - summarization recommended to highlight vulnerability assessment opportunities"
        else:
            recommendation = "Very large context - summarization required for effective VAPT analysis"
        
        return {
            "character_count": char_count,
            "estimated_tokens": estimated_tokens,
            "recommendation": recommendation,
            "should_summarize": estimated_tokens > 5000,
            "security_analysis_complexity": "high" if estimated_tokens > 10000 else "medium" if estimated_tokens > 3000 else "low"
        }

    def set_debug(self, debug: bool):
        """Enable or disable debug output for security testing operations."""
        self.debug = debug

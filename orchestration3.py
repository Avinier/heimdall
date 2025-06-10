# Tool Calling Testing and Orchestration
import sys
import os
from typing import Dict, List, Any, Optional
import json
import time

from tools.llms import LLM
from agents.actioner import ActionerAgent

tools_fw_compatible = [
    # ===== SQL INJECTION TESTING =====
    {
        "type": "function",
        "function": {
            "name": "sql_injection_test",
            "description": "Test a single URL parameter for SQL injection vulnerabilities using multiple payload techniques",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for SQL injection testing"},
                    "parameter": {"type": "string", "description": "Parameter name to test", "default": "id"},
                    "payload": {"type": "string", "description": "Custom SQL injection payload (optional)"},
                    "test_type": {"type": "string", "enum": ["basic", "advanced", "comprehensive"], "description": "Testing intensity level", "default": "basic"}
                },
                "required": ["url"]
            }
        }
    },

    # ===== XSS TESTING =====
    {
        "type": "function",
        "function": {
            "name": "xss_test",
            "description": "Test a single URL parameter for Cross-Site Scripting vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for XSS testing"},
                    "parameter": {"type": "string", "description": "Parameter name to test", "default": "search"},
                    "payload": {"type": "string", "description": "Custom XSS payload (optional)"},
                    "test_type": {"type": "string", "enum": ["basic", "advanced", "comprehensive"], "description": "Testing intensity level", "default": "basic"}
                },
                "required": ["url"]
            }
        }
    },

    # ===== NETWORK RECONNAISSANCE =====
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": "Perform network reconnaissance on a single target using Nmap",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP address or hostname"},
                    "scan_type": {"type": "string", "enum": ["basic", "service", "vuln", "comprehensive"], "description": "Type of scan to perform", "default": "basic"},
                    "ports": {"type": "string", "description": "Port specification (e.g., '1-1000', '80,443,8080')"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "port_scan",
            "description": "Scan specific ports on a single host",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Target host IP address"},
                    "ports": {"type": "array", "items": {"type": "integer"}, "description": "List of ports to scan"},
                    "scan_timeout": {"type": "integer", "description": "Timeout for each port scan in seconds", "default": 5}
                },
                "required": ["host", "ports"]
            }
        }
    },

    # ===== API SECURITY TESTING =====
    {
        "type": "function",
        "function": {
            "name": "api_endpoint_discovery",
            "description": "Discover API endpoints on a single base URL",
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string", "description": "Base URL for API discovery"},
                    "wordlist": {"type": "array", "items": {"type": "string"}, "description": "Custom wordlist for endpoint discovery"},
                    "discovery_level": {"type": "string", "enum": ["basic", "comprehensive", "aggressive"], "description": "Discovery intensity level", "default": "basic"}
                },
                "required": ["base_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "jwt_vulnerability_test",
            "description": "Analyze a single JWT token for security vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "JWT token to analyze"}
                },
                "required": ["token"]
            }
        }
    },

    # ===== SPECIFIC VULNERABILITY TESTS =====
    {
        "type": "function",
        "function": {
            "name": "idor_test",
            "description": "Test a single endpoint for Insecure Direct Object Reference vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string", "description": "Endpoint URL to test for IDOR"},
                    "parameter": {"type": "string", "description": "Parameter name to manipulate"},
                    "test_values": {"type": "array", "items": {"type": "string"}, "description": "Custom test values for IDOR testing"}
                },
                "required": ["endpoint", "parameter"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "command_injection_test",
            "description": "Test a single URL parameter for OS command injection vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for command injection testing"},
                    "parameter": {"type": "string", "description": "Parameter name to test", "default": "cmd"},
                    "payload": {"type": "string", "description": "Custom command injection payload (optional)"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "xxe_test",
            "description": "Test a single endpoint for XML External Entity vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for XXE testing"},
                    "xml_parameter": {"type": "string", "description": "XML parameter name", "default": "data"},
                    "payload": {"type": "string", "description": "Custom XXE payload (optional)"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "information_disclosure_test",
            "description": "Test a single URL for information disclosure vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for information disclosure testing"}
                },
                "required": ["url"]
            }
        }
    },

    # ===== UTILITY FUNCTIONS =====
    {
        "type": "function",
        "function": {
            "name": "create_vulnerability",
            "description": "Create a standardized vulnerability object with proper classification and scoring",
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "Vulnerability type (e.g., 'SQL Injection', 'XSS')"},
                    "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"], "description": "Risk level"},
                    "evidence": {"type": "string", "description": "Description of what was found"},
                    "cvss_score": {"type": "number", "description": "CVSS score 0-10", "default": 0.0},
                    "location": {"type": "string", "description": "Where found (e.g., 'GET parameter', 'POST body')"},
                    "parameter": {"type": "string", "description": "Parameter name if applicable"},
                    "url": {"type": "string", "description": "Full URL tested"},
                    "payload": {"type": "string", "description": "Attack payload used"},
                    "remediation": {"type": "string", "description": "Fix recommendations"}
                },
                "required": ["vuln_type", "severity", "evidence"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_results",
            "description": "Save individual test results to file with proper formatting",
            "parameters": {
                "type": "object",
                "properties": {
                    "results": {"type": "object", "description": "ToolCallResult object to save"},
                    "filename": {"type": "string", "description": "Optional filename for results"}
                },
                "required": ["results"]
            }
        }
    }
]

tools_gemini_compatible = [
    # ===== SQL INJECTION TESTING =====
    {
        "name": "sql_injection_test",
        "description": "Test a single URL parameter for SQL injection vulnerabilities using multiple payload techniques",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for SQL injection testing"},
                "parameter": {"type": "string", "description": "Parameter name to test", "default": "id"},
                "payload": {"type": "string", "description": "Custom SQL injection payload (optional)"},
                "test_type": {"type": "string", "enum": ["basic", "advanced", "comprehensive"], "description": "Testing intensity level", "default": "basic"}
            },
            "required": ["url"]
        }
    },

    # ===== XSS TESTING =====
    {
        "name": "xss_test",
        "description": "Test a single URL parameter for Cross-Site Scripting vulnerabilities",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for XSS testing"},
                "parameter": {"type": "string", "description": "Parameter name to test", "default": "search"},
                "payload": {"type": "string", "description": "Custom XSS payload (optional)"},
                "test_type": {"type": "string", "enum": ["basic", "advanced", "comprehensive"], "description": "Testing intensity level", "default": "basic"}
            },
            "required": ["url"]
        }
    },

    # ===== NETWORK RECONNAISSANCE =====
    {
        "name": "nmap_scan",
        "description": "Perform network reconnaissance on a single target using Nmap",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP address or hostname"},
                "scan_type": {"type": "string", "enum": ["basic", "service", "vuln", "comprehensive"], "description": "Type of scan to perform", "default": "basic"},
                "ports": {"type": "string", "description": "Port specification (e.g., '1-1000', '80,443,8080')"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "port_scan",
        "description": "Scan specific ports on a single host",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target host IP address"},
                "ports": {"type": "array", "items": {"type": "integer"}, "description": "List of ports to scan"},
                "scan_timeout": {"type": "integer", "description": "Timeout for each port scan in seconds", "default": 5}
            },
            "required": ["host", "ports"]
        }
    },

    # ===== API SECURITY TESTING =====
    {
        "name": "api_endpoint_discovery",
        "description": "Discover API endpoints on a single base URL",
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL for API discovery"},
                "wordlist": {"type": "array", "items": {"type": "string"}, "description": "Custom wordlist for endpoint discovery"},
                "discovery_level": {"type": "string", "enum": ["basic", "comprehensive", "aggressive"], "description": "Discovery intensity level", "default": "basic"}
            },
            "required": ["base_url"]
        }
    },
    {
        "name": "jwt_vulnerability_test",
        "description": "Analyze a single JWT token for security vulnerabilities",
        "parameters": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "JWT token to analyze"}
            },
            "required": ["token"]
        }
    },

    # ===== SPECIFIC VULNERABILITY TESTS =====
    {
        "name": "idor_test",
        "description": "Test a single endpoint for Insecure Direct Object Reference vulnerabilities",
        "parameters": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Endpoint URL to test for IDOR"},
                "parameter": {"type": "string", "description": "Parameter name to manipulate"},
                "test_values": {"type": "array", "items": {"type": "string"}, "description": "Custom test values for IDOR testing"}
            },
            "required": ["endpoint", "parameter"]
        }
    },
    {
        "name": "command_injection_test",
        "description": "Test a single URL parameter for OS command injection vulnerabilities",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for command injection testing"},
                "parameter": {"type": "string", "description": "Parameter name to test", "default": "cmd"},
                "payload": {"type": "string", "description": "Custom command injection payload (optional)"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "xxe_test",
        "description": "Test a single endpoint for XML External Entity vulnerabilities",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for XXE testing"},
                "xml_parameter": {"type": "string", "description": "XML parameter name", "default": "data"},
                "payload": {"type": "string", "description": "Custom XXE payload (optional)"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "information_disclosure_test",
        "description": "Test a single URL for information disclosure vulnerabilities",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for information disclosure testing"}
            },
            "required": ["url"]
        }
    },

    # ===== UTILITY FUNCTIONS =====
    {
        "name": "create_vulnerability",
        "description": "Create a standardized vulnerability object with proper classification and scoring",
        "parameters": {
            "type": "object",
            "properties": {
                "vuln_type": {"type": "string", "description": "Vulnerability type (e.g., 'SQL Injection', 'XSS')"},
                "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"], "description": "Risk level"},
                "evidence": {"type": "string", "description": "Description of what was found"},
                "cvss_score": {"type": "number", "description": "CVSS score 0-10", "default": 0.0},
                "location": {"type": "string", "description": "Where found (e.g., 'GET parameter', 'POST body')"},
                "parameter": {"type": "string", "description": "Parameter name if applicable"},
                "url": {"type": "string", "description": "Full URL tested"},
                "payload": {"type": "string", "description": "Attack payload used"},
                "remediation": {"type": "string", "description": "Fix recommendations"}
            },
            "required": ["vuln_type", "severity", "evidence"]
        }
    },
    {
        "name": "save_results",
        "description": "Save individual test results to file with proper formatting",
        "parameters": {
            "type": "object",
            "properties": {
                "results": {"type": "object", "description": "ToolCallResult object to save"},
                "filename": {"type": "string", "description": "Optional filename for results"}
            },
            "required": ["results"]
        }
    }
]

def test_tool_use_functions():
    """
    Test function for gemini_tool_use and fireworks_tool_use functions
    using security testing prompts based on actioner agent scenarios.
    """
    print("=" * 80)
    print("TESTING TOOL USE FUNCTIONS - SECURITY TESTING SIMULATION")
    print("=" * 80)
    
    # Initialize LLM
    llm = LLM("Security Tool Testing LLM")
    
    # Security testing prompts inspired by actioner agent
    test_prompts = [
        {
            "name": "SQL Injection Assessment",
            "prompt": """You are conducting a comprehensive SQL injection security assessment on a high-risk financial application.
            
TARGET: https://bank.example.com/login
BUSINESS IMPACT: CRITICAL - Financial system compromise, regulatory violations (PCI DSS, SOX)
ATTACK COMPLEXITY: HIGH - Advanced evasion techniques required
COMPLIANCE RISK: PCI DSS Level 1, SOX financial reporting controls

Current findings:
- Login form detected with username/password fields
- Parameter 'user_id' in GET requests appears vulnerable
- Error messages revealing database structure
- No apparent WAF protection on login endpoint

You need to:
1. Test the login form for SQL injection vulnerabilities using advanced payloads
2. Create a vulnerability report if injection is confirmed  
3. Save the results for compliance documentation

Use appropriate security testing tools to systematically test for SQL injection with business context awareness."""
        },
        {
            "name": "XSS Vulnerability Discovery",
            "prompt": """You are performing Cross-Site Scripting (XSS) vulnerability testing on a customer-facing e-commerce platform.

TARGET: https://shop.example.com/search
BUSINESS IMPACT: HIGH - Customer data exposure, session hijacking, reputational damage
ATTACK COMPLEXITY: MEDIUM-HIGH - Input validation bypass required
COMPLIANCE RISK: GDPR data protection, consumer privacy regulations

Current context:
- Search functionality with user input reflection
- Customer reviews section with rich text support
- No Content Security Policy headers detected
- Session tokens stored in localStorage

You need to:
1. Test the search parameter for XSS vulnerabilities
2. Test review submission forms for stored XSS
3. Create comprehensive vulnerability documentation
4. Assess business impact and compliance implications

Execute systematic XSS testing with appropriate payload selection for the e-commerce context."""
        },
        {
            "name": "Network Reconnaissance",
            "prompt": """You are conducting network reconnaissance as part of an authorized penetration test for a healthcare organization.

TARGET: 192.168.1.100 (healthcare-app.hospital.com)
BUSINESS IMPACT: CRITICAL - Patient data protection, HIPAA compliance
ATTACK COMPLEXITY: EXPERT - Healthcare networks require sophisticated techniques
COMPLIANCE RISK: HIPAA, HITECH Act, state medical privacy laws

Current intelligence:
- Healthcare application server in DMZ
- Known to run multiple services
- Strict compliance requirements for patient data
- 24/7 availability requirement for emergency systems

You need to:
1. Perform comprehensive network scanning to identify services
2. Conduct targeted port scanning on discovered services
3. Document findings with healthcare compliance context
4. Assess impact on patient care continuity

Execute reconnaissance with minimal impact to critical healthcare operations."""
        },
        {
            "name": "API Security Assessment",
            "prompt": """You are testing API security for a financial trading platform with real-time transaction processing.

TARGET: https://api.trading.example.com/v1/
BUSINESS IMPACT: CATASTROPHIC - Financial fraud, market manipulation, regulatory sanctions
ATTACK COMPLEXITY: VERY HIGH - Advanced financial crime techniques required
COMPLIANCE RISK: SEC regulations, FINRA compliance, anti-money laundering (AML)

Current API analysis:
- RESTful API with OAuth 2.0 authentication
- JWT tokens for session management
- Real-time trading endpoints exposed
- Rate limiting appears insufficient for high-frequency trading

You need to:
1. Discover additional API endpoints beyond documentation
2. Test JWT tokens for manipulation vulnerabilities
3. Assess authorization controls on trading functions
4. Create detailed security findings with financial impact assessment

Execute advanced API security testing appropriate for financial trading systems."""
        }
    ]
    
    # Run tests for each prompt
    for i, test_case in enumerate(test_prompts, 1):
        print(f"\n{'='*60}")
        print(f"TEST CASE {i}: {test_case['name']}")
        print(f"{'='*60}")
        
        try:
            # Test Gemini tool use
            print(f"\n🔍 TESTING GEMINI TOOL USE...")
            print("-" * 40)
            
            gemini_result = llm.gemini_tool_use(
                prompt=test_case['prompt'],
                tools=tools_gemini_compatible,
                model="gemini-2.0-flash"
            )
            
            print(f"✅ Gemini Response:")
            print(f"Text: {gemini_result.get('text', 'No text response')[:200]}...")
            print(f"Function Calls: {len(gemini_result.get('function_calls', []))} tool(s) called")
            
            if gemini_result.get('function_calls'):
                for j, call in enumerate(gemini_result['function_calls'], 1):
                    print(f"  {j}. {call.get('name', 'unknown')}({list(call.get('args', {}).keys())})")
                    
        except Exception as e:
            print(f"❌ Gemini test failed: {str(e)}")
        
        try:
            # Test Fireworks tool use  
            print(f"\n🔥 TESTING FIREWORKS TOOL USE...")
            print("-" * 40)
            
            fireworks_result = llm.fireworks_tool_use(
                prompt=test_case['prompt'],
                tools=tools_fw_compatible,
                model_key="deepseek-v3",
                temperature=0.3,
                system_prompt="You are an elite security testing agent. Analyze the security scenario and select appropriate tools for testing."
            )
            
            print(f"✅ Fireworks Response:")
            print(f"Content: {fireworks_result.get('content', 'No content')[:200]}...")
            print(f"Tool Calls: {len(fireworks_result.get('tool_calls', []))} tool(s) called")
            
            if fireworks_result.get('tool_calls'):
                for j, call in enumerate(fireworks_result['tool_calls'], 1):
                    func = call.get('function', {})
                    print(f"  {j}. {func.get('name', 'unknown')}({list(func.get('arguments', {}).keys()) if isinstance(func.get('arguments'), dict) else 'args'})")
                    
        except Exception as e:
            print(f"❌ Fireworks test failed: {str(e)}")
            
        # Pause between tests
        if i < len(test_prompts):
            print(f"\n⏳ Waiting 2 seconds before next test...")
            time.sleep(2)
    
    print(f"\n{'='*80}")
    print("TOOL USE TESTING COMPLETED")
    print(f"{'='*80}")
    
    # Test additional scenarios
    print(f"\n🧪 TESTING EDGE CASES...")
    print("-" * 40)
    
    # Test with minimal prompt
    minimal_prompt = "Test the URL https://example.com for SQL injection in the 'id' parameter."
    
    try:
        print("Testing minimal prompt with Gemini...")
        minimal_result = llm.gemini_tool_use(
            prompt=minimal_prompt,
            tools=tools_gemini_compatible[:3],  # Only first 3 tools
            model="gemini-2.0-flash"
        )
        print(f"✅ Minimal test: {len(minimal_result.get('function_calls', []))} tools called")
        
    except Exception as e:
        print(f"❌ Minimal test failed: {str(e)}")
    
    # Test with comprehensive security assessment prompt
    comprehensive_prompt = """
    Conduct a comprehensive security assessment of the web application at https://app.example.com with the following requirements:
    
    BUSINESS CONTEXT:
    - E-commerce platform handling credit card transactions
    - Customer PII including names, addresses, payment data
    - Business impact: CRITICAL financial and reputation risk
    - Compliance: PCI DSS Level 1, GDPR, state privacy laws
    
    TECHNICAL SCOPE:
    - Web application security testing (OWASP Top 10)
    - API security assessment (REST/GraphQL)
    - Authentication and session management
    - Input validation and injection vulnerabilities
    - Business logic and authorization flaws
    
    ATTACK COMPLEXITY: HIGH
    - Advanced evasion techniques required
    - WAF bypass methods needed  
    - Custom payload development
    - Multi-vector attack chains
    
    Execute a systematic security assessment using appropriate testing tools and methodologies.
    """
    
    try:
        print("\nTesting comprehensive assessment with Fireworks...")
        comp_result = llm.fireworks_tool_use(
            prompt=comprehensive_prompt,
            tools=tools_fw_compatible,
            model_key="qwen2.5-72b-instruct",
            temperature=0.2,
            system_prompt="You are an expert penetration tester conducting a comprehensive security assessment. Select the most appropriate tools for systematic testing."
        )
        print(f"✅ Comprehensive test: {len(comp_result.get('tool_calls', []))} tools called")
        
        if comp_result.get('tool_calls'):
            print("Tool selection strategy:")
            for call in comp_result['tool_calls']:
                func = call.get('function', {})
                print(f"  - {func.get('name', 'unknown')}")
                
    except Exception as e:
        print(f"❌ Comprehensive test failed: {str(e)}")
    
    print(f"\n🎯 TESTING SUMMARY COMPLETE")
    return True


def test_single_tool_scenario(tool_name: str, prompt: str, api_type: str = "both"):
    """
    Test a specific tool scenario with either Gemini, Fireworks, or both.
    
    Args:
        tool_name: Name of the tool to focus testing on
        prompt: Security testing prompt
        api_type: "gemini", "fireworks", or "both"
    """
    print(f"\n🎯 FOCUSED TOOL TEST: {tool_name}")
    print("-" * 50)
    
    llm = LLM("Focused Tool Testing")
    
    # Filter tools to focus on specific tool
    focused_tools_gemini = [tool for tool in tools_gemini_compatible if tool['name'] == tool_name]
    focused_tools_fw = [tool for tool in tools_fw_compatible if tool['function']['name'] == tool_name]
    
    if not focused_tools_gemini and not focused_tools_fw:
        print(f"❌ Tool '{tool_name}' not found in tool definitions")
        return False
    
    if api_type in ["gemini", "both"] and focused_tools_gemini:
        try:
            print(f"Testing {tool_name} with Gemini...")
            result = llm.gemini_tool_use(
                prompt=prompt,
                tools=focused_tools_gemini,
                model="gemini-2.0-flash"
            )
            print(f"✅ Gemini called {tool_name}: {len(result.get('function_calls', []))} times")
            
            for call in result.get('function_calls', []):
                print(f"  Args: {call.get('args', {})}")
                
        except Exception as e:
            print(f"❌ Gemini {tool_name} test failed: {str(e)}")
    
    if api_type in ["fireworks", "both"] and focused_tools_fw:
        try:
            print(f"Testing {tool_name} with Fireworks...")
            result = llm.fireworks_tool_use(
                prompt=prompt,
                tools=focused_tools_fw,
                model_key="deepseek-v3",
                system_prompt=f"You are testing the {tool_name} security tool. Use it appropriately based on the scenario."
            )
            print(f"✅ Fireworks called {tool_name}: {len(result.get('tool_calls', []))} times")
            
            for call in result.get('tool_calls', []):
                func = call.get('function', {})
                if isinstance(func.get('arguments'), str):
                    try:
                        args = json.loads(func.get('arguments', '{}'))
                    except:
                        args = func.get('arguments', {})
                else:
                    args = func.get('arguments', {})
                print(f"  Args: {args}")
                
        except Exception as e:
            print(f"❌ Fireworks {tool_name} test failed: {str(e)}")
    
    return True


if __name__ == "__main__":
    print("🚀 Starting Tool Use Function Testing...")
    
    # Run comprehensive tests
    test_tool_use_functions()
    
    # Run focused tests
    print(f"\n{'='*60}")
    print("FOCUSED TOOL TESTS")
    print(f"{'='*60}")
    
    # Test SQL injection specifically
    test_single_tool_scenario(
        tool_name="sql_injection_test",
        prompt="Test https://login.bank.com/auth for SQL injection in the username parameter. This is a critical financial system requiring advanced testing techniques.",
        api_type="both"
    )
    
    # Test XSS specifically  
    test_single_tool_scenario(
        tool_name="xss_test",
        prompt="Assess https://forum.example.com/search for XSS vulnerabilities. User input is reflected in search results without proper sanitization.",
        api_type="both"
    )
    
    # Test nmap specifically
    test_single_tool_scenario(
        tool_name="nmap_scan",
        prompt="Perform network reconnaissance on target 192.168.1.50 for a healthcare penetration test. Use comprehensive scanning to identify all services.",
        api_type="both"
    )
    
    print(f"\n✅ ALL TOOL USE TESTING COMPLETED!")


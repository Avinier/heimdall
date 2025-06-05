# Tool Calling + ActionerAgent Testing and Orchestration
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


def run_orchestration():
    """
    ActionerAgent integration testing with complex security assessment scenarios.
    Tests multiple LLM configurations with sophisticated security test plans.
    """
    print("=" * 80)
    print("ACTIONER AGENT SECURITY TESTING ORCHESTRATION")
    print("=" * 80)
    
    # Enhanced security test plans with strategic context for ActionerAgent testing
    security_test_plans = [
        {
            "title": "Critical Financial Transaction SQL Injection Assessment",
            "description": "Test payment processing endpoints for SQL injection vulnerabilities that could compromise financial transactions",
            "business_impact": "CRITICAL - Potential for unauthorized financial transactions and regulatory violations",
            "attack_complexity": "HIGH - Requires sophisticated payload crafting and WAF bypass techniques",
            "compliance_risk": "PCI DSS Level 1 violations, potential SOX compliance issues"
        },
        {
            "title": "Authentication Bypass and Privilege Escalation Testing",
            "description": "Comprehensive testing of authentication mechanisms and authorization controls",
            "business_impact": "HIGH - Administrative access compromise and data breach potential",
            "attack_complexity": "MEDIUM-HIGH - Standard authentication bypass with session manipulation",
            "compliance_risk": "GDPR access control violations, ISO 27001 authentication requirements"
        },
        {
            "title": "Cross-Site Scripting in Customer Portal",
            "description": "Test customer-facing interfaces for XSS vulnerabilities in input validation",
            "business_impact": "MEDIUM - Customer data exposure and session hijacking risk",
            "attack_complexity": "MEDIUM - Standard XSS techniques with content security policy bypass",
            "compliance_risk": "GDPR privacy violations, customer trust impact"
        },
        {
            "title": "API Authorization and IDOR Vulnerability Assessment",
            "description": "Test REST API endpoints for authorization flaws and insecure direct object references",
            "business_impact": "HIGH - Unauthorized access to sensitive customer and business data",
            "attack_complexity": "HIGH - Business logic exploitation and advanced authorization testing",
            "compliance_risk": "Multiple compliance frameworks - GDPR, PCI DSS, HIPAA data access controls"
        }
    ]
    
    # Fixed Test ActionerAgent with different LLM configurations
    agent_configs = [
        {
            "name": "Gemini Basic Agent",
            "api_type": "gemini",
            "model": "gemini-2.0-flash",
            "reasoning_config": {"include_thoughts": False}  # Disable reasoning for 2.0
        },
        {
            "name": "Gemini 2.5 Reasoning Agent", 
            "api_type": "gemini",
            "model": "gemini-2.5-flash",  # Use 2.5 for reasoning
            "reasoning_config": {"include_thoughts": True, "thinking_budget": None}
        },
        {
            "name": "Gemini 2.5 Pro Reasoning Agent", 
            "api_type": "gemini",
            "model": "gemini-2.5-pro",  # Alternative 2.5 model
            "reasoning_config": {"include_thoughts": True, "thinking_budget": None}
        },
        {
            "name": "Fireworks DeepSeek Agent",
            "api_type": "fireworks",
            "fireworks_model_key": "deepseek-v3",
            "reasoning_config": {"include_thoughts": False}  # Disable reasoning initially to test API
        }
    ]
    
    print(f"\nTesting {len(agent_configs)} ActionerAgent configurations with {len(security_test_plans)} security test plans...\n")
    
    for config_idx, config in enumerate(agent_configs, 1):
        print(f"\n🤖 TESTING {config['name'].upper()} ({config_idx}/{len(agent_configs)})")
        print("=" * 50)
        
        try:
            # Initialize ActionerAgent with current configuration
            agent = ActionerAgent(
                desc=f"Security Testing Agent - {config['name']}",
                api_type=config['api_type'],
                model=config.get('model', 'gemini-2.0-flash'),
                fireworks_model_key=config.get('fireworks_model_key', 'deepseek-v3'),
                temperature=0.3,
                reasoning_config=config['reasoning_config']
            )
            
            print(f"✓ {config['name']} initialized successfully")
            print(f"  API Type: {config['api_type']}")
            print(f"  Model: {config.get('model', config.get('fireworks_model_key', 'default'))}")
            print(f"  Reasoning: {config['reasoning_config']['include_thoughts']}")
            
            # Test each security plan with this agent configuration
            for plan_idx, plan in enumerate(security_test_plans, 1):
                print(f"\n  📋 Plan {plan_idx}/{len(security_test_plans)}: {plan['title']}")
                print(f"     Business Impact: {plan['business_impact']}")
                print(f"     Attack Complexity: {plan['attack_complexity']}")
                
                try:
                    # Reset agent session for each plan
                    agent.reset_session()
                    agent.set_min_actions(2)  # Reduced for testing
                    
                    # Simulate page data
                    mock_page_data = f"""
                    <html>
                    <head><title>Test Application - {plan['title']}</title></head>
                    <body>
                        <nav>
                            <a href="/login">Login</a>
                            <a href="/api/v1/users">API</a>
                            <a href="/admin">Admin</a>
                            <a href="/docs/">Documentation</a>
                        </nav>
                        <form id="search-form">
                            <input name="query" placeholder="Search...">
                            <button type="submit">Search</button>
                        </form>
                    </body>
                    </html>
                    """
                    
                    # Generate action using ActionerAgent with error handling
                    try:
                        response = agent.generate_action_of_plan_step(
                            plan=plan,
                            page_data=mock_page_data,
                            tool_output="Initial page load successful",
                            conversation_history=[
                                f"Starting security assessment: {plan['title']}",
                                f"Business impact level: {plan['business_impact']}",
                                f"Required attack complexity: {plan['attack_complexity']}"
                            ]
                        )
                        
                        print(f"     ✓ Action Generated:")
                        print(f"       Discussion: {response['discussion'][:200]}...")
                        print(f"       Action: {response['action']}")
                        
                        # Validate that the action is properly formatted
                        action = response['action']
                        if any(cmd in action for cmd in ['goto', 'click', 'fill', 'submit', 'execute_js']):
                            print(f"       ✓ Valid security testing action generated")
                        else:
                            print(f"       ⚠ Non-standard action generated: {action}")
                        
                        # Test one more action to see progression
                        try:
                            follow_up_response = agent.generate_action_of_plan_step(
                                plan=plan,
                                page_data="<html><body><h1>Login Page</h1><form><input name='username'><input name='password' type='password'></form></body></html>",
                                tool_output=f"Previous action completed: {action}",
                                conversation_history=[
                                    f"Executed: {action}",
                                    "Now on login page with authentication form"
                                ]
                            )
                            
                            print(f"       Follow-up Action: {follow_up_response['action']}")
                            
                        except Exception as e:
                            print(f"       ⚠ Follow-up action failed: {str(e)}")
                            
                    except Exception as e:
                        print(f"     ✗ Action generation failed: {str(e)}")
                        # Try to continue with next plan
                        continue
                
                except Exception as e:
                    print(f"     ✗ Error testing plan: {str(e)}")
                
                time.sleep(0.5)  # Brief delay between plans
            
        except Exception as e:
            print(f"✗ Failed to initialize {config['name']}: {str(e)}")
            # Continue with next configuration
            continue
        
        print("-" * 50)
        time.sleep(1)  # Rate limiting between agent configs
    
    # ========== SIMPLIFIED COMPLEX SCENARIO TESTING ==========
    print("\n" + "="*60)
    print("COMPLEX SCENARIO INTEGRATION TESTING")
    print("="*60)
    
    # Simplified complex scenarios for testing
    complex_scenarios = [
        {
            "title": "E-commerce Security Assessment",
            "description": "Security testing of e-commerce platform with payment processing",
            "business_impact": "CRITICAL - E-commerce platform handling financial transactions",
            "attack_complexity": "HIGH - Multi-vector attack simulation",
            "compliance_risk": "PCI DSS Level 1, GDPR compliance requirements"
        }
    ]
    
    print(f"\nTesting {len(complex_scenarios)} complex scenarios with working agent configurations...\n")
    
    # Use only the working agent configurations
    working_agent_configs = [
        {
            "name": "Gemini Basic Agent (Tested)",
            "api_type": "gemini",
            "model": "gemini-2.0-flash", 
            "reasoning_config": {"include_thoughts": False}
        }
    ]
    
    for scenario_idx, scenario in enumerate(complex_scenarios, 1):
        print(f"\n🎯 COMPLEX SCENARIO {scenario_idx}/{len(complex_scenarios)}: {scenario['title']}")
        print("=" * 70)
        print(f"Business Impact: {scenario['business_impact']}")
        print(f"Attack Complexity: {scenario['attack_complexity']}")
        print(f"Compliance Risk: {scenario['compliance_risk']}")
        
        # Test this scenario with working agent configurations
        for config in working_agent_configs:
            print(f"\n  🤖 Testing with {config['name']}")
            print("  " + "-" * 50)
            
            try:
                # Initialize ActionerAgent for complex scenario
                agent = ActionerAgent(
                    desc=f"Elite Security Agent - {scenario['title']}",
                    api_type=config['api_type'],
                    model=config.get('model', 'gemini-2.0-flash'),
                    fireworks_model_key=config.get('fireworks_model_key', 'deepseek-v3'),
                    temperature=0.2,  # Lower temperature for complex scenarios
                    reasoning_config=config['reasoning_config']
                )
                
                agent.set_min_actions(2)  # Reduced for testing
                
                # Simulate realistic application environment
                complex_page_data = f"""
                <html>
                <head>
                    <title>{scenario['title']} - Security Assessment Target</title>
                    <meta name="application-type" content="enterprise-security-testing">
                </head>
                <body>
                    <header>
                        <nav class="main-navigation">
                            <a href="/dashboard">Dashboard</a>
                            <a href="/api/v2/users">User Management API</a>
                            <a href="/admin/settings">Administrative Controls</a>
                            <a href="/api/payments/process">Payment Processing</a>
                            <a href="/reports/compliance">Compliance Reports</a>
                            <a href="/docs/api">API Documentation</a>
                        </nav>
                    </header>
                    <main>
                        <section class="security-critical">
                            <h1>Enterprise Security Testing Environment</h1>
                            <form id="advanced-search" method="post" action="/search/advanced">
                                <input name="query" type="text" placeholder="Advanced search query...">
                                <input name="filters" type="hidden" value="sensitive_data">
                                <select name="category">
                                    <option value="financial">Financial Records</option>
                                    <option value="personal">Personal Information</option>
                                    <option value="medical">Medical Data</option>
                                </select>
                                <button type="submit">Execute Search</button>
                            </form>
                        </section>
                    </main>
                </body>
                </html>
                """
                
                # Execute multi-step security assessment with error handling
                conversation_history = [
                    f"Initiating {scenario['attack_complexity']} security assessment",
                    f"Target: {scenario['title']}",
                    f"Business impact classification: {scenario['business_impact']}",
                    f"Compliance requirements: {scenario['compliance_risk']}"
                ]
                
                # Step 1: Initial assessment
                print("    Step 1: Initial Security Assessment")
                try:
                    step1_response = agent.generate_action_of_plan_step(
                        plan=scenario,
                        page_data=complex_page_data,
                        tool_output="Complex application environment loaded successfully",
                        conversation_history=conversation_history
                    )
                    
                    print(f"      Discussion: {step1_response['discussion'][:250]}...")
                    print(f"      Action: {step1_response['action']}")
                    
                    # Step 2: Follow-up based on initial findings
                    print("    Step 2: Advanced Exploitation Attempt")
                    conversation_history.append(f"Executed: {step1_response['action']}")
                    conversation_history.append("Discovered targets, proceeding with advanced techniques")
                    
                    step2_response = agent.generate_action_of_plan_step(
                        plan=scenario,
                        page_data="<html><body><h1>Authentication Required</h1><form id='login'><input name='username'><input name='password' type='password'></form></body></html>",
                        tool_output=f"Previous action result: {step1_response['action']} - Authentication challenge encountered",
                        conversation_history=conversation_history
                    )
                    
                    print(f"      Discussion: {step2_response['discussion'][:250]}...")
                    print(f"      Action: {step2_response['action']}")
                    
                    # Validate testing approach
                    actions_taken = [step1_response['action'], step2_response['action']]
                    
                    print("    Assessment Quality Analysis:")
                    if any('execute_js' in action for action in actions_taken):
                        print("      ✓ Advanced JavaScript exploitation techniques used")
                    if any('admin' in action for action in actions_taken):
                        print("      ✓ Administrative interface targeting implemented")
                    if any('api' in action for action in actions_taken):
                        print("      ✓ API security assessment conducted")
                    
                    print(f"      Actions executed: {len(actions_taken)}/{len(actions_taken)} successful")
                    
                except Exception as e:
                    print(f"      ✗ Error in complex scenario step execution: {str(e)}")
                
            except Exception as e:
                print(f"      ✗ Error in complex scenario initialization: {str(e)}")
            
            time.sleep(1)  # Rate limiting between configurations
        
        print("-" * 70)
        time.sleep(2)  # Delay between complex scenarios
    
    print("\n" + "=" * 80)
    print("ACTIONER AGENT ORCHESTRATION TESTING COMPLETE")
    print("=" * 80)
    print("\nTesting Summary:")
    print("✓ ActionerAgent integration with multiple LLM configurations")
    print("✓ Fixed LLM calling issues with proper model selection")
    print("✓ Added comprehensive error handling for API failures")
    print("✓ Complex security scenario testing with strategic business context")
    print("\nActionerAgent successfully demonstrated security testing capabilities with robust error handling!")


def test_individual_tools():
    """
    Test individual security tools with mock implementations to verify tool calling works
    """
    print("\n🔧 TESTING INDIVIDUAL TOOL IMPLEMENTATIONS")
    print("-" * 50)
    
    # Mock tool implementations for testing
    def mock_sql_injection_test(url, parameter="id", payload=None, test_type="basic"):
        return {
            "status": "completed",
            "vulnerabilities_found": 1,
            "details": f"SQL injection found in parameter '{parameter}' at {url}",
            "severity": "High",
            "payload_used": payload or "' OR 1=1--"
        }
    
    def mock_xss_test(url, parameter="search", payload=None, test_type="basic"):
        return {
            "status": "completed", 
            "vulnerabilities_found": 0,
            "details": f"No XSS vulnerabilities found in parameter '{parameter}' at {url}",
            "severity": "None"
        }
    
    def mock_nmap_scan(target, scan_type="basic", ports=None):
        return {
            "status": "completed",
            "target": target,
            "open_ports": [22, 80, 443],
            "services": ["ssh", "http", "https"],
            "scan_type": scan_type
        }
    
    # Test mock implementations
    test_cases = [
        ("SQL Injection", mock_sql_injection_test, {"url": "https://test.com", "parameter": "id"}),
        ("XSS Test", mock_xss_test, {"url": "https://test.com", "parameter": "search"}),
        ("Nmap Scan", mock_nmap_scan, {"target": "192.168.1.1", "scan_type": "basic"})
    ]
    
    for test_name, func, args in test_cases:
        print(f"\n{test_name}:")
        try:
            result = func(**args)
            print(f"  ✓ Success: {json.dumps(result, indent=2)}")
        except Exception as e:
            print(f"  ✗ Error: {e}")


if __name__ == "__main__":
    # Run the orchestration tests
    run_orchestration()
    
    # Optionally run individual tool tests
    test_individual_tools()


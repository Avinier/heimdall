# AVINIERNOTES: Final orchestration with planner, actioner, context manager, 
#               and tool calling with final report generation.

import time
import re
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urljoin, urlparse
from tools.webproxy import WebProxy
from tools.pagedata_extractor import PageDataExtractor
from agents.planner import PlannerAgent
from agents.actioner import ActionerAgent
from agents.context_manager import ContextManagerAgent

# NEW IMPORTS FOR ENHANCED WORKFLOW
from tools.llms import LLM
from tools.tool_calls import ToolCallResult
from tools.browser import PlaywrightTools
import tools.tool_calls as tool_calls_module

securitytools_fw_compatible = [
    # ===== SQL INJECTION TESTING =====
    {
        "type": "function",
        "function": {
            "name": "sql_injection_test",
            "description": "Test a single URL parameter for SQL injection vulnerabilities using multiple payload techniques with context-aware optimization",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for SQL injection testing"},
                    "parameter": {"type": "string", "description": "Parameter name to test", "default": "id"},
                    "payloads": {"type": "array", "items": {"type": "string"}, "description": "Custom SQL injection payloads (optional)"},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework (django, laravel, rails, express, asp.net, etc.)"},
                            "database": {"type": "string", "description": "Database type (mysql, postgresql, mssql, oracle, sqlite)"},
                            "web_server": {"type": "string", "description": "Web server (nginx, apache, iis, tomcat)"},
                            "language": {"type": "string", "description": "Programming language (python, php, java, nodejs, csharp)"},
                            "cms": {"type": "string", "description": "CMS type (wordpress, drupal, joomla)"},
                            "supports_post": {"type": "boolean", "description": "Whether target supports POST requests", "default": "true"},
                            "supports_json": {"type": "boolean", "description": "Whether target accepts JSON payloads", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type (cookie, bearer, basic)"},
                            "has_waf": {"type": "boolean", "description": "Whether WAF protection is detected", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding (url, base64, none)"},
                            "custom_headers": {"type": "object", "description": "Custom headers as key-value pairs"}
                        }
                    }
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "sqlmap_campaign",
            "description": "Advanced SQLMap campaign with context-aware optimization and multiple attack vectors",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for SQLMap testing"},
                    "options": {
                        "type": "object", 
                        "description": "SQLMap options",
                        "properties": {
                            "data": {"type": "string", "description": "POST data"},
                            "headers": {"type": "array", "items": {"type": "string"}, "description": "Custom headers"},
                            "cookie": {"type": "string", "description": "Cookie string"},
                            "proxy": {"type": "string", "description": "Proxy URL"},
                            "auth_header": {"type": "string", "description": "Authorization header value"},
                            "auth_creds": {"type": "string", "description": "Basic auth credentials"}
                        }
                    },
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    },
                    "campaign_mode": {"type": "string", "enum": ["basic", "comprehensive", "stealth", "aggressive"], "description": "Campaign intensity", "default": "comprehensive"}
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
            "description": "Test a single URL parameter for Cross-Site Scripting vulnerabilities with context-aware payloads",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for XSS testing"},
                    "parameter": {"type": "string", "description": "Parameter name to test", "default": "search"},
                    "payloads": {"type": "array", "items": {"type": "string"}, "description": "Custom XSS payloads (optional)"},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    },
                    "test_mode": {"type": "string", "enum": ["basic", "advanced", "comprehensive"], "description": "Testing intensity level", "default": "basic"}
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
            "description": "Intelligent Nmap scanning with context-aware vulnerability detection and optimization",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP address, hostname, or CIDR range"},
                    "scan_type": {"type": "string", "enum": ["basic", "service", "vuln", "comprehensive", "stealth", "compliance", "discovery"], "description": "Type of scan to perform", "default": "basic"},
                    "ports": {"type": "array", "items": {"type": "integer"}, "description": "Specific ports to scan (LLM-provided list)"},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    },
                    "scan_mode": {"type": "string", "enum": ["comprehensive", "stealth", "aggressive", "compliance"], "description": "Scan execution mode", "default": "comprehensive"},
                    "custom_scripts": {"type": "array", "items": {"type": "string"}, "description": "LLM-provided NSE scripts to run"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "enterprise_port_scan",
            "description": "Advanced threaded port scanner with intelligent service detection and context-aware analysis",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Target host IP address"},
                    "ports": {"type": "array", "items": {"type": "integer"}, "description": "List of ports to scan"},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    },
                    "scan_mode": {"type": "string", "enum": ["comprehensive", "stealth", "aggressive", "compliance"], "description": "Scan execution mode", "default": "comprehensive"},
                    "scan_method": {"type": "string", "enum": ["tcp_syn", "tcp_connect", "udp"], "description": "Scan method", "default": "tcp_syn"},
                    "custom_service_probes": {"type": "array", "items": {"type": "string"}, "description": "Custom service detection probes"}
                },
                "required": ["host"]
            }
        }
    },

    # ===== API SECURITY TESTING =====
    {
        "type": "function",
        "function": {
            "name": "api_endpoint_discovery",
            "description": "Intelligent API endpoint discovery with context-aware wordlists and vulnerability analysis",
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string", "description": "Base URL for API discovery"},
                    "wordlist": {"type": "array", "items": {"type": "string"}, "description": "Custom wordlist for endpoint discovery"},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    },
                    "discovery_mode": {"type": "string", "enum": ["basic", "comprehensive", "aggressive"], "description": "Discovery intensity level", "default": "comprehensive"},
                    "http_methods": {"type": "array", "items": {"type": "string"}, "description": "HTTP methods to test"},
                    "custom_headers": {"type": "object", "description": "Custom headers for requests"}
                },
                "required": ["base_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "jwt_vulnerability_test",
            "description": "Comprehensive JWT security analysis with context-aware vulnerability detection",
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "JWT token to analyze"},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    }
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
            "description": "Test endpoint for Insecure Direct Object Reference vulnerabilities with context-aware payloads",
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string", "description": "Endpoint URL to test for IDOR"},
                    "parameters": {"type": "array", "items": {"type": "string"}, "description": "Parameter names to manipulate"},
                    "payloads": {"type": "array", "items": {"type": "string"}, "description": "Custom test values for IDOR testing"},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    }
                },
                "required": ["endpoint"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "information_disclosure_test",
            "description": "Test URL for information disclosure vulnerabilities with context-aware path detection",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for information disclosure testing"},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    }
                },
                "required": ["url"]
            }
        }
    },

    # ===== BUSINESS LOGIC TESTING =====
    {
        "type": "function",
        "function": {
            "name": "business_logic_data_validation_test",
            "description": "Test Business Logic Data Validation - WSTG-BUSL-01. Tests for logical data validation bypasses including SSN, date, currency manipulation",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for business logic data validation testing"},
                    "parameters": {"type": "array", "items": {"type": "string"}, "description": "Parameter names to test", "default": ["id", "price", "quantity", "amount", "ssn", "date", "user_id"]},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    },
                    "test_mode": {"type": "string", "enum": ["basic", "comprehensive", "advanced"], "description": "Testing intensity level", "default": "comprehensive"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "workflow_circumvention_test",
            "description": "Test for Circumvention of Work Flows - WSTG-BUSL-06. Tests workflow bypass and step skipping vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL for workflow circumvention testing"},
                    "workflow_steps": {"type": "array", "items": {"type": "string"}, "description": "Expected workflow steps", "default": ["step1", "step2", "step3", "complete"]},
                    "target_context": {
                        "type": "object",
                        "description": "Target environment context for optimization",
                        "properties": {
                            "framework": {"type": "string", "description": "Web framework"},
                            "database": {"type": "string", "description": "Database type"},
                            "web_server": {"type": "string", "description": "Web server"},
                            "language": {"type": "string", "description": "Programming language"},
                            "cms": {"type": "string", "description": "CMS type"},
                            "supports_post": {"type": "boolean", "default": "true"},
                            "supports_json": {"type": "boolean", "default": "false"},
                            "authentication_type": {"type": "string", "description": "Authentication type"},
                            "has_waf": {"type": "boolean", "default": "false"},
                            "payload_encoding": {"type": "string", "description": "Payload encoding"},
                            "custom_headers": {"type": "object", "description": "Custom headers"}
                        }
                    }
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
                    "endpoint": {"type": "string", "description": "API endpoint"},
                    "payload": {"type": "string", "description": "Attack payload used"},
                    "response_code": {"type": "integer", "description": "HTTP response code"},
                    "port": {"type": "string", "description": "Network port"},
                    "service": {"type": "string", "description": "Network service"},
                    "target": {"type": "string", "description": "Network target"},
                    "tool": {"type": "string", "description": "Tool that found it"},
                    "technique": {"type": "string", "description": "Attack technique used"},
                    "dbms": {"type": "string", "description": "Database type for SQL injection"},
                    "business_impact": {"type": "string", "description": "Business impact description"},
                    "remediation": {"type": "string", "description": "Fix recommendations"},
                    "references": {"type": "array", "items": {"type": "string"}, "description": "CVE, CWE references"}
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

# Combined security tools and browser automation for comprehensive testing
securitytools_gemini_compatible = [
    # ===== ESSENTIAL BROWSER AUTOMATION TOOLS =====
    {
        "name": "goto",
        "description": "Navigate to a URL with intelligent path mapping and security-focused navigation",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL or path to navigate to (supports keywords like 'docs', 'api', 'login')"}
            },
            "required": ["url"]
        }
    },
    {
        "type": "function", 
        "function": {
            "name": "click",
            "description": "Click on an element using CSS selector for interaction testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector for element to click"}
                },
                "required": ["selector"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fill",
            "description": "Fill an input field with specified value for form testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector for input field"},
                    "value": {"type": "string", "description": "Value to fill in the field"}
                },
                "required": ["selector", "value"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit",
            "description": "Submit a form using CSS selector for form-based security testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector for form to submit"}
                },
                "required": ["selector"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "execute_js",
            "description": "Execute JavaScript code for DOM manipulation and advanced testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "JavaScript code to execute"}
                },
                "required": ["code"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "complete",
            "description": "Mark the current security test as complete",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },

    {
        "type": "function",
        "function": {
            "name": "refresh",
            "description": "Refresh the current page for state testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "presskey",
            "description": "Press keyboard keys for interaction testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Key to press (e.g., 'Enter', 'Tab', 'Escape')"}
                },
                "required": ["key"]
            }
        }
    },

    # ===== ADVANCED BROWSER TESTING =====
    {
        "type": "function",
        "function": {
            "name": "wait_for_element",
            "description": "Wait for specific elements to appear for dynamic content testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "css_selector": {"type": "string", "description": "CSS selector for the element to wait for"},
                    "timeout": {"type": "integer", "description": "Timeout in milliseconds", "default": 10000}
                },
                "required": ["css_selector"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "screenshot",
            "description": "Take screenshots for evidence collection and documentation",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Optional filename for the screenshot"},
                    "full_page": {"type": "boolean", "description": "Capture full page or viewport only", "default": "true"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_cookies",
            "description": "Extract all cookies for session analysis and security testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "set_cookies",
            "description": "Set cookies for session manipulation and privilege escalation testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "cookies": {"type": "string", "description": "JSON string of cookie objects to set"}
                },
                "required": ["cookies"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "clear_cookies",
            "description": "Clear all cookies for fresh session testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "set_headers",
            "description": "Set custom HTTP headers for bypass and injection testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "headers": {"type": "string", "description": "JSON string of headers to set"}
                },
                "required": ["headers"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bypass_csp",
            "description": "Inject CSP bypass scripts for XSS testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bypass_waf",
            "description": "Configure headers and settings for WAF bypass testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fill_form_with_payload",
            "description": "Fill forms with security payloads for vulnerability testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "form_selector": {"type": "string", "description": "CSS selector for the form"},
                    "payload": {"type": "string", "description": "Security payload to inject"},
                    "field_name": {"type": "string", "description": "Specific field name to target (optional)"}
                },
                "required": ["form_selector", "payload"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit_form_and_get_response",
            "description": "Submit form and capture response for vulnerability analysis",
            "parameters": {
                "type": "object",
                "properties": {
                    "form_selector": {"type": "string", "description": "CSS selector for the form to submit"}
                },
                "required": ["form_selector"]
            }
        }
    },

    # ===== SQL INJECTION TESTING =====
    {
        "name": "sql_injection_test",
        "description": "Test a single URL parameter for SQL injection vulnerabilities using multiple payload techniques with context-aware optimization",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for SQL injection testing"},
                "parameter": {"type": "string", "description": "Parameter name to test", "default": "id"},
                "payloads": {"type": "array", "items": {"type": "string"}, "description": "Custom SQL injection payloads (optional)"},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework (django, laravel, rails, express, asp.net, etc.)"},
                        "database": {"type": "string", "description": "Database type (mysql, postgresql, mssql, oracle, sqlite)"},
                        "web_server": {"type": "string", "description": "Web server (nginx, apache, iis, tomcat)"},
                        "language": {"type": "string", "description": "Programming language (python, php, java, nodejs, csharp)"},
                        "cms": {"type": "string", "description": "CMS type (wordpress, drupal, joomla)"},
                        "supports_post": {"type": "boolean", "description": "Whether target supports POST requests", "default": "true"},
                        "supports_json": {"type": "boolean", "description": "Whether target accepts JSON payloads", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type (cookie, bearer, basic)"},
                        "has_waf": {"type": "boolean", "description": "Whether WAF protection is detected", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding (url, base64, none)"},
                        "custom_headers": {"type": "object", "description": "Custom headers as key-value pairs"}
                    }
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "sqlmap_campaign",
        "description": "Advanced SQLMap campaign with context-aware optimization and multiple attack vectors",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for SQLMap testing"},
                "options": {
                    "type": "object", 
                    "description": "SQLMap options",
                    "properties": {
                        "data": {"type": "string", "description": "POST data"},
                        "headers": {"type": "array", "items": {"type": "string"}, "description": "Custom headers"},
                        "cookie": {"type": "string", "description": "Cookie string"},
                        "proxy": {"type": "string", "description": "Proxy URL"},
                        "auth_header": {"type": "string", "description": "Authorization header value"},
                        "auth_creds": {"type": "string", "description": "Basic auth credentials"}
                    }
                },
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                },
                "campaign_mode": {"type": "string", "enum": ["basic", "comprehensive", "stealth", "aggressive"], "description": "Campaign intensity", "default": "comprehensive"}
            },
            "required": ["url"]
        }
    },

    # ===== XSS TESTING =====
    {
        "name": "xss_test",
        "description": "Test a single URL parameter for Cross-Site Scripting vulnerabilities with context-aware payloads",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for XSS testing"},
                "parameter": {"type": "string", "description": "Parameter name to test", "default": "search"},
                "payloads": {"type": "array", "items": {"type": "string"}, "description": "Custom XSS payloads (optional)"},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                },
                "test_mode": {"type": "string", "enum": ["basic", "advanced", "comprehensive"], "description": "Testing intensity level", "default": "basic"}
            },
            "required": ["url"]
        }
    },

    # ===== NETWORK RECONNAISSANCE =====
    {
        "name": "nmap_scan",
        "description": "Intelligent Nmap scanning with context-aware vulnerability detection and optimization",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP address, hostname, or CIDR range"},
                "scan_type": {"type": "string", "enum": ["basic", "service", "vuln", "comprehensive", "stealth", "compliance", "discovery"], "description": "Type of scan to perform", "default": "basic"},
                "ports": {"type": "array", "items": {"type": "integer"}, "description": "Specific ports to scan (LLM-provided list)"},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                },
                "scan_mode": {"type": "string", "enum": ["comprehensive", "stealth", "aggressive", "compliance"], "description": "Scan execution mode", "default": "comprehensive"},
                "custom_scripts": {"type": "array", "items": {"type": "string"}, "description": "LLM-provided NSE scripts to run"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "enterprise_port_scan",
        "description": "Advanced threaded port scanner with intelligent service detection and context-aware analysis",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target host IP address"},
                "ports": {"type": "array", "items": {"type": "integer"}, "description": "List of ports to scan"},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                },
                "scan_mode": {"type": "string", "enum": ["comprehensive", "stealth", "aggressive", "compliance"], "description": "Scan execution mode", "default": "comprehensive"},
                "scan_method": {"type": "string", "enum": ["tcp_syn", "tcp_connect", "udp"], "description": "Scan method", "default": "tcp_syn"},
                "custom_service_probes": {"type": "array", "items": {"type": "string"}, "description": "Custom service detection probes"}
            },
            "required": ["host"]
        }
    },

    # ===== API SECURITY TESTING =====
    {
        "name": "api_endpoint_discovery",
        "description": "Intelligent API endpoint discovery with context-aware wordlists and vulnerability analysis",
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL for API discovery"},
                "wordlist": {"type": "array", "items": {"type": "string"}, "description": "Custom wordlist for endpoint discovery"},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                },
                "discovery_mode": {"type": "string", "enum": ["basic", "comprehensive", "aggressive"], "description": "Discovery intensity level", "default": "comprehensive"},
                "http_methods": {"type": "array", "items": {"type": "string"}, "description": "HTTP methods to test"},
                "custom_headers": {"type": "object", "description": "Custom headers for requests"}
            },
            "required": ["base_url"]
        }
    },
    {
        "name": "jwt_vulnerability_test",
        "description": "Comprehensive JWT security analysis with context-aware vulnerability detection",
        "parameters": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "JWT token to analyze"},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                }
            },
            "required": ["token"]
        }
    },

    # ===== SPECIFIC VULNERABILITY TESTS =====
    {
        "name": "idor_test",
        "description": "Test endpoint for Insecure Direct Object Reference vulnerabilities with context-aware payloads",
        "parameters": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Endpoint URL to test for IDOR"},
                "parameters": {"type": "array", "items": {"type": "string"}, "description": "Parameter names to manipulate"},
                "payloads": {"type": "array", "items": {"type": "string"}, "description": "Custom test values for IDOR testing"},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                }
            },
            "required": ["endpoint"]
        }
    },
    {
        "name": "information_disclosure_test",
        "description": "Test URL for information disclosure vulnerabilities with context-aware path detection",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for information disclosure testing"},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                }
            },
            "required": ["url"]
        }
    },

    # ===== BUSINESS LOGIC TESTING =====
    {
        "name": "business_logic_data_validation_test",
        "description": "Test Business Logic Data Validation - WSTG-BUSL-01. Tests for logical data validation bypasses including SSN, date, currency manipulation",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for business logic data validation testing"},
                "parameters": {"type": "array", "items": {"type": "string"}, "description": "Parameter names to test", "default": ["id", "price", "quantity", "amount", "ssn", "date", "user_id"]},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                },
                "test_mode": {"type": "string", "enum": ["basic", "comprehensive", "advanced"], "description": "Testing intensity level", "default": "comprehensive"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "workflow_circumvention_test",
        "description": "Test for Circumvention of Work Flows - WSTG-BUSL-06. Tests workflow bypass and step skipping vulnerabilities",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL for workflow circumvention testing"},
                "workflow_steps": {"type": "array", "items": {"type": "string"}, "description": "Expected workflow steps", "default": ["step1", "step2", "step3", "complete"]},
                "target_context": {
                    "type": "object",
                    "description": "Target environment context for optimization",
                    "properties": {
                        "framework": {"type": "string", "description": "Web framework"},
                        "database": {"type": "string", "description": "Database type"},
                        "web_server": {"type": "string", "description": "Web server"},
                        "language": {"type": "string", "description": "Programming language"},
                        "cms": {"type": "string", "description": "CMS type"},
                        "supports_post": {"type": "boolean", "default": "true"},
                        "supports_json": {"type": "boolean", "default": "false"},
                        "authentication_type": {"type": "string", "description": "Authentication type"},
                        "has_waf": {"type": "boolean", "default": "false"},
                        "payload_encoding": {"type": "string", "description": "Payload encoding"},
                        "custom_headers": {"type": "object", "description": "Custom headers"}
                    }
                }
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
                "endpoint": {"type": "string", "description": "API endpoint"},
                "payload": {"type": "string", "description": "Attack payload used"},
                "response_code": {"type": "integer", "description": "HTTP response code"},
                "port": {"type": "string", "description": "Network port"},
                "service": {"type": "string", "description": "Network service"},
                "target": {"type": "string", "description": "Network target"},
                "tool": {"type": "string", "description": "Tool that found it"},
                "technique": {"type": "string", "description": "Attack technique used"},
                "dbms": {"type": "string", "description": "Database type for SQL injection"},
                "business_impact": {"type": "string", "description": "Business impact description"},
                "remediation": {"type": "string", "description": "Fix recommendations"},
                "references": {"type": "array", "items": {"type": "string"}, "description": "CVE, CWE references"}
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

browsertools_fw_compatible = [
    # ===== BASIC BROWSER ACTIONS =====
    {
        "type": "function",
        "function": {
            "name": "goto",
            "description": "Navigate to a URL with intelligent path mapping and security-focused navigation",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL or path to navigate to (supports keywords like 'docs', 'api', 'login')"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "click",
            "description": "Click on an element using CSS selector for interactive testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "css_selector": {"type": "string", "description": "CSS selector for the element to click"}
                },
                "required": ["css_selector"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fill",
            "description": "Fill form fields with values, including security payloads for testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "css_selector": {"type": "string", "description": "CSS selector for the input field"},
                    "value": {"type": "string", "description": "Value to fill in the field (can be security payloads)"}
                },
                "required": ["css_selector", "value"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit",
            "description": "Submit forms for security testing and vulnerability discovery",
            "parameters": {
                "type": "object",
                "properties": {
                    "css_selector": {"type": "string", "description": "CSS selector for the submit button or form"}
                },
                "required": ["css_selector"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "execute_js",
            "description": "Execute JavaScript code for DOM manipulation and advanced testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "js_code": {"type": "string", "description": "JavaScript code to execute in the browser"}
                },
                "required": ["js_code"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "refresh",
            "description": "Refresh the current page for state testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "presskey",
            "description": "Press keyboard keys for interaction testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Key to press (e.g., 'Enter', 'Tab', 'Escape')"}
                },
                "required": ["key"]
            }
        }
    },

    # ===== ADVANCED BROWSER TESTING =====
    {
        "type": "function",
        "function": {
            "name": "wait_for_element",
            "description": "Wait for specific elements to appear for dynamic content testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "css_selector": {"type": "string", "description": "CSS selector for the element to wait for"},
                    "timeout": {"type": "integer", "description": "Timeout in milliseconds", "default": 10000}
                },
                "required": ["css_selector"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "wait_for_navigation",
            "description": "Wait for page navigation to complete",
            "parameters": {
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Timeout in milliseconds", "default": 30000}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "screenshot",
            "description": "Take screenshots for evidence collection and documentation",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Optional filename for the screenshot"},
                    "full_page": {"type": "boolean", "description": "Capture full page or viewport only", "default": "true"}
                },
                "required": []
            }
        }
    },

    # ===== SESSION AND COOKIE MANAGEMENT =====
    {
        "type": "function",
        "function": {
            "name": "get_cookies",
            "description": "Extract all cookies for session analysis and security testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "set_cookies",
            "description": "Set cookies for session manipulation and privilege escalation testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "cookies": {"type": "string", "description": "JSON string of cookie objects to set"}
                },
                "required": ["cookies"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "clear_cookies",
            "description": "Clear all cookies for fresh session testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },

    # ===== NETWORK AND TRAFFIC ANALYSIS =====
    {
        "type": "function",
        "function": {
            "name": "set_headers",
            "description": "Set custom HTTP headers for bypass and injection testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "headers": {"type": "string", "description": "JSON string of headers to set"}
                },
                "required": ["headers"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "intercept_requests",
            "description": "Enable request interception for traffic analysis and modification",
            "parameters": {
                "type": "object",
                "properties": {
                    "url_pattern": {"type": "string", "description": "URL pattern to intercept", "default": "*"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_intercepted_requests",
            "description": "Retrieve intercepted requests for analysis",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_network_traffic",
            "description": "Analyze network traffic for security vulnerabilities and missing headers",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },

    # ===== SECURITY-SPECIFIC BROWSER TOOLS =====
    {
        "type": "function",
        "function": {
            "name": "bypass_csp",
            "description": "Inject CSP bypass scripts for XSS testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bypass_waf",
            "description": "Configure headers and settings for WAF bypass testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_forms",
            "description": "Extract all forms from the page for systematic security testing",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_links",
            "description": "Extract all links for crawling and discovery",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fill_form_with_payload",
            "description": "Fill forms with security payloads for vulnerability testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "form_selector": {"type": "string", "description": "CSS selector for the form"},
                    "payload": {"type": "string", "description": "Security payload to inject"},
                    "field_name": {"type": "string", "description": "Specific field name to target (optional)"}
                },
                "required": ["form_selector", "payload"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit_form_and_get_response",
            "description": "Submit form and capture response for vulnerability analysis",
            "parameters": {
                "type": "object",
                "properties": {
                    "form_selector": {"type": "string", "description": "CSS selector for the form to submit"}
                },
                "required": ["form_selector"]
            }
        }
    },

    # ===== UTILITY FUNCTIONS =====
    {
        "type": "function",
        "function": {
            "name": "get_page_source",
            "description": "Get complete HTML source for analysis",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "set_input_value",
            "description": "Set value for specific input elements",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector for the input"},
                    "value": {"type": "string", "description": "Value to set"}
                },
                "required": ["selector", "value"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "simulate_user_interaction",
            "description": "Simulate complex user interactions for behavioral testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "actions": {"type": "string", "description": "JSON string of actions to perform"}
                },
                "required": ["actions"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "set_geolocation",
            "description": "Set geolocation for location-based security testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "latitude": {"type": "number", "description": "Latitude coordinate"},
                    "longitude": {"type": "number", "description": "Longitude coordinate"}
                },
                "required": ["latitude", "longitude"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "block_resources",
            "description": "Block specific resource types for testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "resource_types": {"type": "string", "description": "JSON array of resource types to block"}
                },
                "required": ["resource_types"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "modify_response",
            "description": "Modify HTTP responses for testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "url_pattern": {"type": "string", "description": "URL pattern to match"},
                    "new_body": {"type": "string", "description": "New response body content"}
                },
                "required": ["url_pattern", "new_body"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_page_access",
            "description": "Navigate to URL and analyze access permissions and redirects",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to check access for"}
                },
                "required": ["url"]
            }
        }
    },

    # ===== WORKFLOW CONTROL =====
    {
        "type": "function",
        "function": {
            "name": "python_interpreter",
            "description": "Execute Python code for custom analysis and processing",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Python code to execute"}
                },
                "required": ["code"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "auth_needed",
            "description": "Pause for manual authentication when required",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_user_input",
            "description": "Get input from user for interactive testing",
            "parameters": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "description": "Prompt message for the user"}
                },
                "required": ["prompt"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "complete",
            "description": "Mark testing phase complete when sufficient security actions performed",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }
]

browsertools_gemini_compatible = [
    # ===== BASIC BROWSER ACTIONS =====
    {
        "name": "goto",
        "description": "Navigate to a URL with intelligent path mapping and security-focused navigation",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL or path to navigate to (supports keywords like 'docs', 'api', 'login')"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "click",
        "description": "Click on an element using CSS selector for interactive testing",
        "parameters": {
            "type": "object",
            "properties": {
                "css_selector": {"type": "string", "description": "CSS selector for the element to click"}
            },
            "required": ["css_selector"]
        }
    },
    {
        "name": "fill",
        "description": "Fill form fields with values, including security payloads for testing",
        "parameters": {
            "type": "object",
            "properties": {
                "css_selector": {"type": "string", "description": "CSS selector for the input field"},
                "value": {"type": "string", "description": "Value to fill in the field (can be security payloads)"}
            },
            "required": ["css_selector", "value"]
        }
    },
    {
        "name": "submit",
        "description": "Submit forms for security testing and vulnerability discovery",
        "parameters": {
            "type": "object",
            "properties": {
                "css_selector": {"type": "string", "description": "CSS selector for the submit button or form"}
            },
            "required": ["css_selector"]
        }
    },
    {
        "name": "execute_js",
        "description": "Execute JavaScript code for DOM manipulation and advanced testing",
        "parameters": {
            "type": "object",
            "properties": {
                "js_code": {"type": "string", "description": "JavaScript code to execute in the browser"}
            },
            "required": ["js_code"]
        }
    },
    {
        "name": "refresh",
        "description": "Refresh the current page for state testing",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "presskey",
        "description": "Press keyboard keys for interaction testing",
        "parameters": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Key to press (e.g., 'Enter', 'Tab', 'Escape')"}
            },
            "required": ["key"]
        }
    },

    # ===== ADVANCED BROWSER TESTING =====
    {
        "name": "wait_for_element",
        "description": "Wait for specific elements to appear for dynamic content testing",
        "parameters": {
            "type": "object",
            "properties": {
                "css_selector": {"type": "string", "description": "CSS selector for the element to wait for"},
                "timeout": {"type": "integer", "description": "Timeout in milliseconds", "default": 10000}
            },
            "required": ["css_selector"]
        }
    },
    {
        "name": "wait_for_navigation",
        "description": "Wait for page navigation to complete",
        "parameters": {
            "type": "object",
            "properties": {
                "timeout": {"type": "integer", "description": "Timeout in milliseconds", "default": 30000}
            },
            "required": []
        }
    },
    {
        "name": "screenshot",
        "description": "Take screenshots for evidence collection and documentation",
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Optional filename for the screenshot"},
                "full_page": {"type": "boolean", "description": "Capture full page or viewport only", "default": "true"}
            },
            "required": []
        }
    },

    # ===== SESSION AND COOKIE MANAGEMENT =====
    {
        "name": "get_cookies",
        "description": "Extract all cookies for session analysis and security testing",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "set_cookies",
        "description": "Set cookies for session manipulation and privilege escalation testing",
        "parameters": {
            "type": "object",
            "properties": {
                "cookies": {"type": "string", "description": "JSON string of cookie objects to set"}
            },
            "required": ["cookies"]
        }
    },
    {
        "name": "clear_cookies",
        "description": "Clear all cookies for fresh session testing",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },

    # ===== NETWORK AND TRAFFIC ANALYSIS =====
    {
        "name": "set_headers",
        "description": "Set custom HTTP headers for bypass and injection testing",
        "parameters": {
            "type": "object",
            "properties": {
                "headers": {"type": "string", "description": "JSON string of headers to set"}
            },
            "required": ["headers"]
        }
    },
    {
        "name": "intercept_requests",
        "description": "Enable request interception for traffic analysis and modification",
        "parameters": {
            "type": "object",
            "properties": {
                "url_pattern": {"type": "string", "description": "URL pattern to intercept", "default": "*"}
            },
            "required": []
        }
    },
    {
        "name": "get_intercepted_requests",
        "description": "Retrieve intercepted requests for analysis",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "analyze_network_traffic",
        "description": "Analyze network traffic for security vulnerabilities and missing headers",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },

    # ===== SECURITY-SPECIFIC BROWSER TOOLS =====
    {
        "name": "bypass_csp",
        "description": "Inject CSP bypass scripts for XSS testing",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "bypass_waf",
        "description": "Configure headers and settings for WAF bypass testing",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "extract_forms",
        "description": "Extract all forms from the page for systematic security testing",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "extract_links",
        "description": "Extract all links for crawling and discovery",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "fill_form_with_payload",
        "description": "Fill forms with security payloads for vulnerability testing",
        "parameters": {
            "type": "object",
            "properties": {
                "form_selector": {"type": "string", "description": "CSS selector for the form"},
                "payload": {"type": "string", "description": "Security payload to inject"},
                "field_name": {"type": "string", "description": "Specific field name to target (optional)"}
            },
            "required": ["form_selector", "payload"]
        }
    },
    {
        "name": "submit_form_and_get_response",
        "description": "Submit form and capture response for vulnerability analysis",
        "parameters": {
            "type": "object",
            "properties": {
                "form_selector": {"type": "string", "description": "CSS selector for the form to submit"}
            },
            "required": ["form_selector"]
        }
    },

    # ===== UTILITY FUNCTIONS =====
    {
        "name": "get_page_source",
        "description": "Get complete HTML source for analysis",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "set_input_value",
        "description": "Set value for specific input elements",
        "parameters": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS selector for the input"},
                "value": {"type": "string", "description": "Value to set"}
            },
            "required": ["selector", "value"]
        }
    },
    {
        "name": "simulate_user_interaction",
        "description": "Simulate complex user interactions for behavioral testing",
        "parameters": {
            "type": "object",
            "properties": {
                "actions": {"type": "string", "description": "JSON string of actions to perform"}
            },
            "required": ["actions"]
        }
    },
    {
        "name": "set_geolocation",
        "description": "Set geolocation for location-based security testing",
        "parameters": {
            "type": "object",
            "properties": {
                "latitude": {"type": "number", "description": "Latitude coordinate"},
                "longitude": {"type": "number", "description": "Longitude coordinate"}
            },
            "required": ["latitude", "longitude"]
        }
    },
    {
        "name": "block_resources",
        "description": "Block specific resource types for testing",
        "parameters": {
            "type": "object",
            "properties": {
                "resource_types": {"type": "string", "description": "JSON array of resource types to block"}
            },
            "required": ["resource_types"]
        }
    },
    {
        "name": "modify_response",
        "description": "Modify HTTP responses for testing",
        "parameters": {
            "type": "object",
            "properties": {
                "url_pattern": {"type": "string", "description": "URL pattern to match"},
                "new_body": {"type": "string", "description": "New response body content"}
            },
            "required": ["url_pattern", "new_body"]
        }
    },
    {
        "name": "check_page_access",
        "description": "Navigate to URL and analyze access permissions and redirects",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to check access for"}
            },
            "required": ["url"]
        }
    },

    # ===== WORKFLOW CONTROL =====
    {
        "name": "python_interpreter",
        "description": "Execute Python code for custom analysis and processing",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python code to execute"}
            },
            "required": ["code"]
        }
    },
    {
        "name": "auth_needed",
        "description": "Pause for manual authentication when required",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_user_input",
        "description": "Get input from user for interactive testing",
        "parameters": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "description": "Prompt message for the user"}
            },
            "required": ["prompt"]
        }
    },
    {
        "name": "complete",
        "description": "Mark testing phase complete when sufficient security actions performed",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
]


def run_orchestration(expand_scope=True, max_iterations=10, keep_messages=12):
    """
    Run the complete security analysis orchestration with nested loop structure.
    
    Parameters:
    - expand_scope: Whether to add discovered URLs to the queue
    - max_iterations: Maximum iterations per plan execution
    - keep_messages: Number of recent messages to keep in conversation history
    """
    
    # INITIALIZE: Create web proxy and scanner
    base_url = "https://dev.quantumsenses.com"  # Change this to your target URL
    total_token_counter = 0
    
    print("=" * 80)
    print("SECURITY ANALYSIS ORCHESTRATION - PHASE 3")
    print("=" * 80)
    print(f"Base URL: {base_url}")
    print(f"Expand Scope: {expand_scope}")
    print(f"Max Iterations per Plan: {max_iterations}")
    print()
    
    # Initialize URL queue with starting URL
    urls_to_parse = [base_url]
    visited_urls = set()
    
    # Initialize agents and tools
    print("Initializing agents and tools...")
    try:
        web_proxy = WebProxy(starting_url=base_url)
        browser, context, page, playwright = web_proxy.create_proxy()
        planner = PlannerAgent(
            desc="Security test planner for orchestration phase 3",
            api_type="gemini",
            model_key="gemini-2.5-flash-preview-05-20",
            reasoning=True,
            temperature=0.3
        )
        actioner = ActionerAgent(
            desc="Security test executor for orchestration phase 3",
            api_type="gemini",
            model="gemini-2.5-flash-preview-05-20",
            fireworks_model_key="deepseek-v3",
            temperature=0.3,
            reasoning_config={
                "include_thoughts": True,
                "thinking_budget": None
            }
        )
        context_manager = ContextManagerAgent(
            desc="Context management for orchestration phase 3",
            debug=False,
            api_type="fireworks",
            model_key="qwen3-30b-a3b",
            reasoning=False,
            temperature=0.2
        )
        print("✓ All agents and tools initialized successfully")
        print()
    except Exception as e:
        print(f"✗ Failed to initialize: {str(e)}")
        return
    
    all_findings = []
    
    try:
        # OUTER LOOP (URL Processing)
        while urls_to_parse:
            url = urls_to_parse.pop(0)
            
            # Skip if already visited
            if url in visited_urls:
                continue
                
            visited_urls.add(url)
            
            print("=" * 60)
            print(f"ANALYZING URL: {url}")
            print("=" * 60)
            
            try:
                # Scan current URL to extract page content and structure
                print(f"Navigating to: {url}")
                page.goto(url, wait_until='networkidle', timeout=100000)
                print(f"✓ Successfully navigated to {url}")
                print(f"✓ Page title: {page.title()}")
                
                # Wait for dynamic content
                time.sleep(2)
                
                # Extract page data
                print("Extracting page data...")
                extractor = PageDataExtractor(page)
                raw_page_data = extractor.extract_page_data()
                print(f"✓ Page data extracted ({len(raw_page_data)} characters)")
                
                # Parse discovered URLs from page content
                if expand_scope:
                    print("Processing discovered links...")
                    new_links_count = 0
                    
                    # Extract links using the same logic as before
                    if hasattr(extractor, 'links') and extractor.links:
                        for link_info in extractor.links:
                            link_url = link_info.get('url', '')
                            
                            # Skip asset files (images, fonts, etc.)
                            if link_url and _is_asset_file(link_url):
                                print(f"  - Skipped (asset file): {link_url}")
                                continue
                            
                            if link_url and _is_same_domain(base_url, link_url):
                                if link_url not in visited_urls and link_url not in urls_to_parse:
                                    urls_to_parse.append(link_url)
                                    new_links_count += 1
                                    print(f"  + Added: {link_url}")
                    else:
                        # Fallback link extraction
                        links_match = re.search(r"Links: \[(.*?)\]", raw_page_data)
                        if links_match:
                            links_str = links_match.group(1)
                            fallback_links = re.findall(r"'([^']+)'", links_str)
                            
                            for link_url in fallback_links:
                                # Skip asset files (images, fonts, etc.)
                                if link_url and _is_asset_file(link_url):
                                    print(f"  - Skipped (asset file, fallback): {link_url}")
                                    continue
                                
                                if link_url and _is_same_domain(base_url, link_url):
                                    if link_url not in visited_urls and link_url not in urls_to_parse:
                                        urls_to_parse.append(link_url)
                                        new_links_count += 1
                                        print(f"  + Added (fallback): {link_url}")
                    
                    print(f"✓ Added {new_links_count} new links to scan queue")
                
                # Summarize page content to reduce token usage
                print("Summarizing page content...")
                summarized_page_data = context_manager.summarize_page_source(raw_page_data, url)
                page_data_context = f"URL: {url}\n\nSUMMARIZED PAGE ANALYSIS:\n{summarized_page_data}"
                
                # Check context stats
                context_stats = context_manager.get_context_stats(page_data_context)
                print(f"✓ Page data summarized (Tokens: ~{context_stats['estimated_tokens']})")
                total_token_counter += context_stats['estimated_tokens']
                
                # PLANNER: Generate security test plans for current URL
                print("Generating security test plans...")
                plans = planner.plan(raw_page_data)
                print(f"✓ Generated {len(plans)} security test plans")
                
                # Display all plans to user
                _print_plans_for_url(url, plans)
                
                # MIDDLE LOOP (Plan Steps Execution)
                for plan_idx, plan in enumerate(plans, 1):
                    print("=" * 50)
                    print(f"EXECUTING PLAN {plan_idx}/{len(plans)}: {plan.get('title', 'Untitled Plan')}")
                    
                    # Display plan context for execution
                    business_impact = plan.get('business_impact', '')
                    attack_complexity = plan.get('attack_complexity', '')
                    compliance_risk = plan.get('compliance_risk', '')
                    
                    if business_impact:
                        impact_level = "UNKNOWN"
                        if any(term in business_impact.upper() for term in ['CRITICAL', 'CATASTROPHIC']):
                            impact_level = "🔴 CRITICAL"
                        elif 'HIGH' in business_impact.upper():
                            impact_level = "🟠 HIGH"
                        elif 'MEDIUM' in business_impact.upper():
                            impact_level = "🟡 MEDIUM"
                        elif 'LOW' in business_impact.upper():
                            impact_level = "🟢 LOW"
                        print(f"Business Impact: {impact_level}")
                    
                    if attack_complexity:
                        complexity_level = "STANDARD"
                        if any(term in attack_complexity.upper() for term in ['EXPERT', 'VERY HIGH']):
                            complexity_level = "🔥 EXPERT"
                        elif 'HIGH' in attack_complexity.upper():
                            complexity_level = "⚡ HIGH"
                        elif 'MEDIUM' in attack_complexity.upper():
                            complexity_level = "⚙️ MEDIUM"
                        elif 'LOW' in attack_complexity.upper():
                            complexity_level = "🔧 LOW"
                        print(f"Attack Complexity: {complexity_level}")
                    
                    print("=" * 50)
                    
                    # Reset conversation history to initial messages (no system prompt needed - handled by ActionerAgent)
                    conversation_history = [
                        {"role": "user", "content": page_data_context}
                    ]
                    
                    # Enhanced plan instructions with strategic context
                    enhanced_plan_instructions = f"""ENHANCED SECURITY TEST PLAN:
                                                Title: {plan.get('title', 'Security Test')}
                                                Description: {plan.get('description', 'Perform security testing')}"""
                    
                    # Add enhanced fields to instructions
                    if business_impact:
                        enhanced_plan_instructions += f"\nBusiness Impact: {business_impact}"
                    if attack_complexity:
                        enhanced_plan_instructions += f"\nAttack Complexity: {attack_complexity}"
                    if compliance_risk:
                        enhanced_plan_instructions += f"\nCompliance Risk: {compliance_risk}"
                    
                    enhanced_plan_instructions += "\n\nExecute this enhanced security test plan using the available tools, considering the business impact, attack complexity, and compliance requirements."
                    
                    conversation_history.append({"role": "user", "content": enhanced_plan_instructions})
                    
                    iteration_counter = 0
                    plan_findings = []
                    
                    # INNER LOOP (Action Execution)
                    while iteration_counter < max_iterations:
                        print(f"\n--- Action Iteration {iteration_counter + 1}/{max_iterations} ---")
                        
                        # Manage conversation history length
                        if len(conversation_history) > keep_messages:
                            print("Managing conversation history length...")
                            # Preserve first 2 critical messages (page context + plan instructions)
                            critical_messages = conversation_history[:2]
                            recent_messages = conversation_history[-(keep_messages-2):]
                            
                            # Summarize middle portion
                            middle_portion = conversation_history[2:-(keep_messages-2)]
                            if middle_portion:
                                summarized_middle = context_manager.summarize_conversation(middle_portion)
                                # Reconstruct history
                                conversation_history = critical_messages + summarized_middle + recent_messages
                            else:
                                conversation_history = critical_messages + recent_messages
                        
                        # Count tokens in current history
                        history_text = "\n".join([msg["content"] for msg in conversation_history])
                        history_stats = context_manager.get_context_stats(history_text)
                        print(f"History tokens: ~{history_stats['estimated_tokens']}")
                        total_token_counter += history_stats['estimated_tokens']
                        
                        # Send history to LLM for next action decision
                        print("Generating next security action...")
                        try:
                            # Get the most recent action output if available
                            recent_tool_output = ""
                            if iteration_counter > 0 and len(conversation_history) > 2:
                                # Look for the most recent "Action Result:" message
                                for msg in reversed(conversation_history):
                                    if msg["content"].startswith("Action Result:"):
                                        recent_tool_output = msg["content"].replace("Action Result: ", "")
                                        break
                            
                            # ACTIONER: Generate strategic tool intent using actioner
                            actioner_response = actioner.generate_action_of_plan_step(
                                plan=plan,
                                summarized_page_data=page_data_context,
                                tool_output=recent_tool_output,
                                conversation_history=[msg["content"] for msg in conversation_history]
                            )
                            
                            discussion = actioner_response.get('discussion', '')
                            action_command = actioner_response.get('action', '')
                            
                            print(f"Strategic Tool Intent: {discussion}")
                            print(f"Tool Selector Command: {action_command}")
                            
                            # Check if ActionAgent indicates completion - skip tool calling if so
                            completion_indicators = ["complete()", "completed", "assessment complete", "scan finished", "testing complete", "analysis complete"]
                            action_indicates_completion = any(indicator.lower() in action_command.lower() or indicator.lower() in discussion.lower() 
                                                            for indicator in completion_indicators)
                            
                            if action_indicates_completion:
                                print("🏁 ActionAgent indicates completion - skipping tool calling LLM")
                                combined_output = f"ActionAgent marked task as complete: {discussion}\nAction: {action_command}"
                                all_tool_results = []  # Empty results for completion
                            else:
                                # ENHANCED WORKFLOW: Initialize browser tools
                                browser_tools = PlaywrightTools(page)
                                
                                # TOOL CALLING LLM FLOW STARTED
                                print("Invoking Gemini Function Calling LLM...")
                                
                                # Initialize Gemini LLM for function calling
                                gemini_llm = LLM(
                                    api_type="gemini",
                                    model="gemini-2.5-flash-preview-05-20",
                                    temperature=0.2
                                )
                                
                                # Format actioner output for Gemini tool calling
                                tool_calling_prompt = f"""
                                        You are an elite security testing agent with access to specialized security tools and browser automation. Execute comprehensive security assessments using progressive testing methodology.
                                        STRATEGIC SECURITY TEST INTENT:
                                        {discussion}

                                        TOOL SELECTION GUIDANCE:
                                        {action_command}

                                        CURRENT CONTEXT:
                                        - URL: {page.url}
                                        - Page Title: {page.title()}
                                        - Recent Tool Output: {recent_tool_output[:200] if recent_tool_output else 'None'}

                                        AVAILABLE TOOLS:
                                        You have access to a comprehensive suite of both browser automation and security testing functions:

                                        BROWSER AUTOMATION: goto, click, fill, submit, execute_js, refresh, presskey, complete
                                        ADVANCED BROWSER: wait_for_element, screenshot, get_cookies, set_cookies, clear_cookies, set_headers
                                        SECURITY BROWSER: bypass_csp, bypass_waf, fill_form_with_payload, submit_form_and_get_response
                                        SECURITY TESTING: sql_injection_test, xss_test, nmap_scan, enterprise_port_scan, sqlmap_campaign
                                        WEB APP TESTING: api_endpoint_discovery, jwt_vulnerability_test, idor_test, information_disclosure_test
                                        BUSINESS LOGIC: business_logic_data_validation_test, workflow_circumvention_test

                                        Based on the strategic intent above, select and execute the most appropriate function(s) with precise parameters to advance the security assessment.  
                                        IMPORTANT RULE: If the *Tool Selector Command* provided by ActionerAgent is syntactically valid and its function exists in the AVAILABLE TOOLS list, you MUST call that exact function with the same arguments. Only choose a different function if that command is invalid or unsupported.  
                                        You can combine browser automation (goto, click, fill) with security testing functions for comprehensive testing. Focus on the specific vulnerability type mentioned in the strategic intent.
                                """
                                
                                # ENHANCED WORKFLOW: Gemini Function Calling
                                try:
                                    function_call_response = gemini_llm.gemini_tool_use(
                                        prompt=tool_calling_prompt,
                                        tools=securitytools_gemini_compatible
                                    )
                                    
                                    print(f"Gemini Function Call Response: {function_call_response}")
                                    
                                    # Extract single function call from Gemini response
                                    function_call = function_call_response.get('function_call')
                                    
                                    print(f"Extracted Function Call: {function_call}")
                                    
                                    # SINGLE TOOL EXECUTION: Execute the single tool function per iteration
                                    if function_call:
                                        print(f"Executing single function: {function_call['name']} with args: {function_call['args']}")
                                        
                                        # Execute the single tool function and get ToolCallResult
                                        tool_result = _execute_tool_function_call(function_call, page, browser_tools)
                                        
                                        print(f"Tool Result: Success={tool_result.success}, Output Length={len(str(tool_result.output)) if tool_result.output else 0}")
                                        
                                        # Format single tool result
                                        combined_output = (
                                            f"Tool: {tool_result.tool_name}\n"
                                            f"Success: {tool_result.success}\n"
                                            f"Execution Time: {tool_result.execution_time:.2f}s\n"
                                            f"Output: {str(tool_result.output)[:500] if tool_result.output else 'No output'}\n"
                                            f"Error: {tool_result.error if tool_result.error else 'None'}"
                                        )
                                        
                                        # Add a concise success signal for the next reasoning step
                                        signal_msg = f"Tool Signal: name={tool_result.tool_name}, success={tool_result.success}, output_len={len(str(tool_result.output)) if tool_result.output else 0}"
                                        conversation_history.append({"role": "user", "content": signal_msg})
                                        
                                        # Store as single-item list for compatibility with existing code
                                        all_tool_results = [tool_result]
                                    else:
                                        combined_output = "No tools were executed"
                                        all_tool_results = []
                                    
                                    print(f"Combined Tool Output Length: {len(combined_output)}")
                                    
                                except Exception as gemini_error:
                                    print(f"Gemini function calling error: {str(gemini_error)}")
                                    # Fallback: Use simple navigation if no function calls were extracted
                                    combined_output = f"Error in function calling: {str(gemini_error)}. Attempted action: {action_command}"
                                    all_tool_results = []
                            
                            # Capture action result and summarize for context
                            summarized_action_result = context_manager.summarize(
                                llm_response=discussion,
                                tool_use=str(function_call) if 'function_call' in locals() and function_call else action_command,
                                tool_output=combined_output
                            )
                            
                            # Append to conversation history
                            conversation_history.append({"role": "assistant", "content": discussion})
                            conversation_history.append({"role": "user", "content": f"Action Result: {summarized_action_result}"})
                            
                            # Check if action indicates completion or if tool results show significant findings
                            completion_indicators = ["complete()", "completed", "assessment complete", "scan finished"]
                            has_significant_findings = any(
                                result.success and result.output and len(str(result.output)) > 100 
                                for result in (all_tool_results if 'all_tool_results' in locals() else [])
                            )
                            
                            if any(indicator in combined_output.lower() for indicator in completion_indicators) or has_significant_findings:
                                print("Plan execution completed or significant findings detected.")
                                
                                # Analyze conversation for security findings
                                findings = _analyze_conversation_for_findings(conversation_history)
                                plan_findings.extend(findings)
                                
                                if findings:
                                    print(f"✓ Security findings detected: {len(findings)}")
                                    for finding in findings:
                                        print(f"  - {finding}")
                                    break
                                else:
                                    print("No security findings detected, continuing...")
                            
                            # Capture network traffic context (placeholder)
                            network_context = f"Network activity captured for iteration {iteration_counter + 1}"
                            conversation_history.append({"role": "user", "content": network_context})
                            
                        except Exception as e:
                            print(f"Error in action execution: {str(e)}")
                            error_context = f"Error occurred: {str(e)}"
                            conversation_history.append({"role": "user", "content": error_context})
                        
                        iteration_counter += 1
                        
                        # Brief pause between iterations
                        time.sleep(1)
                    
                    # Store plan findings
                    all_findings.extend(plan_findings)
                    print(f"Plan {plan_idx} completed with {len(plan_findings)} findings")
                
                print(f"✓ URL analysis complete. Total findings so far: {len(all_findings)}")
                
            except Exception as e:
                print(f"✗ Error analyzing {url}: {str(e)}")
                continue
    
    finally:
        # Clean up browser resources
        try:
            print("Cleaning up browser resources...")
            context.close()
            browser.close()
            playwright.stop()
            print("✓ Browser resources cleaned up")
        except Exception as e:
            print(f"Warning: Error during cleanup: {str(e)}")
    
    # FINALIZE: Generate enhanced summary of all findings with business intelligence
    print()
    print("=" * 80)
    print("ENHANCED ORCHESTRATION COMPLETE - EXECUTIVE SUMMARY")
    print("=" * 80)
    print(f"Total URLs analyzed: {len(visited_urls)}")
    print(f"Remaining URLs in queue: {len(urls_to_parse)}")
    print(f"Total tokens used: ~{total_token_counter}")
    print(f"Total security findings: {len(all_findings)}")
    
    if all_findings:
        # Categorize findings by business impact
        critical_findings = [f for f in all_findings if any(term in f for term in ['🔴 CRITICAL', 'CATASTROPHIC', 'STRATEGIC ALERT'])]
        high_findings = [f for f in all_findings if '🟠 HIGH' in f and f not in critical_findings]
        medium_findings = [f for f in all_findings if '🟡 MEDIUM' in f and f not in critical_findings and f not in high_findings]
        low_findings = [f for f in all_findings if '🟢 LOW' in f and f not in critical_findings and f not in high_findings and f not in medium_findings]
        other_findings = [f for f in all_findings if f not in critical_findings and f not in high_findings and f not in medium_findings and f not in low_findings]
        
        print(f"\n📊 BUSINESS IMPACT ANALYSIS:")
        print("-" * 40)
        print(f"🔴 Critical/Catastrophic Findings: {len(critical_findings)}")
        print(f"🟠 High Business Impact: {len(high_findings)}")
        print(f"🟡 Medium Business Impact: {len(medium_findings)}")
        print(f"🟢 Low Business Impact: {len(low_findings)}")
        print(f"📋 Other Findings: {len(other_findings)}")
        
        print("\n🔍 DETAILED SECURITY FINDINGS:")
        print("-" * 40)
        
        if critical_findings:
            print("\n🚨 CRITICAL/CATASTROPHIC FINDINGS (IMMEDIATE EXECUTIVE ATTENTION REQUIRED):")
            for i, finding in enumerate(critical_findings, 1):
                print(f"  {i}. {finding}")
        
        if high_findings:
            print("\n🟠 HIGH BUSINESS IMPACT FINDINGS:")
            for i, finding in enumerate(high_findings, 1):
                print(f"  {i}. {finding}")
        
        if medium_findings:
            print("\n🟡 MEDIUM BUSINESS IMPACT FINDINGS:")
            for i, finding in enumerate(medium_findings, 1):
                print(f"  {i}. {finding}")
        
        if low_findings:
            print("\n🟢 LOW BUSINESS IMPACT FINDINGS:")
            for i, finding in enumerate(low_findings, 1):
                print(f"  {i}. {finding}")
        
        if other_findings:
            print("\n📋 ADDITIONAL FINDINGS:")
            for i, finding in enumerate(other_findings, 1):
                print(f"  {i}. {finding}")
        
        # Executive recommendation section
        print("\n💼 EXECUTIVE RECOMMENDATIONS:")
        print("-" * 40)
        if critical_findings:
            print("🚨 IMMEDIATE ACTION REQUIRED:")
            print("  - Schedule emergency security meeting within 24 hours")
            print("  - Implement temporary mitigations for critical vulnerabilities")
            print("  - Consider temporary service restrictions if necessary")
            print("  - Prepare incident response team activation")
        
        if high_findings:
            print("⚡ HIGH PRIORITY ACTIONS (Next 7 days):")
            print("  - Prioritize high-impact vulnerability remediation")
            print("  - Review and update security controls")
            print("  - Consider third-party security assessment")
        
        if len(all_findings) > 5:
            print("📈 STRATEGIC SECURITY INVESTMENT:")
            print("  - Consider enhanced security program investment")
            print("  - Evaluate current security architecture adequacy")
            print("  - Plan comprehensive security framework upgrade")
        
        # Compliance implications
        compliance_findings = [f for f in all_findings if any(term in f.lower() for term in ['compliance', 'pci dss', 'gdpr', 'sox', 'hipaa', 'iso 27001'])]
        if compliance_findings:
            print("\n⚖️  REGULATORY COMPLIANCE IMPLICATIONS:")
            print(f"  - {len(compliance_findings)} compliance-related findings detected")
            print("  - Consider regulatory notification requirements")
            print("  - Schedule compliance team review")
            print("  - Prepare audit trail documentation")
        
    else:
        print("\n✅ No security vulnerabilities detected in this assessment.")
        print("\n💼 EXECUTIVE SUMMARY:")
        print("  - Current security posture appears adequate")
        print("  - Consider periodic reassessment schedule")
        print("  - Maintain continuous monitoring capabilities")

def _execute_tool_function_call(function_call: dict, page, browser_tools: PlaywrightTools) -> ToolCallResult:
    """
    Execute a function call from Gemini and return a ToolCallResult.
    This handles both security tools and browser tools.
    """
    function_name = function_call.get('name', '')
    function_args = function_call.get('args', {})
    
    print(f"Executing function: {function_name} with args: {function_args}")
    
    try:
        # Handle browser tools (essential automation functions)
        if function_name in ['goto', 'click', 'fill', 'submit', 'execute_js', 'complete',
                           'refresh', 'presskey', 'screenshot', 'get_cookies', 'set_cookies', 
                           'clear_cookies', 'extract_forms', 'extract_links', 'get_page_source',
                           'wait_for_element', 'set_headers', 'bypass_csp', 'bypass_waf',
                           'fill_form_with_payload', 'submit_form_and_get_response']:
            
            # Execute browser tool function using PlaywrightTools
            if hasattr(browser_tools, function_name):
                browser_func = getattr(browser_tools, function_name)
                
                # Handle different function signatures
                if function_name == 'goto':
                    # goto(page, url)
                    url = function_args.get('url', '')
                    result = browser_func(page, url)
                elif function_name == 'click':
                    # click(page, selector)
                    selector = function_args.get('selector', '')
                    result = browser_func(page, selector)
                elif function_name == 'fill':
                    # fill(page, selector, value)
                    selector = function_args.get('selector', '')
                    value = function_args.get('value', '')
                    result = browser_func(page, selector, value)
                elif function_name == 'submit':
                    # submit(page, selector)
                    selector = function_args.get('selector', '')
                    result = browser_func(page, selector)
                elif function_name == 'execute_js':
                    # execute_js(page, code) - note: parameter is 'code' not 'script'
                    code = function_args.get('code', '')
                    # Handle legacy 'js_code' parameter name as well
                    if not code:
                        code = function_args.get('js_code', '')
                    result = browser_func(page, code)
                elif function_name == 'complete':
                    # complete() - no parameters
                    result = browser_func()
                elif function_name == 'wait_for_element':
                    # wait_for_element(page, css_selector, timeout=10000)
                    css_selector = function_args.get('css_selector', '')
                    timeout = function_args.get('timeout', 10000)
                    result = browser_func(page, css_selector, timeout)
                elif function_name == 'fill_form_with_payload':
                    # fill_form_with_payload(page, form_selector, payload, field_name=None)
                    form_selector = function_args.get('form_selector', '')
                    payload = function_args.get('payload', '')
                    field_name = function_args.get('field_name', None)
                    if field_name:
                        result = browser_func(page, form_selector, payload, field_name)
                    else:
                        result = browser_func(page, form_selector, payload)
                elif function_name == 'submit_form_and_get_response':
                    # submit_form_and_get_response(page, form_selector)
                    form_selector = function_args.get('form_selector', '')
                    result = browser_func(page, form_selector)
                else:
                    # For other browser functions that require page parameter
                    if function_name in ['refresh', 'presskey', 'screenshot', 'get_cookies', 'set_cookies',
                                       'clear_cookies', 'extract_forms', 'extract_links', 'get_page_source',
                                       'set_headers', 'bypass_csp', 'bypass_waf']:
                        # Most browser functions need page as first argument
                        if function_args:
                            result = browser_func(page, **function_args)
                        else:
                            result = browser_func(page)
                    else:
                        result = browser_func(**function_args)
                
                return ToolCallResult(
                    success=True,
                    tool_name=function_name,
                    output=result,
                    metadata={"result": result, "tool_type": "browser"},
                    execution_time=0.1
                )
        
        # Handle security testing tools
        elif function_name in ['sql_injection_test', 'xss_test', 'nmap_scan', 'enterprise_port_scan',
                              'api_endpoint_discovery', 'jwt_vulnerability_test', 'idor_test',
                              'information_disclosure_test', 'business_logic_data_validation_test',
                              'workflow_circumvention_test', 'sqlmap_campaign']:
            
            # Dynamically get the function from tool_calls module
            if hasattr(sys.modules['tools.tool_calls'], function_name):
                tool_func = getattr(sys.modules['tools.tool_calls'], function_name)
                result = tool_func(**function_args)
                
                # tool_calls functions already return ToolCallResult objects
                if isinstance(result, ToolCallResult):
                    return result
                else:
                    # Fallback if function doesn't return ToolCallResult
                    return ToolCallResult(
                        success=True,
                        tool_name=function_name,
                        metadata={"result": result, "tool_type": "security"},
                        execution_time=0.1
                    )
        
        # Handle utility functions
        elif function_name in ['create_vulnerability', 'save_results']:
            if hasattr(sys.modules['tools.tool_calls'], function_name):
                tool_func = getattr(sys.modules['tools.tool_calls'], function_name)
                result = tool_func(**function_args)
                
                return ToolCallResult(
                    success=True,
                    tool_name=function_name,
                    metadata={"result": result, "tool_type": "utility"},
                    execution_time=0.1
                )
        
        else:
            return ToolCallResult(
                success=False,
                tool_name=function_name,
                error=f"Unknown function: {function_name}",
                execution_time=0.0
            )
    
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name=function_name,
            error=f"Error executing {function_name}: {str(e)}",
            execution_time=0.0
        )

def _analyze_conversation_for_findings(conversation_history) -> list:
    """
    Enhanced analysis of conversation history to detect security findings with business context.
    Returns a list of detected security issues with risk assessment.
    """
    findings = []
    
    # Convert conversation to text for analysis
    conversation_text = "\n".join([msg["content"] for msg in conversation_history])
    
    # Extract business context from conversation
    business_impact_context = ""
    attack_complexity_context = ""
    compliance_context = ""
    
    # Look for enhanced plan fields in conversation
    if "Business Impact:" in conversation_text:
        impact_match = re.search(r'Business Impact:\s*([^\n]+)', conversation_text)
        if impact_match:
            business_impact_context = impact_match.group(1)
    
    if "Attack Complexity:" in conversation_text:
        complexity_match = re.search(r'Attack Complexity:\s*([^\n]+)', conversation_text)
        if complexity_match:
            attack_complexity_context = complexity_match.group(1)
    
    if "Compliance Risk:" in conversation_text:
        compliance_match = re.search(r'Compliance Risk:\s*([^\n]+)', conversation_text)
        if compliance_match:
            compliance_context = compliance_match.group(1)
    
    # Enhanced security indicators with business context
    security_indicators = [
        ("Critical SQL Injection", ["sql error", "mysql error", "postgresql error", "syntax error", "union select", "sql injection bypass"]),
        ("Advanced XSS Vulnerability", ["script>alert", "javascript:", "onerror=", "xss", "cross-site scripting", "dom manipulation", "session hijacking"]),
        ("Authentication Architecture Compromise", ["login bypass", "admin access", "unauthorized access", "session hijack", "jwt manipulation", "oauth bypass"]),
        ("Business Logic Exploitation", ["workflow bypass", "transaction manipulation", "privilege escalation", "business rule violation", "approval process bypass"]),
        ("Information Disclosure", ["debug info", "stack trace", "error message", "database schema", "version info", "api documentation", "configuration exposure"]),
        ("Authorization Control Bypass", ["privilege escalation", "idor", "access control", "unauthorized operation", "rbac bypass", "role manipulation"]),
        ("Advanced CSRF Attack", ["csrf token missing", "cross-site request", "state changing operation", "sameSite bypass", "csrf protection bypass"]),
        ("Financial System Compromise", ["payment bypass", "transaction manipulation", "balance modification", "currency conversion abuse", "financial workflow exploit"]),
        ("API Security Vulnerability", ["api authorization bypass", "jwt token manipulation", "graphql introspection", "rest api abuse", "microservices exploitation"]),
        ("Session Management Flaw", ["session fixation", "concurrent session abuse", "token entropy weakness", "session hijacking", "cookie manipulation"]),
        ("Compliance Violation", ["pci dss violation", "gdpr breach", "sox control failure", "hipaa violation", "regulatory control bypass"]),
        ("Enterprise Infrastructure Compromise", ["cloud misconfiguration", "container escape", "devops pipeline compromise", "supply chain attack"]),
        ("Advanced Persistent Threat Simulation", ["stealth technique", "evasion method", "anti-forensics", "persistence mechanism", "lateral movement"]),
        ("Information Warfare Intelligence", ["competitive intelligence", "trade secret exposure", "strategic information disclosure", "intellectual property leak"])
    ]
    
    for vulnerability_type, indicators in security_indicators:
        for indicator in indicators:
            if indicator.lower() in conversation_text.lower():
                # Build enhanced finding with business context
                finding = f"{vulnerability_type}: {indicator} detected"
                
                # Add business impact context if available
                if business_impact_context:
                    if any(term in business_impact_context.upper() for term in ['CRITICAL', 'CATASTROPHIC']):
                        finding += " [🔴 CRITICAL BUSINESS IMPACT]"
                    elif 'HIGH' in business_impact_context.upper():
                        finding += " [🟠 HIGH BUSINESS IMPACT]"
                    elif 'MEDIUM' in business_impact_context.upper():
                        finding += " [🟡 MEDIUM BUSINESS IMPACT]"
                    elif 'LOW' in business_impact_context.upper():
                        finding += " [🟢 LOW BUSINESS IMPACT]"
                
                # Add attack complexity context
                if attack_complexity_context:
                    if any(term in attack_complexity_context.upper() for term in ['EXPERT', 'VERY HIGH']):
                        finding += " [Expert-level exploitation required]"
                    elif 'HIGH' in attack_complexity_context.upper():
                        finding += " [Advanced techniques utilized]"
                
                # Add compliance context
                if compliance_context:
                    finding += f" [Compliance Risk: {compliance_context[:50]}...]"
                
                findings.append(finding)
                break  # Only add each vulnerability type once per conversation
    
    # Look for specific business impact indicators
    business_impact_indicators = [
        ("Financial Loss Potential", ["unauthorized transfer", "payment manipulation", "transaction fraud", "financial system compromise"]),
        ("Data Breach Risk", ["customer data access", "pii exposure", "database compromise", "sensitive information disclosure"]),
        ("Regulatory Compliance Failure", ["audit trail compromise", "control bypass", "compliance violation", "regulatory requirement failure"]),
        ("Operational Disruption", ["system availability impact", "service interruption", "business continuity threat", "operational compromise"]),
        ("Competitive Intelligence Exposure", ["trade secret access", "strategic information leak", "competitive advantage loss", "intellectual property exposure"])
    ]
    
    for impact_type, indicators in business_impact_indicators:
        for indicator in indicators:
            if indicator.lower() in conversation_text.lower():
                findings.append(f"Business Impact: {impact_type} - {indicator} identified")
                break
    
    # Add summary of strategic findings if any critical issues found
    critical_findings = [f for f in findings if any(term in f for term in ['CRITICAL', 'Financial', 'Data Breach', 'Compliance'])]
    if critical_findings:
        findings.append(f"⚠️  STRATEGIC ALERT: {len(critical_findings)} critical business-impact vulnerabilities detected requiring immediate executive attention")
    
    return findings

def _is_same_domain(base_url: str, link_url: str) -> bool:
    """Check if the link URL is from the exact same domain as the base URL (excludes subdomains)."""
    try:
        base_domain = urlparse(base_url).netloc
        link_domain = urlparse(link_url).netloc
        
        # Only allow exact domain match, not subdomains
        return base_domain == link_domain
    except Exception:
        return False

def _is_asset_file(url: str) -> bool:
    """Check if a URL points to an asset file (images, fonts, stylesheets, etc.)."""
    if not url or not isinstance(url, str):
        return False
    
    # Remove query parameters and fragments for extension checking
    parsed_url = urlparse(url)
    path = parsed_url.path.lower()
    
    # Common asset file extensions to skip
    asset_extensions = {
        # Images
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff', '.tif',
        # Fonts
        '.ttf', '.otf', '.woff', '.woff2', '.eot',
        # Stylesheets (already handled in CSS extraction)
        '.css',
        # Client-side scripts (not useful for server-side pentesting)
        '.js',
        # Media files
        '.mp3', '.mp4', '.wav', '.avi', '.mov', '.wmv', '.flv', '.webm', '.ogg',
        # Documents (might be interesting but usually not for crawling)
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # Archives (might be interesting but usually not for crawling)
        '.zip', '.tar', '.gz', '.rar', '.7z',
        # Other common assets
        '.swf', '.manifest', '.map'  # source maps
    }
    
    # Check if the URL ends with any asset extension
    for ext in asset_extensions:
        if path.endswith(ext):
            return True
    
    return False

def _print_plans_for_url(url: str, plans: list):
    """Print enhanced security test plans for a URL in a structured format."""
    print("🔍 ENHANCED SECURITY TEST PLANS")
    print("-" * 50)
    print(f"URL: {url}")
    print(f"Plans Generated: {len(plans)}")
    print()
    
    if not plans:
        print("❌ No security test plans generated for this URL")
        print()
        return
    
    for i, plan in enumerate(plans, 1):
        title = plan.get('title', 'Untitled Plan')
        description = plan.get('description', 'No description available')
        business_impact = plan.get('business_impact', '')
        attack_complexity = plan.get('attack_complexity', '')
        compliance_risk = plan.get('compliance_risk', '')
        
        print(f"📋 Plan {i}: {title}")
        print(f"   Description: {description[:150]}{'...' if len(description) > 150 else ''}")
        
        # Display enhanced fields if available
        if business_impact:
            # Extract impact level for display
            impact_level = "UNKNOWN"
            if any(term in business_impact.upper() for term in ['CRITICAL', 'CATASTROPHIC']):
                impact_level = "🔴 CRITICAL"
            elif 'HIGH' in business_impact.upper():
                impact_level = "🟠 HIGH"
            elif 'MEDIUM' in business_impact.upper():
                impact_level = "🟡 MEDIUM"
            elif 'LOW' in business_impact.upper():
                impact_level = "🟢 LOW"
            
            print(f"   Business Impact: {impact_level}")
            print(f"     Details: {business_impact[:100]}{'...' if len(business_impact) > 100 else ''}")
        
        if attack_complexity:
            # Extract complexity level for display
            complexity_level = "STANDARD"
            if any(term in attack_complexity.upper() for term in ['EXPERT', 'VERY HIGH']):
                complexity_level = "🔥 EXPERT"
            elif 'HIGH' in attack_complexity.upper():
                complexity_level = "⚡ HIGH"
            elif 'MEDIUM' in attack_complexity.upper():
                complexity_level = "⚙️ MEDIUM"
            elif 'LOW' in attack_complexity.upper():
                complexity_level = "🔧 LOW"
            
            print(f"   Attack Complexity: {complexity_level}")
        
        if compliance_risk:
            print(f"   Compliance Risk: {compliance_risk[:80]}{'...' if len(compliance_risk) > 80 else ''}")
        
        print()
    
    print("-" * 50)
    print()

def main():
    try:
        run_orchestration()
    except KeyboardInterrupt:
        print("\nOrchestration interrupted by user")
    except Exception as e:
        print(f"Orchestration failed: {str(e)}")

if __name__ == "__main__":
    main()
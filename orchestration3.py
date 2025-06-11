# Tool Calling Testing and Orchestration
import sys
import os
from typing import Dict, List, Any, Optional
import json
import time

from tools.llms import LLM
from agents.actioner import ActionerAgent

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

securitytools_gemini_compatible = [
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
                    "full_page": {"type": "boolean", "description": "Capture full page or viewport only", "default": true}
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
                "full_page": {"type": "boolean", "description": "Capture full page or viewport only", "default": true}
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
    return "true"


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
        return "false"
    
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
    
    return "true"


def test_browser_tool_use():
    """
    Test function for browser tools using both Gemini and Fireworks tool use
    """
    print("=" * 80)
    print("TESTING BROWSER TOOL USE FUNCTIONS - WEB SECURITY AUTOMATION")
    print("=" * 80)
    
    # Initialize LLM
    llm = LLM("Browser Testing LLM")
    
    # Browser automation testing prompts
    browser_test_prompts = [
        {
            "name": "Web Application Reconnaissance",
            "prompt": """You are conducting reconnaissance on a web application for security testing.

TARGET: https://webapp.example.com/
OBJECTIVE: Initial discovery and mapping of the application
TESTING APPROACH: Systematic browser-based exploration

Current task:
- Navigate to the main application
- Extract and analyze all forms for potential injection points
- Identify all links for crawling and discovery
- Take screenshots for documentation
- Analyze cookies and session management

Use browser automation tools to systematically explore and document the web application."""
        },
        {
            "name": "Form-Based Vulnerability Testing",
            "prompt": """You are testing form-based vulnerabilities in a web application.

TARGET: Login form at https://app.example.com/login
VULNERABILITIES TO TEST: XSS, SQL injection, authentication bypass
TESTING METHOD: Automated payload injection and response analysis

Current testing requirements:
- Fill login form with XSS payloads to test for reflected XSS
- Submit forms and analyze responses for vulnerability indicators
- Test different payload encodings and bypass techniques
- Document all findings with screenshots

Execute systematic form-based security testing using browser automation."""
        },
        {
            "name": "Session and Authentication Testing",
            "prompt": """You are testing session management and authentication controls.

TARGET: https://secure.example.com/dashboard
TESTING FOCUS: Session fixation, privilege escalation, cookie security
ATTACK VECTORS: Session manipulation, cookie tampering, privilege bypass

Testing requirements:
- Extract and analyze all cookies for security attributes
- Test session manipulation techniques
- Attempt privilege escalation through cookie modification
- Analyze authentication bypass opportunities
- Test session timeout and management

Use browser tools to comprehensively test session security."""
        },
        {
            "name": "Advanced Web Application Testing",
            "prompt": """You are performing advanced web application security testing.

TARGET: https://api.webapp.com/
TESTING SCOPE: WAF bypass, CSP bypass, response manipulation
COMPLEXITY LEVEL: Advanced - requires sophisticated techniques

Testing objectives:
- Configure WAF bypass headers for evasion
- Bypass Content Security Policy for XSS testing
- Intercept and modify HTTP responses for testing
- Analyze network traffic for security issues
- Test geolocation-based access controls

Execute advanced browser-based security testing with evasion techniques."""
        }
    ]
    
    # Run tests for each prompt
    for i, test_case in enumerate(browser_test_prompts, 1):
        print(f"\n{'='*60}")
        print(f"BROWSER TEST CASE {i}: {test_case['name']}")
        print(f"{'='*60}")
        
        try:
            # Test Gemini tool use
            print(f"\n🔍 TESTING GEMINI BROWSER TOOLS...")
            print("-" * 40)
            
            gemini_result = llm.gemini_tool_use(
                prompt=test_case['prompt'],
                tools=browsertools_gemini_compatible,
                model="gemini-2.0-flash"
            )
            
            print(f"✅ Gemini Response:")
            print(f"Text: {gemini_result.get('text', 'No text response')[:200]}...")
            print(f"Function Calls: {len(gemini_result.get('function_calls', []))} browser tool(s) called")
            
            if gemini_result.get('function_calls'):
                for j, call in enumerate(gemini_result['function_calls'], 1):
                    print(f"  {j}. {call.get('name', 'unknown')}({list(call.get('args', {}).keys())})")
                    
        except Exception as e:
            print(f"❌ Gemini browser test failed: {str(e)}")
        
        try:
            # Test Fireworks tool use  
            print(f"\n🔥 TESTING FIREWORKS BROWSER TOOLS...")
            print("-" * 40)
            
            fireworks_result = llm.fireworks_tool_use(
                prompt=test_case['prompt'],
                tools=browsertools_fw_compatible,
                model_key="deepseek-v3",
                temperature=0.3,
                system_prompt="You are an expert web application security tester. Use browser automation tools to systematically test for vulnerabilities."
            )
            
            print(f"✅ Fireworks Response:")
            print(f"Content: {fireworks_result.get('content', 'No content')[:200]}...")
            print(f"Tool Calls: {len(fireworks_result.get('tool_calls', []))} browser tool(s) called")
            
            if fireworks_result.get('tool_calls'):
                for j, call in enumerate(fireworks_result['tool_calls'], 1):
                    func = call.get('function', {})
                    print(f"  {j}. {func.get('name', 'unknown')}({list(func.get('arguments', {}).keys()) if isinstance(func.get('arguments'), dict) else 'args'})")
                    
        except Exception as e:
            print(f"❌ Fireworks browser test failed: {str(e)}")
            
        # Pause between tests
        if i < len(browser_test_prompts):
            print(f"\n⏳ Waiting 2 seconds before next test...")
            time.sleep(2)
    
    print(f"\n{'='*80}")
    print("BROWSER TOOL TESTING COMPLETED")
    print(f"{'='*80}")
    
    return "true"


def test_combined_security_and_browser_tools():
    """
    Test function combining both security tools and browser tools
    """
    print("=" * 80)
    print("TESTING COMBINED SECURITY + BROWSER TOOLS")
    print("=" * 80)
    
    llm = LLM("Combined Testing LLM")
    
    # Combined tools - merge both security and browser tools
    combined_fw_tools = securitytools_fw_compatible + browsertools_fw_compatible
    combined_gemini_tools = securitytools_gemini_compatible + browsertools_gemini_compatible
    
    combined_prompt = """
    You are conducting a comprehensive web application security assessment that requires both automated security testing tools and browser automation.
    
    TARGET: https://webapp.vulnerable.com/
    BUSINESS IMPACT: CRITICAL - E-commerce platform with customer payment data
    TESTING SCOPE: Full-stack web application security assessment
    
    ASSESSMENT REQUIREMENTS:
    1. Network reconnaissance to identify services and ports
    2. Web application discovery using browser automation
    3. Form-based vulnerability testing (XSS, SQL injection)
    4. Session management and authentication testing
    5. API security assessment
    6. Comprehensive vulnerability documentation
    
    You have access to both security testing tools (sqlmap, nmap, XSS testing, etc.) and browser automation tools (goto, fill, click, extract_forms, etc.).
    
    Execute a systematic security assessment using the most appropriate tools for each testing phase.
    """
    
    try:
        print(f"\n🔍 TESTING COMBINED TOOLS WITH GEMINI...")
        print("-" * 50)
        
        gemini_result = llm.gemini_tool_use(
            prompt=combined_prompt,
            tools=combined_gemini_tools,
            model="gemini-2.0-flash"
        )
        
        print(f"✅ Gemini Combined Response:")
        print(f"Text: {gemini_result.get('text', 'No text response')[:300]}...")
        print(f"Total Function Calls: {len(gemini_result.get('function_calls', []))}")
        
        # Categorize tools called
        security_tools = []
        browser_tools = []
        
        for call in gemini_result.get('function_calls', []):
            tool_name = call.get('name', 'unknown')
            if any(tool['name'] == tool_name for tool in securitytools_gemini_compatible):
                security_tools.append(tool_name)
            elif any(tool['name'] == tool_name for tool in browsertools_gemini_compatible):
                browser_tools.append(tool_name)
        
        print(f"Security Tools Called: {len(security_tools)} - {security_tools}")
        print(f"Browser Tools Called: {len(browser_tools)} - {browser_tools}")
        
    except Exception as e:
        print(f"❌ Gemini combined test failed: {str(e)}")
    
    try:
        print(f"\n🔥 TESTING COMBINED TOOLS WITH FIREWORKS...")
        print("-" * 50)
        
        fireworks_result = llm.fireworks_tool_use(
            prompt=combined_prompt,
            tools=combined_fw_tools,
            model_key="qwen2.5-72b-instruct",
            temperature=0.2,
            system_prompt="You are an expert penetration tester with access to both automated security tools and browser automation. Create a comprehensive testing strategy using the most appropriate tools."
        )
        
        print(f"✅ Fireworks Combined Response:")
        print(f"Content: {fireworks_result.get('content', 'No content')[:300]}...")
        print(f"Total Tool Calls: {len(fireworks_result.get('tool_calls', []))}")
        
        # Categorize tools called
        security_tools = []
        browser_tools = []
        
        for call in fireworks_result.get('tool_calls', []):
            func = call.get('function', {})
            tool_name = func.get('name', 'unknown')
            if any(tool['function']['name'] == tool_name for tool in securitytools_fw_compatible):
                security_tools.append(tool_name)
            elif any(tool['function']['name'] == tool_name for tool in browsertools_fw_compatible):
                browser_tools.append(tool_name)
        
        print(f"Security Tools Called: {len(security_tools)} - {security_tools}")
        print(f"Browser Tools Called: {len(browser_tools)} - {browser_tools}")
        
    except Exception as e:
        print(f"❌ Fireworks combined test failed: {str(e)}")
    
    return "true"


if __name__ == "__main__":
    print("🚀 Starting Tool Use Function Testing...")
    
    # Run comprehensive tests
    test_tool_use_functions()
    
    # Run browser tool tests
    test_browser_tool_use()
    
    # Run combined security and browser tests
    test_combined_security_and_browser_tools()
    
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
    
    # Test browser tools specifically
    test_single_tool_scenario(
        tool_name="goto",
        prompt="Navigate to https://webapp.example.com/login and analyze the login form for security testing opportunities.",
        api_type="both"
    )
    
    test_single_tool_scenario(
        tool_name="fill_form_with_payload",
        prompt="Test XSS vulnerability by filling the search form with payload: <script>alert('XSS')</script>",
        api_type="both"
    )
    
    print(f"\n✅ ALL TOOL USE TESTING COMPLETED!")


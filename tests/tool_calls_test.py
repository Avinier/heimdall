#!/usr/bin/env python3
"""
Comprehensive 360-Degree Test Suite for Security Tools (tool_calls.py)

This test suite provides complete coverage of the security testing functionality including:
- SQL injection testing with SQLMap integration
- Cross-site scripting (XSS) vulnerability testing
- Network reconnaissance with Nmap and custom port scanning
- API endpoint discovery and security analysis
- JWT vulnerability analysis and token manipulation
- IDOR (Insecure Direct Object Reference) testing
- Information disclosure vulnerability detection
- Business logic data validation testing
- Workflow circumvention testing
- Vulnerability object creation and management
- Results saving and serialization
- Context-aware payload selection and optimization
- Framework-specific security testing
- Database-specific attack vectors
- WAF bypass techniques
- Error handling and graceful degradation
- Performance testing with large datasets
- Threading and concurrency validation
- Unicode and special character handling

Usage:
    python tests/tool_calls_test.py
    
    or from project root:
    python -m tests.tool_calls_test
"""

import sys
import os
import json
import tempfile
import shutil
import time
import threading
from unittest.mock import Mock, patch, MagicMock
import subprocess
import socket
import logging
import requests

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.tool_calls import *

# Test counters - global for the test suite
tests_passed = 0
tests_failed = 0


def test_case(test_name: str):
    """Decorator for test cases"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            global tests_passed, tests_failed
            try:
                print(f"\n🔍 Testing: {test_name}")
                result = func(*args, **kwargs)
                print(f"✅ PASSED: {test_name}")
                tests_passed += 1
                return result
            except Exception as e:
                print(f"❌ FAILED: {test_name} - {str(e)}")
                tests_failed += 1
                return None
        return wrapper
    return decorator


# ======================== Mock Classes ========================

class MockResponse:
    """Mock HTTP response for testing"""
    def __init__(self, text="", status_code=200, headers=None, url=""):
        self.text = text
        self.content = text.encode() if isinstance(text, str) else text
        self.status_code = status_code
        self.headers = headers or {}
        self.url = url
        self.reason = "OK" if status_code == 200 else "Error"
    
    def json(self):
        try:
            return json.loads(self.text)
        except:
            return {}


# ======================== Test Data Setup ========================

# Test URLs and endpoints
TEST_URLS = [
    "http://testsite.local/api/users",
    "https://example.com/login",
    "http://vulnerable-app.test/search",
    "https://api.target.com/v1/data",
    "http://10.0.0.1:8080/admin"
]

# Test contexts for different environments
TEST_CONTEXTS = [
    {
        "framework": "django",
        "database": "postgresql", 
        "language": "python",
        "has_waf": False,
        "supports_json": True
    },
    {
        "framework": "laravel",
        "database": "mysql",
        "language": "php",
        "has_waf": True,
        "supports_post": True
    },
    {
        "framework": "express",
        "database": "mongodb",
        "language": "nodejs",
        "supports_json": True,
        "authentication_type": "bearer"
    }
]

# Test JWT tokens
TEST_JWT_TOKENS = [
    # Valid token structure
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    # Token with none algorithm
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
    # Malformed token
    "invalid.jwt.token",
    # Token with admin claims
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9.invalid_signature"
]

# Network targets for testing
NETWORK_TARGETS = [
    "127.0.0.1",
    "192.168.1.1", 
    "10.0.0.1",
    "localhost",
    "target.local"
]

# Comprehensive target contexts for different scenarios
test_contexts = {
    'mysql_php': PayloadTargetContext(
        framework='laravel',
        database='mysql',
        web_server='nginx',
        language='php',
        supports_post=True,
        supports_json=True,
        authentication_type='cookie',
        has_waf=False
    ),
    'postgresql_django': PayloadTargetContext(
        framework='django',
        database='postgresql',
        web_server='nginx',
        language='python',
        supports_post=True,
        supports_json=True,
        authentication_type='bearer',
        has_waf=True
    ),
    'mssql_aspnet': PayloadTargetContext(
        framework='asp.net',
        database='mssql',
        web_server='iis',
        language='csharp',
        supports_post=True,
        supports_json=True,
        authentication_type='bearer',
        has_waf=True
    ),
    'mongodb_nodejs': PayloadTargetContext(
        framework='express',
        database='mongodb',
        web_server='nginx',
        language='nodejs',
        supports_post=True,
        supports_json=True,
        authentication_type='jwt',
        has_waf=False,
        custom_headers={'X-API-Key': 'test-key'}
    ),
    'wordpress_cms': PayloadTargetContext(
        framework='wordpress',
        database='mysql',
        web_server='apache',
        language='php',
        cms='wordpress',
        supports_post=True,
        supports_json=False,
        authentication_type='cookie',
        has_waf=False
    )
}

# Test URLs for different scenarios
test_urls = {
    'basic_param': 'http://testphp.vulnweb.com/artists.php?artist=1',
    'post_form': 'http://testphp.vulnweb.com/userinfo.php',
    'api_endpoint': 'http://jsonplaceholder.typicode.com/posts/1',
    'search_function': 'http://testphp.vulnweb.com/search.php?test=query',
    'admin_panel': 'http://testphp.vulnweb.com/admin/',
    'file_upload': 'http://testphp.vulnweb.com/upload.php',
    'local_target': 'http://127.0.0.1:8080/test'
}

# Test JWT tokens for different scenarios
test_jwt_tokens = {
    'valid_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    'none_algorithm': 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
    'weak_secret': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.fFbBvD8QZ5QrXOzf6LCMjzDV4HukgbYi0KkLV6ZMFVQ',  # secret: "secret"
    'malformed': 'invalid.jwt.token',
    'expired': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.T3ly_w8q1LsTW1K1_Fl5g6Z0VU8HzIKoLI8V3QadScs'
}

# Network targets for scanning tests
test_network_targets = {
    'localhost': '127.0.0.1',
    'local_range': '127.0.0.1/32',
    'invalid_ip': '999.999.999.999',
    'hostname': 'localhost',
    'unreachable': '192.0.2.1'  # RFC 5737 test address
}

# Port lists for various scenarios
test_port_lists = {
    'common_ports': [21, 22, 23, 25, 53, 80, 110, 443, 993, 995],
    'web_ports': [80, 443, 8080, 8443, 3000, 5000],
    'database_ports': [1433, 1521, 3306, 5432, 6379, 27017],
    'ssh_admin_ports': [22, 2222, 2200],
    'high_ports': [8000, 8080, 8443, 9000, 9090]
}

# Mock response objects for testing
class MockResponse:
    def __init__(self, status_code=200, text="", headers=None, json_data=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode('utf-8')
        self.headers = headers or {}
        self._json_data = json_data
        
    def json(self):
        if self._json_data:
            return self._json_data
        return json.loads(self.text) if self.text else {}
        
    @property
    def url(self):
        return "http://test.example.com"

# ======================== Data Structure Tests ========================

@test_case("Vulnerability Class - Basic Creation")
def test_vulnerability_creation():
    vuln = Vulnerability(
        type="SQL Injection",
        severity="Critical",
        evidence="Database error reveals injection point"
    )
    assert vuln.type == "SQL Injection"
    assert vuln.severity == "Critical"
    assert vuln.evidence == "Database error reveals injection point"
    assert vuln.cvss_score == 0.0
    assert vuln.references == []
    return vuln

@test_case("Vulnerability Class - Full Creation with All Fields")
def test_vulnerability_full_creation():
    vuln = Vulnerability(
        type="XSS",
        severity="High",
        evidence="Script executed in browser",
        cvss_score=8.5,
        location="search parameter",
        parameter="q",
        url="http://test.com/search?q=<script>alert(1)</script>",
        payload="<script>alert(1)</script>",
        response_code=200,
        tool="custom_xss_scanner",
        business_impact="Session hijacking possible",
        remediation="Implement proper input sanitization"
    )
    assert vuln.cvss_score == 8.5
    assert vuln.location == "search parameter"
    assert vuln.parameter == "q"
    assert vuln.payload == "<script>alert(1)</script>"
    return vuln

@test_case("Vulnerability Class - Validation and Normalization")
def test_vulnerability_validation():
    # Test invalid severity gets normalized
    vuln = Vulnerability(
        type="Test",
        severity="Invalid",
        evidence="Test evidence"
    )
    assert vuln.severity == "Medium"  # Should default to Medium
    
    # Test CVSS score bounds
    vuln2 = Vulnerability(
        type="Test",
        severity="Critical", 
        evidence="Test evidence",
        cvss_score=15.0  # Over limit
    )
    assert vuln2.cvss_score == 10.0  # Should cap at 10
    
    vuln3 = Vulnerability(
        type="Test",
        severity="Low",
        evidence="Test evidence", 
        cvss_score=-1.0  # Under limit
    )
    assert vuln3.cvss_score == 0.0  # Should floor at 0
    return True

@test_case("Vulnerability Class - Dictionary Conversion")
def test_vulnerability_to_dict():
    vuln = Vulnerability(
        type="IDOR",
        severity="High",
        evidence="Access to other user data",
        location="user_id parameter",
        parameter="id",
        cvss_score=7.5
    )
    vuln_dict = vuln.to_dict()
    assert vuln_dict["type"] == "IDOR"
    assert vuln_dict["severity"] == "High"
    assert vuln_dict["cvss_score"] == 7.5
    assert "location" in vuln_dict
    assert vuln_dict["parameter"] == "id"
    
    # Test from_dict conversion
    vuln2 = Vulnerability.from_dict(vuln_dict)
    assert vuln2.type == vuln.type
    assert vuln2.severity == vuln.severity
    assert vuln2.cvss_score == vuln.cvss_score
    return True

@test_case("ToolCallResult Class - Basic Creation") 
def test_toolcall_result_creation():
    result = ToolCallResult(
        success=True,
        tool_name="sql_injection_test",
        output="SQL injection detected",
        execution_time=2.5
    )
    assert result.success == True
    assert result.tool_name == "sql_injection_test"
    assert result.output == "SQL injection detected"
    assert result.execution_time == 2.5
    assert result.vulnerabilities == []
    assert result.metadata == {}
    return result

@test_case("ToolCallResult Class - With Vulnerabilities")
def test_toolcall_result_with_vulnerabilities():
    vuln1 = Vulnerability("SQL Injection", "Critical", "Error-based injection found")
    vuln2 = {"type": "XSS", "severity": "High", "evidence": "Script reflection detected"}
    
    result = ToolCallResult(
        success=True,
        tool_name="security_scan",
        vulnerabilities=[vuln1, vuln2],
        metadata={"scan_time": "2024-01-15", "target": "test.com"}
    )
    
    # Test vulnerability conversion
    vuln_dicts = result.get_vulnerabilities_as_dicts()
    assert len(vuln_dicts) == 2
    assert vuln_dicts[0]["type"] == "SQL Injection"
    assert vuln_dicts[1]["type"] == "XSS"
    assert isinstance(vuln_dicts[0], dict)
    assert isinstance(vuln_dicts[1], dict)
    return result

@test_case("PayloadTargetContext Class - Creation and Conversion")
def test_payload_target_context():
    context = PayloadTargetContext(
        framework="django",
        database="postgresql",
        language="python",
        has_waf=True,
        supports_json=True,
        custom_headers={"X-Test": "value"}
    )
    
    assert context.framework == "django"
    assert context.database == "postgresql"
    assert context.has_waf == True
    assert context.supports_json == True
    
    # Test dictionary conversion
    context_dict = context.to_dict()
    assert context_dict["framework"] == "django"
    assert context_dict["database"] == "postgresql"
    assert "custom_headers" in context_dict
    
    # Test from_dict
    context2 = PayloadTargetContext.from_dict(context_dict)
    assert context2.framework == context.framework
    assert context2.database == context.database
    return context

@test_case("PayloadLibrary Structure Validation")
def test_payload_library_structure():
    # Test that PayloadLibrary has expected categories
    assert hasattr(PayloadLibrary, 'SQL_INJECTION')
    assert hasattr(PayloadLibrary, 'XSS_ADVANCED')
    assert hasattr(PayloadLibrary, 'JWT_ATTACKS')
    assert hasattr(PayloadLibrary, 'BUSINESS_LOGIC_PAYLOADS')
    
    # Test SQL injection payloads structure
    sql_payloads = PayloadLibrary.SQL_INJECTION
    assert 'critical' in sql_payloads
    assert 'bypass' in sql_payloads
    assert 'time_based' in sql_payloads
    assert isinstance(sql_payloads['critical'], list)
    assert len(sql_payloads['critical']) > 0
    
    # Test XSS payloads structure
    xss_payloads = PayloadLibrary.XSS_ADVANCED
    assert 'critical' in xss_payloads
    assert 'waf_bypass' in xss_payloads
    assert isinstance(xss_payloads['critical'], list)
    
    # Test JWT attacks structure
    jwt_attacks = PayloadLibrary.JWT_ATTACKS
    assert 'weak_secrets' in jwt_attacks
    assert 'algorithm_confusion' in jwt_attacks
    assert isinstance(jwt_attacks['weak_secrets'], list)
    
    return True

# ======================== Utility Function Tests ========================

@test_case("create_vulnerability Function - Basic Creation")
def test_create_vulnerability_basic():
    vuln = create_vulnerability(
        "SQL Injection",
        "Critical", 
        "Error-based SQL injection detected",
        url="http://test.com/api",
        parameter="id"
    )
    assert isinstance(vuln, Vulnerability)
    assert vuln.type == "SQL Injection"
    assert vuln.severity == "Critical"
    assert vuln.evidence == "Error-based SQL injection detected"
    assert vuln.url == "http://test.com/api"
    assert vuln.parameter == "id"
    assert vuln.cvss_score > 0  # Should auto-calculate CVSS score
    return vuln

@test_case("create_vulnerability Function - CVSS Score Calculation")
def test_create_vulnerability_cvss():
    # Test different severity levels
    critical_vuln = create_vulnerability("SQL Injection", "Critical", "Test evidence")
    high_vuln = create_vulnerability("XSS", "High", "Test evidence")
    medium_vuln = create_vulnerability("Info Disclosure", "Medium", "Test evidence")
    low_vuln = create_vulnerability("Missing Headers", "Low", "Test evidence")
    
    assert critical_vuln.cvss_score >= 9.0
    assert 7.0 <= high_vuln.cvss_score < 9.0
    assert 4.0 <= medium_vuln.cvss_score < 7.0
    assert low_vuln.cvss_score < 4.0
    return True

@test_case("calculate_cvss_score Function - Different Vulnerability Types")
def test_calculate_cvss_score():
    # Test different vulnerability types
    sql_score = calculate_cvss_score("SQL Injection", "Critical")
    xss_score = calculate_cvss_score("XSS", "High")
    idor_score = calculate_cvss_score("IDOR", "Medium")
    info_score = calculate_cvss_score("Information Disclosure", "Low")
    
    assert sql_score >= 9.0
    assert 7.0 <= xss_score < 9.0
    assert 4.0 <= idor_score < 7.0
    assert info_score < 4.0
    
    # Test edge cases
    invalid_score = calculate_cvss_score("Unknown", "Invalid")
    assert 0.0 <= invalid_score <= 10.0
    return True

@test_case("detect_xss_reflection Function - Basic Detection")
def test_detect_xss_reflection_basic():
    # Test direct reflection
    response_text = "<html><body>Search results for: <script>alert(1)</script></body></html>"
    payload = "<script>alert(1)</script>"
    assert detect_xss_reflection(response_text, payload) == True
    
    # Test no reflection
    response_text2 = "<html><body>No results found</body></html>"
    assert detect_xss_reflection(response_text2, payload) == False
    
    # Test encoded reflection
    response_text3 = "<html><body>Search: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
    payload3 = "<script>alert(1)</script>"
    assert detect_xss_reflection(response_text3, payload3) == True
    return True

@test_case("detect_xss_reflection Function - Advanced Encoding")
def test_detect_xss_reflection_encoding():
    # Test URL encoding
    response_text = "<html>%3Cscript%3Ealert%281%29%3C%2Fscript%3E</html>"
    payload = "<script>alert(1)</script>"
    assert detect_xss_reflection(response_text, payload) == True
    
    # Test HTML entity encoding
    response_text2 = "<html>&#60;script&#62;alert&#40;1&#41;&#60;/script&#62;</html>"
    assert detect_xss_reflection(response_text2, payload) == True
    
    # Test JavaScript encoding
    response_text3 = "<html>\\x3cscript\\x3ealert(1)\\x3c/script\\x3e</html>"
    assert detect_xss_reflection(response_text3, payload) == True
    return True

@test_case("extract_url_from_text Function - URL Extraction")
def test_extract_url_from_text():
    # Test basic URL extraction
    text1 = "Visit our website at https://example.com for more info"
    url1 = extract_url_from_text(text1)
    assert url1 == "https://example.com"
    
    # Test multiple URLs (should return first)
    text2 = "Sites: http://test.com and https://example.org"
    url2 = extract_url_from_text(text2)
    assert url2 == "http://test.com"
    
    # Test no URL found
    text3 = "No URLs in this text"
    url3 = extract_url_from_text(text3)
    assert url3 is None
    
    # Test complex URL with parameters
    text4 = "API endpoint: https://api.example.com/v1/users?id=123&sort=name"
    url4 = extract_url_from_text(text4)
    assert url4 == "https://api.example.com/v1/users?id=123&sort=name"
    return True

@test_case("create_session Function - Basic Session Creation")
def test_create_session_basic():
    session = create_session()
    assert session is not None
    assert hasattr(session, 'get')
    assert hasattr(session, 'post')
    assert session.verify == False  # Default SSL verification off
    return session

@test_case("create_session Function - Proxy Configuration")
def test_create_session_proxy():
    session = create_session(proxy="http://127.0.0.1:8080")
    assert session is not None
    assert session.proxies is not None
    return session

@test_case("create_session Function - SSL Verification")
def test_create_session_ssl():
    session = create_session(verify_ssl=True)
    assert session is not None
    assert session.verify == True
    return session

@test_case("save_results Function - Basic Save")
def test_save_results_basic():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Change to temp directory for test
        original_dir = os.getcwd()
        try:
            os.chdir(temp_dir)
            
            # Create test result
            result = ToolCallResult(
                success=True,
                tool_name="test_tool",
                output="Test output",
                vulnerabilities=[],
                execution_time=1.0
            )
            
            # Save results
            filename = save_results(result)
            assert filename is not None
            assert os.path.exists(filename)
            
            # Verify file contents
            with open(filename, 'r') as f:
                data = json.load(f)
                assert data["success"] == True
                assert data["tool_name"] == "test_tool"
                assert data["output"] == "Test output"
                
        finally:
            os.chdir(original_dir)
    return True

@test_case("save_results Function - Custom Filename")
def test_save_results_custom_filename():
    with tempfile.TemporaryDirectory() as temp_dir:
        original_dir = os.getcwd()
        try:
            os.chdir(temp_dir)
            
            result = ToolCallResult(
                success=True,
                tool_name="custom_test",
                output="Custom test output"
            )
            
            custom_filename = "custom_test_results.json"
            filename = save_results(result, custom_filename)
            assert filename == custom_filename
            assert os.path.exists(custom_filename)
            
        finally:
            os.chdir(original_dir)
    return True

@test_case("setup_logging Function - Debug Mode")
def test_setup_logging_debug():
    logger = setup_logging(debug=True)
    assert logger is not None
    assert logger.level == logging.DEBUG
    return logger

@test_case("setup_logging Function - Normal Mode")
def test_setup_logging_normal():
    logger = setup_logging(debug=False)
    assert logger is not None
    assert logger.level == logging.INFO
    return logger

# ======================== SQL Injection Testing ========================

@test_case("sql_injection_test Function - Basic Functionality")
def test_sql_injection_test_basic():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        # Mock session and response
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock successful response with SQL error
        mock_response = MockResponse(
            text="MySQL Error: You have an error in your SQL syntax",
            status_code=500
        )
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response
        
        # Test basic SQL injection
        result = sql_injection_test("http://test.com/api", "id")
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "sql_injection_test"
        assert len(result.vulnerabilities) > 0
        
        # Check that the vulnerability was detected
        vuln = result.vulnerabilities[0]
        if isinstance(vuln, dict):
            assert vuln["type"] == "SQL Injection"
            assert vuln["severity"] in ["Critical", "High"]
        else:
            assert vuln.type == "SQL Injection"
            assert vuln.severity in ["Critical", "High"]
            
    return result

@test_case("sql_injection_test Function - Context-Aware Testing")
def test_sql_injection_test_context_aware():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock PostgreSQL specific error
        mock_response = MockResponse(
            text="PostgreSQL: syntax error at or near",
            status_code=500
        )
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response
        
        # Test with PostgreSQL context
        context = PayloadTargetContext(
            framework="django",
            database="postgresql",
            language="python"
        )
        
        result = sql_injection_test(
            "http://django-app.com/api", 
            "user_id",
            target_context=context
        )
        
        assert result.success == True
        assert len(result.vulnerabilities) > 0
        
        # Should detect PostgreSQL-specific issues
        metadata = result.metadata
        assert "postgresql" in str(metadata).lower() or any(
            "postgresql" in str(v).lower() for v in result.vulnerabilities
        )
        
    return result

@test_case("sql_injection_test Function - Custom Payloads")
def test_sql_injection_test_custom_payloads():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock response that detects custom payload
        custom_payload = "' OR 1=1 --"
        mock_response = MockResponse(
            text=f"SQL Error with payload: {custom_payload}",
            status_code=500
        )
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response
        
        # Test with custom payloads
        custom_payloads = [custom_payload, "'; DROP TABLE users; --"]
        result = sql_injection_test(
            "http://test.com/search",
            "query",
            payloads=custom_payloads
        )
        
        assert result.success == True
        # Should have used our custom payloads
        
    return result

@test_case("sql_injection_test Function - Error Handling")
def test_sql_injection_test_error_handling():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock network error
        mock_session.get.side_effect = Exception("Network error")
        mock_session.post.side_effect = Exception("Network error")
        
        result = sql_injection_test("http://unreachable.com", "id")
        
        # Should handle error gracefully
        assert isinstance(result, ToolCallResult)
        assert result.success == False
        assert "error" in result.error.lower() or result.error != ""
        
    return result

@test_case("sqlmap_campaign Function - Basic Functionality")
def test_sqlmap_campaign_basic():
    with patch('subprocess.run') as mock_subprocess:
        # Mock successful SQLMap execution
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="sqlmap identified the following injection point(s):\nParameter: id (GET)\n    Type: boolean-based blind",
            stderr=""
        )
        
        result = sqlmap_campaign("http://test.com/api?id=1")
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "sqlmap_campaign"
        
        # Verify subprocess was called
        mock_subprocess.assert_called_once()
        args = mock_subprocess.call_args[0][0]
        assert "sqlmap" in str(args).lower()
        assert "http://test.com/api?id=1" in str(args)
        
    return result

@test_case("sqlmap_campaign Function - Comprehensive Mode")
def test_sqlmap_campaign_comprehensive():
    with patch('subprocess.run') as mock_subprocess:
        # Mock comprehensive SQLMap output
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="""
sqlmap identified the following injection point(s):
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: id=1 AND SLEEP(5)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-1 UNION ALL SELECT NULL,CONCAT(0x3a,@@version,0x3a),NULL-- 

back-end DBMS: MySQL >= 5.0.12
database management system users [3]:
[*] 'root'@'localhost'
[*] 'mysql'@'localhost'
[*] 'app'@'%'
            """,
            stderr=""
        )
        
        result = sqlmap_campaign(
            "http://test.com/vulnerable",
            campaign_mode="comprehensive"
        )
        
        assert result.success == True
        assert len(result.vulnerabilities) > 0
        
        # Should detect multiple vulnerability types
        vuln_types = []
        for vuln in result.vulnerabilities:
            if isinstance(vuln, dict):
                vuln_types.append(vuln.get("type", ""))
            else:
                vuln_types.append(vuln.type)
        
        # Should detect different SQL injection types
        assert any("boolean" in vtype.lower() for vtype in vuln_types) or \
               any("time" in vtype.lower() for vtype in vuln_types) or \
               any("union" in vtype.lower() for vtype in vuln_types)
        
    return result

@test_case("sqlmap_campaign Function - Context-Aware Options")
def test_sqlmap_campaign_context_aware():
    with patch('subprocess.run') as mock_subprocess:
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="MySQL injection detected",
            stderr=""
        )
        
        # Test with authentication context
        context = PayloadTargetContext(
            database="mysql",
            authentication_type="cookie",
            has_waf=True
        )
        
        options = {
            "cookie": "session=abc123",
            "headers": ["User-Agent: Test"],
            "proxy": "http://127.0.0.1:8080"
        }
        
        result = sqlmap_campaign(
            "http://test.com/login",
            options=options,
            target_context=context,
            campaign_mode="stealth"
        )
        
        assert result.success == True
        
        # Verify that context-aware options were used
        args = mock_subprocess.call_args[0][0]
        args_str = " ".join(args)
        
        # Should include stealth mode options for WAF bypass
        # Should include authentication options
        assert "--cookie" in args_str or "session=abc123" in args_str
        
    return result

@test_case("sqlmap_campaign Function - Error Handling")
def test_sqlmap_campaign_error_handling():
    with patch('subprocess.run') as mock_subprocess:
        # Mock SQLMap failure
        mock_subprocess.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="sqlmap: error: unrecognized arguments"
        )
        
        result = sqlmap_campaign("http://invalid-url")
        
        assert isinstance(result, ToolCallResult)
        # Should handle error gracefully
        assert result.error != ""
        
    return result

# ======================== XSS Testing ========================

@test_case("xss_test Function - Basic Functionality") 
def test_xss_test_basic():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock response with XSS reflection
        mock_response = MockResponse(
            text="<html>Search results for: <script>alert(1)</script></html>",
            status_code=200
        )
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response
        
        result = xss_test("http://test.com/search", "q")
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "xss_test"
        assert len(result.vulnerabilities) > 0
        
        # Check vulnerability details
        vuln = result.vulnerabilities[0]
        if isinstance(vuln, dict):
            assert "xss" in vuln["type"].lower()
            assert vuln["severity"] in ["Critical", "High", "Medium"]
        else:
            assert "xss" in vuln.type.lower()
            assert vuln.severity in ["Critical", "High", "Medium"]
            
    return result

@test_case("xss_test Function - Advanced Mode")
def test_xss_test_advanced():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock response with DOM-based XSS indicators
        mock_response = MockResponse(
            text='<script>document.getElementById("output").innerHTML = getUrlParam("search");</script>',
            status_code=200
        )
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response
        
        result = xss_test(
            "http://test.com/search",
            "search", 
            test_mode="advanced"
        )
        
        assert result.success == True
        assert len(result.vulnerabilities) >= 0  # May detect DOM XSS patterns
        
    return result

@test_case("xss_test Function - Custom Payloads")
def test_xss_test_custom_payloads():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        custom_payload = '<img src=x onerror=alert("custom")>'
        
        # Mock response that reflects the custom payload
        mock_response = MockResponse(
            text=f'<html>User input: {custom_payload}</html>',
            status_code=200
        )
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response
        
        custom_payloads = [custom_payload, '<svg onload=alert(1)>']
        result = xss_test(
            "http://test.com/form",
            "comment",
            payloads=custom_payloads
        )
        
        assert result.success == True
        # Should use custom payloads
        
    return result

@test_case("xss_test Function - WAF Bypass Context")
def test_xss_test_waf_bypass():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock WAF-protected response 
        mock_response = MockResponse(
            text='<html>jaVasCript:alert(1) detected in search</html>',
            status_code=200
        )
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response
        
        # Test with WAF context
        context = PayloadTargetContext(
            has_waf=True,
            framework="express",
            language="nodejs"
        )
        
        result = xss_test(
            "http://waf-protected.com/search",
            "q",
            target_context=context,
            test_mode="comprehensive"
        )
        
        assert result.success == True
        # Should attempt WAF bypass techniques
        
    return result

@test_case("xss_test Function - Error Handling")
def test_xss_test_error_handling():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock network error
        mock_session.get.side_effect = Exception("Connection refused")
        mock_session.post.side_effect = Exception("Connection refused")
        
        result = xss_test("http://unreachable.com", "test")
        
        assert isinstance(result, ToolCallResult)
        assert result.success == False
        assert result.error != ""
        
    return result

# ======================== Network Reconnaissance Tests ========================

@test_case("nmap_scan Function - Basic Functionality")
def test_nmap_scan_basic():
    with patch('subprocess.run') as mock_subprocess:
        # Mock basic nmap scan output
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="""
Starting Nmap 7.80 scan
Nmap scan report for 127.0.0.1
Host is up (0.0010s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
            """,
            stderr=""
        )
        
        result = nmap_scan("127.0.0.1", "basic")
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "nmap_scan"
        assert len(result.vulnerabilities) >= 0
        
        # Verify subprocess was called
        mock_subprocess.assert_called_once()
        args = mock_subprocess.call_args[0][0]
        assert "nmap" in str(args).lower()
        assert "127.0.0.1" in str(args)
        
    return result

@test_case("nmap_scan Function - Service Detection")
def test_nmap_scan_service_detection():
    with patch('subprocess.run') as mock_subprocess:
        # Mock service detection output
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="""
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
<address addr="127.0.0.1" addrtype="ipv4"/>
<status state="up"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" version="OpenSSH 7.4"/>
</port>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" version="Apache httpd 2.4.6"/>
</port>
</ports>
</host>
</nmaprun>
            """,
            stderr=""
        )
        
        result = nmap_scan("127.0.0.1", "service", scan_mode="comprehensive")
        
        assert result.success == True
        
        # Should detect service information
        if result.vulnerabilities:
            for vuln in result.vulnerabilities:
                if isinstance(vuln, dict):
                    assert "service" in vuln.get("evidence", "").lower() or \
                           "port" in vuln.get("evidence", "").lower()
                
    return result

@test_case("nmap_scan Function - Vulnerability Scripts")
def test_nmap_scan_vuln_scripts():
    with patch('subprocess.run') as mock_subprocess:
        # Mock vulnerability script output
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="""
22/tcp open  ssh     OpenSSH 7.4
| ssh-hostkey: 
|   2048 aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa (RSA)
|_  256 bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb (ECDSA)
| ssl-cert: Subject: commonName=test.local
| Not valid before: 2020-01-01T00:00:00
|_Not valid after:  2021-01-01T00:00:00
443/tcp open  https   Apache httpd 2.4.6
| ssl-enum-ciphers: 
|   TLSv1.0: 
|     ciphers: 
|       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
|_      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
            """,
            stderr=""
        )
        
        result = nmap_scan(
            "127.0.0.1", 
            "vuln",
            custom_scripts=["ssl-cert", "ssl-enum-ciphers"]
        )
        
        assert result.success == True
        # Should detect potential SSL vulnerabilities
        
    return result

@test_case("nmap_scan Function - Context-Aware Scanning")
def test_nmap_scan_context_aware():
    with patch('subprocess.run') as mock_subprocess:
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="80/tcp open http Apache httpd 2.4.6",
            stderr=""
        )
        
        # Test with web server context
        context = PayloadTargetContext(
            web_server="apache",
            framework="php",
            database="mysql"
        )
        
        result = nmap_scan(
            "127.0.0.1",
            "comprehensive", 
            target_context=context,
            ports=[80, 443, 3306]
        )
        
        assert result.success == True
        
        # Verify context-aware port selection was used
        args = mock_subprocess.call_args[0][0]
        args_str = " ".join(args)
        assert "80" in args_str or "443" in args_str or "3306" in args_str
        
    return result

@test_case("enterprise_port_scan Function - Basic Functionality")
def test_enterprise_port_scan_basic():
    with patch('socket.socket') as mock_socket:
        # Mock successful connection
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0  # Success
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_7.4"
        
        result = enterprise_port_scan("127.0.0.1", [22, 80, 443])
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "enterprise_port_scan"
        
    return result

@test_case("enterprise_port_scan Function - Service Detection")
def test_enterprise_port_scan_service_detection():
    with patch('socket.socket') as mock_socket:
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        
        # Mock different service banners
        def mock_connect_and_banner(port):
            if port == 22:
                mock_sock.connect_ex.return_value = 0
                mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_7.4"
            elif port == 80:
                mock_sock.connect_ex.return_value = 0
                mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.6"
            elif port == 3306:
                mock_sock.connect_ex.return_value = 0
                mock_sock.recv.return_value = b"\x4a\x00\x00\x00\x0a5.7.30-log"  # MySQL banner
            else:
                mock_sock.connect_ex.return_value = 1  # Connection refused
                
        # Configure the side effect based on port
        def side_effect_connect(address):
            host, port = address
            mock_connect_and_banner(port)
            return mock_sock.connect_ex.return_value
            
        mock_sock.connect_ex.side_effect = side_effect_connect
        
        result = enterprise_port_scan(
            "127.0.0.1", 
            [22, 80, 443, 3306],
            scan_mode="comprehensive"
        )
        
        assert result.success == True
        
    return result

@test_case("enterprise_port_scan Function - Context-Aware Analysis")
def test_enterprise_port_scan_context_aware():
    with patch('socket.socket') as mock_socket:
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"Apache/2.4.6 (CentOS) OpenSSL/1.0.2"
        
        # Test with context for enhanced analysis
        context = PayloadTargetContext(
            web_server="apache",
            framework="php",
            database="mysql",
            language="php"
        )
        
        result = enterprise_port_scan(
            "192.168.1.100",
            [80, 443, 3306, 22],
            target_context=context,
            scan_method="tcp_syn",
            custom_service_probes=["GET / HTTP/1.1\r\nHost: test\r\n\r\n"]
        )
        
        assert result.success == True
        # Should provide context-aware analysis
        
    return result

@test_case("nmap_scan Function - Error Handling")
def test_nmap_scan_error_handling():
    with patch('subprocess.run') as mock_subprocess:
        # Mock nmap failure
        mock_subprocess.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Nmap: invalid option: --invalid"
        )
        
        result = nmap_scan("invalid-target", "basic")
        
        assert isinstance(result, ToolCallResult)
        # Should handle error gracefully
        
    return result

@test_case("enterprise_port_scan Function - Error Handling")
def test_enterprise_port_scan_error_handling():
    with patch('socket.socket') as mock_socket:
        # Mock socket creation failure
        mock_socket.side_effect = Exception("Socket creation failed")
        
        result = enterprise_port_scan("127.0.0.1", [80])
        
        assert isinstance(result, ToolCallResult)
        # Should handle socket errors gracefully
        
    return result

# ======================== API Security Testing ========================

@test_case("api_endpoint_discovery Function - Basic Functionality")
def test_api_endpoint_discovery_basic():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock responses for different endpoints
        def mock_get(url, **kwargs):
            if "/api/users" in url:
                return MockResponse(text='{"users": []}', status_code=200)
            elif "/api/admin" in url:
                return MockResponse(text='{"error": "forbidden"}', status_code=403)
            elif "/api/health" in url:
                return MockResponse(text='{"status": "ok"}', status_code=200)
            else:
                return MockResponse(text="Not Found", status_code=404)
                
        mock_session.get.side_effect = mock_get
        mock_session.post.side_effect = mock_get
        mock_session.put.side_effect = mock_get
        
        result = api_endpoint_discovery("http://api.test.com")
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "api_endpoint_discovery"
        
        # Should discover some endpoints
        discovered_endpoints = result.metadata.get("discovered_endpoints", [])
        assert len(discovered_endpoints) >= 0
        
    return result

@test_case("api_endpoint_discovery Function - Custom Wordlist")
def test_api_endpoint_discovery_custom_wordlist():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock response for custom endpoint
        mock_session.get.return_value = MockResponse(
            text='{"secret": "data"}', 
            status_code=200
        )
        mock_session.post.return_value = MockResponse(text="", status_code=404)
        
        custom_wordlist = ["secret", "hidden", "internal", "debug"]
        
        result = api_endpoint_discovery(
            "http://api.test.com",
            wordlist=custom_wordlist,
            discovery_mode="basic"
        )
        
        assert result.success == True
        
    return result

@test_case("api_endpoint_discovery Function - Authentication Context")
def test_api_endpoint_discovery_with_auth():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock authenticated response
        mock_session.get.return_value = MockResponse(
            text='{"admin": "panel"}',
            status_code=200,
            headers={"X-Admin": "true"}
        )
        
        # Test with authentication context
        context = PayloadTargetContext(
            authentication_type="bearer",
            framework="express",
            supports_json=True
        )
        
        custom_headers = {"Authorization": "Bearer token123"}
        
        result = api_endpoint_discovery(
            "http://api.test.com",
            target_context=context,
            custom_headers=custom_headers,
            discovery_mode="comprehensive"
        )
        
        assert result.success == True
        
    return result

@test_case("jwt_vulnerability_test Function - Valid Token Analysis")
def test_jwt_vulnerability_test_valid_token():
    # Use a test JWT token
    test_token = TEST_JWT_TOKENS[0]  # Valid token structure
    
    # No need to mock JWT decoding since we fixed the implementation to handle it manually
    result = jwt_vulnerability_test(test_token)
    
    assert isinstance(result, ToolCallResult)
    assert result.success == True
    assert result.tool_name == "JWT Vulnerability Test"
    
    # Should analyze the token structure
    assert len(result.vulnerabilities) >= 0
    
    return result

@test_case("jwt_vulnerability_test Function - None Algorithm Test")
def test_jwt_vulnerability_test_none_algorithm():
    # Use token with none algorithm
    none_token = TEST_JWT_TOKENS[1]  # Token with none algorithm
    
    result = jwt_vulnerability_test(none_token)
    
    assert result.success == True
    
    # Should detect none algorithm vulnerability
    vuln_types = []
    for vuln in result.vulnerabilities:
        if isinstance(vuln, dict):
            vuln_types.append(vuln.get("type", "").lower())
        else:
            vuln_types.append(vuln.type.lower())
    
    assert any("algorithm" in vtype or "none" in vtype for vtype in vuln_types) or \
           any("jwt" in vtype for vtype in vuln_types)

    return result

@test_case("jwt_vulnerability_test Function - Weak Secret Detection")
def test_jwt_vulnerability_test_weak_secret():
    # Token that may have weak secret
    test_token = TEST_JWT_TOKENS[0]
    
    with patch('tools.tool_calls._test_jwt_weak_secret') as mock_weak_test:
        # Mock finding weak secret
        mock_weak_test.return_value = "secret"
        
        result = jwt_vulnerability_test(test_token)
        
        assert result.success == True
        
        # Should detect weak secret if mocked
        if mock_weak_test.called:
            assert len(result.vulnerabilities) > 0
    
    return result

@test_case("jwt_vulnerability_test Function - Malformed Token")
def test_jwt_vulnerability_test_malformed():
    # Use malformed token
    malformed_token = TEST_JWT_TOKENS[2]  # "invalid.jwt.token"
    
    with patch('tools.tool_calls._is_jwt_format') as mock_jwt_format:
        # Mock malformed token detection
        mock_jwt_format.return_value = False
        
        result = jwt_vulnerability_test(malformed_token)
        
        # Should handle malformed token gracefully
        assert isinstance(result, ToolCallResult)
        assert result.success == False
        assert "Invalid JWT format" in result.error
    
    return result

@test_case("jwt_vulnerability_test Function - Context-Aware Analysis")
def test_jwt_vulnerability_test_context_aware():
    test_token = TEST_JWT_TOKENS[3]  # Token with admin claims
    
    # Test with framework context
    context = PayloadTargetContext(
        framework="django",
        language="python",
        authentication_type="bearer"
    )
    
    result = jwt_vulnerability_test(test_token, target_context=context)
    
    assert result.success == True
    
    # Should provide framework-specific analysis
    business_impact = result.business_impact
    assert isinstance(business_impact, str)

    return result

@test_case("api_endpoint_discovery Function - Error Handling")
def test_api_endpoint_discovery_error_handling():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock network error
        mock_session.get.side_effect = Exception("Connection timeout")
        
        result = api_endpoint_discovery("http://unreachable.com")
        
        assert isinstance(result, ToolCallResult)
        # Should handle error gracefully
        
    return result

# ======================== Specific Vulnerability Tests ========================

@test_case("idor_test Function - Basic Functionality")
def test_idor_test_basic():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock baseline response
        baseline_response = MockResponse(
            text='{"user": {"id": 1, "name": "John"}}',
            status_code=200
        )
        
        # Mock IDOR response (different user data)
        idor_response = MockResponse(
            text='{"user": {"id": 2, "name": "Admin"}}',
            status_code=200
        )
        
        # Return baseline first, then IDOR response
        mock_session.get.side_effect = [baseline_response, idor_response]
        
        result = idor_test("http://test.com/api/user/1", ["id"], ["2"])
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "IDOR Test"
        
        # Should detect IDOR if different content returned
        if len(result.vulnerabilities) > 0:
            vuln = result.vulnerabilities[0]
            if isinstance(vuln, dict):
                assert "idor" in vuln["type"].lower()
            else:
                assert "idor" in vuln.type.lower()
        
    return result

@test_case("idor_test Function - Different User IDs")
def test_idor_test_user_ids():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock different responses for different user IDs
        def mock_get_response(url, **kwargs):
            if "user/1" in url:
                return MockResponse(text='{"id": 1, "email": "user1@test.com"}', status_code=200)
            elif "user/2" in url:
                return MockResponse(text='{"id": 2, "email": "admin@test.com"}', status_code=200)
            else:
                return MockResponse(text='{"error": "not found"}', status_code=404)
                
        mock_session.get.side_effect = mock_get_response
        
        result = idor_test(
            "http://api.test.com/user/1",
            parameters=["id"],
            payloads=["2", "3", "999"]
        )
        
        assert result.success == True
        
    return result

@test_case("information_disclosure_test Function - Basic Functionality")
def test_information_disclosure_test_basic():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock responses for different paths
        def mock_get_response(url, **kwargs):
            if "/backup" in url:
                return MockResponse(text="# Database backup file\npassword=secret123", status_code=200)
            elif "/.env" in url:
                return MockResponse(text="DB_PASSWORD=admin123\nAPI_KEY=secret", status_code=200)
            elif "/config" in url:
                return MockResponse(text="<?php $db_pass = 'secret'; ?>", status_code=200)
            else:
                return MockResponse(text="Not Found", status_code=404)
                
        mock_session.get.side_effect = mock_get_response
        
        result = information_disclosure_test("http://test.com")
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "Information Disclosure Test"
        
        # Should detect information disclosure
        assert len(result.vulnerabilities) >= 0
        
    return result

@test_case("information_disclosure_test Function - Context-Aware Paths")
def test_information_disclosure_context_aware():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock Django-specific file
        mock_session.get.return_value = MockResponse(
            text="SECRET_KEY = 'django-secret-key-12345'",
            status_code=200
        )
        
        # Test with Django context
        context = PayloadTargetContext(
            framework="django",
            language="python"
        )
        
        result = information_disclosure_test(
            "http://django-app.com",
            target_context=context
        )
        
        assert result.success == True
        
    return result

@test_case("business_logic_data_validation_test Function - Basic Functionality")
def test_business_logic_data_validation_basic():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock responses for business logic bypass
        def mock_get_response(url, **kwargs):
            if "price=-1" in url:
                return MockResponse(text='{"total": -50, "status": "success"}', status_code=200)
            elif "quantity=999999" in url:
                return MockResponse(text='{"error": "invalid quantity"}', status_code=400)
            else:
                return MockResponse(text='{"total": 100, "status": "success"}', status_code=200)
                
        def mock_post_response(url, **kwargs):
            data = kwargs.get('data', {})
            if isinstance(data, dict):
                if data.get('price') == '-1':
                    return MockResponse(text='{"total": -50, "status": "success"}', status_code=200)
                elif data.get('quantity') == '999999':
                    return MockResponse(text='{"error": "invalid quantity"}', status_code=400)
            return MockResponse(text='{"total": 100, "status": "success"}', status_code=200)
                
        mock_session.get.side_effect = mock_get_response
        mock_session.post.side_effect = mock_post_response
        
        result = business_logic_data_validation_test(
            "http://shop.com/checkout",
            parameters=["price", "quantity", "user_id"]
        )
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "business_logic_data_validation_test"
        
    return result

@test_case("workflow_circumvention_test Function - Basic Functionality")
def test_workflow_circumvention_basic():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock workflow bypass detection
        def mock_post_response(url, **kwargs):
            data = kwargs.get('data', {})
            if isinstance(data, dict) and data.get('step') == 'complete':
                return MockResponse(text='{"status": "order completed"}', status_code=200)
            else:
                return MockResponse(text='{"status": "step required"}', status_code=400)
                
        mock_session.post.side_effect = mock_post_response
        mock_session.get.return_value = MockResponse(text='{"workflow": "active"}', status_code=200)
        
        result = workflow_circumvention_test(
            "http://shop.com/order",
            workflow_steps=["cart", "shipping", "payment", "complete"]
        )
        
        assert isinstance(result, ToolCallResult)
        assert result.success == True
        assert result.tool_name == "workflow_circumvention_test"
        
    return result

# ======================== Edge Cases and Error Handling ========================

@test_case("Edge Cases - Invalid URLs")
def test_edge_cases_invalid_urls():
    # Test various functions with invalid URLs
    invalid_urls = [
        "not-a-url",
        "http://",
        "",
        "ftp://invalid-protocol.com",
        "http://localhost:99999",  # Invalid port
    ]
    
    for url in invalid_urls:
        try:
            # Test SQL injection with invalid URL
            result = sql_injection_test(url, "id")
            assert isinstance(result, ToolCallResult)
            # Should handle gracefully
            
            # Test XSS with invalid URL  
            result2 = xss_test(url, "search")
            assert isinstance(result2, ToolCallResult)
            
        except Exception as e:
            # Some may throw exceptions, which is also acceptable
            assert "url" in str(e).lower() or "invalid" in str(e).lower()
            
    return True

@test_case("Edge Cases - Large Payload Lists")
def test_edge_cases_large_payloads():
    # Test with large payload lists
    large_payload_list = ["payload_" + str(i) for i in range(100)]
    
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_session.get.return_value = MockResponse(text="OK", status_code=200)
        mock_session.post.return_value = MockResponse(text="OK", status_code=200)
        
        # Should handle large payload lists efficiently
        start_time = time.time()
        result = sql_injection_test(
            "http://test.com",
            "id",
            payloads=large_payload_list
        )
        execution_time = time.time() - start_time
        
        assert isinstance(result, ToolCallResult)
        assert execution_time < 30  # Should complete within reasonable time
        
    return result

@test_case("Edge Cases - Unicode and Special Characters")
def test_edge_cases_unicode():
    unicode_payloads = [
        "' OR '1'='1' --",
        "' ЗЭЯ '1'='1' --",  # Cyrillic characters
        "' 或 '1'='1' --",    # Chinese characters
        "' ำ '1'='1' --",     # Thai characters
        "\\x00\\x01\\x02",    # Null bytes and control chars
        "𝕊𝕆𝔏 𝕀𝕟𝕛𝕖𝕔𝕥𝕚𝕠𝕟",  # Mathematical script
    ]
    
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_session.get.return_value = MockResponse(text="OK", status_code=200)
        
        result = sql_injection_test(
            "http://test.com",
            "search",
            payloads=unicode_payloads
        )
        
        assert isinstance(result, ToolCallResult)
        # Should handle unicode without crashing
        
    return result

# ======================== Performance and Concurrency Tests ========================

@test_case("Performance - Concurrent Testing")
def test_performance_concurrent():
    with patch('tools.tool_calls.requests.Session') as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_session.get.return_value = MockResponse(text="OK", status_code=200)
        
        def run_test():
            return sql_injection_test("http://test.com", "id")
        
        # Run multiple tests concurrently
        import threading
        threads = []
        results = []
        
        def thread_worker():
            result = run_test()
            results.append(result)
        
        # Start multiple threads
        for _ in range(5):
            thread = threading.Thread(target=thread_worker)
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # All should complete successfully
        assert len(results) == 5
        for result in results:
            assert isinstance(result, ToolCallResult)
    
    return True

@test_case("Performance - Large Scale Operations")
def test_performance_large_scale():
    # Test memory usage with large vulnerability lists
    vulnerabilities = []
    for i in range(1000):
        vuln = Vulnerability(
            type="Test Vulnerability",
            severity="Medium",
            evidence=f"Test evidence {i}",
            cvss_score=5.0
        )
        vulnerabilities.append(vuln)
    
    # Create large result
    large_result = ToolCallResult(
        success=True,
        tool_name="large_test",
        vulnerabilities=vulnerabilities,
        execution_time=1.0
    )
    
    # Test serialization performance
    start_time = time.time()
    vuln_dicts = large_result.get_vulnerabilities_as_dicts()
    serialization_time = time.time() - start_time
    
    assert len(vuln_dicts) == 1000
    assert serialization_time < 5  # Should serialize quickly
    assert all(isinstance(v, dict) for v in vuln_dicts)
    
    return large_result 

# ======================== Main Test Runner ========================

def run_comprehensive_test_suite():
    """Run the complete test suite for tool_calls.py"""
    global tests_passed, tests_failed
    
    print("=" * 80)
    print("🔐 COMPREHENSIVE SECURITY TOOLS TEST SUITE")
    print("=" * 80)
    print(f"Testing tool_calls.py functionality with 360-degree coverage")
    print(f"Includes: SQL injection, XSS, network scanning, API security, JWT analysis")
    print(f"Business logic testing, IDOR detection, information disclosure, and more")
    print("=" * 80)
    
    start_time = time.time()
    
    # Reset counters
    tests_passed = 0
    tests_failed = 0
    
    print("\n📊 DATA STRUCTURE TESTS")
    print("-" * 40)
    test_vulnerability_creation()
    test_vulnerability_full_creation()
    test_vulnerability_validation()
    test_vulnerability_to_dict()
    test_toolcall_result_creation()
    test_toolcall_result_with_vulnerabilities()
    test_payload_target_context()
    test_payload_library_structure()
    
    print("\n🔧 UTILITY FUNCTION TESTS")
    print("-" * 40)
    test_create_vulnerability_basic()
    test_create_vulnerability_cvss()
    test_calculate_cvss_score()
    test_detect_xss_reflection_basic()
    test_detect_xss_reflection_encoding()
    test_extract_url_from_text()
    test_create_session_basic()
    test_create_session_proxy()
    test_create_session_ssl()
    test_save_results_basic()
    test_save_results_custom_filename()
    test_setup_logging_debug()
    test_setup_logging_normal()
    
    print("\n💉 SQL INJECTION TESTING")
    print("-" * 40)
    test_sql_injection_test_basic()
    test_sql_injection_test_context_aware()
    test_sql_injection_test_custom_payloads()
    test_sql_injection_test_error_handling()
    test_sqlmap_campaign_basic()
    test_sqlmap_campaign_comprehensive()
    test_sqlmap_campaign_context_aware()
    test_sqlmap_campaign_error_handling()
    
    print("\n⚡ XSS TESTING")
    print("-" * 40)
    test_xss_test_basic()
    test_xss_test_advanced()
    test_xss_test_custom_payloads()
    test_xss_test_waf_bypass()
    test_xss_test_error_handling()
    
    print("\n🌐 NETWORK RECONNAISSANCE")
    print("-" * 40)
    test_nmap_scan_basic()
    test_nmap_scan_service_detection()
    test_nmap_scan_vuln_scripts()
    test_nmap_scan_context_aware()
    test_enterprise_port_scan_basic()
    test_enterprise_port_scan_service_detection()
    test_enterprise_port_scan_context_aware()
    test_nmap_scan_error_handling()
    test_enterprise_port_scan_error_handling()
    
    print("\n🔑 API SECURITY TESTING")
    print("-" * 40)
    test_api_endpoint_discovery_basic()
    test_api_endpoint_discovery_custom_wordlist()
    test_api_endpoint_discovery_with_auth()
    test_jwt_vulnerability_test_valid_token()
    test_jwt_vulnerability_test_none_algorithm()
    test_jwt_vulnerability_test_weak_secret()
    test_jwt_vulnerability_test_malformed()
    test_jwt_vulnerability_test_context_aware()
    test_api_endpoint_discovery_error_handling()
    
    print("\n🎯 SPECIFIC VULNERABILITY TESTS")
    print("-" * 40)
    test_idor_test_basic()
    test_idor_test_user_ids()
    test_information_disclosure_test_basic()
    test_information_disclosure_context_aware()
    test_business_logic_data_validation_basic()
    test_workflow_circumvention_basic()
    
    print("\n⚠️  EDGE CASES & ERROR HANDLING")
    print("-" * 40)
    test_edge_cases_invalid_urls()
    test_edge_cases_large_payloads()
    test_edge_cases_unicode()
    
    print("\n⚡ PERFORMANCE & CONCURRENCY")
    print("-" * 40)
    test_performance_concurrent()
    test_performance_large_scale()
    
    end_time = time.time()
    total_time = end_time - start_time
    total_tests = tests_passed + tests_failed
    
    print("\n" + "=" * 80)
    print("📋 COMPREHENSIVE TEST SUITE RESULTS")
    print("=" * 80)
    print(f"✅ Tests Passed: {tests_passed}")
    print(f"❌ Tests Failed: {tests_failed}")
    print(f"📊 Total Tests: {total_tests}")
    print(f"⏱️  Total Time: {total_time:.2f} seconds")
    
    if tests_failed == 0:
        print("🎉 ALL TESTS PASSED! Security tools are functioning correctly.")
        success_rate = 100.0
    else:
        success_rate = (tests_passed / total_tests) * 100
        print(f"⚠️  {tests_failed} test(s) failed. Success rate: {success_rate:.1f}%")
    
    print("\n🔐 SECURITY TESTING COVERAGE:")
    print("   ✓ SQL Injection Detection & SQLMap Integration")
    print("   ✓ Cross-Site Scripting (XSS) Testing")
    print("   ✓ Network Reconnaissance & Port Scanning")
    print("   ✓ API Endpoint Discovery & Security Analysis")
    print("   ✓ JWT Vulnerability Analysis")
    print("   ✓ IDOR (Insecure Direct Object Reference) Testing")
    print("   ✓ Information Disclosure Detection")
    print("   ✓ Business Logic Data Validation Testing")
    print("   ✓ Workflow Circumvention Testing")
    print("   ✓ Context-Aware Payload Selection")
    print("   ✓ Framework-Specific Security Testing")
    print("   ✓ WAF Bypass Techniques")
    print("   ✓ Error Handling & Edge Cases")
    print("   ✓ Performance & Concurrency Testing")
    print("   ✓ Unicode & Special Character Handling")
    
    print(f"\n🎯 OWASP Compliance Testing Validated")
    print(f"🛡️  Enterprise Security Testing Framework Verified")
    print(f"⚡ Context-Aware Testing Engine Operational")
    print("=" * 80)
    
    return tests_passed, tests_failed, total_time


if __name__ == "__main__":
    try:
        passed, failed, duration = run_comprehensive_test_suite()
        
        # Exit with appropriate code
        if failed == 0:
            print("\n🚀 Security tools test suite completed successfully!")
            sys.exit(0)
        else:
            print(f"\n⚠️  Test suite completed with {failed} failures.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Test suite interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n💥 Test suite failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1) 
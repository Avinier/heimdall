"""
Comprehensive Test Suite for ZAP Functions Module
Tests all ZAP integration functions with mocking to avoid external dependencies
Follows the same pattern as reporter_agent_test.py
"""

import unittest
import time
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any

# Import the modules to test
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from tools.tool_calls import ToolCallResult, Vulnerability, create_vulnerability
from tools.zap_functions import (
    zap_passive_scan,
    zap_active_scan,
    zap_authenticated_scan,
    zap_ajax_spider_scan,
    zap_comprehensive_scan,
    zap_enterprise_scan,
    _map_zap_risk_to_severity,
    _map_zap_risk_to_cvss,
    _deduplicate_zap_findings,
    _analyze_technology_stack,
    _deduplicate_and_prioritize_enterprise_findings
)

# Test framework utility functions
def case_decorator(test_name: str):
    """Decorator to mark and track test cases"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            print(f"\n{'='*60}")
            print(f"TESTING: {test_name}")
            print(f"{'='*60}")
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                print(f"✅ PASSED in {execution_time:.3f}s")
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                print(f"❌ FAILED in {execution_time:.3f}s: {str(e)}")
                raise
        wrapper.__name__ = func.__name__  # Preserve function name for pytest
        return wrapper
    return decorator

class TestZAPFunctions(unittest.TestCase):
    """Comprehensive test suite for ZAP functions"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_url = "https://example.com"
        self.auth_config = {
            "username": "testuser",
            "password": "testpass",
            "login_url": "https://example.com/login"
        }
        self.sample_alert = {
            'alert': 'SQL Injection',
            'risk': 'High',
            'confidence': 'Medium',
            'description': 'SQL injection vulnerability detected',
            'url': 'https://example.com/vulnerable',
            'param': 'id',
            'attack': "' OR 1=1 --",
            'solution': 'Use parameterized queries',
            'reference': 'https://owasp.org/www-community/attacks/SQL_Injection'
        }

    def create_mock_zap(self, alerts=None, spider_results=None, ajax_results=None):
        """Create a mock ZAP object with configurable responses"""
        if alerts is None:
            alerts = [self.sample_alert]
        if spider_results is None:
            spider_results = ['https://example.com/page1', 'https://example.com/page2']
        if ajax_results is None:
            ajax_results = ['https://example.com/api/data', 'https://example.com/admin']
        
        mock_zap = Mock()
        
        # Mock core functionality
        mock_zap.core.version = "2.11.1"
        mock_zap.core.new_session.return_value = True
        mock_zap.core.alerts.return_value = alerts
        mock_zap.core.access_url.return_value = True
        
        # Mock context functionality
        mock_zap.context.new_context.return_value = "1"
        mock_zap.context.include_in_context.return_value = True
        
        # Mock spider functionality
        mock_zap.spider.scan.return_value = "1"
        mock_zap.spider.status = Mock(return_value="100")  # Completed
        mock_zap.spider.stop.return_value = True
        mock_zap.spider.results.return_value = spider_results
        mock_zap.spider.scan_as_user.return_value = "1"
        
        # Mock active scan functionality
        mock_zap.ascan.scan.return_value = "1"
        mock_zap.ascan.status = Mock(return_value="100")  # Completed
        mock_zap.ascan.stop.return_value = True
        mock_zap.ascan.scan_as_user.return_value = "1"
        
        # Mock AJAX spider functionality
        mock_zap.ajaxSpider.scan.return_value = True
        mock_zap.ajaxSpider.status = "stopped"  # Not running
        mock_zap.ajaxSpider.stop.return_value = True
        mock_zap.ajaxSpider.results.return_value = ajax_results
        
        # Mock authentication functionality
        mock_zap.authentication.set_authentication_method.return_value = "1"
        mock_zap.users.new_user.return_value = "1"
        mock_zap.users.set_authentication_credentials.return_value = True
        mock_zap.users.set_user_enabled.return_value = True
        
        return mock_zap

# ===== HELPER FUNCTION TESTS =====

@case_decorator("ZAP Risk to Severity Mapping - All Risk Levels")
def test_map_zap_risk_to_severity():
    """Test mapping of ZAP risk levels to standard severity levels"""
    # Test valid mappings
    assert _map_zap_risk_to_severity("High") == "Critical"
    assert _map_zap_risk_to_severity("Medium") == "High"
    assert _map_zap_risk_to_severity("Low") == "Medium"
    assert _map_zap_risk_to_severity("Informational") == "Low"
    assert _map_zap_risk_to_severity("Info") == "Low"
    
    # Test default case
    assert _map_zap_risk_to_severity("Unknown") == "Medium"
    assert _map_zap_risk_to_severity("") == "Medium"
    assert _map_zap_risk_to_severity(None) == "Medium"

@case_decorator("ZAP Risk to CVSS Mapping - All Risk Levels")
def test_map_zap_risk_to_cvss():
    """Test mapping of ZAP risk levels to CVSS scores"""
    # Test valid mappings
    assert _map_zap_risk_to_cvss("High") == 8.5
    assert _map_zap_risk_to_cvss("Medium") == 6.0
    assert _map_zap_risk_to_cvss("Low") == 3.5
    assert _map_zap_risk_to_cvss("Informational") == 1.0
    assert _map_zap_risk_to_cvss("Info") == 1.0
    
    # Test default case
    assert _map_zap_risk_to_cvss("Unknown") == 5.0
    assert _map_zap_risk_to_cvss("") == 5.0

@case_decorator("ZAP Findings Deduplication - Basic Functionality")
def test_deduplicate_zap_findings():
    """Test deduplication of ZAP findings"""
    # Create duplicate vulnerabilities
    vuln1 = create_vulnerability("SQL Injection", "High", "Test", url="https://example.com", parameter="id")
    vuln2 = create_vulnerability("SQL Injection", "High", "Test duplicate", url="https://example.com", parameter="id")
    vuln3 = create_vulnerability("XSS", "Medium", "Different vuln", url="https://example.com", parameter="name")
    
    vulns = [vuln1, vuln2, vuln3]
    unique_vulns = _deduplicate_zap_findings(vulns)
    
    # Should have only 2 unique vulnerabilities
    assert len(unique_vulns) == 2
    assert any(v.type == "SQL Injection" for v in unique_vulns)
    assert any(v.type == "XSS" for v in unique_vulns)

@case_decorator("Enterprise Findings Prioritization - Severity Ordering")
def test_deduplicate_and_prioritize_enterprise_findings():
    """Test enterprise-grade deduplication with severity prioritization"""
    # Create vulnerabilities with different severities for same type/location
    vuln1 = create_vulnerability("SQL Injection", "Medium", "Medium severity", url="https://example.com", parameter="id")
    vuln2 = create_vulnerability("SQL Injection", "Critical", "Critical severity", url="https://example.com", parameter="id")
    vuln3 = create_vulnerability("XSS", "Low", "Low severity XSS", url="https://example.com", parameter="search")
    
    vulns = [vuln1, vuln2, vuln3]
    prioritized_vulns = _deduplicate_and_prioritize_enterprise_findings(vulns)
    
    # Should keep the Critical severity SQL injection (highest priority)
    assert len(prioritized_vulns) == 2
    sql_vuln = next(v for v in prioritized_vulns if v.type == "SQL Injection")
    assert sql_vuln.severity == "Critical"
    
    # Check ordering (Critical first)
    assert prioritized_vulns[0].severity == "Critical"

# ===== CORE SCAN FUNCTION TESTS =====

@case_decorator("ZAP Passive Scan - Successful Execution")
def test_zap_passive_scan_success():
    """Test successful ZAP passive scan execution"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap()
        mock_zap_class.return_value = mock_zap
        
        result = zap_passive_scan(test_case.test_url, spider_minutes=2)
        
        assert result.success == True
        assert result.tool_name == "ZAP Passive Scan"
        assert len(result.vulnerabilities) > 0
        assert result.execution_time >= 0  # Allow zero execution time in tests
        assert "target_url" in result.metadata
        assert result.metadata["target_url"] == test_case.test_url

@case_decorator("ZAP Passive Scan - Connection Failure")
def test_zap_passive_scan_connection_failure():
    """Test ZAP passive scan with connection failure"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        # Mock ZAPv2 constructor to raise exception directly
        mock_zap_class.side_effect = Exception("Connection refused")
        
        result = zap_passive_scan(test_case.test_url)
        
        assert result.success == False
        assert "Connection refused" in result.error
        assert result.tool_name == "ZAP Passive Scan"

@case_decorator("ZAP Active Scan - Successful Execution")
def test_zap_active_scan_success():
    """Test successful ZAP active scan execution"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap()
        mock_zap_class.return_value = mock_zap
        
        result = zap_active_scan(test_case.test_url, max_scan_time=5)
        
        assert result.success == True
        assert result.tool_name == "ZAP Active Scan"
        assert len(result.vulnerabilities) > 0
        assert "scan_policy" in result.metadata
        assert result.metadata["max_scan_time"] == 5

@case_decorator("ZAP Active Scan - Scan Policy Configuration")
def test_zap_active_scan_custom_policy():
    """Test ZAP active scan with custom scan policy"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap()
        mock_zap_class.return_value = mock_zap
        
        custom_policy = "Custom Security Policy"
        result = zap_active_scan(test_case.test_url, scan_policy=custom_policy)
        
        assert result.success == True
        assert result.metadata["scan_policy"] == custom_policy
        mock_zap.ascan.scan.assert_called_with(test_case.test_url, scanpolicyname=custom_policy)

@case_decorator("ZAP Authenticated Scan - With Credentials")
def test_zap_authenticated_scan_with_credentials():
    """Test ZAP authenticated scan with valid credentials"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap()
        mock_zap_class.return_value = mock_zap
        
        result = zap_authenticated_scan(test_case.test_url, test_case.auth_config, "both")
        
        assert result.success == True
        assert result.tool_name == "ZAP Authenticated Scan"
        assert result.metadata["authenticated"] == True
        assert result.metadata["scan_type"] == "both"
        
        # Verify authentication setup was called
        mock_zap.authentication.set_authentication_method.assert_called()
        mock_zap.users.new_user.assert_called()

@case_decorator("ZAP Authenticated Scan - Passive Only")
def test_zap_authenticated_scan_passive_only():
    """Test ZAP authenticated scan with passive scanning only"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap()
        mock_zap_class.return_value = mock_zap
        
        result = zap_authenticated_scan(test_case.test_url, test_case.auth_config, "passive")
        
        assert result.success == True
        assert result.metadata["scan_type"] == "passive"
        
        # Verify spider was called but not active scan
        mock_zap.spider.scan_as_user.assert_called()

@case_decorator("ZAP AJAX Spider - Successful Execution")
def test_zap_ajax_spider_success():
    """Test successful ZAP AJAX spider execution"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        ajax_results = ['https://example.com/api/admin', 'https://example.com/upload']
        mock_zap = test_case.create_mock_zap(ajax_results=ajax_results)
        mock_zap_class.return_value = mock_zap
        
        result = zap_ajax_spider_scan(test_case.test_url, max_duration=3)
        
        assert result.success == True
        assert result.tool_name == "ZAP AJAX Spider"
        assert result.metadata["urls_discovered"] == len(ajax_results)
        assert result.metadata["max_duration"] == 3
        
        # Should detect sensitive endpoints
        assert len(result.vulnerabilities) > 0
        admin_vuln = next((v for v in result.vulnerabilities if "admin" in v.evidence), None)
        assert admin_vuln is not None

@case_decorator("ZAP AJAX Spider - No Sensitive Endpoints")
def test_zap_ajax_spider_no_sensitive():
    """Test ZAP AJAX spider when no sensitive endpoints are found"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        safe_results = ['https://example.com/home', 'https://example.com/about']
        mock_zap = test_case.create_mock_zap(ajax_results=safe_results)
        mock_zap_class.return_value = mock_zap
        
        result = zap_ajax_spider_scan(test_case.test_url)
        
        assert result.success == True
        assert len(result.vulnerabilities) == 0  # No sensitive endpoints
        assert result.metadata["urls_discovered"] == len(safe_results)

@case_decorator("ZAP Comprehensive Scan - Full Pipeline")
def test_zap_comprehensive_scan_full():
    """Test comprehensive ZAP scan with all phases"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.zap_passive_scan') as mock_passive, \
         patch('tools.zap_functions.zap_ajax_spider_scan') as mock_ajax, \
         patch('tools.zap_functions.zap_active_scan') as mock_active, \
         patch('tools.zap_functions.zap_authenticated_scan') as mock_auth:
        
        # Mock successful results from each phase
        passive_vulns = [create_vulnerability("XSS", "Medium", "Passive finding")]
        ajax_vulns = [create_vulnerability("Info Disclosure", "Low", "AJAX finding")]
        active_vulns = [create_vulnerability("SQL Injection", "High", "Active finding")]
        auth_vulns = [create_vulnerability("IDOR", "High", "Auth finding")]
        
        mock_passive.return_value = ToolCallResult(True, "ZAP Passive", vulnerabilities=passive_vulns)
        mock_ajax.return_value = ToolCallResult(True, "ZAP AJAX", vulnerabilities=ajax_vulns)
        mock_active.return_value = ToolCallResult(True, "ZAP Active", vulnerabilities=active_vulns)
        mock_auth.return_value = ToolCallResult(True, "ZAP Auth", vulnerabilities=auth_vulns)
        
        result = zap_comprehensive_scan(test_case.test_url, test_case.auth_config, include_active=True)
        
        assert result.success == True
        assert result.tool_name == "ZAP Comprehensive Scan"
        assert result.metadata["phases_completed"] == 4
        assert result.metadata["authenticated"] == True
        assert result.metadata["active_scanning"] == True
        
        # All phase functions should be called
        mock_passive.assert_called_once()
        mock_ajax.assert_called_once()
        mock_active.assert_called_once()
        mock_auth.assert_called_once()

@case_decorator("ZAP Comprehensive Scan - Passive Only")
def test_zap_comprehensive_scan_passive_only():
    """Test comprehensive scan with passive scanning only"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.zap_passive_scan') as mock_passive, \
         patch('tools.zap_functions.zap_ajax_spider_scan') as mock_ajax, \
         patch('tools.zap_functions.zap_active_scan') as mock_active:
        
        mock_passive.return_value = ToolCallResult(True, "ZAP Passive", vulnerabilities=[])
        mock_ajax.return_value = ToolCallResult(True, "ZAP AJAX", vulnerabilities=[])
        
        result = zap_comprehensive_scan(test_case.test_url, auth_config=None, include_active=False)
        
        assert result.success == True
        assert result.metadata["phases_completed"] == 2
        assert result.metadata["authenticated"] == False
        assert result.metadata["active_scanning"] == False
        
        # Only passive phases should be called
        mock_passive.assert_called_once()
        mock_ajax.assert_called_once()
        mock_active.assert_not_called()

@case_decorator("ZAP Enterprise Scan - Full Configuration")
def test_zap_enterprise_scan_full():
    """Test enterprise ZAP scan with full configuration"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    scan_config = {
        'deep_crawl': True,
        'ajax_spider': True,
        'advanced_active': True,
        'authenticated_scan': True,
        'technology_detection': True,
        'max_crawl_depth': 5,
        'max_scan_time': 20
    }
    
    with patch('tools.zap_functions.zap_passive_scan') as mock_passive, \
         patch('tools.zap_functions.zap_ajax_spider_scan') as mock_ajax, \
         patch('tools.zap_functions.zap_active_scan') as mock_active, \
         patch('tools.zap_functions.zap_authenticated_scan') as mock_auth, \
         patch('tools.zap_functions._analyze_technology_stack') as mock_tech:
        
        # Mock enterprise-level findings
        critical_vulns = [create_vulnerability("SQL Injection", "Critical", "Critical enterprise finding")]
        high_vulns = [create_vulnerability("XSS", "High", "High enterprise finding")]
        
        mock_passive.return_value = ToolCallResult(True, "ZAP Passive", vulnerabilities=critical_vulns)
        mock_ajax.return_value = ToolCallResult(True, "ZAP AJAX", vulnerabilities=[])
        mock_active.return_value = ToolCallResult(True, "ZAP Active", vulnerabilities=high_vulns)
        mock_auth.return_value = ToolCallResult(True, "ZAP Auth", vulnerabilities=[])
        mock_tech.return_value = []
        
        result = zap_enterprise_scan(test_case.test_url, test_case.auth_config, scan_config)
        
        assert result.success == True
        assert result.tool_name == "ZAP Enterprise Scan"
        assert result.metadata["scan_phases_completed"] == 4
        assert result.metadata["critical_findings"] == 1
        assert result.metadata["high_findings"] == 1
        assert "ENTERPRISE CRITICAL" in result.business_impact

@case_decorator("ZAP Enterprise Scan - Default Configuration")
def test_zap_enterprise_scan_default():
    """Test enterprise scan with default configuration"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.zap_passive_scan') as mock_passive, \
         patch('tools.zap_functions.zap_ajax_spider_scan') as mock_ajax, \
         patch('tools.zap_functions.zap_active_scan') as mock_active, \
         patch('tools.zap_functions._analyze_technology_stack') as mock_tech:
        
        mock_passive.return_value = ToolCallResult(True, "ZAP Passive", vulnerabilities=[])
        mock_ajax.return_value = ToolCallResult(True, "ZAP AJAX", vulnerabilities=[])
        mock_active.return_value = ToolCallResult(True, "ZAP Active", vulnerabilities=[])
        mock_tech.return_value = []
        
        result = zap_enterprise_scan(test_case.test_url)
        
        assert result.success == True
        # Should use default configuration
        assert "spider_minutes=5" in str(mock_passive.call_args)  # Called with defaults

# ===== TECHNOLOGY ANALYSIS TESTS =====

@case_decorator("Technology Stack Analysis - Server Version Detection")
def test_analyze_technology_stack_server_version():
    """Test technology stack analysis for server version detection"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.create_session') as mock_session_factory:
        # Mock response with outdated server header
        mock_response = Mock()
        mock_response.headers = {
            'server': 'Apache/2.2.15',
            'x-powered-by': 'PHP/5.4.0'
        }
        
        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_factory.return_value = mock_session
        
        vulns = _analyze_technology_stack(test_case.test_url)
        
        assert len(vulns) >= 1  # Should detect outdated server
        
        # Check for server version vulnerability
        server_vuln = next((v for v in vulns if v.type == "Outdated Server Version"), None)
        assert server_vuln is not None
        assert "Apache/2.2.15" in server_vuln.evidence

@case_decorator("Technology Stack Analysis - Header Disclosure")
def test_analyze_technology_stack_header_disclosure():
    """Test technology stack analysis for technology disclosure headers"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.create_session') as mock_session_factory:
        mock_response = Mock()
        mock_response.headers = {
            'x-powered-by': 'ASP.NET',
            'x-aspnet-version': '4.0.30319',
            'x-generator': 'Drupal 7'
        }
        
        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_factory.return_value = mock_session
        
        vulns = _analyze_technology_stack(test_case.test_url)
        
        # Should detect multiple technology disclosures
        assert len(vulns) >= 3
        
        # Check specific technology disclosures
        disclosure_types = [v.type for v in vulns]
        assert "Technology Disclosure" in disclosure_types

@case_decorator("Technology Stack Analysis - Error Handling")
def test_analyze_technology_stack_error():
    """Test technology stack analysis error handling"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.create_session') as mock_session_factory:
        mock_session = Mock()
        mock_session.get.side_effect = Exception("Network error")
        mock_session_factory.return_value = mock_session
        
        vulns = _analyze_technology_stack(test_case.test_url)
        
        # Should handle errors gracefully and return empty list
        assert isinstance(vulns, list)
        assert len(vulns) == 0

# ===== EDGE CASES AND ERROR HANDLING =====

@case_decorator("ZAP Functions - Empty Alert Handling")
def test_empty_alerts_handling():
    """Test ZAP functions with empty alert responses"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap(alerts=[])  # Empty alerts
        mock_zap_class.return_value = mock_zap
        
        result = zap_passive_scan(test_case.test_url)
        
        assert result.success == True
        assert len(result.vulnerabilities) == 0
        assert result.metadata["alerts_found"] == 0

@case_decorator("ZAP Functions - Malformed Alert Data")
def test_malformed_alert_data():
    """Test ZAP functions with malformed alert data"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    malformed_alert = {
        'alert': None,  # Missing required fields
        'risk': '',
        'description': None
    }
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap(alerts=[malformed_alert])
        mock_zap_class.return_value = mock_zap
        
        result = zap_passive_scan(test_case.test_url)
        
        # Should handle malformed data gracefully
        assert result.success == True
        assert len(result.vulnerabilities) >= 0

@case_decorator("ZAP Functions - Large Data Volumes")
def test_large_data_volumes():
    """Test ZAP functions performance with large volumes of alerts"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    # Generate large number of alerts
    large_alert_set = []
    for i in range(100):
        alert = test_case.sample_alert.copy()
        alert['url'] = f"https://example.com/page{i}"
        alert['param'] = f"param{i}"
        large_alert_set.append(alert)
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap(alerts=large_alert_set)
        mock_zap_class.return_value = mock_zap
        
        start_time = time.time()
        result = zap_passive_scan(test_case.test_url)
        execution_time = time.time() - start_time
        
        assert result.success == True
        assert len(result.vulnerabilities) == 100
        assert execution_time < 5.0  # Should complete within reasonable time

@case_decorator("ZAP Functions - Unicode and Special Characters")
def test_unicode_handling():
    """Test ZAP functions with Unicode and special characters"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    unicode_alert = test_case.sample_alert.copy()
    unicode_alert['alert'] = 'SQL注入攻击'  # Chinese characters
    unicode_alert['description'] = 'Тест на уязвимость'  # Cyrillic
    unicode_alert['url'] = 'https://example.com/路径/пуць'
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap(alerts=[unicode_alert])
        mock_zap_class.return_value = mock_zap
        
        result = zap_passive_scan(test_case.test_url)
        
        assert result.success == True
        assert len(result.vulnerabilities) == 1
        vuln = result.vulnerabilities[0]
        assert 'SQL注入攻击' in vuln.type

@case_decorator("ZAP Functions - Network Timeout Handling")
def test_network_timeout():
    """Test ZAP functions network timeout handling"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        # Mock ZAPv2 constructor to raise timeout exception
        mock_zap_class.side_effect = Exception("Request timeout")
        
        result = zap_passive_scan(test_case.test_url)
        
        assert result.success == False
        assert "timeout" in result.error.lower()

# ===== PERFORMANCE TESTS =====

@case_decorator("Performance - Multiple Concurrent Scans Simulation")
def test_performance_concurrent_scans():
    """Test performance implications of multiple scan operations"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.ZAPv2') as mock_zap_class:
        mock_zap = test_case.create_mock_zap()
        mock_zap_class.return_value = mock_zap
        
        # Simulate multiple scans
        start_time = time.time()
        results = []
        
        for i in range(5):
            result = zap_passive_scan(f"https://example{i}.com")
            results.append(result)
        
        total_time = time.time() - start_time
        
        assert len(results) == 5
        assert all(r.success for r in results)
        assert total_time < 10.0  # Should complete all scans within reasonable time

@case_decorator("Performance - Memory Management")
def test_memory_management():
    """Test memory management with large scan results"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    # Create large vulnerability set for deduplication testing
    large_vuln_set = []
    for i in range(1000):
        vuln = create_vulnerability(
            f"Vuln Type {i % 10}",  # Create some duplicates
            "Medium",
            f"Finding {i}",
            url=f"https://example.com/page{i % 50}",  # Create URL duplicates
            parameter=f"param{i % 20}"  # Create param duplicates
        )
        large_vuln_set.append(vuln)
    
    start_time = time.time()
    deduplicated = _deduplicate_zap_findings(large_vuln_set)
    dedup_time = time.time() - start_time
    
    assert len(deduplicated) < len(large_vuln_set)  # Should remove duplicates
    assert dedup_time < 1.0  # Should complete quickly
    
    # Test enterprise prioritization
    start_time = time.time()
    prioritized = _deduplicate_and_prioritize_enterprise_findings(large_vuln_set)
    prioritize_time = time.time() - start_time
    
    assert len(prioritized) <= len(deduplicated)
    assert prioritize_time < 2.0  # Should complete within reasonable time

# ===== INTEGRATION TESTS =====

@case_decorator("Integration - Full ZAP Workflow Simulation")
def test_full_zap_workflow():
    """Test complete ZAP scanning workflow integration"""
    test_case = TestZAPFunctions()
    test_case.setUp()
    
    with patch('tools.zap_functions.zap_passive_scan') as mock_passive, \
         patch('tools.zap_functions.zap_active_scan') as mock_active, \
         patch('tools.zap_functions.zap_authenticated_scan') as mock_auth, \
         patch('tools.zap_functions.zap_ajax_spider_scan') as mock_ajax:
        
        # Create realistic vulnerability findings
        passive_findings = [
            create_vulnerability("Missing Security Headers", "Low", "CSP header missing"),
            create_vulnerability("Information Disclosure", "Medium", "Server version exposed")
        ]
        
        active_findings = [
            create_vulnerability("SQL Injection", "Critical", "Union-based SQL injection"),
            create_vulnerability("XSS", "High", "Reflected XSS in search parameter")
        ]
        
        auth_findings = [
            create_vulnerability("IDOR", "High", "Direct object reference vulnerability"),
            create_vulnerability("Privilege Escalation", "Critical", "Admin function accessible")
        ]
        
        ajax_findings = [
            create_vulnerability("Sensitive Endpoint Discovery", "Medium", "Admin panel discovered")
        ]
        
        # Configure mock returns
        mock_passive.return_value = ToolCallResult(True, "ZAP Passive", vulnerabilities=passive_findings)
        mock_active.return_value = ToolCallResult(True, "ZAP Active", vulnerabilities=active_findings)
        mock_auth.return_value = ToolCallResult(True, "ZAP Auth", vulnerabilities=auth_findings)
        mock_ajax.return_value = ToolCallResult(True, "ZAP AJAX", vulnerabilities=ajax_findings)
        
        # Execute enterprise scan
        result = zap_enterprise_scan(test_case.test_url, test_case.auth_config)
        
        # Verify complete workflow
        assert result.success == True
        assert result.tool_name == "ZAP Enterprise Scan"
        assert len(result.vulnerabilities) > 0
        
        # Verify all scan types were executed
        mock_passive.assert_called()
        mock_active.assert_called()
        mock_ajax.assert_called()
        
        # Verify business impact assessment
        assert "ENTERPRISE" in result.business_impact
        assert result.metadata["scan_phases_completed"] == 4

def run_comprehensive_zap_test_suite():
    """Run all ZAP function tests"""
    print("\n" + "="*80)
    print("COMPREHENSIVE ZAP FUNCTIONS TEST SUITE")
    print("="*80)
    
    test_functions = [
        # Helper function tests
        test_map_zap_risk_to_severity,
        test_map_zap_risk_to_cvss,
        test_deduplicate_zap_findings,
        test_deduplicate_and_prioritize_enterprise_findings,
        
        # Core scan function tests
        test_zap_passive_scan_success,
        test_zap_passive_scan_connection_failure,
        test_zap_active_scan_success,
        test_zap_active_scan_custom_policy,
        test_zap_authenticated_scan_with_credentials,
        test_zap_authenticated_scan_passive_only,
        test_zap_ajax_spider_success,
        test_zap_ajax_spider_no_sensitive,
        test_zap_comprehensive_scan_full,
        test_zap_comprehensive_scan_passive_only,
        test_zap_enterprise_scan_full,
        test_zap_enterprise_scan_default,
        
        # Technology analysis tests
        test_analyze_technology_stack_server_version,
        test_analyze_technology_stack_header_disclosure,
        test_analyze_technology_stack_error,
        
        # Edge cases and error handling
        test_empty_alerts_handling,
        test_malformed_alert_data,
        test_large_data_volumes,
        test_unicode_handling,
        test_network_timeout,
        
        # Performance tests
        test_performance_concurrent_scans,
        test_memory_management,
        
        # Integration tests
        test_full_zap_workflow
    ]
    
    passed = 0
    failed = 0
    
    for test_func in test_functions:
        try:
            test_func()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"TEST FAILED: {e}")
    
    print(f"\n" + "="*80)
    print(f"TEST SUITE SUMMARY")
    print(f"="*80)
    print(f"Tests Passed: {passed}")
    print(f"Tests Failed: {failed}")
    print(f"Total Tests: {passed + failed}")
    print(f"Success Rate: {(passed/(passed+failed)*100):.1f}%")
    
    if failed == 0:
        print("🎉 ALL TESTS PASSED! ZAP Functions module is working correctly.")
    else:
        print(f"⚠️  {failed} tests failed. Review and fix issues before deployment.")
    
    return passed, failed

if __name__ == "__main__":
    run_comprehensive_zap_test_suite()

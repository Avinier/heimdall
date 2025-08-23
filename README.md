# Project Heimdall - Comprehensive Penetration Testing System

## Overview

Project Heimdall is a sophisticated, AI-powered penetration testing framework that integrates multiple security tools and automates vulnerability assessment through intelligent test plan generation and execution.

## 🏗️ Architecture of the system

```
┌─────────────────────────────────────────────────────────┐
│                Project Heimdall                         │
│                                                         │
│  ┌─────────────┐    ┌──────────────────────────────────┐ │
│  │ PlannerAgent│───▶│        ToolCall System           │ │
│  │             │    │                                  │ │
│  │ • Gemini LLM│    │ ┌─────────────┐ ┌──────────────┐ │ │
│  │ • OWASP     │    │ │   Security  │ │   Browser    │ │ │
│  │   Based     │    │ │    Tools    │ │  Automation  │ │ │
│  │ • YAML      │    │ │             │ │              │ │ │
│  │   Parsing   │    │ │ • SQLMap    │ │ • Playwright │ │ │
│  │             │    │ │ • Nmap      │ │ • Dynamic    │ │ │
│  └─────────────┘    │ │ • Nikto     │ │   Testing    │ │ │
│                     │ │ • OWASP ZAP │ │ • Form       │ │ │
│                     │ │ • Hydra     │ │   Automation │ │ │
│                     │ │ • Gobuster  │ │              │ │ │
│                     │ └─────────────┘ └──────────────┘ │ │
│                     └──────────────────────────────────┘ │
│                                   │                      │
│                     ┌─────────────▼──────────────────────┐ │
│                     │      Vulnerability Report         │ │
│                     │ • Severity Classification         │ │
│                     │ • Tool Performance Metrics       │ │
│                     │ • Recommendations                 │ │
│                     │ • JSON Export                     │ │
│                     └───────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## 🧠 Core Components

### 1. PlannerAgent (`agents/planner.py`)

**Purpose**: AI-powered security test plan generation using Google's Gemini 2.0-flash model.

**Key Features**:

- **LLM-Powered Analysis**: Uses Gemini 2.0-flash for intelligent security assessment planning
- **OWASP-Based Methodology**: Follows industry-standard vulnerability testing frameworks
- **YAML Parsing**: Structured plan extraction with fallback mechanisms
- **Comprehensive Input Analysis**: Processes HTML, forms, APIs, headers, and reconnaissance data

**System Prompt Capabilities**:

```yaml
Security Testing Areas:
  - Authentication & Session Management
  - Input Validation (SQL Injection, XSS, Command Injection)
  - Authorization & Access Control (IDOR, Privilege Escalation)
  - Business Logic Vulnerabilities
  - Information Disclosure
  - File Upload Security
  - API Security Testing
  - Network Infrastructure Assessment
```

**Example Generated Plan**:

```json
{
  "title": "SQL Injection via Authentication Bypass",
  "description": "Test the /auth/login endpoint for SQL injection vulnerabilities using various payloads including union-based, boolean-based, and time-based techniques. Focus on username and password parameters with payloads like ' OR '1'='1' -- and UNION SELECT statements."
}
```

### 2. ToolCall System (`tools/tool_calls.py`)

**Purpose**: Automated execution of penetration testing tools based on generated test plans.

**Architecture**:

- **1000+ line implementation** with comprehensive tool integration
- **Intelligent Tool Selection**: Maps test plan keywords to appropriate security tools
- **Concurrent Execution**: Async/await patterns for performance
- **Error Handling**: Robust timeout and failure management
- **Results Aggregation**: Structured vulnerability reporting

#### Supported Security Tools

| Category                  | Tools                        | Purpose                                            |
| ------------------------- | ---------------------------- | -------------------------------------------------- |
| **SQL Injection**         | SQLMap                       | Automated SQL injection detection and exploitation |
| **XSS Testing**           | XSStrike, Browser Automation | Cross-site scripting vulnerability detection       |
| **Network Scanning**      | Nmap, Masscan                | Port scanning and service enumeration              |
| **Web Scanning**          | Nikto, OWASP ZAP             | Web server vulnerability scanning                  |
| **Directory Enumeration** | Gobuster, FFUF, DIRB         | Hidden directory and file discovery                |
| **Authentication**        | Hydra, Custom Scripts        | Brute force and authentication bypass testing      |
| **Browser Automation**    | Playwright                   | Dynamic testing and manual verification            |

#### Tool Selection Logic

```python
# Intelligent mapping based on plan keywords
if 'sql injection' in plan_description:
    → Execute SQLMap + Browser automation + ZAP SQL scan

elif 'xss' in plan_description:
    → Execute XSStrike + Browser XSS testing + ZAP XSS scan

elif 'api' in plan_description:
    → Execute API enumeration + IDOR testing + Authorization checks

elif 'authentication' in plan_description:
    → Execute browser auth testing + Hydra brute force + Session analysis
```

### 3. Browser Automation (`tools/browser.py`)

**Purpose**: Playwright-based dynamic security testing.

**Capabilities**:

- **Dynamic Form Testing**: Automated form interaction and payload injection
- **Session Management**: Cookie and authentication state handling
- **JavaScript Execution**: Custom security testing scripts
- **Screenshot Capture**: Visual evidence collection
- **Response Analysis**: Content parsing and vulnerability detection

**Security Testing Actions**:

```python
# Core browser automation methods
goto(page, url)                    # Navigate to target URL
fill(page, selector, payload)      # Inject test payloads
click(page, selector)              # Interact with elements
execute_js(page, script)           # Run custom security scripts
submit(page, form_selector)        # Submit forms with payloads
```

## 🔍 Testing Methodologies

### SQL Injection Testing

```python
async def sql_injection_testing(plan):
    # 1. SQLMap automated testing
    sqlmap_result = await run_sqlmap(target_url, plan)

    # 2. Manual browser-based testing
    browser_result = await manual_sql_injection_test(target_url, plan)

    # 3. OWASP ZAP SQL injection scan
    zap_result = await zap_sql_injection_scan(target_url)

    # Aggregate results and recommendations
    return combined_results
```

### XSS Testing

```python
async def xss_testing(plan):
    # 1. XSStrike automated XSS detection
    xsstrike_result = await run_xsstrike(target_url, plan)

    # 2. Browser-based payload injection
    browser_result = await manual_xss_test(target_url, plan)

    # 3. ZAP XSS scanning
    zap_result = await zap_xss_scan(target_url)

    return aggregated_xss_results
```

### API Security Testing

```python
async def api_security_testing(plan):
    # 1. API endpoint enumeration
    ffuf_result = await run_ffuf_api_enum(target_url)

    # 2. IDOR vulnerability testing
    idor_result = await test_idor_vulnerabilities(target_url, plan)

    # 3. Authorization bypass testing
    auth_result = await test_api_authorization(target_url, plan)

    return api_security_results
```

## 📊 Vulnerability Reporting

### ToolResult Structure

```python
@dataclass
class ToolResult:
    success: bool
    tool_name: str
    command: str
    output: str
    error: str = ""
    execution_time: float = 0.0
    vulnerabilities_found: List[Dict] = None
    recommendations: List[str] = None
```

### Vulnerability Classification

```python
# Severity levels with automatic classification
vulnerability = {
    'type': 'SQL Injection',
    'severity': 'Critical',  # Critical, High, Medium, Low
    'tool': 'SQLMap',
    'evidence': 'Injectable parameter found: username',
    'recommendation': 'Use parameterized queries'
}
```

### Comprehensive Report Generation

```json
{
  "summary": {
    "total_tests_executed": 8,
    "total_execution_time": 45.2,
    "total_vulnerabilities_found": 12,
    "critical_vulnerabilities": 3,
    "high_vulnerabilities": 4,
    "medium_vulnerabilities": 4,
    "low_vulnerabilities": 1
  },
  "vulnerabilities_by_severity": { ... },
  "vulnerabilities_by_type": { ... },
  "tools_performance": { ... },
  "recommendations": [ ... ]
}
```

## 🛠️ Configuration & Setup

### Tool Availability Detection

```python
available_tools = {
    'nmap': check_command('nmap'),
    'sqlmap': check_command('sqlmap'),
    'nikto': check_command('nikto'),
    'zap': ZAP_AVAILABLE,
    'playwright': PLAYWRIGHT_AVAILABLE,
    # ... additional tools
}
```

### Configuration Options

```python
config = {
    'zap_proxy': 'http://127.0.0.1:8080',
    'zap_api_key': None,
    'timeout': 300,  # 5 minutes default
    'max_threads': 5,
    'output_dir': './pentest_results',
    'wordlists': {
        'common': '/usr/share/wordlists/dirb/common.txt',
        'big': '/usr/share/wordlists/dirb/big.txt'
    }
}
```

## 🎯 Usage Examples

### Basic Integration

```python
from agents.planner import PlannerAgent
from tools.tool_calls import ToolCall

# Initialize components
planner = PlannerAgent(desc="Security testing planner")
tool_executor = ToolCall(config={'timeout': 60})

# Generate test plans
plans = planner.plan(target_data)

# Execute each plan
for plan in plans:
    result = await tool_executor.execute_plan_step(plan)
    print(f"Tool: {result.tool_name}, Vulnerabilities: {len(result.vulnerabilities_found)}")
```

### Full Orchestration

```python
# Use the provided orchestrator
orchestrator = PenetrationTestingOrchestrator(config)
report = await orchestrator.run_comprehensive_security_test(target_data)
orchestrator.print_report(report)
orchestrator.save_report(report, "security_report.json")
```

## 🔐 Security Testing Capabilities

### Authentication & Session Management

- ✅ Login form bypass testing
- ✅ Session fixation detection
- ✅ Session timeout validation
- ✅ Multi-factor authentication bypass
- ✅ Credential brute force attacks

### Input Validation Testing

- ✅ SQL injection (Union, Boolean, Time-based)
- ✅ Cross-site scripting (Reflected, Stored, DOM)
- ✅ Command injection
- ✅ LDAP injection
- ✅ XML injection

### Authorization & Access Control

- ✅ Insecure Direct Object Reference (IDOR)
- ✅ Privilege escalation testing
- ✅ Horizontal access control bypass
- ✅ Vertical access control bypass
- ✅ Role-based access testing

### API Security

- ✅ REST API enumeration
- ✅ GraphQL testing
- ✅ API versioning vulnerabilities
- ✅ Rate limiting bypass
- ✅ API key exposure

### Infrastructure Security

- ✅ Network port scanning
- ✅ Service enumeration
- ✅ SSL/TLS configuration testing
- ✅ Web server vulnerability scanning
- ✅ Directory enumeration

## 📈 Performance & Scalability

### Concurrent Execution

- **Async/await patterns** for parallel tool execution
- **Configurable timeouts** to prevent hanging
- **Resource pooling** for browser instances
- **Thread management** for CPU-intensive tasks

### Error Handling

- **Graceful degradation** when tools are unavailable
- **Fallback mechanisms** for failed tests
- **Comprehensive logging** for debugging
- **Timeout protection** for long-running scans

### Output Management

- **Structured JSON reports** for programmatic processing
- **Human-readable summaries** for analysts
- **Evidence preservation** with screenshots and logs
- **Export capabilities** for integration with other tools

## 🚀 Getting Started

1. **Install Dependencies**:

   ```bash
   pip install playwright zapv2 requests
   playwright install
   ```

2. **Install Security Tools**:

   ```bash
   # On Ubuntu/Debian
   apt-get install nmap sqlmap nikto gobuster ffuf hydra

   # OWASP ZAP (download from official site)
   # Configure ZAP API access
   ```

3. **Run Demo**:

   ```bash
   python pentest_integration_demo.py
   ```

4. **Integration**:

   ```python
   from pentest_integration_demo import PenetrationTestingOrchestrator

   orchestrator = PenetrationTestingOrchestrator()
   report = await orchestrator.run_comprehensive_security_test(your_target_data)
   ```

## 📋 Key Features Summary

- ✅ **AI-Powered Planning**: Gemini 2.0-flash for intelligent test generation
- ✅ **26+ Security Tools**: Integration with industry-standard tools
- ✅ **Automated Tool Selection**: Smart mapping based on plan content
- ✅ **Browser Automation**: Playwright for dynamic testing
- ✅ **Comprehensive Reporting**: Detailed vulnerability analysis
- ✅ **OWASP Methodology**: Industry-standard testing approaches
- ✅ **Concurrent Execution**: High-performance parallel testing
- ✅ **Extensible Architecture**: Easy to add new tools and methods
- ✅ **Production Ready**: Error handling and timeout management
- ✅ **Evidence Collection**: Screenshots, logs, and detailed output

This system represents a sophisticated, enterprise-grade penetration testing framework that combines the power of AI planning with comprehensive tool automation for effective security assessment.

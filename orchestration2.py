#!/usr/bin/env python3
"""
Comprehensive Penetration Testing Integration Demo

This script demonstrates how Project Heimdall's penetration testing system works:
1. PlannerAgent generates intelligent security test plans using Gemini LLM
2. ToolCall system executes the plans using various security tools
3. Results are aggregated and reported with vulnerability findings

Features demonstrated:
- Integration between PlannerAgent and ToolCall
- Automated tool selection based on test plan content
- Support for OWASP ZAP, SQLMap, Nmap, Nikto, browser automation, and more
- Comprehensive vulnerability reporting with recommendations
"""

import asyncio
import json
import time
from typing import List, Dict, Any
from pathlib import Path

# Import your existing classes
from agents.planner import PlannerAgent
from tools.tool_calls import ToolCall, ToolResult


class PenetrationTestingOrchestrator:
    """
    Main orchestrator that combines PlannerAgent with ToolCall system
    for comprehensive automated penetration testing.
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.planner = PlannerAgent(desc="Automated penetration testing planner")
        self.tool_executor = ToolCall(config=self.config)
        
        # Results storage
        self.test_results = []
        self.vulnerabilities_found = []
        self.execution_summary = {}
        
        print("🔒 Project Heimdall - Penetration Testing System Initialized")
        print(f"🛠️  Available tools: {list(self.tool_executor.available_tools.keys())}")
        print(f"✅ Enabled tools: {[k for k, v in self.tool_executor.available_tools.items() if v]}")
        print()
    
    async def run_comprehensive_security_test(self, target_data: str) -> Dict[str, Any]:
        """
        Run a complete penetration testing cycle:
        1. Generate test plans using PlannerAgent
        2. Execute plans using ToolCall system
        3. Aggregate and report results
        """
        start_time = time.time()
        
        print("🎯 Starting Comprehensive Security Assessment")
        print("=" * 60)
        
        # Step 1: Generate security test plans
        print("📋 Step 1: Generating Security Test Plans...")
        test_plans = self.planner.plan(target_data)
        print(f"✅ Generated {len(test_plans)} security test plans")
        
        # Display generated plans
        for i, plan in enumerate(test_plans, 1):
            print(f"   {i}. {plan['title']}")
        print()
        
        # Step 2: Execute each test plan
        print("⚡ Step 2: Executing Security Tests...")
        for i, plan in enumerate(test_plans, 1):
            print(f"🔍 Executing Test {i}/{len(test_plans)}: {plan['title']}")
            
            try:
                # Execute the plan step using ToolCall
                result = await self.tool_executor.execute_plan_step(plan)
                self.test_results.append({
                    'plan': plan,
                    'result': result,
                    'test_number': i
                })
                
                # Collect vulnerabilities
                if result.vulnerabilities_found:
                    self.vulnerabilities_found.extend(result.vulnerabilities_found)
                
                # Print execution summary
                status = "✅ PASSED" if result.success else "❌ FAILED"
                print(f"   {status} | Tool: {result.tool_name} | Time: {result.execution_time:.2f}s")
                
                if result.vulnerabilities_found:
                    print(f"   🚨 Found {len(result.vulnerabilities_found)} vulnerabilities")
                
                print()
                
            except Exception as e:
                print(f"   ❌ ERROR: {str(e)}")
                print()
        
        # Step 3: Generate comprehensive report
        execution_time = time.time() - start_time
        report = self._generate_security_report(execution_time)
        
        return report
    
    def _generate_security_report(self, execution_time: float) -> Dict[str, Any]:
        """Generate a comprehensive security assessment report"""
        
        # Categorize vulnerabilities by severity
        critical_vulns = [v for v in self.vulnerabilities_found if v.get('severity') == 'Critical']
        high_vulns = [v for v in self.vulnerabilities_found if v.get('severity') == 'High']
        medium_vulns = [v for v in self.vulnerabilities_found if v.get('severity') == 'Medium']
        low_vulns = [v for v in self.vulnerabilities_found if v.get('severity') == 'Low']
        
        # Categorize by vulnerability type
        vuln_types = {}
        for vuln in self.vulnerabilities_found:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Tools used summary
        tools_used = {}
        for result in self.test_results:
            tool_name = result['result'].tool_name
            if tool_name not in tools_used:
                tools_used[tool_name] = {
                    'executions': 0,
                    'success_rate': 0,
                    'total_time': 0,
                    'vulnerabilities_found': 0
                }
            
            tools_used[tool_name]['executions'] += 1
            tools_used[tool_name]['total_time'] += result['result'].execution_time
            if result['result'].success:
                tools_used[tool_name]['success_rate'] += 1
            if result['result'].vulnerabilities_found:
                tools_used[tool_name]['vulnerabilities_found'] += len(result['result'].vulnerabilities_found)
        
        # Calculate success rates
        for tool in tools_used:
            tools_used[tool]['success_rate'] = tools_used[tool]['success_rate'] / tools_used[tool]['executions']
        
        report = {
            'summary': {
                'total_tests_executed': len(self.test_results),
                'total_execution_time': execution_time,
                'total_vulnerabilities_found': len(self.vulnerabilities_found),
                'critical_vulnerabilities': len(critical_vulns),
                'high_vulnerabilities': len(high_vulns),
                'medium_vulnerabilities': len(medium_vulns),
                'low_vulnerabilities': len(low_vulns)
            },
            'vulnerabilities_by_severity': {
                'Critical': critical_vulns,
                'High': high_vulns,
                'Medium': medium_vulns,
                'Low': low_vulns
            },
            'vulnerabilities_by_type': vuln_types,
            'tools_performance': tools_used,
            'test_results': self.test_results,
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on found vulnerabilities"""
        recommendations = []
        
        # Get all unique recommendations from test results
        all_recommendations = set()
        for result in self.test_results:
            if result['result'].recommendations:
                all_recommendations.update(result['result'].recommendations)
        
        recommendations.extend(list(all_recommendations))
        
        # Add general security recommendations
        recommendations.extend([
            "Implement a comprehensive security testing pipeline",
            "Regular security assessments and code reviews",
            "Keep all software components up to date",
            "Implement proper logging and monitoring",
            "Follow OWASP security guidelines",
            "Conduct regular penetration testing"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def print_report(self, report: Dict[str, Any]):
        """Print a formatted security assessment report"""
        print("📊 SECURITY ASSESSMENT REPORT")
        print("=" * 60)
        
        # Summary
        summary = report['summary']
        print("🔍 EXECUTIVE SUMMARY")
        print(f"   Tests Executed: {summary['total_tests_executed']}")
        print(f"   Execution Time: {summary['total_execution_time']:.2f} seconds")
        print(f"   Total Vulnerabilities: {summary['total_vulnerabilities_found']}")
        print()
        
        # Vulnerability breakdown
        print("🚨 VULNERABILITY BREAKDOWN")
        print(f"   🔴 Critical: {summary['critical_vulnerabilities']}")
        print(f"   🟠 High: {summary['high_vulnerabilities']}")
        print(f"   🟡 Medium: {summary['medium_vulnerabilities']}")
        print(f"   🟢 Low: {summary['low_vulnerabilities']}")
        print()
        
        # Vulnerability types
        if report['vulnerabilities_by_type']:
            print("📝 VULNERABILITY TYPES FOUND")
            for vuln_type, vulns in report['vulnerabilities_by_type'].items():
                print(f"   {vuln_type}: {len(vulns)} instances")
                for vuln in vulns[:3]:  # Show first 3 of each type
                    print(f"     - {vuln.get('tool', 'Unknown')}: {vuln.get('evidence', 'No details')[:80]}...")
            print()
        
        # Tools performance
        print("🛠️  TOOLS PERFORMANCE")
        for tool_name, performance in report['tools_performance'].items():
            success_rate_pct = performance['success_rate'] * 100
            avg_time = performance['total_time'] / performance['executions']
            print(f"   {tool_name}:")
            print(f"     Executions: {performance['executions']}")
            print(f"     Success Rate: {success_rate_pct:.1f}%")
            print(f"     Avg Time: {avg_time:.2f}s")
            print(f"     Vulnerabilities Found: {performance['vulnerabilities_found']}")
        print()
        
        # Recommendations
        print("💡 SECURITY RECOMMENDATIONS")
        for i, rec in enumerate(report['recommendations'][:10], 1):  # Show top 10
            print(f"   {i}. {rec}")
        print()
    
    def save_report(self, report: Dict[str, Any], filename: str = None):
        """Save the security report to a JSON file"""
        if not filename:
            timestamp = int(time.time())
            filename = f"security_report_{timestamp}.json"
        
        # Convert ToolResult objects to dictionaries for JSON serialization
        serializable_report = self._make_serializable(report)
        
        with open(filename, 'w') as f:
            json.dump(serializable_report, f, indent=2, default=str)
        
        print(f"📄 Report saved to: {filename}")
    
    def _make_serializable(self, obj):
        """Convert objects to JSON-serializable format"""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            return self._make_serializable(obj.__dict__)
        else:
            return obj


async def demo_penetration_testing():
    """Demonstrate the complete penetration testing workflow"""
    
    # Sample target data (as would be extracted from a real application)
    sample_target_data = """
Summarized HTML:
<html>
<head>
    <title>VulnBank - Vulnerable Banking Application</title>
    <meta name="generator" content="PHP/7.4.3">
</head>
<body>
    <!-- Login Form - Potential SQL Injection -->
    <form action="/auth/login" method="POST" id="loginForm">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <input type="submit" value="Login">
    </form>
    
    <!-- Search - Potential XSS -->
    <form action="/search" method="GET">
        <input type="text" name="q" placeholder="Search...">
        <input type="submit" value="Search">
    </form>
    
    <!-- File Upload - Potential RCE -->
    <form action="/upload/document" method="POST" enctype="multipart/form-data">
        <input type="file" name="document">
        <input type="submit" value="Upload">
    </form>
    
    <!-- API Documentation Link -->
    <a href="/api/v1/docs">API Documentation</a>
    <a href="/admin/dashboard">Admin Panel</a>
</body>
</html>

Application Fingerprinting:
- Links: ['/dashboard', '/admin/dashboard', '/profile', '/api/v1/docs', '/logout']
- Forms: [
    {'action': '/auth/login', 'method': 'POST', 'fields': ['username', 'password']},
    {'action': '/search', 'method': 'GET', 'fields': ['q']},
    {'action': '/upload/document', 'method': 'POST', 'fields': ['document']}
]
- Technologies: ['PHP/7.4.3', 'Apache/2.4.41', 'MySQL']

Request and Response Data:
- Request: GET / HTTP/1.1
- Response: HTTP/1.1 200 OK, Server: Apache/2.4.41, X-Powered-By: PHP/7.4.3
- API endpoints: ['/api/v1/users', '/api/v1/accounts', '/api/v1/transactions']

Security Headers Analysis:
- Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
- Present: Strict-Transport-Security (max-age=31536000)

Path Analysis:
- Accessible: ['/admin/', '/api/', '/config/', '/phpinfo.php', '/.git/']
- Sensitive files: ['/.env', '/config.php', '/backup.sql']
"""

    # Initialize the orchestrator
    orchestrator = PenetrationTestingOrchestrator({
        'timeout': 60,
        'output_dir': './pentest_results'
    })
    
    # Run comprehensive security test
    print("🚀 Starting Project Heimdall Penetration Testing Demo")
    print("=" * 60)
    
    report = await orchestrator.run_comprehensive_security_test(sample_target_data)
    
    # Display results
    orchestrator.print_report(report)
    
    # Save report
    orchestrator.save_report(report, "heimdall_demo_report.json")
    
    print("🎉 Penetration testing demo completed!")
    print("\nThis demonstrates how Project Heimdall integrates:")
    print("✅ PlannerAgent - AI-powered test plan generation using Gemini LLM")
    print("✅ ToolCall System - Automated execution of security tools")
    print("✅ Multiple Security Tools - SQLMap, Nmap, Nikto, OWASP ZAP, Browser automation")
    print("✅ Intelligent Tool Selection - Based on plan content and keywords")
    print("✅ Comprehensive Reporting - Vulnerabilities, recommendations, performance metrics")


if __name__ == "__main__":
    print("🔒 Project Heimdall - Penetration Testing Integration Demo")
    print("=" * 60)
    print("This script demonstrates the integration between:")
    print("• PlannerAgent: AI-powered security test plan generation")
    print("• ToolCall System: Automated security tool execution")
    print("• Multiple Security Tools: SQLMap, OWASP ZAP, Nmap, Nikto, etc.")
    print("• Browser Automation: Playwright-based dynamic testing")
    print("• Comprehensive Reporting: Vulnerability analysis and recommendations")
    print()
    
    # Run the demo
    asyncio.run(demo_penetration_testing()) 
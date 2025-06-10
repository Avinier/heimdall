"""
OWASP ZAP Integration Module for Project Heimdall
Comprehensive ZAP scanning functions with enterprise-grade capabilities
"""

import time
import logging
import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Import core structures from main module
try:
    from .tool_calls import (
        VAPTResult, Vulnerability, create_vulnerability, 
        create_session, VAPT_CONFIG
    )
except ImportError:
    # Fallback for direct import
    from tool_calls import (
        VAPTResult, Vulnerability, create_vulnerability,
        create_session, VAPT_CONFIG
    )

# ZAP-specific imports
from zapv2 import ZAPv2

# Configure logging
logger = logging.getLogger(__name__)

# ===== CORE ZAP FUNCTIONS =====

def zap_passive_scan(target_url: str, spider_minutes: int = 2) -> VAPTResult:
    """
    Execute OWASP ZAP passive scan with spidering
    
    Args:
        target_url: Target URL for scanning
        spider_minutes: Minutes to spend spidering
    
    Returns:
        VAPTResult with ZAP passive scan findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    try:
        # Initialize ZAP connection
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Test ZAP connection
        try:
            zap.core.version
        except Exception as e:
            return VAPTResult(
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
        logger.info(f"Starting ZAP spider on {target_url}")
        spider_id = zap.spider.scan(target_url)
        
        # Wait for spider completion or timeout
        spider_timeout = spider_minutes * 60
        start_spider = time.time()
        
        while int(zap.spider.status(spider_id)) < 100:
            if time.time() - start_spider > spider_timeout:
                zap.spider.stop(spider_id)
                break
            time.sleep(2)
        
        logger.info(f"Spider completed. Found {len(zap.spider.results(spider_id))} URLs")
        
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
        
        return VAPTResult(
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
        return VAPTResult(
            success=False,
            tool_name="ZAP Passive Scan",
            error=f"ZAP scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_active_scan(target_url: str, scan_policy: str = "Default Policy", 
                   max_scan_time: int = 10) -> VAPTResult:
    """
    Execute OWASP ZAP active vulnerability scan
    
    Args:
        target_url: Target URL for active scanning
        scan_policy: ZAP scan policy to use
        max_scan_time: Maximum scan time in minutes
    
    Returns:
        VAPTResult with ZAP active scan findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Test connection
        try:
            zap.core.version
        except Exception as e:
            return VAPTResult(
                success=False,
                tool_name="ZAP Active Scan",
                error=f"Cannot connect to ZAP: {str(e)}",
                execution_time=time.time() - start_time
            )
        
        # Access the target first (for session establishment)
        logger.info(f"Accessing target: {target_url}")
        zap.core.access_url(target_url)
        
        # Start active scan
        logger.info(f"Starting ZAP active scan on {target_url}")
        scan_id = zap.ascan.scan(target_url, scanpolicyname=scan_policy)
        
        # Monitor scan progress
        scan_timeout = max_scan_time * 60
        scan_start = time.time()
        
        while int(zap.ascan.status(scan_id)) < 100:
            progress = int(zap.ascan.status(scan_id))
            logger.info(f"Active scan progress: {progress}%")
            
            if time.time() - scan_start > scan_timeout:
                logger.info("Scan timeout reached, stopping active scan")
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
        
        return VAPTResult(
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
        return VAPTResult(
            success=False,
            tool_name="ZAP Active Scan",
            error=f"ZAP active scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_authenticated_scan(target_url: str, auth_config: Dict[str, str], 
                          scan_type: str = "both") -> VAPTResult:
    """
    Execute authenticated ZAP scan with session management
    
    Args:
        target_url: Target URL
        auth_config: Authentication configuration
        scan_type: "passive", "active", or "both"
    
    Returns:
        VAPTResult with authenticated scan findings
    """
    start_time = time.time()
    vulnerabilities = []
    
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
            logger.info("Starting authenticated spider")
            spider_id = zap.spider.scan_as_user(context_id, user_id if 'user_id' in locals() else None, target_url)
            
            # Wait for spider completion
            while int(zap.spider.status(spider_id)) < 100:
                time.sleep(2)
        
        # Perform active scan if requested
        if scan_type in ["active", "both"]:
            logger.info("Starting authenticated active scan")
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
        
        return VAPTResult(
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
        return VAPTResult(
            success=False,
            tool_name="ZAP Authenticated Scan",
            error=f"Authenticated scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_ajax_spider_scan(target_url: str, max_duration: int = 5) -> VAPTResult:
    """
    Execute OWASP ZAP AJAX Spider for JavaScript-heavy applications
    
    Args:
        target_url: Target URL for AJAX spidering
        max_duration: Maximum duration in minutes
    
    Returns:
        VAPTResult with AJAX spider findings
    """
    start_time = time.time()
    vulnerabilities = []
    
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Test ZAP connection
        try:
            zap.core.version
        except Exception as e:
            return VAPTResult(
                success=False,
                tool_name="ZAP AJAX Spider",
                error=f"Cannot connect to ZAP: {str(e)}",
                execution_time=time.time() - start_time
            )
        
        # Start AJAX spider
        logger.info(f"Starting ZAP AJAX spider on {target_url}")
        zap.ajaxSpider.scan(target_url)
        
        # Monitor AJAX spider progress
        max_duration_seconds = max_duration * 60
        start_ajax = time.time()
        
        while zap.ajaxSpider.status == 'running':
            if time.time() - start_ajax > max_duration_seconds:
                logger.info("AJAX spider timeout reached, stopping")
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
        
        return VAPTResult(
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
        return VAPTResult(
            success=False,
            tool_name="ZAP AJAX Spider",
            error=f"AJAX spider failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_comprehensive_scan(target_url: str, auth_config: Dict[str, str] = None,
                          include_active: bool = True) -> VAPTResult:
    """
    Execute comprehensive ZAP scan combining multiple techniques
    
    Args:
        target_url: Target URL for scanning
        auth_config: Optional authentication configuration
        include_active: Whether to include active scanning
    
    Returns:
        VAPTResult with comprehensive scan findings
    """
    start_time = time.time()
    all_vulnerabilities = []
    
    try:
        # Phase 1: Passive Scan
        passive_result = zap_passive_scan(target_url, spider_minutes=3)
        if passive_result.success:
            all_vulnerabilities.extend(passive_result.vulnerabilities)
        
        # Phase 2: AJAX Spider
        ajax_result = zap_ajax_spider_scan(target_url, max_duration=3)
        if ajax_result.success:
            all_vulnerabilities.extend(ajax_result.vulnerabilities)
        
        # Phase 3: Active Scan (if requested)
        if include_active:
            active_result = zap_active_scan(target_url, max_scan_time=10)
            if active_result.success:
                all_vulnerabilities.extend(active_result.vulnerabilities)
        
        # Phase 4: Authenticated Scan (if credentials provided)
        if auth_config:
            auth_result = zap_authenticated_scan(target_url, auth_config, "both" if include_active else "passive")
            if auth_result.success:
                all_vulnerabilities.extend(auth_result.vulnerabilities)
        
        # Deduplicate vulnerabilities
        unique_vulnerabilities = _deduplicate_zap_findings(all_vulnerabilities)
        
        execution_time = time.time() - start_time
        
        return VAPTResult(
            success=True,
            tool_name="ZAP Comprehensive Scan",
            vulnerabilities=unique_vulnerabilities,
            execution_time=execution_time,
            metadata={
                'target_url': target_url,
                'phases_completed': 4 if auth_config else (3 if include_active else 2),
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
        return VAPTResult(
            success=False,
            tool_name="ZAP Comprehensive Scan",
            error=f"Comprehensive scan failed: {str(e)}",
            execution_time=time.time() - start_time
        )

def zap_enterprise_scan(target_url: str, auth_config: Dict[str, str] = None,
                       scan_config: Dict[str, Any] = None) -> VAPTResult:
    """
    Execute enterprise-grade ZAP scan with advanced analysis
    
    Args:
        target_url: Target URL for enterprise scanning
        auth_config: Authentication configuration
        scan_config: Advanced scan configuration
    
    Returns:
        VAPTResult with enterprise-grade findings
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
        # Phase 1: Deep crawling
        if scan_config.get('deep_crawl', True):
            logger.info("Phase 1: Enterprise deep crawling")
            # Combine passive and AJAX scanning
            passive_result = zap_passive_scan(target_url, spider_minutes=5)
            if passive_result.success:
                all_vulnerabilities.extend(passive_result.vulnerabilities)
                scan_metadata['passive_urls'] = passive_result.metadata.get('urls_found', 0)
            
            ajax_result = zap_ajax_spider_scan(target_url, max_duration=5)
            if ajax_result.success:
                all_vulnerabilities.extend(ajax_result.vulnerabilities)
                scan_metadata['ajax_urls'] = ajax_result.metadata.get('urls_discovered', 0)
        
        # Phase 2: Advanced active scanning
        if scan_config.get('advanced_active', True):
            logger.info("Phase 2: Enterprise active scanning")
            active_result = zap_active_scan(
                target_url,
                max_scan_time=scan_config.get('max_scan_time', 20)
            )
            if active_result.success:
                all_vulnerabilities.extend(active_result.vulnerabilities)
                scan_metadata['active_alerts'] = len(active_result.vulnerabilities)
        
        # Phase 3: Authenticated scanning
        if scan_config.get('authenticated_scan', False) and auth_config:
            logger.info("Phase 3: Enterprise authenticated scanning")
            auth_result = zap_authenticated_scan(target_url, auth_config, "both")
            if auth_result.success:
                all_vulnerabilities.extend(auth_result.vulnerabilities)
                scan_metadata['auth_findings'] = len(auth_result.vulnerabilities)
        
        # Phase 4: Technology analysis
        if scan_config.get('technology_detection', True):
            logger.info("Phase 4: Technology stack analysis")
            tech_vulns = _analyze_technology_stack(target_url)
            all_vulnerabilities.extend(tech_vulns)
            scan_metadata['tech_findings'] = len(tech_vulns)
        
        # Enterprise-grade deduplication and prioritization
        unique_vulnerabilities = _deduplicate_and_prioritize_enterprise_findings(all_vulnerabilities)
        
        execution_time = time.time() - start_time
        
        # Calculate business impact
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
        
        return VAPTResult(
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
        return VAPTResult(
            success=False,
            tool_name="ZAP Enterprise Scan",
            error=f"Enterprise scan failed: {str(e)}",
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

# ===== ADVANCED ANALYSIS FUNCTIONS =====

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

def _analyze_technology_stack(target_url: str) -> List[Vulnerability]:
    """Analyze technology stack for known vulnerabilities"""
    vulnerabilities = []
    
    try:
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
        logger.error(f"Error analyzing technology stack: {e}")
    
    return vulnerabilities

def _deduplicate_and_prioritize_enterprise_findings(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """Enterprise-grade deduplication and prioritization"""
    seen = {}
    
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

# ===== MODULE EXPORTS =====

__all__ = [
    'zap_passive_scan',
    'zap_active_scan', 
    'zap_authenticated_scan',
    'zap_ajax_spider_scan',
    'zap_comprehensive_scan',
    'zap_enterprise_scan'
]

# Module initialization
logger.info("OWASP ZAP integration module loaded successfully")

#AVINIERNOTES: 2st Phase of Orchestration: Context Mgmt for Actioner and Reporter Agent.
#              So this will generate the actions which will be tool called

import sys
import time
import re
from urllib.parse import urljoin, urlparse
from tools.webproxy import WebProxy
from tools.pagedata_extractor import PageDataExtractor
from agents.planner import PlannerAgent
from agents.actioner import ActionerAgent
from agents.context_manager import ContextManagerAgent

def run_orchestration(expand_scope=True, max_iterations=10, keep_messages=12):
    """
    Run the complete security analysis orchestration with nested loop structure.
    
    Parameters:
    - expand_scope: Whether to add discovered URLs to the queue
    - max_iterations: Maximum iterations per plan execution
    - keep_messages: Number of recent messages to keep in conversation history
    """
    
    # INITIALIZE: Create web proxy and scanner
    base_url = "https://dev.quantumsenses.com"  # Change this to your target URL
    total_token_counter = 0
    
    print("=" * 80)
    print("SECURITY ANALYSIS ORCHESTRATION - PHASE 2")
    print("=" * 80)
    print(f"Base URL: {base_url}")
    print(f"Expand Scope: {expand_scope}")
    print(f"Max Iterations per Plan: {max_iterations}")
    print()
    
    # Initialize URL queue with starting URL
    urls_to_parse = [base_url]
    visited_urls = set()
    
    # Initialize agents and tools
    print("Initializing agents and tools...")
    try:
        web_proxy = WebProxy(starting_url=base_url)
        browser, context, page, playwright = web_proxy.create_proxy()
        planner = PlannerAgent(
            desc="Security test planner for orchestration phase 2",
            api_type="gemini",
            model_key="gemini-2.5-flash-preview-05-20",
            reasoning=True,
            temperature=0.3
        )
        actioner = ActionerAgent(
            desc="Security test executor for orchestration phase 2",
            api_type="gemini",
            model="gemini-2.5-flash-preview-05-20",
            fireworks_model_key="deepseek-v3",
            temperature=0.3,
            reasoning_config={
                "include_thoughts": True,
                "thinking_budget": None
            }
        )
        context_manager = ContextManagerAgent(
            desc="Context management for orchestration phase 2",
            debug=False,
            api_type="fireworks",
            model_key="qwen3-30b-a3b",
            reasoning=False,
            temperature=0.2
        )
        print("✓ All agents and tools initialized successfully")
        print()
    except Exception as e:
        print(f"✗ Failed to initialize: {str(e)}")
        return
    
    all_findings = []
    
    try:
        # OUTER LOOP (URL Processing)
        while urls_to_parse:
            url = urls_to_parse.pop(0)
            
            # Skip if already visited
            if url in visited_urls:
                continue
                
            visited_urls.add(url)
            
            print("=" * 60)
            print(f"ANALYZING URL: {url}")
            print("=" * 60)
            
            try:
                # Scan current URL to extract page content and structure
                print(f"Navigating to: {url}")
                page.goto(url, wait_until='networkidle', timeout=100000)
                print(f"✓ Successfully navigated to {url}")
                print(f"✓ Page title: {page.title()}")
                
                # Wait for dynamic content
                time.sleep(2)
                
                # Extract page data
                print("Extracting page data...")
                extractor = PageDataExtractor(page)
                raw_page_data = extractor.extract_page_data()
                print(f"✓ Page data extracted ({len(raw_page_data)} characters)")
                
                # Parse discovered URLs from page content
                if expand_scope:
                    print("Processing discovered links...")
                    new_links_count = 0
                    
                    # Extract links using the same logic as before
                    if hasattr(extractor, 'links') and extractor.links:
                        for link_info in extractor.links:
                            link_url = link_info.get('url', '')
                            
                            # Skip asset files (images, fonts, etc.)
                            if link_url and _is_asset_file(link_url):
                                print(f"  - Skipped (asset file): {link_url}")
                                continue
                            
                            if link_url and _is_same_domain(base_url, link_url):
                                if link_url not in visited_urls and link_url not in urls_to_parse:
                                    urls_to_parse.append(link_url)
                                    new_links_count += 1
                                    print(f"  + Added: {link_url}")
                    else:
                        # Fallback link extraction
                        links_match = re.search(r"Links: \[(.*?)\]", raw_page_data)
                        if links_match:
                            links_str = links_match.group(1)
                            fallback_links = re.findall(r"'([^']+)'", links_str)
                            
                            for link_url in fallback_links:
                                # Skip asset files (images, fonts, etc.)
                                if link_url and _is_asset_file(link_url):
                                    print(f"  - Skipped (asset file, fallback): {link_url}")
                                    continue
                                
                                if link_url and _is_same_domain(base_url, link_url):
                                    if link_url not in visited_urls and link_url not in urls_to_parse:
                                        urls_to_parse.append(link_url)
                                        new_links_count += 1
                                        print(f"  + Added (fallback): {link_url}")
                    
                    print(f"✓ Added {new_links_count} new links to scan queue")
                
                # Summarize page content to reduce token usage
                print("Summarizing page content...")
                summarized_page_data = context_manager.summarize_page_source(raw_page_data, url)
                page_data_context = f"URL: {url}\n\nSUMMARIZED PAGE ANALYSIS:\n{summarized_page_data}"
                
                # Check context stats
                context_stats = context_manager.get_context_stats(page_data_context)
                print(f"✓ Page data summarized (Tokens: ~{context_stats['estimated_tokens']})")
                total_token_counter += context_stats['estimated_tokens']
                
                # PLANNER: Generate security test plans for current URL
                print("Generating security test plans...")
                plans = planner.plan(raw_page_data)
                print(f"✓ Generated {len(plans)} security test plans")
                
                # Display all plans to user
                _print_plans_for_url(url, plans)
                
                # MIDDLE LOOP (Plan Steps Execution)
                for plan_idx, plan in enumerate(plans, 1):
                    print("=" * 50)
                    print(f"EXECUTING PLAN {plan_idx}/{len(plans)}: {plan.get('title', 'Untitled Plan')}")
                    
                    # Display plan context for execution
                    business_impact = plan.get('business_impact', '')
                    attack_complexity = plan.get('attack_complexity', '')
                    compliance_risk = plan.get('compliance_risk', '')
                    
                    if business_impact:
                        impact_level = "UNKNOWN"
                        if any(term in business_impact.upper() for term in ['CRITICAL', 'CATASTROPHIC']):
                            impact_level = "🔴 CRITICAL"
                        elif 'HIGH' in business_impact.upper():
                            impact_level = "🟠 HIGH"
                        elif 'MEDIUM' in business_impact.upper():
                            impact_level = "🟡 MEDIUM"
                        elif 'LOW' in business_impact.upper():
                            impact_level = "🟢 LOW"
                        print(f"Business Impact: {impact_level}")
                    
                    if attack_complexity:
                        complexity_level = "STANDARD"
                        if any(term in attack_complexity.upper() for term in ['EXPERT', 'VERY HIGH']):
                            complexity_level = "🔥 EXPERT"
                        elif 'HIGH' in attack_complexity.upper():
                            complexity_level = "⚡ HIGH"
                        elif 'MEDIUM' in attack_complexity.upper():
                            complexity_level = "⚙️ MEDIUM"
                        elif 'LOW' in attack_complexity.upper():
                            complexity_level = "🔧 LOW"
                        print(f"Attack Complexity: {complexity_level}")
                    
                    print("=" * 50)
                    
                    # Reset conversation history to initial messages (no system prompt needed - handled by ActionerAgent)
                    conversation_history = [
                        {"role": "user", "content": page_data_context}
                    ]
                    
                    # Enhanced plan instructions with strategic context
                    enhanced_plan_instructions = f"""ENHANCED SECURITY TEST PLAN:
Title: {plan.get('title', 'Security Test')}
Description: {plan.get('description', 'Perform security testing')}"""
                    
                    # Add enhanced fields to instructions
                    if business_impact:
                        enhanced_plan_instructions += f"\nBusiness Impact: {business_impact}"
                    if attack_complexity:
                        enhanced_plan_instructions += f"\nAttack Complexity: {attack_complexity}"
                    if compliance_risk:
                        enhanced_plan_instructions += f"\nCompliance Risk: {compliance_risk}"
                    
                    enhanced_plan_instructions += "\n\nExecute this enhanced security test plan using the available tools, considering the business impact, attack complexity, and compliance requirements."
                    
                    conversation_history.append({"role": "user", "content": enhanced_plan_instructions})
                    
                    iteration_counter = 0
                    plan_findings = []
                    
                    # INNER LOOP (Action Execution)
                    while iteration_counter < max_iterations:
                        print(f"\n--- Action Iteration {iteration_counter + 1}/{max_iterations} ---")
                        
                        # Manage conversation history length
                        if len(conversation_history) > keep_messages:
                            print("Managing conversation history length...")
                            # Preserve first 2 critical messages (page context + plan instructions)
                            critical_messages = conversation_history[:2]
                            recent_messages = conversation_history[-(keep_messages-2):]
                            
                            # Summarize middle portion
                            middle_portion = conversation_history[2:-(keep_messages-2)]
                            if middle_portion:
                                summarized_middle = context_manager.summarize_conversation(middle_portion)
                                # Reconstruct history
                                conversation_history = critical_messages + summarized_middle + recent_messages
                            else:
                                conversation_history = critical_messages + recent_messages
                        
                        # Count tokens in current history
                        history_text = "\n".join([msg["content"] for msg in conversation_history])
                        history_stats = context_manager.get_context_stats(history_text)
                        print(f"History tokens: ~{history_stats['estimated_tokens']}")
                        total_token_counter += history_stats['estimated_tokens']
                        
                        # Send history to LLM for next action decision
                        print("Generating next security action...")
                        try:
                            # Get the most recent action output if available
                            recent_tool_output = ""
                            if iteration_counter > 0 and len(conversation_history) > 2:
                                # Look for the most recent "Action Result:" message
                                for msg in reversed(conversation_history):
                                    if msg["content"].startswith("Action Result:"):
                                        recent_tool_output = msg["content"].replace("Action Result: ", "")
                                        break
                            
                            # ACTIONER: Generate action using actioner
                            actioner_response = actioner.generate_action_of_plan_step(
                                plan=plan,
                                page_data=page_data_context,
                                tool_output=recent_tool_output,
                                conversation_history=[msg["content"] for msg in conversation_history]
                            )
                            
                            discussion = actioner_response.get('discussion', '')
                            action_command = actioner_response.get('action', '')
                            
                            print(f"Action Discussion: {discussion}")
                            print(f"Action Command: {action_command}")
                            
                            # Execute action command (simulated for now)
                            action_output = _execute_action_command(action_command, page)
                            print(f"Action Output: {action_output}")
                            
                            # Capture action result and summarize for context
                            summarized_action_result = context_manager.summarize(
                                llm_response=discussion,
                                tool_use=action_command,
                                tool_output=action_output
                            )
                            
                            # Append to conversation history
                            conversation_history.append({"role": "assistant", "content": discussion})
                            conversation_history.append({"role": "user", "content": f"Action Result: {summarized_action_result}"})
                            
                            # Check if action indicates completion
                            if "complete()" in action_command.lower() or "completed" in action_output.lower():
                                print("Plan execution completed.")
                                
                                # Analyze conversation for security findings
                                findings = _analyze_conversation_for_findings(conversation_history)
                                plan_findings.extend(findings)
                                
                                if findings:
                                    print(f"✓ Security findings detected: {len(findings)}")
                                    for finding in findings:
                                        print(f"  - {finding}")
                                    break
                                else:
                                    print("No security findings detected, continuing...")
                            
                            # Capture network traffic context (placeholder)
                            network_context = f"Network activity captured for iteration {iteration_counter + 1}"
                            conversation_history.append({"role": "user", "content": network_context})
                            
                        except Exception as e:
                            print(f"Error in action execution: {str(e)}")
                            error_context = f"Error occurred: {str(e)}"
                            conversation_history.append({"role": "user", "content": error_context})
                        
                        iteration_counter += 1
                        
                        # Brief pause between iterations
                        time.sleep(1)
                    
                    # Store plan findings
                    all_findings.extend(plan_findings)
                    print(f"Plan {plan_idx} completed with {len(plan_findings)} findings")
                
                print(f"✓ URL analysis complete. Total findings so far: {len(all_findings)}")
                
            except Exception as e:
                print(f"✗ Error analyzing {url}: {str(e)}")
                continue
    
    finally:
        # Clean up browser resources
        try:
            print("Cleaning up browser resources...")
            context.close()
            browser.close()
            playwright.stop()
            print("✓ Browser resources cleaned up")
        except Exception as e:
            print(f"Warning: Error during cleanup: {str(e)}")
    
    # FINALIZE: Generate enhanced summary of all findings with business intelligence
    print()
    print("=" * 80)
    print("ENHANCED ORCHESTRATION COMPLETE - EXECUTIVE SUMMARY")
    print("=" * 80)
    print(f"Total URLs analyzed: {len(visited_urls)}")
    print(f"Remaining URLs in queue: {len(urls_to_parse)}")
    print(f"Total tokens used: ~{total_token_counter}")
    print(f"Total security findings: {len(all_findings)}")
    
    if all_findings:
        # Categorize findings by business impact
        critical_findings = [f for f in all_findings if any(term in f for term in ['🔴 CRITICAL', 'CATASTROPHIC', 'STRATEGIC ALERT'])]
        high_findings = [f for f in all_findings if '🟠 HIGH' in f and f not in critical_findings]
        medium_findings = [f for f in all_findings if '🟡 MEDIUM' in f and f not in critical_findings and f not in high_findings]
        low_findings = [f for f in all_findings if '🟢 LOW' in f and f not in critical_findings and f not in high_findings and f not in medium_findings]
        other_findings = [f for f in all_findings if f not in critical_findings and f not in high_findings and f not in medium_findings and f not in low_findings]
        
        print(f"\n📊 BUSINESS IMPACT ANALYSIS:")
        print("-" * 40)
        print(f"🔴 Critical/Catastrophic Findings: {len(critical_findings)}")
        print(f"🟠 High Business Impact: {len(high_findings)}")
        print(f"🟡 Medium Business Impact: {len(medium_findings)}")
        print(f"🟢 Low Business Impact: {len(low_findings)}")
        print(f"📋 Other Findings: {len(other_findings)}")
        
        print("\n🔍 DETAILED SECURITY FINDINGS:")
        print("-" * 40)
        
        if critical_findings:
            print("\n🚨 CRITICAL/CATASTROPHIC FINDINGS (IMMEDIATE EXECUTIVE ATTENTION REQUIRED):")
            for i, finding in enumerate(critical_findings, 1):
                print(f"  {i}. {finding}")
        
        if high_findings:
            print("\n🟠 HIGH BUSINESS IMPACT FINDINGS:")
            for i, finding in enumerate(high_findings, 1):
                print(f"  {i}. {finding}")
        
        if medium_findings:
            print("\n🟡 MEDIUM BUSINESS IMPACT FINDINGS:")
            for i, finding in enumerate(medium_findings, 1):
                print(f"  {i}. {finding}")
        
        if low_findings:
            print("\n🟢 LOW BUSINESS IMPACT FINDINGS:")
            for i, finding in enumerate(low_findings, 1):
                print(f"  {i}. {finding}")
        
        if other_findings:
            print("\n📋 ADDITIONAL FINDINGS:")
            for i, finding in enumerate(other_findings, 1):
                print(f"  {i}. {finding}")
        
        # Executive recommendation section
        print("\n💼 EXECUTIVE RECOMMENDATIONS:")
        print("-" * 40)
        if critical_findings:
            print("🚨 IMMEDIATE ACTION REQUIRED:")
            print("  - Schedule emergency security meeting within 24 hours")
            print("  - Implement temporary mitigations for critical vulnerabilities")
            print("  - Consider temporary service restrictions if necessary")
            print("  - Prepare incident response team activation")
        
        if high_findings:
            print("⚡ HIGH PRIORITY ACTIONS (Next 7 days):")
            print("  - Prioritize high-impact vulnerability remediation")
            print("  - Review and update security controls")
            print("  - Consider third-party security assessment")
        
        if len(all_findings) > 5:
            print("📈 STRATEGIC SECURITY INVESTMENT:")
            print("  - Consider enhanced security program investment")
            print("  - Evaluate current security architecture adequacy")
            print("  - Plan comprehensive security framework upgrade")
        
        # Compliance implications
        compliance_findings = [f for f in all_findings if any(term in f.lower() for term in ['compliance', 'pci dss', 'gdpr', 'sox', 'hipaa', 'iso 27001'])]
        if compliance_findings:
            print("\n⚖️  REGULATORY COMPLIANCE IMPLICATIONS:")
            print(f"  - {len(compliance_findings)} compliance-related findings detected")
            print("  - Consider regulatory notification requirements")
            print("  - Schedule compliance team review")
            print("  - Prepare audit trail documentation")
        
    else:
        print("\n✅ No security vulnerabilities detected in this assessment.")
        print("\n💼 EXECUTIVE SUMMARY:")
        print("  - Current security posture appears adequate")
        print("  - Consider periodic reassessment schedule")
        print("  - Maintain continuous monitoring capabilities")

def _execute_action_command(action_command: str, page) -> str:
    """
    Execute the action command and return the result.
    This is a simplified version for the orchestration framework.
    """
    try:
        # Parse the action command
        if action_command.startswith('goto('):
            # Extract URL from goto command
            url_match = re.search(r'goto\s*\(\s*page\s*,\s*["\']([^"\']*)["\']', action_command)
            if url_match:
                target_url = url_match.group(1)
                if target_url.startswith('/'):
                    # Relative URL, construct full URL
                    current_url = page.url
                    base_url = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}"
                    full_url = urljoin(base_url, target_url)
                else:
                    full_url = target_url
                
                page.goto(full_url, wait_until='networkidle', timeout=10000)
                return f"Successfully navigated to {full_url}. Page title: {page.title()}"
            else:
                return "Error: Could not parse URL from goto command"
        
        elif action_command.startswith('click('):
            # Extract selector from click command
            selector_match = re.search(r'click\s*\(\s*page\s*,\s*["\']([^"\']*)["\']', action_command)
            if selector_match:
                selector = selector_match.group(1)
                element = page.query_selector(selector)
                if element:
                    element.click()
                    return f"Successfully clicked element: {selector}"
                else:
                    return f"Element not found: {selector}"
            else:
                return "Error: Could not parse selector from click command"
        
        elif action_command.startswith('execute_js('):
            # Extract JavaScript from execute_js command
            js_match = re.search(r'execute_js\s*\(\s*page\s*,\s*["\']([^"\']*)["\']', action_command)
            if js_match:
                js_code = js_match.group(1)
                result = page.evaluate(js_code)
                return f"JavaScript executed. Result: {str(result)[:200]}"
            else:
                return "Error: Could not parse JavaScript from execute_js command"
        
        elif action_command.startswith('complete('):
            return "Completed"
        
        else:
            return f"Action command not implemented: {action_command}"
    
    except Exception as e:
        return f"Error executing action: {str(e)}"

def _analyze_conversation_for_findings(conversation_history) -> list:
    """
    Enhanced analysis of conversation history to detect security findings with business context.
    Returns a list of detected security issues with risk assessment.
    """
    findings = []
    
    # Convert conversation to text for analysis
    conversation_text = "\n".join([msg["content"] for msg in conversation_history])
    
    # Extract business context from conversation
    business_impact_context = ""
    attack_complexity_context = ""
    compliance_context = ""
    
    # Look for enhanced plan fields in conversation
    if "Business Impact:" in conversation_text:
        impact_match = re.search(r'Business Impact:\s*([^\n]+)', conversation_text)
        if impact_match:
            business_impact_context = impact_match.group(1)
    
    if "Attack Complexity:" in conversation_text:
        complexity_match = re.search(r'Attack Complexity:\s*([^\n]+)', conversation_text)
        if complexity_match:
            attack_complexity_context = complexity_match.group(1)
    
    if "Compliance Risk:" in conversation_text:
        compliance_match = re.search(r'Compliance Risk:\s*([^\n]+)', conversation_text)
        if compliance_match:
            compliance_context = compliance_match.group(1)
    
    # Enhanced security indicators with business context
    security_indicators = [
        ("Critical SQL Injection", ["sql error", "mysql error", "postgresql error", "syntax error", "union select", "sql injection bypass"]),
        ("Advanced XSS Vulnerability", ["script>alert", "javascript:", "onerror=", "xss", "cross-site scripting", "dom manipulation", "session hijacking"]),
        ("Authentication Architecture Compromise", ["login bypass", "admin access", "unauthorized access", "session hijack", "jwt manipulation", "oauth bypass"]),
        ("Business Logic Exploitation", ["workflow bypass", "transaction manipulation", "privilege escalation", "business rule violation", "approval process bypass"]),
        ("Information Disclosure", ["debug info", "stack trace", "error message", "database schema", "version info", "api documentation", "configuration exposure"]),
        ("Authorization Control Bypass", ["privilege escalation", "idor", "access control", "unauthorized operation", "rbac bypass", "role manipulation"]),
        ("Advanced CSRF Attack", ["csrf token missing", "cross-site request", "state changing operation", "sameSite bypass", "csrf protection bypass"]),
        ("Financial System Compromise", ["payment bypass", "transaction manipulation", "balance modification", "currency conversion abuse", "financial workflow exploit"]),
        ("API Security Vulnerability", ["api authorization bypass", "jwt token manipulation", "graphql introspection", "rest api abuse", "microservices exploitation"]),
        ("Session Management Flaw", ["session fixation", "concurrent session abuse", "token entropy weakness", "session hijacking", "cookie manipulation"]),
        ("Compliance Violation", ["pci dss violation", "gdpr breach", "sox control failure", "hipaa violation", "regulatory control bypass"]),
        ("Enterprise Infrastructure Compromise", ["cloud misconfiguration", "container escape", "devops pipeline compromise", "supply chain attack"]),
        ("Advanced Persistent Threat Simulation", ["stealth technique", "evasion method", "anti-forensics", "persistence mechanism", "lateral movement"]),
        ("Information Warfare Intelligence", ["competitive intelligence", "trade secret exposure", "strategic information disclosure", "intellectual property leak"])
    ]
    
    for vulnerability_type, indicators in security_indicators:
        for indicator in indicators:
            if indicator.lower() in conversation_text.lower():
                # Build enhanced finding with business context
                finding = f"{vulnerability_type}: {indicator} detected"
                
                # Add business impact context if available
                if business_impact_context:
                    if any(term in business_impact_context.upper() for term in ['CRITICAL', 'CATASTROPHIC']):
                        finding += " [🔴 CRITICAL BUSINESS IMPACT]"
                    elif 'HIGH' in business_impact_context.upper():
                        finding += " [🟠 HIGH BUSINESS IMPACT]"
                    elif 'MEDIUM' in business_impact_context.upper():
                        finding += " [🟡 MEDIUM BUSINESS IMPACT]"
                    elif 'LOW' in business_impact_context.upper():
                        finding += " [🟢 LOW BUSINESS IMPACT]"
                
                # Add attack complexity context
                if attack_complexity_context:
                    if any(term in attack_complexity_context.upper() for term in ['EXPERT', 'VERY HIGH']):
                        finding += " [Expert-level exploitation required]"
                    elif 'HIGH' in attack_complexity_context.upper():
                        finding += " [Advanced techniques utilized]"
                
                # Add compliance context
                if compliance_context:
                    finding += f" [Compliance Risk: {compliance_context[:50]}...]"
                
                findings.append(finding)
                break  # Only add each vulnerability type once per conversation
    
    # Look for specific business impact indicators
    business_impact_indicators = [
        ("Financial Loss Potential", ["unauthorized transfer", "payment manipulation", "transaction fraud", "financial system compromise"]),
        ("Data Breach Risk", ["customer data access", "pii exposure", "database compromise", "sensitive information disclosure"]),
        ("Regulatory Compliance Failure", ["audit trail compromise", "control bypass", "compliance violation", "regulatory requirement failure"]),
        ("Operational Disruption", ["system availability impact", "service interruption", "business continuity threat", "operational compromise"]),
        ("Competitive Intelligence Exposure", ["trade secret access", "strategic information leak", "competitive advantage loss", "intellectual property exposure"])
    ]
    
    for impact_type, indicators in business_impact_indicators:
        for indicator in indicators:
            if indicator.lower() in conversation_text.lower():
                findings.append(f"Business Impact: {impact_type} - {indicator} identified")
                break
    
    # Add summary of strategic findings if any critical issues found
    critical_findings = [f for f in findings if any(term in f for term in ['CRITICAL', 'Financial', 'Data Breach', 'Compliance'])]
    if critical_findings:
        findings.append(f"⚠️  STRATEGIC ALERT: {len(critical_findings)} critical business-impact vulnerabilities detected requiring immediate executive attention")
    
    return findings

def _is_same_domain(base_url: str, link_url: str) -> bool:
    """Check if the link URL is from the exact same domain as the base URL (excludes subdomains)."""
    try:
        base_domain = urlparse(base_url).netloc
        link_domain = urlparse(link_url).netloc
        
        # Only allow exact domain match, not subdomains
        return base_domain == link_domain
    except Exception:
        return False

def _is_asset_file(url: str) -> bool:
    """Check if a URL points to an asset file (images, fonts, stylesheets, etc.)."""
    if not url or not isinstance(url, str):
        return False
    
    # Remove query parameters and fragments for extension checking
    parsed_url = urlparse(url)
    path = parsed_url.path.lower()
    
    # Common asset file extensions to skip
    asset_extensions = {
        # Images
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff', '.tif',
        # Fonts
        '.ttf', '.otf', '.woff', '.woff2', '.eot',
        # Stylesheets (already handled in CSS extraction)
        '.css',
        # Client-side scripts (not useful for server-side pentesting)
        '.js',
        # Media files
        '.mp3', '.mp4', '.wav', '.avi', '.mov', '.wmv', '.flv', '.webm', '.ogg',
        # Documents (might be interesting but usually not for crawling)
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # Archives (might be interesting but usually not for crawling)
        '.zip', '.tar', '.gz', '.rar', '.7z',
        # Other common assets
        '.swf', '.manifest', '.map'  # source maps
    }
    
    # Check if the URL ends with any asset extension
    for ext in asset_extensions:
        if path.endswith(ext):
            return True
    
    return False

def _print_plans_for_url(url: str, plans: list):
    """Print enhanced security test plans for a URL in a structured format."""
    print("🔍 ENHANCED SECURITY TEST PLANS")
    print("-" * 50)
    print(f"URL: {url}")
    print(f"Plans Generated: {len(plans)}")
    print()
    
    if not plans:
        print("❌ No security test plans generated for this URL")
        print()
        return
    
    for i, plan in enumerate(plans, 1):
        title = plan.get('title', 'Untitled Plan')
        description = plan.get('description', 'No description available')
        business_impact = plan.get('business_impact', '')
        attack_complexity = plan.get('attack_complexity', '')
        compliance_risk = plan.get('compliance_risk', '')
        
        print(f"📋 Plan {i}: {title}")
        print(f"   Description: {description[:150]}{'...' if len(description) > 150 else ''}")
        
        # Display enhanced fields if available
        if business_impact:
            # Extract impact level for display
            impact_level = "UNKNOWN"
            if any(term in business_impact.upper() for term in ['CRITICAL', 'CATASTROPHIC']):
                impact_level = "🔴 CRITICAL"
            elif 'HIGH' in business_impact.upper():
                impact_level = "🟠 HIGH"
            elif 'MEDIUM' in business_impact.upper():
                impact_level = "🟡 MEDIUM"
            elif 'LOW' in business_impact.upper():
                impact_level = "🟢 LOW"
            
            print(f"   Business Impact: {impact_level}")
            print(f"     Details: {business_impact[:100]}{'...' if len(business_impact) > 100 else ''}")
        
        if attack_complexity:
            # Extract complexity level for display
            complexity_level = "STANDARD"
            if any(term in attack_complexity.upper() for term in ['EXPERT', 'VERY HIGH']):
                complexity_level = "🔥 EXPERT"
            elif 'HIGH' in attack_complexity.upper():
                complexity_level = "⚡ HIGH"
            elif 'MEDIUM' in attack_complexity.upper():
                complexity_level = "⚙️ MEDIUM"
            elif 'LOW' in attack_complexity.upper():
                complexity_level = "🔧 LOW"
            
            print(f"   Attack Complexity: {complexity_level}")
        
        if compliance_risk:
            print(f"   Compliance Risk: {compliance_risk[:80]}{'...' if len(compliance_risk) > 80 else ''}")
        
        print()
    
    print("-" * 50)
    print()

def main():
    try:
        run_orchestration()
    except KeyboardInterrupt:
        print("\nOrchestration interrupted by user")
    except Exception as e:
        print(f"Orchestration failed: {str(e)}")

if __name__ == "__main__":
    main()

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
    base_url = "https://github.com/Avinier"  # Change this to your target URL
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
        planner = PlannerAgent(desc="Security test planner for orchestration phase 2")
        actioner = ActionerAgent(desc="Security test executor for orchestration phase 2")
        context_manager = ContextManagerAgent(desc="Context management for orchestration phase 2")
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
                    print("=" * 50)
                    
                    # Reset conversation history to initial messages (no system prompt needed - handled by ActionerAgent)
                    conversation_history = [
                        {"role": "user", "content": page_data_context}
                    ]
                    
                    # Add tool context and plan-specific instructions to history
                    plan_instructions = f"SECURITY TEST PLAN:\nTitle: {plan.get('title', 'Security Test')}\nDescription: {plan.get('description', 'Perform security testing')}\n\nExecute this plan using the available security testing tools."
                    conversation_history.append({"role": "user", "content": plan_instructions})
                    
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
                            # ACTIONER: Generate action using actioner
                            actioner_response = actioner.generate_action_of_plan_step(
                                plan=plan,
                                page_data=page_data_context,
                                tool_output="",
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
    
    # FINALIZE: Generate summary of all findings
    print()
    print("=" * 80)
    print("ORCHESTRATION COMPLETE - FINAL SUMMARY")
    print("=" * 80)
    print(f"Total URLs analyzed: {len(visited_urls)}")
    print(f"Remaining URLs in queue: {len(urls_to_parse)}")
    print(f"Total tokens used: ~{total_token_counter}")
    print(f"Total security findings: {len(all_findings)}")
    
    if all_findings:
        print("\n🔍 SECURITY FINDINGS SUMMARY:")
        print("-" * 40)
        for i, finding in enumerate(all_findings, 1):
            print(f"{i}. {finding}")
    else:
        print("\n❌ No security vulnerabilities detected in this assessment.")

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
    Analyze conversation history to detect security findings.
    Returns a list of detected security issues.
    """
    findings = []
    
    # Convert conversation to text for analysis
    conversation_text = "\n".join([msg["content"] for msg in conversation_history])
    
    # Look for security indicators
    security_indicators = [
        ("SQL Injection", ["sql error", "mysql error", "postgresql error", "syntax error", "union select"]),
        ("XSS Vulnerability", ["script>alert", "javascript:", "onerror=", "xss", "cross-site scripting"]),
        ("Authentication Bypass", ["login bypass", "admin access", "unauthorized access", "session hijack"]),
        ("Information Disclosure", ["debug info", "stack trace", "error message", "database schema", "version info"]),
        ("Authorization Flaw", ["privilege escalation", "idor", "access control", "unauthorized operation"]),
        ("CSRF Vulnerability", ["csrf token missing", "cross-site request", "state changing operation"])
    ]
    
    for vulnerability_type, indicators in security_indicators:
        for indicator in indicators:
            if indicator.lower() in conversation_text.lower():
                findings.append(f"{vulnerability_type}: {indicator} detected")
                break  # Only add each vulnerability type once per conversation
    
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

def _print_plans_for_url(url: str, plans: list):
    """Print security test plans for a URL in a structured format."""
    print("🔍 SECURITY TEST PLANS")
    print("-" * 40)
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
        
        print(f"📋 Plan {i}: {title}")
        print(f"   Description: {description}")
        print()
    
    print("-" * 40)
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

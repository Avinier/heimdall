# Page Data extraction and planner orchestration

import sys
import time
from tools.webproxy import WebProxy
from tools.pagedata_extractor import PageDataExtractor
from agents.planner import Planner

class SimpleLogger:
    """Simple logger for the orchestration script."""
    
    def info(self, message, color=None):
        """Log info message with optional color."""
        print(f"[INFO] {message}")

def orchestrate_security_analysis(target_url: str):
    """
    Orchestrate the complete security analysis flow.
    
    Args:
        target_url: The URL to analyze
    """
    logger = SimpleLogger()
    
    print("=" * 60)
    print("SECURITY ANALYSIS ORCHESTRATION")
    print("=" * 60)
    print(f"Target URL: {target_url}")
    print()
    
    # Step 1: Initialize Web Proxy and Browser
    print("Step 1: Initializing Web Proxy and Browser...")
    try:
        web_proxy = WebProxy(starting_url=target_url, logger=logger)
        browser, context, page, playwright = web_proxy.create_proxy()
        print("✓ Browser initialized successfully")
        print()
    except Exception as e:
        print(f"✗ Failed to initialize browser: {str(e)}")
        return
    
    try:
        # Step 2: Navigate to target URL
        print("Step 2: Navigating to target URL...")
        page.goto(target_url, wait_until='networkidle', timeout=30000)
        print(f"✓ Successfully navigated to {target_url}")
        print(f"✓ Page title: {page.title()}")
        print()
        
        # Wait a moment for any dynamic content to load
        time.sleep(2)
        
        # Step 3: Extract Page Data
        print("Step 3: Extracting page data...")
        extractor = PageDataExtractor(page)
        page_data = extractor.extract_page_data()
        print("✓ Page data extracted successfully")
        print(f"✓ Data length: {len(page_data)} characters")
        print()
        
        # Step 4: Generate Security Test Plans
        print("Step 4: Generating security test plans...")
        planner = Planner(desc="Security analysis planner")
        security_plans = planner.plan(page_data)
        print(f"✓ Generated {len(security_plans)} security test plans")
        print()
        
        # Step 5: Display Results
        print("=" * 60)
        print("EXTRACTED PAGE DATA")
        print("=" * 60)
        print(page_data)
        print()
        
        print("=" * 60)
        print("GENERATED SECURITY TEST PLANS")
        print("=" * 60)
        
        if security_plans:
            for i, plan in enumerate(security_plans, 1):
                print(f"{i}. {plan['title']}")
                print(f"   Description: {plan['description']}")
                print()
        else:
            print("No security test plans were generated.")
        
        # Step 6: Display Network Traffic (if any was captured)
        print("=" * 60)
        print("CAPTURED NETWORK TRAFFIC")
        print("=" * 60)
        
        network_data = web_proxy.get_network_data()
        if network_data['requests']:
            print(f"Captured {len(network_data['requests'])} requests")
            traffic_summary = web_proxy.pretty_print_traffic()
            if traffic_summary:
                print(traffic_summary)
            else:
                print("No detailed traffic data available")
        else:
            print("No network traffic was captured during the analysis")
        
        print()
        print("=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)
        
    except Exception as e:
        print(f"✗ Error during analysis: {str(e)}")
        
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

def main():
    """Main function to run the orchestration."""
    
    # Default test URL - can be changed for different targets
    default_url = "https://httpbin.org/forms/post"
    
    # Check if URL provided as command line argument
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = default_url
        print(f"No URL provided, using default: {default_url}")
        print("Usage: python orchestration1.py <target_url>")
        print()
    
    # Validate URL format
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
        print(f"Added https:// prefix: {target_url}")
        print()
    
    # Run the orchestration
    try:
        orchestrate_security_analysis(target_url)
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
    except Exception as e:
        print(f"Orchestration failed: {str(e)}")

if __name__ == "__main__":
    main()

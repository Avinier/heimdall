#AVINIERNOTES: 1st Phase of Orchestration: Page Data extraction and Planner testing.
#              So only pagedata_extraction and plans printed.

import sys
import time
import re
from urllib.parse import urljoin, urlparse
from tools.webproxy import WebProxy
from tools.pagedata_extractor import PageDataExtractor
from agents.planner import PlannerAgent

def run_orchestration():
    """
    Run the complete security analysis orchestration.
    
    Steps:
    1. Define base URL to be tested
    2. Initialize urls_to_parse array
    3. Run pagedata_extractor.py
    4. Add found links to the array
    5. While loop: visit URLs, generate plans, print results
    """
    
    # Step 1: Base URL to be tested
    base_url = "https://dev.quantumsenses.com"  # Change this to your target URL
    
    print("=" * 80)
    print("SECURITY ANALYSIS ORCHESTRATION")
    print("=" * 80)
    print(f"Base URL: {base_url}")
    print()
    
    # Step 2: URLs to parse array
    urls_to_parse = [base_url]
    visited_urls = set()
    
    # Initialize browser and planner
    print("Initializing browser and planner...")
    try:
        web_proxy = WebProxy(starting_url=base_url)
        browser, context, page, playwright = web_proxy.create_proxy()
        planner = PlannerAgent(
            desc="Testing planner for first phase of orchestration",
            api_type="fireworks",
            model_key="qwen3-30b-a3b",
            reasoning=True,
            temperature=0.3
        )
        print("✓ Browser and planner initialized successfully")
        print()
    except Exception as e:
        print(f"✗ Failed to initialize: {str(e)}")
        return
    
    try:
        # Step 5: While loop to process URLs
        while urls_to_parse:
            # Visit the URL and start scanning it
            url = urls_to_parse.pop(0)
            
            # Skip if already visited
            if url in visited_urls:
                continue
                
            visited_urls.add(url)
            
            print("=" * 60)
            print(f"ANALYZING URL: {url}")
            print("=" * 60)
            
            try:
                # Navigate to the URL
                print(f"Navigating to: {url}")
                page.goto(url, wait_until='networkidle', timeout=30000)
                print(f"✓ Successfully navigated to {url}")
                print(f"✓ Page title: {page.title()}")
                
                # Wait for dynamic content
                time.sleep(2)
                
                # Step 3: Run pagedata_extractor.py
                print("Extracting page data...")
                extractor = PageDataExtractor(page)
                page_data = extractor.extract_page_data()
                print(f"✓ Page data extracted ({len(page_data)} characters)")
                
                # Step 4: Add found links to the array
                print("Processing discovered links...")
                new_links_count = 0
                
                # Debug: Print extractor attributes
                print(f"  Debug: extractor.links exists: {hasattr(extractor, 'links')}")
                if hasattr(extractor, 'links'):
                    print(f"  Debug: Number of links found: {len(extractor.links)}")
                    print(f"  Debug: First few links: {extractor.links[:3] if extractor.links else 'None'}")
                
                # Extract links from the page data
                if hasattr(extractor, 'links') and extractor.links:
                    for link_info in extractor.links:
                        link_url = link_info.get('url', '')
                        
                        # Skip asset files (images, fonts, etc.)
                        if link_url and _is_asset_file(link_url):
                            print(f"  - Skipped (asset file): {link_url}")
                            continue
                        
                        # Only add links from the same domain
                        if link_url and _is_same_domain(base_url, link_url):
                            if link_url not in visited_urls and link_url not in urls_to_parse:
                                urls_to_parse.append(link_url)
                                new_links_count += 1
                                print(f"  + Added: {link_url}")
                        else:
                            if link_url:
                                print(f"  - Skipped (different domain): {link_url}")
                else:
                    # Fallback: Try to extract links from the formatted page data
                    print("  Fallback: Extracting links from formatted page data...")
                    try:
                        # Look for the Links: [...] pattern in the formatted data
                        links_match = re.search(r"Links: \[(.*?)\]", page_data)
                        if links_match:
                            links_str = links_match.group(1)
                            # Extract URLs from the string (they're in single quotes)
                            fallback_links = re.findall(r"'([^']+)'", links_str)
                            print(f"  Debug: Found {len(fallback_links)} links via fallback method")
                            
                            for link_url in fallback_links:
                                # Skip asset files (images, fonts, etc.)
                                if link_url and _is_asset_file(link_url):
                                    print(f"  - Skipped (asset file, fallback): {link_url}")
                                    continue
                                
                                # Only add links from the same domain
                                if link_url and _is_same_domain(base_url, link_url):
                                    if link_url not in visited_urls and link_url not in urls_to_parse:
                                        urls_to_parse.append(link_url)
                                        new_links_count += 1
                                        print(f"  + Added (fallback): {link_url}")
                                else:
                                    if link_url:
                                        print(f"  - Skipped (different domain, fallback): {link_url}")
                        else:
                            print("  No links found in formatted page data")
                    except Exception as fallback_error:
                        print(f"  Fallback link extraction failed: {str(fallback_error)}")
                
                print(f"✓ Added {new_links_count} new links to scan queue")
                print(f"✓ Queue size: {len(urls_to_parse)}, Visited: {len(visited_urls)}")
                print()
                
                # Generate plan for current URL
                print("Generating security test plans...")
                plans = planner.plan(page_data)
                print(f"✓ Generated {len(plans)} security test plans")
                print()
                
                # Print plans in structured format
                _print_plans_for_url(url, plans)
                
            except Exception as e:
                print(f"✗ Error analyzing {url}: {str(e)}")
                print()
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
    
    print()
    print("=" * 80)
    print("ORCHESTRATION COMPLETE")
    print("=" * 80)
    print(f"Total URLs analyzed: {len(visited_urls)}")
    print(f"Remaining URLs in queue: {len(urls_to_parse)}")

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

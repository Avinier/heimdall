import asyncio
import json
import time
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, ElementHandle
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PlaywrightCrawler:
    """
    Comprehensive Playwright browser automation class designed to be controlled by LLM responses.
    Provides all essential browser operations for web automation tasks.
    """
    
    def __init__(self, 
                 headless: bool = False,
                 browser_type: str = "chromium",
                 viewport_size: Dict[str, int] = None,
                 user_agent: str = None,
                 timeout: int = 30000):
        """
        Initialize the Playwright crawler.
        
        Args:
            headless (bool): Run browser in headless mode
            browser_type (str): Browser type ('chromium', 'firefox', 'webkit')
            viewport_size (Dict): Viewport dimensions {'width': 1920, 'height': 1080}
            user_agent (str): Custom user agent string
            timeout (int): Default timeout in milliseconds
        """
        self.headless = headless
        self.browser_type = browser_type
        self.viewport_size = viewport_size or {"width": 1920, "height": 1080}
        self.user_agent = user_agent
        self.timeout = timeout
        
        # Browser instances
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        
        # State tracking
        self.is_initialized = False
        self.current_url = None
        self.page_title = None
        
    async def initialize(self) -> Dict[str, Any]:
        """
        Initialize the browser and create a new page.
        
        Returns:
            Dict: Initialization status and browser info
        """
        try:
            self.playwright = await async_playwright().start()
            
            # Get browser launcher based on type
            if self.browser_type == "chromium":
                browser_launcher = self.playwright.chromium
            elif self.browser_type == "firefox":
                browser_launcher = self.playwright.firefox
            elif self.browser_type == "webkit":
                browser_launcher = self.playwright.webkit
            else:
                raise ValueError(f"Unsupported browser type: {self.browser_type}")
            
            # Launch browser
            self.browser = await browser_launcher.launch(
                headless=self.headless,
                args=['--no-sandbox', '--disable-dev-shm-usage'] if self.browser_type == "chromium" else None
            )
            
            # Create context
            context_options = {
                "viewport": self.viewport_size,
                "ignore_https_errors": True,
            }
            if self.user_agent:
                context_options["user_agent"] = self.user_agent
                
            self.context = await self.browser.new_context(**context_options)
            
            # Set default timeout
            self.context.set_default_timeout(self.timeout)
            
            # Create page
            self.page = await self.context.new_page()
            
            self.is_initialized = True
            
            logger.info(f"Browser initialized: {self.browser_type}, headless: {self.headless}")
            
            return {
                "status": "success",
                "browser_type": self.browser_type,
                "headless": self.headless,
                "viewport": self.viewport_size,
                "user_agent": self.user_agent or "default"
            }
            
        except Exception as e:
            logger.error(f"Failed to initialize browser: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def navigate_to(self, url: str, wait_until: str = "networkidle") -> Dict[str, Any]:
        """
        Navigate to a URL.
        
        Args:
            url (str): URL to navigate to
            wait_until (str): When to consider navigation complete
                            ('load', 'domcontentloaded', 'networkidle')
        
        Returns:
            Dict: Navigation result with page info
        """
        if not self.is_initialized:
            await self.initialize()
        
        try:
            response = await self.page.goto(url, wait_until=wait_until)
            
            # Update state
            self.current_url = self.page.url
            self.page_title = await self.page.title()
            
            result = {
                "status": "success",
                "url": self.current_url,
                "title": self.page_title,
                "status_code": response.status if response else None,
                "final_url": self.current_url  # In case of redirects
            }
            
            logger.info(f"Navigated to: {self.current_url}")
            return result
            
        except PlaywrightTimeoutError:
            return {
                "status": "error",
                "error": f"Navigation timeout after {self.timeout}ms",
                "url": url
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "url": url
            }
    
    async def get_page_content(self) -> Dict[str, Any]:
        """
        Get current page content and metadata.
        
        Returns:
            Dict: Page content and metadata
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            content = await self.page.content()
            title = await self.page.title()
            url = self.page.url
            
            return {
                "status": "success",
                "url": url,
                "title": title,
                "html_content": content,
                "content_length": len(content)
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def get_text_content(self, selector: str = "body") -> Dict[str, Any]:
        """
        Extract text content from page or specific element.
        
        Args:
            selector (str): CSS selector for element (default: "body")
        
        Returns:
            Dict: Text content
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            element = await self.page.query_selector(selector)
            if element:
                text = await element.text_content()
                return {
                    "status": "success",
                    "selector": selector,
                    "text": text,
                    "length": len(text) if text else 0
                }
            else:
                return {
                    "status": "error",
                    "error": f"Element not found: {selector}"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "selector": selector
            }
    
    async def click_element(self, selector: str, timeout: int = None) -> Dict[str, Any]:
        """
        Click on an element.
        
        Args:
            selector (str): CSS selector for element to click
            timeout (int): Timeout in milliseconds
        
        Returns:
            Dict: Click result
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            await self.page.click(selector, timeout=timeout or self.timeout)
            
            return {
                "status": "success",
                "action": "click",
                "selector": selector,
                "current_url": self.page.url
            }
            
        except PlaywrightTimeoutError:
            return {
                "status": "error",
                "error": f"Element not found or not clickable: {selector}",
                "selector": selector
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "selector": selector
            }
    
    async def fill_input(self, selector: str, text: str, clear_first: bool = True) -> Dict[str, Any]:
        """
        Fill an input field with text.
        
        Args:
            selector (str): CSS selector for input element
            text (str): Text to fill
            clear_first (bool): Clear field before filling
        
        Returns:
            Dict: Fill result
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            if clear_first:
                await self.page.fill(selector, "")
            
            await self.page.fill(selector, text)
            
            return {
                "status": "success",
                "action": "fill",
                "selector": selector,
                "text_length": len(text)
            }
            
        except PlaywrightTimeoutError:
            return {
                "status": "error",
                "error": f"Input field not found: {selector}",
                "selector": selector
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "selector": selector
            }
    
    async def select_option(self, selector: str, value: str = None, label: str = None, index: int = None) -> Dict[str, Any]:
        """
        Select an option from a dropdown.
        
        Args:
            selector (str): CSS selector for select element
            value (str): Option value to select
            label (str): Option label to select
            index (int): Option index to select
        
        Returns:
            Dict: Selection result
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            if value is not None:
                await self.page.select_option(selector, value=value)
                selected = value
            elif label is not None:
                await self.page.select_option(selector, label=label)
                selected = label
            elif index is not None:
                await self.page.select_option(selector, index=index)
                selected = f"index_{index}"
            else:
                return {
                    "status": "error",
                    "error": "Must provide value, label, or index"
                }
            
            return {
                "status": "success",
                "action": "select",
                "selector": selector,
                "selected": selected
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "selector": selector
            }
    
    async def wait_for_element(self, selector: str, state: str = "visible", timeout: int = None) -> Dict[str, Any]:
        """
        Wait for an element to reach a specific state.
        
        Args:
            selector (str): CSS selector for element
            state (str): State to wait for ('visible', 'hidden', 'attached', 'detached')
            timeout (int): Timeout in milliseconds
        
        Returns:
            Dict: Wait result
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            await self.page.wait_for_selector(selector, state=state, timeout=timeout or self.timeout)
            
            return {
                "status": "success",
                "action": "wait",
                "selector": selector,
                "state": state
            }
            
        except PlaywrightTimeoutError:
            return {
                "status": "error",
                "error": f"Element did not reach state '{state}': {selector}",
                "selector": selector,
                "state": state
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "selector": selector
            }
    
    async def get_elements(self, selector: str) -> Dict[str, Any]:
        """
        Get information about elements matching a selector.
        
        Args:
            selector (str): CSS selector
        
        Returns:
            Dict: Elements information
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            elements = await self.page.query_selector_all(selector)
            
            elements_info = []
            for i, element in enumerate(elements):
                try:
                    text = await element.text_content()
                    is_visible = await element.is_visible()
                    tag_name = await element.evaluate("el => el.tagName.toLowerCase()")
                    
                    element_info = {
                        "index": i,
                        "tag": tag_name,
                        "text": text[:100] + "..." if text and len(text) > 100 else text,
                        "visible": is_visible
                    }
                    
                    # Get common attributes
                    for attr in ["id", "class", "href", "src", "type", "name"]:
                        value = await element.get_attribute(attr)
                        if value:
                            element_info[attr] = value
                    
                    elements_info.append(element_info)
                    
                except Exception as e:
                    elements_info.append({
                        "index": i,
                        "error": str(e)
                    })
            
            return {
                "status": "success",
                "selector": selector,
                "count": len(elements),
                "elements": elements_info
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "selector": selector
            }
    
    async def take_screenshot(self, path: str = None, full_page: bool = False) -> Dict[str, Any]:
        """
        Take a screenshot of the current page.
        
        Args:
            path (str): File path to save screenshot (optional)
            full_page (bool): Capture full page or just viewport
        
        Returns:
            Dict: Screenshot result
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            if path is None:
                timestamp = int(time.time())
                path = f"screenshot_{timestamp}.png"
            
            # Ensure directory exists
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            
            await self.page.screenshot(path=path, full_page=full_page)
            
            return {
                "status": "success",
                "action": "screenshot",
                "path": path,
                "full_page": full_page,
                "url": self.page.url
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "path": path
            }
    
    async def execute_javascript(self, script: str) -> Dict[str, Any]:
        """
        Execute JavaScript code on the page.
        
        Args:
            script (str): JavaScript code to execute
        
        Returns:
            Dict: Execution result
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            result = await self.page.evaluate(script)
            
            return {
                "status": "success",
                "action": "javascript",
                "result": result,
                "script_length": len(script)
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "script": script[:100] + "..." if len(script) > 100 else script
            }
    
    async def scroll_page(self, direction: str = "down", amount: int = None) -> Dict[str, Any]:
        """
        Scroll the page.
        
        Args:
            direction (str): Scroll direction ('up', 'down', 'top', 'bottom')
            amount (int): Scroll amount in pixels (for up/down)
        
        Returns:
            Dict: Scroll result
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            if direction == "top":
                await self.page.evaluate("window.scrollTo(0, 0)")
            elif direction == "bottom":
                await self.page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            elif direction == "down":
                scroll_amount = amount or self.viewport_size["height"]
                await self.page.evaluate(f"window.scrollBy(0, {scroll_amount})")
            elif direction == "up":
                scroll_amount = amount or self.viewport_size["height"]
                await self.page.evaluate(f"window.scrollBy(0, -{scroll_amount})")
            else:
                return {
                    "status": "error",
                    "error": f"Invalid direction: {direction}"
                }
            
            return {
                "status": "success",
                "action": "scroll",
                "direction": direction,
                "amount": amount
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "direction": direction
            }
    
    async def get_page_info(self) -> Dict[str, Any]:
        """
        Get comprehensive information about the current page.
        
        Returns:
            Dict: Page information
        """
        if not self.page:
            return {"status": "error", "error": "No page available"}
        
        try:
            info = {
                "status": "success",
                "url": self.page.url,
                "title": await self.page.title(),
                "viewport": await self.page.viewport_size(),
            }
            
            # Get page metrics via JavaScript
            metrics = await self.page.evaluate("""
                () => {
                    return {
                        scroll_position: {
                            x: window.pageXOffset,
                            y: window.pageYOffset
                        },
                        page_size: {
                            width: document.body.scrollWidth,
                            height: document.body.scrollHeight
                        },
                        viewport_size: {
                            width: window.innerWidth,
                            height: window.innerHeight
                        },
                        ready_state: document.readyState,
                        forms_count: document.forms.length,
                        links_count: document.links.length,
                        images_count: document.images.length
                    }
                }
            """)
            
            info.update(metrics)
            return info
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def close(self) -> Dict[str, Any]:
        """
        Close the browser and clean up resources.
        
        Returns:
            Dict: Cleanup result
        """
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            
            # Reset state
            self.page = None
            self.context = None
            self.browser = None
            self.playwright = None
            self.is_initialized = False
            
            logger.info("Browser closed successfully")
            
            return {
                "status": "success",
                "action": "close"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    # Context manager support
    async def __aenter__(self):
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# Convenience function for quick usage
async def create_crawler(headless: bool = False, browser_type: str = "chromium") -> PlaywrightCrawler:
    """
    Create and initialize a PlaywrightCrawler instance.
    
    Args:
        headless (bool): Run browser in headless mode
        browser_type (str): Browser type ('chromium', 'firefox', 'webkit')
    
    Returns:
        PlaywrightCrawler: Initialized crawler instance
    """
    crawler = PlaywrightCrawler(headless=headless, browser_type=browser_type)
    await crawler.initialize()
    return crawler


# Example usage and testing function
async def demo_crawler():
    """
    Demonstration of the PlaywrightCrawler capabilities.
    """
    print("🎭 Playwright Crawler Demo")
    print("=" * 50)
    
    # Create crawler
    async with PlaywrightCrawler(headless=False) as crawler:
        print("✅ Browser initialized")
        
        # Navigate to a page
        result = await crawler.navigate_to("https://example.com")
        print(f"📍 Navigation: {result['status']} - {result.get('title', 'No title')}")
        
        # Get page info
        info = await crawler.get_page_info()
        print(f"📊 Page info: {info['url']} ({info.get('ready_state', 'unknown')})")
        
        # Take screenshot
        screenshot_result = await crawler.take_screenshot("demo_screenshot.png")
        print(f"📸 Screenshot: {screenshot_result['status']}")
        
        # Get text content
        text_result = await crawler.get_text_content("body")
        if text_result['status'] == 'success':
            text_preview = text_result['text'][:100] + "..." if len(text_result['text']) > 100 else text_result['text']
            print(f"📝 Text content: {text_preview}")
        
        print("🎭 Demo completed!")


if __name__ == "__main__":
    # Run demo if script is executed directly
    asyncio.run(demo_crawler())

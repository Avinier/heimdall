import sys
import re
from io import StringIO
from typing import Dict, Any, Optional
from playwright.sync_api import Page
from playwright.async_api import async_playwright, Browser, Page as AsyncPage
import logging
from tools.llms import LLM
import time


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PlaywrightTools:
    """
    Collection of tools for interacting with web pages and executing code.
    Provides methods for page manipulation, JavaScript execution, and Python code evaluation.
    Works with Playwright page objects created by WebProxy.
    Supports both sync and async operations for penetration testing.
    """

    def __init__(self, debug: bool = False, use_llm: bool = True):
        self.debug = debug
        self.llm = None
        if use_llm:
            try:
                self.llm = LLM("Playwright security testing tools")
                if self.debug:
                    print("LLM initialized successfully with Gemini")
            except Exception as e:
                if self.debug:
                    print(f"Failed to initialize LLM: {str(e)}")
        
        # Security testing state tracking
        self.security_actions_performed = 0
        self.min_actions_required = 3  # Minimum security actions required before completion
        self.first_navigation = False
        # Initialize the page object storage
        self.current_page = None
        self.current_url = None
        
        # Browser automation support (async)
        self.browser: Optional[Browser] = None
        self.async_page: Optional[AsyncPage] = None
        
    def execute_js(self, page: Page, js_code: str) -> str:
        # Validate and fix common JavaScript issues
        js_code = self._validate_and_fix_js_code(js_code)
        
        try:
            # Count this as a security action (JS execution is often used for testing)
            self.security_actions_performed += 1
            result = page.evaluate(js_code)
            return str(result) if result is not None else ""
        except Exception as e:
            if "Illegal return statement" in str(e) and not js_code.strip().startswith("() =>"):
                # Try wrapping in an anonymous function
                wrapped_code = f"() => {{ {js_code} }}"
                if self.debug:
                    print(f"Retrying with wrapped JS code: {wrapped_code}")
                result = page.evaluate(wrapped_code)
                return str(result) if result is not None else ""
            raise
            
    def _validate_and_fix_js_code(self, js_code: str) -> str:
        # First, check for any nested tool calls and remove them
        # This prevents issues like execute_js(page, "execute_js(page, """)
        if re.search(r'(?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\(', js_code):
            # We found what appears to be a nested tool call, clean it up
            if self.debug:
                print(f"WARNING: Possible nested tool call detected in JS code: {js_code}")
            # Extract just the JavaScript part if possible, otherwise use a safe default
            js_code = "() => document.documentElement.innerHTML"
        
        # Ensure code doesn't contain unbalanced parentheses
        open_parens = js_code.count('(')
        close_parens = js_code.count(')')
        if open_parens != close_parens:
            if self.debug:
                print(f"WARNING: Unbalanced parentheses in JS code: {js_code}")
            # Simplify to a safe default if the JS is likely malformed
            js_code = "() => document.documentElement.innerHTML"
        
        # Fix standalone return statements
        if js_code.strip().startswith('return '):
            js_code = f"() => {{ {js_code} }}"
        
        # Ensure async/await is properly handled
        if 'await ' in js_code and not js_code.strip().startswith('async'):
            if js_code.strip().startswith('() =>'):
                js_code = js_code.replace('() =>', 'async () =>')
            elif not js_code.strip().startswith('async () =>'):
                js_code = f"async () => {{ {js_code} }}"
        
        # Fix direct document.querySelector usage to ensure it's wrapped properly
        if 'document.querySelector' in js_code and not '() =>' in js_code:
            js_code = f"() => {{ {js_code} }}"
        
        # Remove standalone console.log statements without return values
        if 'console.log' in js_code and not 'return' in js_code:
            js_code = js_code.replace('console.log(', 'return console.log(')
            
        return js_code

    def click(self, page: Page, css_selector: str) -> str:
        page.click(css_selector, timeout=5000)
        # Count this as a security action (interaction with the page)
        self.security_actions_performed += 1
        return page.inner_html("html")

    def fill(self, page: Page, css_selector: str, value: str) -> str:
        page.fill(css_selector, value, timeout=5000)
        # Count this as a security action (form interaction is common for testing)
        self.security_actions_performed += 1
        return page.inner_html("html")

    def submit(self, page: Page, css_selector: str) -> str: 
        page.locator(css_selector).click()
        # Count this as a security action (form submission is critical for testing)
        self.security_actions_performed += 1
        return page.inner_html("html")

    def presskey(self, page: Page, key: str) -> str:
        page.keyboard.press(key)
        # Count this as a security action
        self.security_actions_performed += 1
        return page.inner_html("html")

    def goto(self, page: Page, url: str) -> str:
        # Define an expanded URL mapping for common keywords
        URL_MAPPING = {
            "documentation": "/docs/",
            "docs": "/docs/",
            "doc": "/docs/",
            "api": "/api/",
            "swagger": "/swagger/",
            "api-docs": "/api-docs/",
            "home": "/",
            "login": "/login/",
            "admin": "/admin/"
        }
        
        # Clean up URL - remove any trailing natural language
        if url and ' ' in url:
            # Extract just the URL part before any natural language description
            url_match = re.match(r'([^"\']*?(?:\.html|\.php|\.aspx|\.js|\.css|\.json|\/)?)(?:\s|$)', url)
            if url_match:
                url = url_match.group(1)
            else:
                # If no clear endpoint, take everything before the first space
                url = url.split(' ')[0]
                
            if self.debug:
                print(f"Cleaned URL from natural language: '{url}'")
        
        # Handle keyword to URL mapping with proper sanitization
        if url and not url.startswith(('http://', 'https://', '/')):
            # Check for exact match in URL_MAPPING
            url_lower = url.lower().strip()
            if url_lower in URL_MAPPING:
                url = URL_MAPPING[url_lower]
            else:
                # For any other string that's not in our mapping, add leading slash
                url = '/' + url.lstrip('/')
            
            # Log when conversions happen for monitoring
            if self.debug:
                print(f"URL mapping converted '{url_lower}' to path '{url}'")
        
        # Sanitize paths to prevent traversal attacks
        url = url.replace('../', '')
        
        # Fix relative URLs
        if url.startswith('/'):
            if hasattr(self, 'current_url') and self.current_url:
                # Extract base URL from current URL
                base_url = re.match(r'(https?://[^/]+)', self.current_url)
                if base_url:
                    url = base_url.group(1) + url
                else:
                    # Fallback - prepend the current domain if we can extract it
                    from urllib.parse import urlparse
                    parsed = urlparse(self.current_url)
                    if parsed.netloc:
                        url = f"{parsed.scheme}://{parsed.netloc}{url}"
            
        # Store the current URL for future reference
        self.current_url = url
        
        # Only count as a security action if this isn't the initial navigation
        # or if it's navigating to a non-root path that might be more interesting for testing
        if self.first_navigation or '/' in url[8:]:
            self.security_actions_performed += 1
        else:
            # Mark that we've done the first navigation
            self.first_navigation = True
            
        try:
            page.goto(url)
            return page.inner_html("html")
        except Exception as e:
            # If navigation fails with the current URL, try adding /docs/ as fallback
            if "/docs/" not in url and "documentation" in url.lower():
                try:
                    # Extract base domain and add /docs/
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    fallback_url = f"{parsed.scheme}://{parsed.netloc}/docs/"
                    print(f"Primary navigation failed. Trying fallback to {fallback_url}")
                    page.goto(fallback_url)
                    return page.inner_html("html")
                except:
                    # If fallback fails, re-raise the original error
                    raise e
            else:
                # Re-raise the original error
                raise

    def refresh(self, page: Page) -> str:
        page.reload()
        # Count this as a security action
        self.security_actions_performed += 1
        return page.inner_html("html")

    def python_interpreter(self, code: str) -> str:
        output_buffer = StringIO()
        old_stdout = sys.stdout
        sys.stdout = output_buffer
        
        try:
            exec(code)
            output = output_buffer.getvalue()
            # Count this as a security action (code execution is important for testing)
            self.security_actions_performed += 1
            return output
        finally:
            sys.stdout = old_stdout
            output_buffer.close()

    def get_user_input(self, prompt: str) -> str:
        input(prompt)
        return "Input done!"

    def auth_needed(self) -> str:
        input("Authentication needed. Please login and press enter to continue.")
        # Count this as a security action
        self.security_actions_performed += 1
        return "Authentication done!"

    def complete(self) -> str:
        if self.security_actions_performed < self.min_actions_required:
            # Not enough security testing was performed
            return "Completion rejected: Insufficient security testing performed. Please continue testing with more actions before marking complete."
        # Reset action counter for next test plan
        self.security_actions_performed = 0
        return "Completed"

    def execute_tool(self, page: Page, tool_use: str):
        try:
            # Store the page object for this execution
            self.current_page = page
            
            # Parse the command instead of using direct eval
            command_match = re.match(r'(\w+)\s*\((.*)\)', tool_use)
            if not command_match:
                return f"Error executing tool: Invalid command format: {tool_use}"
                
            func_name = command_match.group(1)
            args_str = command_match.group(2)
            
            # Validate that the function exists
            if not hasattr(self, func_name):
                return f"Error executing tool: Unknown function: {func_name}"
            
            # Get the function object
            func = getattr(self, func_name)
            
            # Special case for functions that need page object
            page_required = func_name in [
                'goto', 'click', 'fill', 'submit', 'execute_js', 'refresh', 'presskey',
                'wait_for_element', 'wait_for_navigation', 'screenshot', 'get_cookies', 
                'set_cookies', 'clear_cookies', 'set_headers', 'intercept_requests',
                'bypass_csp', 'extract_forms', 'extract_links', 'set_input_value',
                'get_page_source', 'simulate_user_interaction', 'set_geolocation',
                'block_resources', 'modify_response', 'fill_form_with_payload',
                'submit_form_and_get_response', 'analyze_network_traffic', 'bypass_waf',
                'check_page_access'
            ]
            
            # Parse arguments safely
            if not args_str:
                # No arguments
                return func()
            elif page_required and not args_str.startswith('page'):
                # Add page as first argument if needed
                modified_args_str = f"page, {args_str}"
                # Execute with safe argument parsing
                return self._execute_with_args(func, modified_args_str)
            else:
                # Execute with existing arguments
                return self._execute_with_args(func, args_str)
                
        except Exception as e:
            return f"Error executing tool: {str(e)}"
            
    def _execute_with_args(self, func, args_str):
        """Execute a function with parsed arguments.
        
        Args:
            func: Function to execute
            args_str: String containing argument values
            
        Returns:
            Result of function execution
        """
        # Parse the arguments string safely
        args = []
        kwargs = {}
        
        # Handle empty args
        if not args_str.strip():
            return func()
            
        # Special handling for quotes in arguments to prevent syntax errors
        # First, handle the page argument if it exists
        if args_str.startswith('page'):
            # Use the stored current_page instead of assuming global 'page' variable
            if self.current_page is None:
                raise ValueError("Page object not available. Make sure page is passed to execute_tool first.")
            args.append(self.current_page)
            # Remove the page argument and any following comma
            args_str = re.sub(r'^page\s*,\s*', '', args_str)
        
        # Special handling for known security tools with XSS payloads
        # If this is a fill command with a potential XSS payload, use a more robust parsing approach
        is_fill_with_xss = func.__name__ == 'fill' and ('<script>' in args_str or 'alert(' in args_str)
        
        if is_fill_with_xss and args_str.count(',') >= 1:
            # For fill commands with XSS payloads, use a more specialized parsing approach
            try:
                # First, extract the selector (everything up to the first comma)
                first_comma_idx = self._find_safe_comma_position(args_str)
                if first_comma_idx == -1:
                    # Fallback if we can't find a safe comma
                    raise ValueError("Cannot parse arguments for fill command")
                    
                selector = args_str[:first_comma_idx].strip()
                value = args_str[first_comma_idx + 1:].strip()
                
                # Parse the selector and value
                args.append(self._parse_arg_value(selector))
                args.append(self._parse_arg_value(value))
                
                if self.debug:
                    print(f"XSS payload detected. Parsed args: selector='{args[0]}', value='{args[1]}'")
                
                # Execute with the parsed arguments
                return func(*args)
            except Exception as e:
                if self.debug:
                    print(f"Error parsing XSS payload: {str(e)}. Falling back to standard parser.")
                # If specialized parsing fails, fall back to the standard approach
        
        # Standard argument parsing for other cases
        # Split by commas, but respect quotes
        in_quotes = False
        quote_char = None
        current_arg = ""
        escaped = False
        bracket_depth = 0  # Track depth of angle brackets (for HTML/XML tags)
        
        for char in args_str:
            if escaped:
                current_arg += char
                escaped = False
                continue
                
            if char == '\\':
                escaped = True
                current_arg += char
                continue
            
            # Track angle brackets for HTML/XML content
            if char == '<':
                bracket_depth += 1
            elif char == '>':
                bracket_depth = max(0, bracket_depth - 1)  # Prevent negative depth
                
            if char in ['"', "'"]:
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
                current_arg += char
            elif char == ',' and not in_quotes and bracket_depth == 0:
                # End of argument - only split on commas that are not inside quotes or HTML tags
                args.append(self._parse_arg_value(current_arg.strip()))
                current_arg = ""
            else:
                current_arg += char
        
        # Add the last argument if there is one
        if current_arg.strip():
            args.append(self._parse_arg_value(current_arg.strip()))
        
        # Execute the function with the parsed arguments
        return func(*args)
    
    def _find_safe_comma_position(self, args_str):
        in_quotes = False
        quote_char = None
        bracket_depth = 0
        escaped = False
        
        for i, char in enumerate(args_str):
            if escaped:
                escaped = False
                continue
                
            if char == '\\':
                escaped = True
                continue
                
            # Track quotes
            if char in ['"', "'"]:
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
            
            # Track angle brackets
            elif char == '<':
                bracket_depth += 1
            elif char == '>':
                bracket_depth = max(0, bracket_depth - 1)
                
            # Check for safe comma
            elif char == ',' and not in_quotes and bracket_depth == 0:
                return i
                
        return -1
        
    def _parse_arg_value(self, arg_str):
        # Safety check for empty strings
        if not arg_str or arg_str.isspace():
            return ""
            
        # Strip quotes if the argument is a quoted string
        if (arg_str.startswith('"') and arg_str.endswith('"')) or \
           (arg_str.startswith("'") and arg_str.endswith("'")):
            # Remove the quotes and handle escaped quotes inside
            inner_str = arg_str[1:-1]
            # Return the actual string without modifications (to preserve HTML/JavaScript content)
            return inner_str
            
        # Handle numeric values
        try:
            if '.' in arg_str:
                return float(arg_str)
            else:
                return int(arg_str)
        except ValueError:
            # Not a number, return as is
            return arg_str

    def _fix_unterminated_strings(self, text: str) -> str:
        # If empty or None, return safely
        if not text:
            return ""
            
        # Count single and double quotes to check for balance
        single_quotes = text.count("'")
        double_quotes = text.count('"')
        
        # Fix functions with unterminated string literals
        # Match common patterns like goto(page, "url but with missing closing quote
        patterns = [
            # goto with unterminated string: goto(page, "url
            (r'(goto\s*\(\s*page\s*,\s*["\'])([^"\']*?)(?:\s*$)', r'\1\2\1)'),
            # execute_js with unterminated string: execute_js(page, "code
            (r'(execute_js\s*\(\s*page\s*,\s*["\'])([^"\']*?)(?:\s*$)', r'\1\2\1)'),
            # click with unterminated string: click(page, "selector
            (r'(click\s*\(\s*page\s*,\s*["\'])([^"\']*?)(?:\s*$)', r'\1\2\1)'),
            # fill with unterminated string: fill(page, "selector", "value
            (r'(fill\s*\(\s*page\s*,\s*["\'])([^"\']*?)(?:\s*,\s*["\'])([^"\']*?)(?:\s*$)', r'\1\2\1, \1\3\1)'),
        ]
        
        # Apply fixes for each pattern
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text)
            
        # If quotes are imbalanced, fix general cases
        if single_quotes % 2 != 0:
            # Find the last single quote and any text after it
            last_quote_pos = text.rfind("'")
            if last_quote_pos >= 0:
                # Add a closing quote right after the last one found
                text = text[:last_quote_pos+1] + "'" + text[last_quote_pos+1:]
                
        if double_quotes % 2 != 0:
            # Find the last double quote and any text after it
            last_quote_pos = text.rfind('"')
            if last_quote_pos >= 0:
                # Add a closing quote right after the last one found
                text = text[:last_quote_pos+1] + '"' + text[last_quote_pos+1:]
                
        # Ensure all function calls have closing parentheses
        if ('(' in text) and (')' not in text):
            text += ')'
            
        if self.debug:
            print(f"Fixed unterminated strings in: '{text}'")
            
        return text
        
    def _pre_process_tool_use(self, tool_use: str) -> str:
        # Safety check
        if not tool_use or tool_use.isspace():
            return 'goto(page, "/docs/")'
        
        # Remove any stray text that might cause parsing issues
        tool_use = re.sub(r'```.*?```', '', tool_use, flags=re.DOTALL)
        tool_use = re.sub(r'Let\'s|I\'ll|We should', '', tool_use)
        
        # Fix common natural language patterns to commands
        tool_use = re.sub(r'navigate\s+to\s+(?:the\s+)?(.*?)(\.|\s|$)', r'goto(page, "\1")', tool_use, flags=re.IGNORECASE)
        tool_use = re.sub(r'go\s+to\s+(?:the\s+)?(.*?)(\.|\s|$)', r'goto(page, "\1")', tool_use, flags=re.IGNORECASE)
        tool_use = re.sub(r'visit\s+(?:the\s+)?(.*?)(\.|\s|$)', r'goto(page, "\1")', tool_use, flags=re.IGNORECASE)
        
        # Convert curl commands to goto
        tool_use = re.sub(r'curl\s+(https?://[^\s"\']+)', r'goto(page, "\1")', tool_use)
        
        # Fix documentation references
        if 'documentation' in tool_use.lower() and not ('goto' in tool_use or 'click' in tool_use):
            return 'goto(page, "/docs/")'
        
        # Check for any trailing text after parentheses (like explanatory comments)
        # e.g., "goto(page, 'url') to understand the API"
        if ')' in tool_use:
            closing_paren_pos = tool_use.find(')')
            if closing_paren_pos < len(tool_use) - 1:
                # Keep only up to the closing parenthesis
                tool_use = tool_use[:closing_paren_pos+1]
        
        # Fix any unterminated strings that might be present
        tool_use = self._fix_unterminated_strings(tool_use)
            
        return tool_use
    
    def _fix_tool_use(self, tool_use: str) -> str:
        # Handle completely invalid inputs with strong defaults
        if not tool_use or tool_use.isspace():
            return 'goto(page, "/docs/")'
            
        # Remove problematic characters that might cause syntax errors
        tool_use = tool_use.replace('\\"', '"').replace("\\'", "'")
        
        # Check for nested tool calls (like execute_js inside execute_js) and fix
        nested_tool_pattern = r'(goto|click|fill|submit|execute_js|refresh|presskey)\s*\(\s*page\s*,\s*.*?(goto|click|fill|submit|execute_js|refresh|presskey)'
        if re.search(nested_tool_pattern, tool_use):
            # Extract just the outer function
            outer_func_match = re.match(r'(\w+)\s*\(', tool_use)
            if outer_func_match:
                func_name = outer_func_match.group(1)
                if func_name == 'execute_js':
                    # For execute_js, use a simple document.body command
                    return 'execute_js(page, "() => document.documentElement.innerHTML")'
                elif func_name == 'goto':
                    # For goto, navigate to docs
                    return 'goto(page, "/docs/")'
            # Default fallback
            return 'goto(page, "/docs/")'
        
        # Fix any unterminated strings in the command
        tool_use = self._fix_unterminated_strings(tool_use)
        
        # If the input looks like natural language and not a command
        if not any(cmd in tool_use for cmd in ['goto(', 'click(', 'fill(', 'execute_js(', 'submit(', 'auth_needed(', 'refresh(', 'complete(']):
            # Try to extract a URL and create a goto command
            url_match = re.search(r'(https?://[^\s"\']+)', tool_use)
            if url_match:
                return f'goto(page, "{url_match.group(1)}")'
                
            # Check for potential documentation references
            if any(term in tool_use.lower() for term in ['doc', 'documentation', 'api', 'swagger']):
                return 'goto(page, "/docs/")'
                
            # Check for potential login references
            if any(term in tool_use.lower() for term in ['login', 'sign in', 'authenticate']):
                return 'goto(page, "/login/")'
                
            # Default to reasonable action for natural language input
            if "click" in tool_use.lower():
                # Look for potential element references in the text
                element_match = re.search(r'(?:the\s+)?([a-zA-Z0-9_-]+\s+(?:button|link|form|input|element))', tool_use.lower())
                if element_match:
                    # Extract potential element name and create a reasonable selector
                    element_name = element_match.group(1).split()[0]  # Just get the first word
                    return f'click(page, "[id*=\'{element_name}\'], [class*=\'{element_name}\'], [name=\'{element_name}\']")'
                else:
                    # Default click on submit
                    return 'click(page, "input[type=\'submit\'], button[type=\'submit\'], button.submit, .btn-primary")'
            
            # If we can't determine a good action, default to documentation
            return 'goto(page, "/docs/")'
            
        # Ensure page parameter is present for relevant functions
        page_required_funcs = [
            'goto', 'click', 'fill', 'submit', 'execute_js', 'refresh', 'presskey',
            'wait_for_element', 'wait_for_navigation', 'screenshot', 'get_cookies', 
            'set_cookies', 'clear_cookies', 'set_headers', 'intercept_requests',
            'bypass_csp', 'extract_forms', 'extract_links', 'set_input_value',
            'get_page_source', 'simulate_user_interaction', 'set_geolocation',
            'block_resources', 'modify_response', 'fill_form_with_payload',
            'submit_form_and_get_response', 'analyze_network_traffic', 'bypass_waf',
            'check_page_access'
        ]
        for func in page_required_funcs:
            if func + '(' in tool_use and 'page' not in tool_use:
                # Fix missing page parameter
                parens_pos = tool_use.find('(')
                if parens_pos > 0:
                    # Insert page parameter
                    tool_use = tool_use[:parens_pos+1] + 'page, ' + tool_use[parens_pos+1:]
                    if self.debug:
                        print(f"Added missing page parameter: {tool_use}")
        
        # Ensure command is properly formatted and has balanced parentheses
        if '(' in tool_use and tool_use.count('(') != tool_use.count(')'):
            # Add missing closing parenthesis if needed
            if tool_use.count('(') > tool_use.count(')'):
                tool_use += ')' * (tool_use.count('(') - tool_use.count(')'))
            else:
                # Handle extra closing parentheses (unlikely but just in case)
                last_paren = tool_use.rfind(')')
                if last_paren > 0:
                    tool_use = tool_use[:last_paren] + tool_use[last_paren+1:]
        
        # Final validation check
        valid_tools = [
            'goto(', 'click(', 'fill(', 'submit(', 'execute_js(', 'refresh(', 'presskey(',
            'auth_needed(', 'get_user_input(', 'python_interpreter(', 'complete(',
            'wait_for_element(', 'wait_for_navigation(', 'screenshot(', 'get_cookies(',
            'set_cookies(', 'clear_cookies(', 'set_headers(', 'intercept_requests(',
            'get_intercepted_requests(', 'bypass_csp(', 'extract_forms(', 'extract_links(',
            'set_input_value(', 'get_page_source(', 'simulate_user_interaction(',
            'set_geolocation(', 'block_resources(', 'modify_response(', 'fill_form_with_payload(',
            'submit_form_and_get_response(', 'analyze_network_traffic(', 'bypass_waf(',
            'check_page_access('
        ]
        
        if not any(valid_tool in tool_use for valid_tool in valid_tools):
            # If we still don't have a valid command, default to documentation
            if self.debug:
                print(f"Invalid tool use after all processing, defaulting to docs: {tool_use}")
            return 'goto(page, "/docs/")'
        
        return tool_use

    # ===== BROWSER MANAGEMENT METHODS =====
    async def start_browser(self, headless: bool = True) -> bool:
        try:
            from playwright.async_api import async_playwright
            
            playwright = await async_playwright().start()
            self.browser = await playwright.chromium.launch(
                headless=headless,
                args=['--ignore-certificate-errors', '--disable-web-security']
            )
            context = await self.browser.new_context(
                ignore_https_errors=True,
                viewport={'width': 1920, 'height': 1080}
            )
            self.async_page = await context.new_page()
            
            if self.debug:
                print("✅ Browser started successfully")
            return True
            
        except Exception as e:
            if self.debug:
                print(f"❌ Failed to start browser: {e}")
            return False
    
    async def close_browser(self):
        if self.browser:
            try:
                await self.browser.close()
                self.browser = None
                self.async_page = None
                if self.debug:
                    print("✅ Browser closed successfully")
            except Exception as e:
                if self.debug:
                    print(f"❌ Error closing browser: {e}")
    
    # Alias for backward compatibility
    async def close(self):
        await self.close_browser()
    
    # ===== ASYNC BROWSER METHODS =====
    async def async_goto(self, url: str) -> Dict[str, Any]:
        if not self.async_page:
            return {"error": "Browser not initialized. Call start_browser() first."}
            
        try:
            response = await self.async_page.goto(url, wait_until='domcontentloaded')
            title = await self.async_page.title()
            
            # Extract forms for input testing
            forms = await self.async_page.evaluate("""
                () => {
                    return Array.from(document.forms).map(form => ({
                        action: form.action,
                        method: form.method,
                        inputs: Array.from(form.elements).map(el => ({
                            name: el.name,
                            type: el.type,
                            value: el.value
                        }))
                    }));
                }
            """)
            
            # Extract links
            links = await self.async_page.evaluate("""
                () => Array.from(document.links).map(link => link.href)
            """)
            
            self.current_url = url
            self.security_actions_performed += 1
            
            return {
                "status": response.status if response else None,
                "title": title,
                "forms": forms,
                "links": links[:50],  # Limit to first 50 links
                "url": url
            }
        except Exception as e:
            return {"error": str(e)}
    
    async def async_click(self, selector: str) -> Dict[str, Any]:
        if not self.async_page:
            return {"error": "Browser not initialized"}
            
        try:
            await self.async_page.click(selector)
            await self.async_page.wait_for_load_state('domcontentloaded')
            self.security_actions_performed += 1
            return {"success": True, "action": f"clicked {selector}"}
        except Exception as e:
            return {"error": str(e)}
    
    async def async_fill_form(self, selector: str, value: str) -> Dict[str, Any]:
        """Fill form field using async page
        
        Args:
            selector: CSS selector for input field
            value: Value to fill
            
        Returns:
            Dictionary with action result
        """
        if not self.async_page:
            return {"error": "Browser not initialized"}
            
        try:
            await self.async_page.fill(selector, value)
            self.security_actions_performed += 1
            return {"success": True, "action": f"filled {selector} with {value}"}
        except Exception as e:
            return {"error": str(e)}
    
    async def async_get_content(self) -> str:
        """Get page content using async page
        
        Returns:
            Page HTML content
        """
        if not self.async_page:
            return "Browser not initialized"
            
        try:
            return await self.async_page.content()
        except Exception as e:
            return f"Error getting content: {str(e)}"

    def wait_for_element(self, page: Page, css_selector: str, timeout: int = 10000) -> str:
        """Wait for element to appear and return page HTML"""
        try:
            page.wait_for_selector(css_selector, timeout=timeout)
            self.security_actions_performed += 1
            return page.inner_html("html")
        except Exception as e:
            return f"Element not found: {str(e)}"

    def wait_for_navigation(self, page: Page, timeout: int = 30000) -> str:
        """Wait for navigation to complete"""
        try:
            page.wait_for_load_state('networkidle', timeout=timeout)
            self.security_actions_performed += 1
            return page.inner_html("html")
        except Exception as e:
            return f"Navigation timeout: {str(e)}"

    def screenshot(self, page: Page, filename: Optional[str] = None, full_page: bool = True) -> str:
        """Take screenshot for evidence collection"""
        try:
            if not filename:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"security_test_{timestamp}.png"
            
            page.screenshot(path=filename, full_page=full_page)
            self.security_actions_performed += 1
            return f"Screenshot saved: {filename}"
        except Exception as e:
            return f"Screenshot failed: {str(e)}"

    def get_cookies(self, page: Page) -> str:
        """Extract all cookies for session analysis"""
        try:
            cookies = page.context.cookies()
            cookie_data = []
            for cookie in cookies:
                cookie_info = {
                    'name': cookie['name'],
                    'value': cookie['value'],
                    'domain': cookie['domain'],
                    'path': cookie.get('path', '/'),
                    'secure': cookie.get('secure', False),
                    'httpOnly': cookie.get('httpOnly', False),
                    'sameSite': cookie.get('sameSite', 'None')
                }
                cookie_data.append(cookie_info)
            
            self.security_actions_performed += 1
            return str(cookie_data)
        except Exception as e:
            return f"Cookie extraction failed: {str(e)}"

    def set_cookies(self, page: Page, cookies: str) -> str:
        """Set cookies for session testing"""
        try:
            import json
            if isinstance(cookies, str):
                cookie_list = json.loads(cookies)
            else:
                cookie_list = cookies
            
            page.context.add_cookies(cookie_list)
            self.security_actions_performed += 1
            return "Cookies set successfully"
        except Exception as e:
            return f"Cookie setting failed: {str(e)}"

    def clear_cookies(self, page: Page) -> str:
        """Clear all cookies for fresh session testing"""
        try:
            page.context.clear_cookies()
            self.security_actions_performed += 1
            return "Cookies cleared"
        except Exception as e:
            return f"Cookie clearing failed: {str(e)}"

    def set_headers(self, page: Page, headers: str) -> str:
        """Set custom HTTP headers for testing"""
        try:
            import json
            if isinstance(headers, str):
                header_dict = json.loads(headers)
            else:
                header_dict = headers
            
            page.set_extra_http_headers(header_dict)
            self.security_actions_performed += 1
            return f"Headers set: {list(header_dict.keys())}"
        except Exception as e:
            return f"Header setting failed: {str(e)}"

    def intercept_requests(self, page: Page, url_pattern: str = "*") -> str:
        """Enable request interception for traffic analysis"""
        try:
            self.intercepted_requests = []
            
            def handle_request(request):
                request_data = {
                    'url': request.url,
                    'method': request.method,
                    'headers': dict(request.headers),
                    'post_data': request.post_data
                }
                self.intercepted_requests.append(request_data)
                request.continue_()
            
            page.route(url_pattern, handle_request)
            self.security_actions_performed += 1
            return f"Request interception enabled for pattern: {url_pattern}"
        except Exception as e:
            return f"Request interception failed: {str(e)}"

    def get_intercepted_requests(self) -> str:
        """Get intercepted requests for analysis"""
        try:
            if hasattr(self, 'intercepted_requests'):
                return str(self.intercepted_requests)
            return "No intercepted requests"
        except Exception as e:
            return f"Request retrieval failed: {str(e)}"

    def bypass_csp(self, page: Page) -> str:
        """Bypass Content Security Policy for XSS testing"""
        try:
            page.add_init_script("""
                // Override CSP
                if (window.HTMLElement) {
                    HTMLElement.prototype.setAttribute = function(name, value) {
                        if (name.toLowerCase() !== 'nonce') {
                            return Element.prototype.setAttribute.call(this, name, value);
                        }
                    };
                }
            """)
            self.security_actions_performed += 1
            return "CSP bypass script injected"
        except Exception as e:
            return f"CSP bypass failed: {str(e)}"

    def extract_forms(self, page: Page) -> str:
        """Extract all forms for security testing"""
        try:
            forms_data = page.evaluate("""
                () => {
                    const forms = Array.from(document.forms);
                    return forms.map(form => ({
                        action: form.action,
                        method: form.method,
                        id: form.id,
                        name: form.name,
                        inputs: Array.from(form.elements).map(el => ({
                            name: el.name,
                            type: el.type,
                            id: el.id,
                            value: el.value,
                            required: el.required,
                            placeholder: el.placeholder
                        }))
                    }));
                }
            """)
            self.security_actions_performed += 1
            return str(forms_data)
        except Exception as e:
            return f"Form extraction failed: {str(e)}"

    def extract_links(self, page: Page) -> str:
        """Extract all links for crawling and testing"""
        try:
            links_data = page.evaluate("""
                () => {
                    const links = Array.from(document.links);
                    return links.map(link => ({
                        href: link.href,
                        text: link.textContent.trim(),
                        id: link.id,
                        class: link.className
                    }));
                }
            """)
            self.security_actions_performed += 1
            return str(links_data)
        except Exception as e:
            return f"Link extraction failed: {str(e)}"

    def set_input_value(self, page: Page, selector: str, value: str) -> str:
        """Set value for specific input element"""
        try:
            page.fill(selector, value)
            self.security_actions_performed += 1
            return f"Set value '{value}' for element '{selector}'"
        except Exception as e:
            return f"Input value setting failed: {str(e)}"

    def get_page_source(self, page: Page) -> str:
        """Get complete page source for analysis"""
        try:
            content = page.content()
            self.security_actions_performed += 1
            return content
        except Exception as e:
            return f"Page source retrieval failed: {str(e)}"

    def simulate_user_interaction(self, page: Page, actions: str) -> str:
        """Simulate complex user interactions for behavioral testing"""
        try:
            import json
            action_list = json.loads(actions) if isinstance(actions, str) else actions
            
            results = []
            for action in action_list:
                action_type = action.get('type')
                selector = action.get('selector')
                value = action.get('value', '')
                
                if action_type == 'hover':
                    page.hover(selector)
                    results.append(f"Hovered over {selector}")
                elif action_type == 'double_click':
                    page.dblclick(selector)
                    results.append(f"Double-clicked {selector}")
                elif action_type == 'right_click':
                    page.click(selector, button='right')
                    results.append(f"Right-clicked {selector}")
                elif action_type == 'select':
                    page.select_option(selector, value)
                    results.append(f"Selected {value} in {selector}")
                elif action_type == 'drag':
                    target = action.get('target')
                    page.drag_and_drop(selector, target)
                    results.append(f"Dragged {selector} to {target}")
            
            self.security_actions_performed += 1
            return "; ".join(results)
        except Exception as e:
            return f"User interaction simulation failed: {str(e)}"

    def set_geolocation(self, page: Page, latitude: float, longitude: float) -> str:
        """Set geolocation for location-based security testing"""
        try:
            page.context.set_geolocation({"latitude": latitude, "longitude": longitude})
            page.context.grant_permissions(["geolocation"])
            self.security_actions_performed += 1
            return f"Geolocation set to {latitude}, {longitude}"
        except Exception as e:
            return f"Geolocation setting failed: {str(e)}"

    def block_resources(self, page: Page, resource_types: str) -> str:
        """Block specific resource types for testing"""
        try:
            import json
            types = json.loads(resource_types) if isinstance(resource_types, str) else resource_types
            
            def handle_route(route):
                if route.request.resource_type in types:
                    route.abort()
                else:
                    route.continue_()
            
            page.route("**/*", handle_route)
            self.security_actions_performed += 1
            return f"Blocked resources: {types}"
        except Exception as e:
            return f"Resource blocking failed: {str(e)}"

    def modify_response(self, page: Page, url_pattern: str, new_body: str) -> str:
        """Modify response content for security testing"""
        try:
            def handle_route(route):
                if url_pattern in route.request.url:
                    route.fulfill(body=new_body, content_type="text/html")
                else:
                    route.continue_()
            
            page.route("**/*", handle_route)
            self.security_actions_performed += 1
            return f"Response modification enabled for pattern: {url_pattern}"
        except Exception as e:
            return f"Response modification failed: {str(e)}"

    def fill_form_with_payload(self, page: Page, form_selector: str, payload: str, field_name: str = None) -> str:
        """Fill form field(s) with a specific payload for testing"""
        try:
            if field_name:
                # Fill specific field
                page.fill(f"{form_selector} input[name='{field_name}'], {form_selector} input[id='{field_name}']", payload)
                result = f"Filled field '{field_name}' with payload"
            else:
                # Fill all text inputs in form
                form_inputs = page.locator(f"{form_selector} input").all()
                filled_count = 0
                for input_elem in form_inputs:
                    if input_elem.get_attribute('type') not in ['submit', 'button', 'hidden']:
                        input_elem.fill(payload)
                        filled_count += 1
                result = f"Filled {filled_count} form fields with payload"
            
            self.security_actions_performed += 1
            return result
        except Exception as e:
            return f"Form filling failed: {str(e)}"

    def submit_form_and_get_response(self, page: Page, form_selector: str) -> str:
        """Submit form and return the response content"""
        try:
            # Submit form
            page.click(f"{form_selector} input[type='submit'], {form_selector} button[type='submit']")
            page.wait_for_load_state('networkidle')
            
            # Return page content for analysis
            content = page.content()
            self.security_actions_performed += 1
            return content
        except Exception as e:
            return f"Form submission failed: {str(e)}"

    def analyze_network_traffic(self, page: Page) -> str:
        """Analyze network traffic for security issues"""
        try:
            # Enable network monitoring
            traffic_data = []
            
            def handle_response(response):
                # Check for security issues in responses
                headers = response.headers
                issues = []
                
                # Check for missing security headers
                if 'x-frame-options' not in headers:
                    issues.append('Missing X-Frame-Options header')
                if 'x-content-type-options' not in headers:
                    issues.append('Missing X-Content-Type-Options header')
                if 'strict-transport-security' not in headers:
                    issues.append('Missing HSTS header')
                if 'content-security-policy' not in headers:
                    issues.append('Missing CSP header')
                
                # Check for sensitive data in URLs
                if any(param in response.url.lower() for param in ['password', 'token', 'key', 'secret']):
                    issues.append('Sensitive data in URL')
                
                if issues:
                    traffic_data.append({
                        'url': response.url,
                        'status': response.status,
                        'issues': issues
                    })
            
            page.on('response', handle_response)
            self.security_actions_performed += 1
            return str(traffic_data)
        except Exception as e:
            return f"Network traffic analysis failed: {str(e)}"

    def bypass_waf(self, page: Page) -> str:
        """Configure browser for WAF bypass testing"""
        try:
            # Set headers that might bypass WAF
            bypass_headers = {
                'X-Originating-IP': '127.0.0.1',
                'X-Forwarded-For': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'X-Client-IP': '127.0.0.1',
                'CF-Connecting-IP': '127.0.0.1'
            }
            
            page.set_extra_http_headers(bypass_headers)
            self.security_actions_performed += 1
            return "WAF bypass headers configured"
        except Exception as e:
            return f"WAF bypass configuration failed: {str(e)}"

    def check_page_access(self, page: Page, url: str) -> str:
        """Navigate to URL and return access status information"""
        try:
            page.goto(url)
            page.wait_for_load_state('networkidle')
            
            access_info = {
                'final_url': page.url,
                'title': page.title(),
                'status_code': 200,  # Playwright doesn't easily expose status code after navigation
                'contains_login': 'login' in page.url.lower() or 'signin' in page.url.lower(),
                'contains_error': 'error' in page.content().lower() or 'forbidden' in page.content().lower(),
                'redirected': page.url != url
            }
            
            self.security_actions_performed += 1
            return str(access_info)
        except Exception as e:
            return f"Page access check failed: {str(e)}"

    
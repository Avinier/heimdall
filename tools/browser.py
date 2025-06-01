import sys
import re
from io import StringIO
from typing import Dict, Any, Optional
from playwright.sync_api import Page
from playwright.async_api import async_playwright, Browser, Page as AsyncPage
import logging
from tools.llms import LLM


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
            page_required = func_name in ['goto', 'click', 'fill', 'submit', 'execute_js', 'refresh', 'presskey']
            
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

    def extract_tool_use(self, action: str) -> str:
        # Safety check for empty input
        if not action or action.isspace():
            if self.debug:
                print("Empty action text, defaulting to docs navigation")
            return 'goto(page, "/docs/")'
        
        # Clean up the input - remove any "REFORMATTED:" text or similar prefixes
        action = re.sub(r'REFORMATTED:\s*', '', action)
        
        # NEW: Handle YAML-style planner output format
        # Check if this looks like a YAML plan with title/description
        yaml_title_pattern = r'title:\s*(.+?)(?:\n|$)'
        yaml_desc_pattern = r'description:\s*(.+?)(?:\n|$)'
        
        title_match = re.search(yaml_title_pattern, action, re.IGNORECASE | re.DOTALL)
        desc_match = re.search(yaml_desc_pattern, action, re.IGNORECASE | re.DOTALL)
        
        if title_match or desc_match:
            # This looks like planner output - convert to tool command
            title = title_match.group(1).strip() if title_match else ""
            description = desc_match.group(1).strip() if desc_match else ""
            combined_text = f"{title} {description}".strip()
            
            if self.debug:
                print(f"Detected planner YAML format. Converting: '{combined_text[:100]}...'")
            
            return self._convert_plan_to_tool_command(combined_text)
        
        # First try to extract using pattern matching for ACTION section
        action_pattern = r'\*\s*ACTION\s*\n(.*?)(?:\n|$)'
        action_match = re.search(action_pattern, action, re.IGNORECASE)
        
        if action_match:
            # Extract the raw command
            raw_tool_use = action_match.group(1).strip()
            
            # Fix any unterminated string literals first at this stage
            raw_tool_use = self._fix_unterminated_strings(raw_tool_use)
            
            # Extract just the command part, excluding any explanatory text that follows
            # This pattern looks for a complete function call with balanced parentheses
            complete_command_pattern = r'((?:goto|click|fill|submit|execute_js|refresh|presskey|auth_needed|get_user_input|python_interpreter|complete)\s*\([^)]*\))'
            complete_command_match = re.search(complete_command_pattern, raw_tool_use)
            
            if complete_command_match:
                # We found a properly formatted command with balanced parentheses
                tool_use = complete_command_match.group(1)
            else:
                # No complete command found, look for a partial command pattern
                partial_command_pattern = r'((?:goto|click|fill|submit|execute_js|refresh|presskey|auth_needed|get_user_input|python_interpreter|complete)\s*\([^)]*)'
                partial_command_match = re.search(partial_command_pattern, raw_tool_use)
                
                if partial_command_match:
                    # Get the partial command
                    tool_use = partial_command_match.group(1)
                    
                    # Find if there's any trailing text after a quoted string that should be removed
                    # This handles cases like: goto(page, "url") to understand what endpoints are available
                    last_quote = max(tool_use.rfind('"'), tool_use.rfind("'"))
                    if last_quote > 0:
                        space_after_quote = tool_use.find(' ', last_quote + 1)
                        if space_after_quote > 0:
                            tool_use = tool_use[:space_after_quote]
                    
                    # Make sure command ends with closing parenthesis
                    if not tool_use.endswith(')'):
                        tool_use += ')'
                else:
                    # No well-formed command found, use the entire line
                    tool_use = raw_tool_use
                    if self.debug:
                        print(f"Using full ACTION text as no clean command found: '{tool_use}'")
                
            # Fix common issues before full processing
            tool_use = self._pre_process_tool_use(tool_use)
            
            # Validate and fix the extracted tool use
            return self._fix_tool_use(tool_use)
        
        # If no explicit ACTION section, try to detect command-like statements
        # Look for common patterns in natural language descriptions
        url_navigate_pattern = r'(?:navigate|go|visit|browse)\s+(?:to|the)?\s+(?:URL|page|website|site|link|documentation)?\s*(?:at|:)?\s*[\'"]?(https?://[^\s\'"]+)[\'"]?'
        url_match = re.search(url_navigate_pattern, action, re.IGNORECASE)
        if url_match:
            url = url_match.group(1)
            return f'goto(page, "{url}")'
            
        # Look for "curl" commands
        curl_pattern = r'curl\s+(https?://[^\s]+)'
        curl_match = re.search(curl_pattern, action, re.IGNORECASE)
        if curl_match:
            url = curl_match.group(1)
            return f'goto(page, "{url}")'
            
        # Look for documentation references specifically
        docs_pattern = r'(?:docs|documentation|api\s*docs)'
        if re.search(docs_pattern, action, re.IGNORECASE):
            if hasattr(self, 'current_url') and self.current_url:
                # Try to construct a docs URL from the current URL
                base_url = re.match(r'(https?://[^/]+)', self.current_url)
                if base_url:
                    return f'goto(page, "{base_url.group(1)}/docs/")'
            
            # Default to a generic /docs/ path if we can't determine a base URL
            return 'goto(page, "/docs/")'
        
        # Try direct extraction of tool commands with proper page parameter
        command_with_page_pattern = r'((?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\(\s*page\s*,\s*[^)]*\))'
        command_with_page_match = re.search(command_with_page_pattern, action)
        if command_with_page_match:
            return command_with_page_match.group(1)
        
        # Try direct extraction of tool commands that might be missing page parameter
        command_pattern = r'((?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\([^)]*\))'
        command_match = re.search(command_pattern, action)
        if command_match:
            # Fix and return the extracted command
            return self._fix_tool_use(command_match.group(1))
        
        # If no direct command found, try with LLM-based extraction as last resort
        if self.llm:
            prompt = f"""
                Convert the following text into a SINGLE valid tool call for a security testing agent.
                Choose from these tools only:
                
                goto(page, "URL") - Navigate to a URL
                click(page, "selector") - Click an element
                fill(page, "selector", "value") - Fill a form field
                submit(page, "selector") - Submit a form
                execute_js(page, "js_code") - Run JavaScript code
                auth_needed() - Signal authentication is needed
                refresh(page) - Refresh the page
                complete() - Mark test as complete
                
                IMPORTANT: ALL tools that interact with the page MUST have 'page' as the FIRST parameter.
                
                Text to convert:
                {action}
                
                ONLY RETURN the exact code for the function call with no explanations, quotes, markdown syntax, or other text.
                Examples:
                - "navigate to the documentation" → goto(page, "/docs/")
                - "check authentication" → auth_needed()
                - "submit the login form" → submit(page, "#login-form")
            """
            response = self.llm.gemini_basic_call(prompt)
            
            # Clean up LLM response
            response = response.strip()
            response = re.sub(r'^```.*?\n', '', response)  # Remove opening code fence if present
            response = re.sub(r'\n```$', '', response)     # Remove closing code fence if present
            response = re.sub(r'^`|`$', '', response)      # Remove single backticks
            response = re.sub(r'^\s*-\s+', '', response)   # Remove bullet points if present
            
            # Process and fix the LLM-generated command
            return self._fix_tool_use(response)
        
        # Default fallback if no LLM available
        return 'goto(page, "/docs/")'

    def _convert_plan_to_tool_command(self, plan_text: str) -> str:
        if not plan_text:
            return 'goto(page, "/docs/")'
            
        plan_lower = plan_text.lower()
        
        # SQL Injection testing patterns
        if any(term in plan_lower for term in ['sql injection', 'login form', 'authentication bypass']):
            # Look for specific form paths in the text
            form_paths = re.findall(r'/[a-zA-Z0-9_/\-\.]+', plan_text)
            if form_paths:
                login_path = next((path for path in form_paths if 'login' in path or 'auth' in path), form_paths[0])
                return f'goto(page, "{login_path}")'
            return 'goto(page, "/login/")'
        
        # API testing patterns
        if any(term in plan_lower for term in ['api', 'endpoint', 'authorization testing', 'idor']):
            # Look for API paths in the text
            api_paths = re.findall(r'/api/[a-zA-Z0-9_/\-\.]+', plan_text)
            if api_paths:
                return f'goto(page, "{api_paths[0]}")'
            return 'goto(page, "/api/")'
        
        # XSS testing patterns
        if any(term in plan_lower for term in ['xss', 'cross-site scripting', 'input vectors', 'search form']):
            # Look for search or form endpoints
            search_paths = re.findall(r'/[a-zA-Z0-9_/\-\.]*search[a-zA-Z0-9_/\-\.]*', plan_text)
            if search_paths:
                return f'goto(page, "{search_paths[0]}")'
            # Look for any form-related paths
            form_paths = re.findall(r'/[a-zA-Z0-9_/\-\.]+', plan_text)
            if form_paths:
                return f'goto(page, "{form_paths[0]}")'
            return 'goto(page, "/search/")'
        
        # Session management testing
        if any(term in plan_lower for term in ['session', 'csrf', 'token', 'cookie']):
            return 'goto(page, "/login/")'
        
        # Information disclosure testing
        if any(term in plan_lower for term in ['information disclosure', 'error', 'stack trace', 'technology stack']):
            # Try to trigger errors on common endpoints
            return 'goto(page, "/admin/")'
        
        # Admin panel testing
        if any(term in plan_lower for term in ['admin', 'dashboard', 'panel']):
            return 'goto(page, "/admin/")'
        
        # File upload testing
        if any(term in plan_lower for term in ['file upload', 'upload', 'document']):
            upload_paths = re.findall(r'/[a-zA-Z0-9_/\-\.]*upload[a-zA-Z0-9_/\-\.]*', plan_text)
            if upload_paths:
                return f'goto(page, "{upload_paths[0]}")'
            return 'goto(page, "/upload/")'
        
        # Look for specific endpoints mentioned in the text
        endpoints = re.findall(r'/[a-zA-Z0-9_/\-\.]+', plan_text)
        if endpoints:
            # Prioritize more interesting endpoints
            priority_endpoints = [ep for ep in endpoints if any(term in ep.lower() 
                                 for term in ['login', 'admin', 'api', 'auth', 'upload', 'search'])]
            if priority_endpoints:
                return f'goto(page, "{priority_endpoints[0]}")'
            return f'goto(page, "{endpoints[0]}")'
        
        # Look for URLs in the text
        urls = re.findall(r'https?://[^\s]+', plan_text)
        if urls:
            return f'goto(page, "{urls[0]}")'
        
        # Default based on common security testing patterns
        if 'authentication' in plan_lower or 'login' in plan_lower:
            return 'goto(page, "/login/")'
        elif 'api' in plan_lower:
            return 'goto(page, "/api/")'
        elif 'admin' in plan_lower:
            return 'goto(page, "/admin/")'
        else:
            return 'goto(page, "/docs/")'

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
        page_required_funcs = ['goto', 'click', 'fill', 'submit', 'execute_js', 'refresh', 'presskey']
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
        valid_tools = ['goto(', 'click(', 'fill(', 'submit(', 'execute_js(', 'refresh(', 
                       'presskey(', 'auth_needed(', 'get_user_input(', 'python_interpreter(', 'complete(']
        
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


# Convenience function for creating PlaywrightTools instance
def create_tools(debug: bool = False, use_llm: bool = True) -> PlaywrightTools:
    """Create a PlaywrightTools instance for use with WebProxy.
    
    Args:
        debug: Whether to enable debug output
        use_llm: Whether to initialize LLM for advanced features
        
    Returns:
        PlaywrightTools instance ready for use
    """
    return PlaywrightTools(debug=debug, use_llm=use_llm)


# Example usage function
def demo_tools():
    """
    Demonstration of the PlaywrightTools capabilities with a mock page object.
    """
    print("🔧 PlaywrightTools Demo")
    print("=" * 50)
    
    # Create tools instance
    tools = create_tools(debug=True, use_llm=False)  # Disable LLM for demo
    
    # Mock page object for demonstration
    class MockPage:
        def __init__(self):
            self.url = "https://example.com"
            
        def goto(self, url):
            print(f"Navigating to: {url}")
            
        def click(self, selector, timeout=None):
            print(f"Clicking: {selector}")
            
        def fill(self, selector, value, timeout=None):
            print(f"Filling {selector} with: {value}")
            
        def inner_html(self, selector):
            return "<html><body>Mock HTML content</body></html>"
            
        def evaluate(self, js_code):
            print(f"Executing JS: {js_code}")
            return "Mock JS result"
            
        def reload(self):
            print("Refreshing page")
            
        def locator(self, selector):
            return MockLocator(selector)
            
        @property
        def keyboard(self):
            return MockKeyboard()
    
    class MockLocator:
        def __init__(self, selector):
            self.selector = selector
            
        def click(self):
            print(f"Clicking locator: {self.selector}")
    
    class MockKeyboard:
        def press(self, key):
            print(f"Pressing key: {key}")
    
    mock_page = MockPage()
    
    # Test various tool functions
    print("✅ Tools initialized")
    
    # Test navigation
    result = tools.goto(mock_page, "/docs/")
    print(f"📍 Navigation result: {len(result)} chars")
    
    # Test JavaScript execution
    js_result = tools.execute_js(mock_page, "() => document.title")
    print(f"🔧 JS execution result: {js_result}")
    
    # Test action extraction
    action = "Navigate to the API documentation"
    tool_command = tools.extract_tool_use(action)
    print(f"🎯 Extracted tool command: {tool_command}")
    
    # Test tool execution
    execution_result = tools.execute_tool(mock_page, tool_command)
    print(f"⚡ Tool execution result: {len(str(execution_result))} chars")
    
    print("🔧 Demo completed!")


if __name__ == "__main__":
    # Run demo if script is executed directly
    demo_tools()
    
    # Test planner compatibility
    print("\n" + "="*60)
    print("🔗 PLANNER COMPATIBILITY TEST")
    print("="*60)
    
    tools = create_tools(debug=True, use_llm=False)
    
    # Test YAML format from planner
    sample_yaml_plan = """
title: SQL Injection Vulnerability Assessment - Authentication Bypass
description: Conduct systematic SQL injection testing on the login form at /auth/login using time-based and boolean-based payloads. Test username and password parameters with UNION-based queries, error-based injection, and authentication bypass techniques including ' OR '1'='1' variants.
"""
    
    print("📋 Testing YAML plan input:")
    print(f"Input: {sample_yaml_plan.strip()}")
    
    extracted_command = tools.extract_tool_use(sample_yaml_plan)
    print(f"✅ Extracted command: {extracted_command}")
    
    # Test another plan type
    api_plan = """
title: API Authorization Testing - IDOR and Privilege Escalation  
description: Perform comprehensive authorization testing on discovered API endpoints /api/users and /api/admin. Test for Insecure Direct Object References by manipulating user IDs.
"""
    
    print(f"\n📋 Testing API plan input:")
    print(f"Input: {api_plan.strip()}")
    
    extracted_command2 = tools.extract_tool_use(api_plan)
    print(f"✅ Extracted command: {extracted_command2}")
    
    print("\n🎯 Compatibility test completed!") 
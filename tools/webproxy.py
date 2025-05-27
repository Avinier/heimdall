from datetime import datetime
import json
from typing import Dict, List
from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext, Request, Response
from urllib.parse import urlparse

class WebProxy:
    """
    A proxy class that monitors and captures web traffic during security testing.
    
    Provides comprehensive request/response monitoring using both Playwright event listeners
    and Chrome DevTools Protocol (CDP). Captures important network traffic like API calls,
    form submissions, and XHR requests.
    """

    def __init__(self, starting_url: str, logger):
        """
        Initialize the web proxy.

        Args:
            starting_url: Base URL to monitor traffic for
            logger: Logger instance for output
        """
        self.requests: List[Dict] = []
        self.responses: List[Dict] = []
        self.request_response_pairs: List[Dict] = []
        self.starting_url = starting_url
        self.starting_hostname = urlparse(starting_url).netloc
        self.logger = logger
        self.cdp_client = None
        self.is_capturing = True
        self.request_map = {}

    def create_proxy(self):
        """
        Create a browser instance with network monitoring capabilities.
        
        Returns:
            Tuple of (browser, context, page, playwright) instances
        """
        playwright = sync_playwright().start()
        browser = playwright.chromium.launch(
            headless=False,
            args=['--disable-blink-features=AutomationControlled', '--disable-automation']
        )
        
        # Create context with needed settings
        context = browser.new_context(
            bypass_csp=True,
            ignore_https_errors=True,
            # Add user agent to avoid detection
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )
        
        # Create page
        page = context.new_page()
        
        # Setup monitoring
        self.setup_monitoring(context, page)
        
        return browser, context, page, playwright

    def setup_monitoring(self, context: BrowserContext, page: Page):
        """
        Set up all monitoring mechanisms.

        Args:
            context: Browser context to monitor
            page: Page instance to monitor
        """
        self._setup_event_listeners(context)
        self._setup_cdp_monitoring(page)
    
    def _setup_event_listeners(self, context: BrowserContext):
        """
        Set up comprehensive event listeners for network traffic.
        
        Args:
            context: Browser context to attach listeners to
        """
        
        def handle_request(request):
            # Check if we should capture this request
            if self._should_capture_request(request):
                url = request.url
                method = request.method
                resource_type = request.resource_type
                
                request_id = f"req_{datetime.now().timestamp()}"
                self.logger.info(f"Captured {method} request to {url} [{resource_type}]", color='cyan')
                
                # Store full request data
                request_data = {
                    'url': url,
                    'method': method,
                    'headers': dict(request.headers),  # Convert to dict to ensure serializability
                    'timestamp': datetime.now().isoformat(),
                    'resource_type': resource_type,
                    'request_id': request_id,
                    'post_data': request.post_data
                }
                
                self.requests.append(request_data)
                self.request_map[url] = request_data
        
        def handle_response(response):
            url = response.url
            status = response.status
            
            # Check if we have a matching request
            if url in self.request_map:
                request_data = self.request_map[url]
                self.logger.info(f"Captured response {status} from {url}", color='green')
                
                # Store response data
                try:
                    response_data = {
                        'url': url,
                        'status': status,
                        'status_text': response.status_text,
                        'headers': dict(response.headers),  # Convert to dict
                        'timestamp': datetime.now().isoformat(),
                        'request_id': request_data.get('request_id')
                    }
                    
                    # Try to get body for important responses
                    try:
                        if self._should_capture_body(response):
                            body = response.body()
                            response_data['body'] = body.decode('utf-8')
                            
                            # Try to parse JSON
                            if 'application/json' in response.headers.get('content-type', ''):
                                try:
                                    json_body = json.loads(response_data['body'])
                                    response_data['json_body'] = json_body
                                except json.JSONDecodeError:
                                    pass
                    except Exception as e:
                        response_data['body_error'] = str(e)
                    
                    self.responses.append(response_data)
                    
                    # Create request-response pair
                    self.request_response_pairs.append({
                        'request': request_data,
                        'response': response_data
                    })
                    
                except Exception as e:
                    self.logger.info(f"Error processing response: {str(e)}", color='red')
        
        # Register event listeners on context
        context.on('request', handle_request)
        context.on('response', handle_response)
    
    def _setup_cdp_monitoring(self, page: Page):
        """
        Set up Chrome DevTools Protocol monitoring as a backup.
        
        Args:
            page: Page instance to monitor via CDP
        """
        try:
            # Create CDP session
            self.cdp_client = page.context.new_cdp_session(page)
            
            # Enable network monitoring
            self.cdp_client.send('Network.enable')
            
            # Track CDP requests separately
            self.cdp_requests = {}
            
            # Handle CDP events
            def handle_cdp_request(params):
                request_id = params.get('requestId', '')
                request = params.get('request', {})
                url = request.get('url', '')
                method = request.get('method', '')
                
                # Check hostname
                request_hostname = urlparse(url).netloc
                if request_hostname != self.starting_hostname:
                    return
                
                # Only process if we haven't already seen this request through event listeners
                if any(r['url'] == url for r in self.requests):
                    return
                
                # Check if this is a request we care about
                if method == 'POST' or '/api/' in url or '.json' in url:
                    self.logger.info(f"CDP captured {method} request to {url}", color='blue')
                    
                    # Store request
                    request_data = {
                        'url': url,
                        'method': method,
                        'headers': request.get('headers', {}),
                        'timestamp': datetime.now().isoformat(),
                        'request_id': f"cdp_{request_id}",
                        'post_data': request.get('postData'),
                        'source': 'cdp'
                    }
                    
                    self.requests.append(request_data)
                    self.cdp_requests[request_id] = request_data
            
            def handle_cdp_response(params):
                request_id = params.get('requestId', '')
                if request_id not in self.cdp_requests:
                    return
                
                request_data = self.cdp_requests[request_id]
                response = params.get('response', {})
                url = response.get('url', '')
                
                self.logger.info(f"CDP captured response from {url}", color='light_blue')
                
                # Store response
                response_data = {
                    'url': url,
                    'status': response.get('status', 0),
                    'status_text': response.get('statusText', ''),
                    'headers': response.get('headers', {}),
                    'timestamp': datetime.now().isoformat(),
                    'request_id': request_data.get('request_id'),
                    'source': 'cdp'
                }
                
                # Try to get body
                try:
                    if 'application/json' in response.get('headers', {}).get('content-type', ''):
                        body_response = self.cdp_client.send('Network.getResponseBody', {'requestId': request_id})
                        if body_response and 'body' in body_response:
                            response_data['body'] = body_response['body']
                except Exception:
                    pass
                
                self.responses.append(response_data)
                
                # Create pair
                self.request_response_pairs.append({
                    'request': request_data,
                    'response': response_data
                })
                
                # Clean up
                del self.cdp_requests[request_id]
            
            # Register CDP event handlers
            self.cdp_client.on('Network.requestWillBeSent', handle_cdp_request)
            self.cdp_client.on('Network.responseReceived', handle_cdp_response)
            
            self.logger.info("CDP monitoring enabled", color='yellow')
        except Exception as e:
            self.logger.info(f"Failed to set up CDP monitoring: {str(e)}", color='red')
    
    def _should_capture_request(self, request):
        """
        Check if we should capture this request based on type and hostname.
        
        Args:
            request: Request to evaluate
            
        Returns:
            bool indicating if request should be captured
        """
        # First check if the hostname matches our starting URL
        request_hostname = urlparse(request.url).netloc
        if request_hostname != self.starting_hostname:
            return False
            
        # Now check request type
        url = request.url
        method = request.method
        resource_type = request.resource_type
        
        # Determine if we should capture this request
        is_xhr = resource_type == 'xhr'
        is_fetch = resource_type == 'fetch'
        is_websocket = resource_type == 'websocket'
        is_post = method == 'POST'
        is_api = '/api/' in url or url.endswith('.json')
        is_form = 'form' in resource_type or 'multipart/form-data' in request.headers.get('content-type', '')
        
        # Capture any request that might be important
        return is_xhr or is_fetch or is_websocket or is_post or is_api or is_form
    
    def _should_capture_body(self, response):
        """
        Check if we should capture the response body based on content type and other factors.
        
        Args:
            response: Response to evaluate
            
        Returns:
            bool indicating if response body should be captured
        """
        # Don't capture body for error responses or redirects
        if response.status >= 400 or (300 <= response.status < 400):
            return False
        
        # Get content type and size
        content_type = response.headers.get('content-type', '').lower()
        content_length = response.headers.get('content-length', '0')
        
        # Skip very large responses (> 1MB)
        try:
            if int(content_length) > 1024 * 1024:
                return False
        except (ValueError, TypeError):
            pass
        
        # Capture important content types
        important_types = [
            'application/json',
            'application/xml',
            'text/xml',
            'text/html',
            'text/plain',
            'application/x-www-form-urlencoded',
            'multipart/form-data'
        ]
        
        # Check if content type matches any important types
        for important_type in important_types:
            if important_type in content_type:
                return True
        
        # Skip binary content types
        binary_types = [
            'image/',
            'video/',
            'audio/',
            'application/pdf',
            'application/zip',
            'application/octet-stream'
        ]
        
        for binary_type in binary_types:
            if binary_type in content_type:
                return False
        
        # Default to capturing if we're unsure and it's not too large
        return True
    
    def get_network_data(self):
        """
        Get all captured network data.
        
        Returns:
            Dict containing requests, responses and request-response pairs
        """
        return {
            'requests': self.requests,
            'responses': self.responses,
            'pairs': self.request_response_pairs
        }
    
    def save_network_data(self, filepath: str):
        """
        Save captured network data to a JSON file.
        
        Args:
            filepath: Path to save JSON file to
        """
        data = {
            'requests': self.requests,
            'responses': self.responses,
            'pairs': self.request_response_pairs,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
    
    def pretty_print_traffic(self):
        """
        Pretty print captured traffic.
        
        Returns:
            Formatted string of traffic or None if no traffic captured
        """
        if not self.request_response_pairs:
            return None
        
        output = []
        output.append(f"Captured {len(self.request_response_pairs)} request-response pairs:")
        
        for idx, pair in enumerate(self.request_response_pairs):
            req = pair['request']
            res = pair['response']
            
            # Request details
            output.append(f"\n=== Request {idx+1} ===")
            output.append(f"Type: {req.get('resource_type', 'unknown')}")
            output.append(f"Method: {req['method']}")
            output.append(f"URL: {req['url']}")
            if req.get('post_data'):
                output.append(f"Parameters: {req['post_data']}")
            
            # Response details  
            output.append(f"\n--- Response {idx+1} ---")
            output.append(f"Status: {res['status']}")
            
            # Response body
            if 'json_body' in res:
                try:
                    body_str = json.dumps(res['json_body'])[:300]
                    output.append(f"Type: JSON")
                    output.append(f"Body: {body_str}")
                except:
                    if 'body' in res:
                        body_str = res['body'][:300]
                        output.append(f"Type: Raw")
                        output.append(f"Body: {body_str}")
            elif 'body' in res:
                body_str = res['body'][:300]
                output.append(f"Type: Raw") 
                output.append(f"Body: {body_str}")
            
            output.append("\n")
            
        return "\n".join(output)
    
    def clear(self):
        """Clear all captured network data."""
        self.requests = []
        self.responses = []
        self.request_response_pairs = []
        self.request_map = {}
        if hasattr(self, 'cdp_requests'):
            self.cdp_requests = {}


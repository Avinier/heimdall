import re
import json
from typing import List, Dict, Any, Optional
from playwright.sync_api import Page
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class PageDataExtractor:
    """
    Extracts comprehensive page data from a Playwright page for security analysis.
    Generates formatted data string for use with the security planner.
    """
    
    def __init__(self, playwright_page: Page):
        """
        Initialize the extractor with a Playwright page object.
        
        Args:
            playwright_page: Active Playwright page object
        """
        self.page = playwright_page
        self.current_url = self.page.url
        self.html_content = ""
        self.links = []
        self.forms = []
        self.sensitive_strings = []
        self.request_data = {}
        self.response_data = {}
        self.api_calls = []
        
        # Patterns for detecting sensitive information
        self.sensitive_patterns = [
            r'(?i)(password|passwd|pwd)',
            r'(?i)(token|jwt|bearer)',
            r'(?i)(api[_-]?key|apikey)',
            r'(?i)(secret|private)',
            r'(?i)(admin|administrator)',
            r'(?i)(auth|authentication)',
            r'(?i)(session|sess)',
            r'(?i)(cookie|csrf)',
            r'(?i)(database|db)',
            r'(?i)(config|configuration)',
            r'(?i)(email|mail)',
            r'(?i)(user|username)',
            r'(?i)(login|signin)',
            r'(?i)(credit[_-]?card|creditcard)',
            r'(?i)(ssn|social[_-]?security)',
            r'(?i)(phone|telephone)',
            r'(?i)(address|addr)',
            r'(?i)(backup|bak)',
            r'(?i)(test|debug)',
            r'(?i)(internal|private)',
            r'(?i)(localhost|127\.0\.0\.1)',
            r'(?i)(staging|dev|development)',
        ]
    
    def extract_page_data(self) -> str:
        """
        Extract all page data and return formatted string for planner.
        
        Returns:
            Formatted page data string
        """
        try:
            # Extract HTML content
            self._extract_html_content()
            
            # Extract links
            self._extract_links()
            
            # Extract forms
            self._extract_forms()
            
            # Extract sensitive strings
            self._extract_sensitive_strings()
            
            # Extract request/response data
            self._extract_request_response_data()
            
            # Extract API calls
            self._extract_api_calls()
            
            # Format and return the data
            return self._format_page_data()
            
        except Exception as e:
            print(f"Error extracting page data: {str(e)}")
            return self._get_fallback_data()
    
    def _extract_html_content(self):
        """Extract and summarize HTML content."""
        try:
            # Get the full HTML content
            full_html = self.page.content()
            
            # Parse with BeautifulSoup for better processing
            soup = BeautifulSoup(full_html, 'html.parser')
            
            # Remove script and style elements for cleaner summary
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Get text content and limit size for summary
            text_content = soup.get_text()
            
            # Create a summarized version of HTML
            # Keep important structural elements but remove excessive content
            summary_soup = BeautifulSoup(full_html, 'html.parser')
            
            # Remove large text blocks but keep structure
            for element in summary_soup.find_all(text=True):
                if len(str(element).strip()) > 100:
                    element.replace_with(str(element)[:100] + "...")
            
            # Limit the overall HTML size
            summarized_html = str(summary_soup)
            if len(summarized_html) > 2000:
                summarized_html = summarized_html[:2000] + "..."
            
            self.html_content = summarized_html
            
        except Exception as e:
            print(f"Error extracting HTML content: {str(e)}")
            self.html_content = "<html><body>Error extracting HTML content</body></html>"
    
    def _extract_links(self):
        """Extract all links from the page."""
        try:
            # Get all anchor tags with href attributes
            links_js = """
            () => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(link => {
                    links.push({
                        href: link.href,
                        text: link.textContent.trim(),
                        target: link.target || '',
                        rel: link.rel.join(' ') || ''
                    });
                });
                return links;
            }
            """
            
            raw_links = self.page.evaluate(links_js)
            
            # Process and clean links
            for link in raw_links:
                href = link.get('href', '')
                text = link.get('text', '')
                
                # Skip empty or javascript links
                if not href or href.startswith('javascript:') or href.startswith('mailto:'):
                    continue
                
                # Convert relative URLs to absolute
                if href.startswith('/') or not href.startswith('http'):
                    href = urljoin(self.current_url, href)
                
                self.links.append({
                    'url': href,
                    'text': text[:50] + "..." if len(text) > 50 else text,
                    'target': link.get('target', ''),
                    'rel': link.get('rel', '')
                })
            
            # Remove duplicates
            seen_urls = set()
            unique_links = []
            for link in self.links:
                if link['url'] not in seen_urls:
                    seen_urls.add(link['url'])
                    unique_links.append(link)
            
            self.links = unique_links[:20]  # Limit to first 20 links
            
        except Exception as e:
            print(f"Error extracting links: {str(e)}")
            self.links = []
    
    def _extract_forms(self):
        """Extract all forms from the page."""
        try:
            forms_js = """
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach((form, index) => {
                    const fields = [];
                    form.querySelectorAll('input, select, textarea').forEach(field => {
                        fields.push({
                            type: field.type || field.tagName.toLowerCase(),
                            name: field.name || '',
                            id: field.id || '',
                            placeholder: field.placeholder || '',
                            required: field.required || false,
                            value: field.value || ''
                        });
                    });
                    
                    forms.push({
                        action: form.action || '',
                        method: form.method || 'GET',
                        enctype: form.enctype || '',
                        id: form.id || '',
                        class: form.className || '',
                        fields: fields
                    });
                });
                return forms;
            }
            """
            
            raw_forms = self.page.evaluate(forms_js)
            
            # Process forms
            for form in raw_forms:
                action = form.get('action', '')
                
                # Convert relative action URLs to absolute
                if action and not action.startswith('http'):
                    action = urljoin(self.current_url, action)
                
                processed_form = {
                    'action': action,
                    'method': form.get('method', 'GET').upper(),
                    'enctype': form.get('enctype', ''),
                    'id': form.get('id', ''),
                    'class': form.get('class', ''),
                    'fields': []
                }
                
                # Process form fields
                for field in form.get('fields', []):
                    processed_field = {
                        'type': field.get('type', ''),
                        'name': field.get('name', ''),
                        'id': field.get('id', ''),
                        'placeholder': field.get('placeholder', ''),
                        'required': field.get('required', False)
                    }
                    
                    # Don't include actual values for security
                    if field.get('type') != 'password':
                        processed_field['value'] = field.get('value', '')[:50]
                    
                    processed_form['fields'].append(processed_field)
                
                self.forms.append(processed_form)
            
        except Exception as e:
            print(f"Error extracting forms: {str(e)}")
            self.forms = []
    
    def _extract_sensitive_strings(self):
        """Extract potentially sensitive strings from the page."""
        try:
            # Get page text content
            page_text = self.page.evaluate("() => document.body.textContent || ''")
            
            # Get HTML source for additional analysis
            html_source = self.page.content()
            
            # Combine text and HTML for analysis
            combined_content = page_text + " " + html_source
            
            sensitive_findings = set()
            
            # Search for sensitive patterns
            for pattern in self.sensitive_patterns:
                matches = re.findall(pattern, combined_content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match else ""
                    
                    if match and len(match) > 2:
                        sensitive_findings.add(match.lower())
            
            # Look for potential API endpoints
            api_patterns = [
                r'/api/[a-zA-Z0-9_/]+',
                r'/v\d+/[a-zA-Z0-9_/]+',
                r'\.json\b',
                r'\.xml\b',
                r'/rest/[a-zA-Z0-9_/]+',
                r'/graphql\b'
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, combined_content)
                for match in matches:
                    sensitive_findings.add(match)
            
            # Look for potential file extensions of interest
            file_patterns = [
                r'\.[a-zA-Z0-9]+\.(bak|backup|old|tmp|log|config|conf|ini|env)',
                r'\.git\b',
                r'\.svn\b',
                r'\.env\b',
                r'config\.[a-zA-Z]+',
                r'\.htaccess\b',
                r'web\.config\b'
            ]
            
            for pattern in file_patterns:
                matches = re.findall(pattern, combined_content, re.IGNORECASE)
                for match in matches:
                    sensitive_findings.add(match)
            
            # Convert to list and limit results
            self.sensitive_strings = list(sensitive_findings)[:30]
            
        except Exception as e:
            print(f"Error extracting sensitive strings: {str(e)}")
            self.sensitive_strings = []
    
    def _extract_request_response_data(self):
        """Extract current request and response information."""
        try:
            # Get current page URL and basic info
            self.request_data = {
                'method': 'GET',  # Default assumption for page load
                'url': self.current_url,
                'headers': {},
                'user_agent': self.page.evaluate("() => navigator.userAgent")
            }
            
            # Get response information
            self.response_data = {
                'status': 200,  # Default assumption
                'headers': {},
                'content_type': 'text/html',
                'title': self.page.title(),
                'url': self.current_url
            }
            
            # Try to get more detailed response info if available
            try:
                response_info = self.page.evaluate("""
                () => {
                    return {
                        referrer: document.referrer,
                        domain: document.domain,
                        cookie: document.cookie,
                        lastModified: document.lastModified,
                        readyState: document.readyState
                    };
                }
                """)
                
                self.response_data.update(response_info)
                
            except Exception:
                pass  # Continue with basic info if detailed extraction fails
            
        except Exception as e:
            print(f"Error extracting request/response data: {str(e)}")
            self.request_data = {'method': 'GET', 'url': self.current_url}
            self.response_data = {'status': 'unknown', 'url': self.current_url}
    
    def _extract_api_calls(self):
        """Extract potential API calls and endpoints."""
        try:
            # Look for AJAX/fetch calls in JavaScript
            api_endpoints = set()
            
            # Get all script tags and analyze for API calls
            scripts_content = self.page.evaluate("""
            () => {
                const scripts = [];
                document.querySelectorAll('script').forEach(script => {
                    if (script.textContent) {
                        scripts.push(script.textContent);
                    }
                });
                return scripts.join(' ');
            }
            """)
            
            # Look for common API call patterns
            api_patterns = [
                r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.get\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.post\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.put\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.delete\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'ajax\s*\(\s*{[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'XMLHttpRequest.*open\s*\(\s*[\'"`][^\'"`]+[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]'
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, scripts_content, re.IGNORECASE)
                for match in matches:
                    if match.startswith('/') or match.startswith('http'):
                        api_endpoints.add(match)
            
            # Look for API endpoints in HTML attributes
            html_content = self.page.content()
            html_api_patterns = [
                r'data-url\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
                r'data-endpoint\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
                r'action\s*=\s*[\'"`]([^\'"`]*api[^\'"`]*)[\'"`]',
                r'href\s*=\s*[\'"`]([^\'"`]*api[^\'"`]*)[\'"`]'
            ]
            
            for pattern in html_api_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if '/api/' in match or match.endswith('.json') or match.endswith('.xml'):
                        api_endpoints.add(match)
            
            # Convert to list of dictionaries with more info
            self.api_calls = []
            for endpoint in list(api_endpoints)[:15]:  # Limit to 15 endpoints
                # Convert relative URLs to absolute
                if endpoint.startswith('/'):
                    endpoint = urljoin(self.current_url, endpoint)
                
                self.api_calls.append({
                    'endpoint': endpoint,
                    'method': 'GET',  # Default assumption
                    'type': 'discovered'
                })
            
        except Exception as e:
            print(f"Error extracting API calls: {str(e)}")
            self.api_calls = []
    
    def _format_page_data(self) -> str:
        """Format all extracted data into the required string format."""
        try:
            # Format links
            links_str = []
            for link in self.links:
                links_str.append(f"'{link['url']}'")
            
            # Format forms
            forms_str = []
            for form in self.forms:
                form_fields = [field['name'] for field in form['fields'] if field['name']]
                forms_str.append(f"{{'action': '{form['action']}', 'method': '{form['method']}', 'fields': {form_fields}}}")
            
            # Format API calls
            api_calls_str = []
            for api_call in self.api_calls:
                api_calls_str.append(f"'{api_call['endpoint']}'")
            
            # Build the formatted string
            formatted_data = f"""Summarized HTML:
{self.html_content}

Page Data:
- Links: [{', '.join(links_str)}]
- Forms: [{', '.join(forms_str)}]
- Sensitive Strings: {self.sensitive_strings}

Request and Response Data:
- Request: {self.request_data['method']} {self.request_data['url']}
- Response: Status: {self.response_data.get('status', 'unknown')}, Title: '{self.response_data.get('title', '')}', Content-Type: {self.response_data.get('content_type', 'unknown')}
- API calls: [{', '.join(api_calls_str)}]"""

            return formatted_data
            
        except Exception as e:
            print(f"Error formatting page data: {str(e)}")
            return self._get_fallback_data()
    
    def _get_fallback_data(self) -> str:
        """Return fallback data if extraction fails."""
        return f"""Summarized HTML:
<html><body>Error extracting page data from {self.current_url}</body></html>

Page Data:
- Links: []
- Forms: []
- Sensitive Strings: []

Request and Response Data:
- Request: GET {self.current_url}
- Response: Status: unknown, Title: '', Content-Type: unknown
- API calls: []"""


# Example usage and testing
if __name__ == "__main__":
    print("PageDataExtractor - Example usage:")
    print("This class requires a Playwright page object to function.")
    print("Usage: extractor = PageDataExtractor(playwright_page)")
    print("       page_data = extractor.extract_page_data()")

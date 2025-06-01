import re
import json
import sys
from typing import List, Dict, Any, Optional
import requests
import time

from playwright.sync_api import Page
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from tools.webproxy import WebProxy

#AVINIERNOTES: this file handles the reconnaisance phase of the attack. No subdomain enumeration added
class PageDataExtractor:
    """
    Extracts comprehensive page data from a Playwright page for security analysis.
    Generates formatted data string for use with the security planner.
    """
    
    def __init__(self, playwright_page: Page):
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
            # Follow redirects and analyze additional pages
            self._follow_redirects()
            # Perform reconnaissance (without subdomain enumeration)
            self._perform_reconnaissance()
            
            # Format and return the data
            return self._format_page_data()
            
        except Exception as e:
            print(f"Error extracting page data: {str(e)}")
            return self._get_fallback_data()
    
    def _extract_html_content(self):
        try:
            # Get the full HTML content
            full_html = self.page.content()
            
            # Parse with BeautifulSoup for better processing
            soup = BeautifulSoup(full_html, 'html.parser')
            
            # Security-focused HTML summarization strategy
            security_summary = self._create_html_summary(soup, full_html)
            
            self.html_content = security_summary
            
        except Exception as e:
            print(f"Error extracting HTML content: {str(e)}")
            self.html_content = "<html><body>Error extracting HTML content</body></html>"
    
    def _create_html_summary(self, soup: BeautifulSoup, full_html: str) -> str:
        try:
            # Create a minimal summary structure
            summary_parts = []
            
            # 1. Critical HEAD elements (very selective)
            head_elements = soup.head if soup.head else soup.find('head')
            if head_elements:
                # Only security-critical meta tags
                security_metas = []
                for meta in head_elements.find_all('meta'):
                    name = meta.get('name', '').lower()
                    http_equiv = meta.get('http-equiv', '').lower()
                    content = meta.get('content', '')
                    
                    if any(keyword in name for keyword in ['csrf', 'security', 'csp']) or \
                       any(keyword in http_equiv for keyword in ['content-security-policy', 'x-frame-options']):
                        security_metas.append(str(meta))
                
                if security_metas:
                    summary_parts.append(f"<head>{''.join(security_metas[:3])}</head>")
                
                # Only external scripts (not inline content)
                external_scripts = []
                for script in head_elements.find_all('script'):
                    if script.get('src'):
                        src = script['src']
                        # Only include if it looks security-relevant or is a major library
                        if any(keyword in src.lower() for keyword in ['auth', 'security', 'csrf', 'jquery', 'react', 'angular', 'vue']):
                            external_scripts.append(f'<script src="{src}"></script>')
                
                if external_scripts:
                    summary_parts.extend(external_scripts[:5])  # Max 5 scripts
            
            # 2. ALL forms (but condensed format)
            forms = soup.find_all('form')
            if forms:
                form_summaries = []
                for form in forms[:10]:  # Max 10 forms
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    
                    # Get input summary (just types and names)
                    inputs = []
                    for inp in form.find_all(['input', 'select', 'textarea']):
                        inp_type = inp.get('type', inp.name)
                        inp_name = inp.get('name', '')
                        if inp_name:
                            inputs.append(f'{inp_type}:{inp_name}')
                    
                    # Check for CSRF tokens
                    csrf_token = form.find('input', attrs={'name': re.compile(r'csrf|token', re.I)})
                    csrf_info = ' [CSRF]' if csrf_token else ''
                    
                    form_summary = f'<form action="{action}" method="{method}"{csrf_info}>{",".join(inputs[:10])}</form>'
                    form_summaries.append(form_summary)
                
                summary_parts.extend(form_summaries)
            
            # 3. Authentication/Admin links (very selective)
            auth_links = []
            auth_patterns = ['login', 'admin', 'auth', 'signin', 'dashboard', 'panel']
            
            for link in soup.find_all('a', href=True)[:50]:  # Check first 50 links only
                href = link.get('href', '').lower()
                text = link.get_text().lower().strip()
                
                if any(pattern in href or pattern in text for pattern in auth_patterns):
                    auth_links.append(f'<a href="{link["href"]}">{text[:20]}</a>')
                    if len(auth_links) >= 5:  # Max 5 auth links
                        break
            
            if auth_links:
                summary_parts.extend(auth_links)
            
            # 4. API endpoints (extract from various sources)
            api_endpoints = set()
            
            # From script content (quick scan)
            for script in soup.find_all('script'):
                if script.string:
                    content = script.string
                    # Quick regex for common API patterns
                    api_matches = re.findall(r'["\']([^"\']*(?:/api/|\.json|graphql)[^"\']*)["\']', content)
                    for match in api_matches[:5]:  # Max 5 per script
                        if len(match) > 5 and len(match) < 100:  # Reasonable length
                            api_endpoints.add(match)
            
            # From data attributes
            for elem in soup.find_all(attrs={'data-url': True, 'data-api': True, 'data-endpoint': True}):
                for attr in ['data-url', 'data-api', 'data-endpoint']:
                    value = elem.get(attr)
                    if value and ('/api/' in value or '.json' in value):
                        api_endpoints.add(value)
            
            if api_endpoints:
                api_list = list(api_endpoints)[:8]  # Max 8 API endpoints
                summary_parts.append(f'<!-- APIs: {", ".join(api_list)} -->')
            
            # 5. Error/Alert elements (condensed)
            error_elements = []
            error_selectors = ['.error', '.alert', '.warning', '#error', '#alert']
            
            for selector in error_selectors:
                elements = soup.select(selector)
                for elem in elements[:2]:  # Max 2 per selector type
                    text = elem.get_text().strip()[:100]  # Max 100 chars
                    if text:
                        error_elements.append(f'<div class="error-msg">{text}</div>')
                        if len(error_elements) >= 3:  # Max 3 total
                            break
                if len(error_elements) >= 3:
                    break
            
            if error_elements:
                summary_parts.extend(error_elements)
            
            # 6. Security-relevant comments (very selective)
            security_comments = []
            comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in str(text))
            
            for comment in comments[:20]:  # Check first 20 comments only
                comment_text = str(comment).lower()
                if any(keyword in comment_text for keyword in ['todo', 'fixme', 'hack', 'admin', 'password', 'key', 'token', 'debug']):
                    clean_comment = str(comment).strip()[:150]  # Max 150 chars
                    security_comments.append(clean_comment)
                    if len(security_comments) >= 3:  # Max 3 comments
                        break
            
            if security_comments:
                summary_parts.append(f'<!-- Security comments: {" | ".join(security_comments)} -->')
            
            # 7. Page structure (minimal)
            title = soup.find('title')
            title_text = title.get_text() if title else 'No title'
            
            # Combine everything into a minimal HTML structure
            summary_html = f'''<html>
                <head><title>{title_text[:50]}</title></head>
                <body>
                {chr(10).join(summary_parts)}
                </body>
                </html>'''
            
            # Final size check - be aggressive about trimming
            if len(summary_html) > 2500:  # Much stricter limit
                # Truncate but preserve structure
                summary_html = summary_html[:2500]
                # Ensure it ends properly
                if '</body>' not in summary_html[-50:]:
                    summary_html += '\n<!-- Truncated -->\n</body></html>'
            
            return summary_html
            
        except Exception as e:
            print(f"Error creating security-focused summary: {str(e)}")
            return self._create_html_fallback(soup)
    
    def _create_html_fallback(self, soup):
        try:
            title = soup.find('title')
            title_text = title.get_text() if title else 'Unknown'
            
            # Just get forms and critical links
            forms = soup.find_all('form')
            form_count = len(forms)
            
            auth_links = []
            for link in soup.find_all('a', href=True)[:20]:
                href = link.get('href', '').lower()
                if any(word in href for word in ['login', 'admin', 'auth']):
                    auth_links.append(href)
                    if len(auth_links) >= 3:
                        break
            
            return f'''<html>
                <head><title>{title_text[:30]}</title></head>
                <body>
                <!-- {form_count} forms found -->
                <!-- Auth links: {", ".join(auth_links)} -->
                </body>
                </html>'''
            
        except Exception:
            return "<html><body>Minimal page summary</body></html>"
    
    def _extract_links(self):
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
                        rel: Array.from(link.rel).join(' ') || ''
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
                    // Also get external script sources
                    if (script.src) {
                        scripts.push('EXTERNAL_SCRIPT: ' + script.src);
                    }
                });
                return scripts.join(' ');
            }
            """)
            
            # Enhanced API call patterns
            api_patterns = [
                # Standard fetch/ajax patterns
                r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.get\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.post\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.put\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.delete\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.patch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'ajax\s*\(\s*{[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'XMLHttpRequest.*open\s*\(\s*[\'"`][^\'"`]+[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]',
                
                # Modern framework patterns
                r'axios\.[a-z]+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'http\.[a-z]+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'request\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                
                # GraphQL patterns
                r'query\s*:\s*[\'"`]([^\'"`]*graphql[^\'"`]*)[\'"`]',
                r'mutation\s*:\s*[\'"`]([^\'"`]*graphql[^\'"`]*)[\'"`]',
                
                # WebSocket patterns
                r'WebSocket\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'socket\.io\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                
                # API endpoint patterns in strings
                r'[\'"`](/api/[a-zA-Z0-9_/\-\.]+)[\'"`]',
                r'[\'"`](/v\d+/[a-zA-Z0-9_/\-\.]+)[\'"`]',
                r'[\'"`]([^\'"`]*\.json)[\'"`]',
                r'[\'"`]([^\'"`]*\.xml)[\'"`]',
                r'[\'"`](/rest/[a-zA-Z0-9_/\-\.]+)[\'"`]',
                r'[\'"`]([^\'"`]*graphql[^\'"`]*)[\'"`]',
                
                # External script sources
                r'EXTERNAL_SCRIPT:\s*(https?://[^\s]+\.js)',
                
                # Configuration objects
                r'baseURL\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'apiUrl\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'endpoint\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, scripts_content, re.IGNORECASE)
                for match in matches:
                    if match.startswith('/') or match.startswith('http'):
                        api_endpoints.add(match)
            
            # Look for API endpoints in HTML attributes with more patterns
            html_content = self.page.content()
            html_api_patterns = [
                r'data-url\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
                r'data-endpoint\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
                r'data-api\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
                r'action\s*=\s*[\'"`]([^\'"`]*api[^\'"`]*)[\'"`]',
                r'href\s*=\s*[\'"`]([^\'"`]*api[^\'"`]*)[\'"`]',
                r'src\s*=\s*[\'"`]([^\'"`]*\.json[^\'"`]*)[\'"`]',
                r'content\s*=\s*[\'"`]([^\'"`]*api[^\'"`]*)[\'"`]',
            ]
            
            for pattern in html_api_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if '/api/' in match or match.endswith('.json') or match.endswith('.xml') or 'graphql' in match:
                        api_endpoints.add(match)
            
            # Look for common API paths in window object and global variables
            try:
                global_vars = self.page.evaluate("""
                () => {
                    const vars = [];
                    // Check window object for API-related properties
                    for (let prop in window) {
                        if (typeof window[prop] === 'string' && 
                            (window[prop].includes('/api/') || 
                             window[prop].includes('.json') || 
                             window[prop].includes('graphql'))) {
                            vars.push(window[prop]);
                        }
                    }
                    
                    // Check for common global config objects
                    const configObjects = ['config', 'API_CONFIG', 'apiConfig', 'endpoints', 'API_ENDPOINTS'];
                    configObjects.forEach(obj => {
                        if (window[obj] && typeof window[obj] === 'object') {
                            vars.push(JSON.stringify(window[obj]));
                        }
                    });
                    
                    return vars;
                }
                """)
                
                for var_content in global_vars:
                    if isinstance(var_content, str):
                        # Extract URLs from global variables
                        url_matches = re.findall(r'https?://[^\s"\']+|/[a-zA-Z0-9_/\-\.]+', var_content)
                        for url in url_matches:
                            if '/api/' in url or url.endswith('.json') or 'graphql' in url:
                                api_endpoints.add(url)
                                
            except Exception:
                pass  # Continue if global variable extraction fails
            
            # Convert to list of dictionaries with more info
            self.api_calls = []
            for endpoint in list(api_endpoints)[:25]:  # Increased limit to 25 endpoints
                # Convert relative URLs to absolute
                if endpoint.startswith('/'):
                    endpoint = urljoin(self.current_url, endpoint)
                
                # Determine likely HTTP method based on endpoint pattern
                method = 'GET'  # Default
                if any(word in endpoint.lower() for word in ['create', 'add', 'new', 'register', 'signup']):
                    method = 'POST'
                elif any(word in endpoint.lower() for word in ['update', 'edit', 'modify']):
                    method = 'PUT'
                elif any(word in endpoint.lower() for word in ['delete', 'remove']):
                    method = 'DELETE'
                
                self.api_calls.append({
                    'endpoint': endpoint,
                    'method': method,
                    'type': 'discovered',
                    'source': 'javascript_analysis'
                })
            
        except Exception as e:
            print(f"Error extracting API calls: {str(e)}")
            self.api_calls = []
    
    def _follow_redirects(self):
        """Follow redirects and analyze additional pages for more comprehensive data."""
        try:
            print("Following redirects and analyzing additional pages...")
            
            # Common paths to check for redirects and additional content
            common_paths = [
                '/robots.txt',
                '/sitemap.xml',
                '/.well-known/security.txt',
                '/api',
                '/api/v1',
                '/api/docs',
                '/swagger',
                '/graphql',
                '/admin',
                '/login',
                '/dashboard'
            ]
            
            base_url = f"{urlparse(self.current_url).scheme}://{urlparse(self.current_url).netloc}"
            additional_findings = {
                'redirects': [],
                'accessible_paths': [],
                'additional_apis': []
            }
            
            for path in common_paths:
                try:
                    test_url = urljoin(base_url, path)
                    
                    # Use requests for quick checks (faster than Playwright for simple requests)
                    response = requests.get(test_url, timeout=5, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 307, 308]:
                        if response.status_code in [301, 302, 307, 308]:
                            redirect_location = response.headers.get('Location', '')
                            additional_findings['redirects'].append({
                                'from': test_url,
                                'to': redirect_location,
                                'status': response.status_code
                            })
                            print(f"Found redirect: {test_url} -> {redirect_location}")
                        else:
                            additional_findings['accessible_paths'].append({
                                'url': test_url,
                                'status': response.status_code,
                                'content_type': response.headers.get('content-type', ''),
                                'content_length': len(response.content)
                            })
                            print(f"Found accessible path: {test_url}")
                            
                            # Check if it's an API endpoint
                            if any(api_indicator in path for api_indicator in ['/api', '/graphql', 'swagger']):
                                additional_findings['additional_apis'].append(test_url)
                    
                except requests.RequestException:
                    continue  # Skip if request fails
                except Exception:
                    continue  # Skip any other errors
            
            # Store additional findings
            self.redirect_data = additional_findings
            
        except Exception as e:
            print(f"Error following redirects: {str(e)}")
            self.redirect_data = {'redirects': [], 'accessible_paths': [], 'additional_apis': []}
    
    def _perform_reconnaissance(self):
        """Perform comprehensive reconnaissance including technology detection."""
        try:
            print("Performing reconnaissance...")
            
            self.recon_data = {
                'technologies': [],
                'security_headers': {},
                'dns_info': {}
            }
            
            # Technology Detection only (subdomain enumeration removed)
            self._detect_technologies()
            
        except Exception as e:
            print(f"Error during reconnaissance: {str(e)}")
            self.recon_data = {'technologies': [], 'security_headers': {}, 'dns_info': {}}
    
    def _detect_technologies(self):
        """Detect technologies used by the website."""
        try:
            print("Detecting technologies...")
            
            # Get current page response headers
            try:
                response = requests.get(self.current_url, timeout=10)
                headers = response.headers
                content = response.text
            except:
                headers = {}
                content = self.page.content()
            
            technologies = []
            
            # Server detection
            server = headers.get('server', '')
            if server:
                technologies.append({
                    'name': 'Server',
                    'value': server,
                    'category': 'Web Server'
                })
            
            # Framework detection from headers
            framework_headers = {
                'x-powered-by': 'Framework',
                'x-aspnet-version': 'ASP.NET',
                'x-generator': 'Generator',
                'x-drupal-cache': 'Drupal',
                'x-craft-powered-by': 'Craft CMS'
            }
            
            for header, tech in framework_headers.items():
                if header in headers:
                    technologies.append({
                        'name': tech,
                        'value': headers[header],
                        'category': 'Framework'
                    })
            
            # Content-based detection
            content_patterns = {
                'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
                'React': [r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                'Angular': [r'ng-version', r'angular', r'@angular'],
                'Vue.js': [r'vue\.js', r'__VUE__', r'v-if'],
                'jQuery': [r'jquery', r'\$\(document\)\.ready'],
                'Bootstrap': [r'bootstrap', r'btn-primary', r'container-fluid'],
                'Django': [r'csrfmiddlewaretoken', r'django'],
                'Laravel': [r'laravel_session', r'_token'],
                'Express.js': [r'express', r'X-Powered-By.*Express'],
                'Next.js': [r'__NEXT_DATA__', r'_next/static'],
                'Nuxt.js': [r'__NUXT__', r'nuxt'],
                'Gatsby': [r'___gatsby', r'gatsby-'],
                'Shopify': [r'shopify', r'cdn\.shopify\.com'],
                'Magento': [r'magento', r'mage/cookies'],
                'Joomla': [r'joomla', r'/media/jui/'],
                'Drupal': [r'drupal', r'sites/default/files']
            }
            
            for tech, patterns in content_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        technologies.append({
                            'name': tech,
                            'category': 'Technology',
                            'confidence': 'High' if len([p for p in patterns if re.search(p, content, re.IGNORECASE)]) > 1 else 'Medium'
                        })
                        break
            
            # JavaScript library detection from page
            try:
                js_libraries = self.page.evaluate("""
                () => {
                    const libs = [];
                    
                    // Check for common libraries
                    if (typeof jQuery !== 'undefined') libs.push('jQuery ' + (jQuery.fn.jquery || ''));
                    if (typeof React !== 'undefined') libs.push('React');
                    if (typeof Vue !== 'undefined') libs.push('Vue.js');
                    if (typeof angular !== 'undefined') libs.push('AngularJS');
                    if (typeof $ !== 'undefined' && $.fn && $.fn.modal) libs.push('Bootstrap');
                    if (typeof moment !== 'undefined') libs.push('Moment.js');
                    if (typeof _ !== 'undefined') libs.push('Lodash/Underscore');
                    if (typeof axios !== 'undefined') libs.push('Axios');
                    if (typeof io !== 'undefined') libs.push('Socket.IO');
                    
                    return libs;
                }
                """)
                
                for lib in js_libraries:
                    technologies.append({
                        'name': lib,
                        'category': 'JavaScript Library',
                        'source': 'runtime_detection'
                    })
                    
            except Exception:
                pass
            
            # Security headers analysis
            security_headers = {
                'strict-transport-security': 'HSTS',
                'content-security-policy': 'CSP',
                'x-frame-options': 'X-Frame-Options',
                'x-content-type-options': 'X-Content-Type-Options',
                'x-xss-protection': 'X-XSS-Protection',
                'referrer-policy': 'Referrer-Policy'
            }
            
            security_analysis = {}
            for header, name in security_headers.items():
                if header in headers:
                    security_analysis[name] = {
                        'present': True,
                        'value': headers[header]
                    }
                else:
                    security_analysis[name] = {'present': False}
            
            self.recon_data['technologies'] = technologies
            self.recon_data['security_headers'] = security_analysis
            
        except Exception as e:
            print(f"Error detecting technologies: {str(e)}")
            self.recon_data['technologies'] = []
            self.recon_data['security_headers'] = {}
    
    def _format_page_data(self) -> str:
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
            
            # Format reconnaissance data
            recon_summary = ""
            if hasattr(self, 'recon_data'):
                technologies = [tech['name'] for tech in self.recon_data.get('technologies', [])]
                security_headers = [name for name, data in self.recon_data.get('security_headers', {}).items() if data.get('present')]
                
                recon_summary = f"""
                Reconnaissance Data:
                - Technologies Detected: {technologies}
                - Security Headers Present: {security_headers}"""
            
            # Format redirect data
            redirect_summary = ""
            if hasattr(self, 'redirect_data'):
                accessible_paths = [path['url'] for path in self.redirect_data.get('accessible_paths', [])]
                redirects = [f"{r['from']} -> {r['to']}" for r in self.redirect_data.get('redirects', [])]
                additional_apis = self.redirect_data.get('additional_apis', [])
                
                redirect_summary = f"""
                Path Analysis:
                - Accessible Paths: {accessible_paths}
                - Redirects Found: {redirects}
                - Additional APIs: {additional_apis}"""
            
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
                - API calls: [{', '.join(api_calls_str)}]{recon_summary}{redirect_summary}"""

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
    # Test URL
    starting_url = "https://github.com/Avinier"
    
    try:
        # Initialize WebProxy
        proxy = WebProxy(starting_url)
        
        # Create browser instance
        browser, context, page, playwright = proxy.create_proxy()
        
        try:
            # Navigate to the URL
            page.goto(starting_url, wait_until="networkidle")
            
            # Initialize PageDataExtractor
            extractor = PageDataExtractor(page)
            
            # Extract page data
            page_data = extractor.extract_page_data()
            
            # Print the extracted data
            print("\n=== Extracted Page Data ===")
            print(page_data)
            
            # Get and print network traffic
            print("\n=== Network Traffic ===")
            traffic = proxy.pretty_print_traffic()
            if traffic:
                print(traffic)
            else:
                print("No network traffic captured")
            
            # Save network data
            proxy.save_network_data("network_capture.json")
            
        finally:
            # Clean up browser resources
            context.close()
            browser.close()
            playwright.stop()
            
    except Exception as e:
        print(f"Error during testing: {str(e)}", file=sys.stderr)
        sys.exit(1)

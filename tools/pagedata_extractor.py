import re
import json
import sys
import socket
import requests
import time
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse, parse_qs

from playwright.sync_api import Page
from bs4 import BeautifulSoup, Comment

from tools.webproxy import WebProxy

class PageDataExtractor:
    """
    Enhanced page data extractor optimized for penetration testing workflows.
    Extracts comprehensive page data with targeted advanced reconnaissance.
    Focuses on actionable intelligence for security testing.
    """
    
    def __init__(self, playwright_page: Page, config: Dict[str, Any] = None):
        self.page = playwright_page
        self.current_url = self.page.url
        self.config = config or {}
        
        # Core data structures
        self.html_content = ""
        self.links = []
        self.forms = []
        self.sensitive_strings = []
        self.api_calls = []
        self.security_headers = {}
        self.cookies_info = {}
        
        # Advanced recon data (focused on pentest value)
        self.hidden_endpoints = []
        self.technology_stack = {}
        self.directory_paths = []
        self.parameter_candidates = {}
        self.error_pages = []
        
        # Penetration testing focused patterns
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
            r'(?i)(backup|bak)',
            r'(?i)(test|debug)',
            r'(?i)(localhost|127\.0\.0\.1)',
            r'(?i)(staging|dev|development)',
            # Additional pentest-valuable patterns
            r'(?i)(mysql|postgres|mongodb|redis)',
            r'(?i)(aws|s3|bucket)',
            r'(?i)(firebase|gcp)',
            r'(?i)(docker|kubernetes)',
        ]
        
        # Advanced endpoint discovery patterns for pentest
        self.endpoint_patterns = [
            # API endpoints
            r'["\'](/api/v?\d*/[a-zA-Z0-9_/\-\.]*)["\']',
            r'["\'](https?://[^"\']*api[^"\']*)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'["\'](/rest/[^"\']*)["\']',
            r'["\'](/[a-zA-Z0-9_/\-]*\.(?:json|xml))["\']',
            
            # Admin/Management interfaces (high pentest value)
            r'["\'](/admin[^"\']*)["\']',
            r'["\'](/manage[^"\']*)["\']',
            r'["\'](/dashboard[^"\']*)["\']',
            r'["\'](/panel[^"\']*)["\']',
            
            # Development/Debug endpoints (critical for pentest)
            r'["\'](/debug[^"\']*)["\']',
            r'["\'](/test[^"\']*)["\']',
            r'["\'](/dev[^"\']*)["\']',
            r'["\'](/staging[^"\']*)["\']',
            
            # File paths of interest
            r'["\'](/[a-zA-Z0-9_/\-]*\.(?:bak|backup|old|tmp|log|sql|zip|tar|gz))["\']',
            r'["\'](\.\.?/[^"\']*)["\']',
            
            # Configuration files
            r'["\'](/\.well-known/[^"\']*)["\']',
            r'["\'](/robots\.txt)["\']',
            r'["\'](/sitemap\.xml)["\']',
            r'["\'](/\.env)["\']',
            r'["\'](/config\.[a-zA-Z]+)["\']',
        ]
        
        # Common vulnerable parameters for testing
        self.vulnerable_params = [
            'id', 'user', 'file', 'path', 'dir', 'page', 'url', 'redirect',
            'callback', 'next', 'cmd', 'exec', 'include', 'source', 'template',
            'q', 'search', 'query', 'filter', 'sort', 'order', 'limit', 'offset'
        ]
    
    def extract_page_data(self) -> str:
        """Extract comprehensive page data optimized for penetration testing."""
        try:
            print("Starting enhanced page data extraction for penetration testing...")
            
            # Core extraction methods
            self._extract_html_content()
            self._extract_links()
            self._extract_forms()
            self._extract_sensitive_strings()
            self._extract_api_calls()
            self._extract_security_headers()
            self._extract_cookies_info()
            
            # Advanced pentest-focused reconnaissance
            self._discover_hidden_endpoints()
            self._detect_technology_stack()
            self._enumerate_directories()
            self._analyze_parameters()
            self._detect_error_patterns()
            
            # Generate comprehensive report
            return self._format_page_data()
            
        except Exception as e:
            print(f"Error extracting page data: {str(e)}")
            return self._get_fallback_data()
    
    def _extract_html_content(self):
        """Extract and summarize HTML content for security analysis."""
        try:
            full_html = self.page.content()
            soup = BeautifulSoup(full_html, 'html.parser')
            
            # Create security-focused summary
            summary_parts = []
            
            # Title
            title = soup.find('title')
            title_text = title.get_text() if title else 'No title'
            
            # Security-relevant meta tags
            security_metas = []
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                http_equiv = meta.get('http-equiv', '').lower()
                if any(keyword in name for keyword in ['csrf', 'security', 'csp']) or \
                   any(keyword in http_equiv for keyword in ['content-security-policy', 'x-frame-options']):
                    security_metas.append(str(meta))
            
            # External scripts (potential security concerns)
            external_scripts = []
            for script in soup.find_all('script'):
                if script.get('src'):
                    src = script['src']
                    if any(keyword in src.lower() for keyword in ['auth', 'security', 'csrf', 'jquery', 'react', 'angular']):
                        external_scripts.append(f'<script src="{src}"></script>')
            
            # Error/alert elements
            error_elements = []
            for selector in ['.error', '.alert', '.warning', '#error', '#alert']:
                elements = soup.select(selector)
                for elem in elements[:2]:
                    text = elem.get_text().strip()[:100]
                    if text:
                        error_elements.append(f'<div class="error-msg">{text}</div>')
            
            # Security comments
            security_comments = []
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            for comment in comments[:10]:
                comment_text = str(comment).lower()
                if any(keyword in comment_text for keyword in ['todo', 'fixme', 'hack', 'admin', 'password', 'key', 'token']):
                    clean_comment = str(comment).strip()[:100]
                    security_comments.append(clean_comment)
            
            # Build summary
            self.html_content = f'''<html>
<head><title>{title_text}</title></head>
<body>
<!-- Security Meta Tags: {len(security_metas)} found -->
<!-- External Scripts: {len(external_scripts)} found -->
<!-- Error Elements: {len(error_elements)} found -->
<!-- Security Comments: {len(security_comments)} found -->
</body>
</html>'''
            
        except Exception as e:
            print(f"Error extracting HTML content: {str(e)}")
            self.html_content = f"<html><body>Error extracting HTML from {self.current_url}</body></html>"
    
    def _extract_links(self):
        """Enhanced link extraction with advanced discovery techniques."""
        try:
            print("Performing advanced link discovery...")
            
            all_discovered_links = set()
            
            # 1. Standard DOM link extraction
            standard_links = self._extract_standard_links()
            all_discovered_links.update(standard_links)
            
            # 2. JavaScript-based link discovery  
            js_links = self._extract_javascript_links()
            all_discovered_links.update(js_links)
            
            # 3. CSS resource link discovery
            css_links = self._extract_css_links()
            all_discovered_links.update(css_links)
            
            # 4. HTML comment link discovery
            comment_links = self._extract_comment_links()
            all_discovered_links.update(comment_links)
            
            # 5. Data attribute link discovery
            data_attr_links = self._extract_data_attribute_links()
            all_discovered_links.update(data_attr_links)
            
            # 6. Form action and dynamic endpoint discovery
            form_links = self._extract_form_endpoints()
            all_discovered_links.update(form_links)
            
            # 7. Source map and webpack link discovery
            sourcemap_links = self._extract_sourcemap_links()
            all_discovered_links.update(sourcemap_links)
            
            # Convert to structured format
            self.links = self._structure_discovered_links(all_discovered_links)
            
            print(f"Advanced link discovery completed: {len(self.links)} unique links found")
            
        except Exception as e:
            print(f"Error in advanced link extraction: {str(e)}")
            self.links = []
    
    def _extract_standard_links(self) -> set:
        """Extract standard DOM anchor links."""
        try:
            links_js = """
            () => {
                const links = new Set();
                
                // Standard anchor tags
                document.querySelectorAll('a[href]').forEach(link => {
                    links.add(link.href);
                });
                
                // Area tags in image maps
                document.querySelectorAll('area[href]').forEach(area => {
                    links.add(area.href);
                });
                
                // Link tags (stylesheets, etc.)
                document.querySelectorAll('link[href]').forEach(link => {
                    links.add(link.href);
                });
                
                return Array.from(links);
            }
            """
            
            raw_links = self.page.evaluate(links_js)
            
            # Filter and convert to absolute URLs
            processed_links = set()
            for link in raw_links:
                if self._is_valid_link(link):
                    absolute_url = self._make_absolute_url(link)
                    if absolute_url:
                        processed_links.add(absolute_url)
            
            return processed_links
            
        except Exception as e:
            print(f"Error extracting standard links: {e}")
            return set()
    
    def _extract_javascript_links(self) -> set:
        """Advanced JavaScript link extraction from all script sources."""
        try:
            print("Extracting JavaScript links...")
            
            discovered_links = set()
            
            # Get all script content (inline and external)
            scripts_content = self.page.evaluate("""
            () => {
                const scripts = [];
                
                // Inline scripts
                document.querySelectorAll('script').forEach(script => {
                    if (script.textContent && script.textContent.trim()) {
                        scripts.push({
                            type: 'inline',
                            content: script.textContent,
                            src: null
                        });
                    }
                    if (script.src) {
                        scripts.push({
                            type: 'external',
                            content: null,
                            src: script.src
                        });
                    }
                });
                
                return scripts;
            }
            """)
            
            # Process each script
            for script in scripts_content:
                if script['type'] == 'inline' and script['content']:
                    links = self._extract_links_from_js_content(script['content'])
                    discovered_links.update(links)
                elif script['type'] == 'external' and script['src']:
                    # Add external script URL
                    discovered_links.add(script['src'])
                    
                    # Try to fetch and analyze external script content
                    try:
                        response = requests.get(script['src'], timeout=5)
                        if response.status_code == 200:
                            external_links = self._extract_links_from_js_content(response.text)
                            discovered_links.update(external_links)
                    except:
                        continue
            
            # Also check for dynamic URL construction in global variables
            global_urls = self.page.evaluate("""
            () => {
                const urls = [];
                
                // Check common global config objects
                const configObjects = ['config', 'API_CONFIG', 'apiConfig', 'endpoints', 'API_ENDPOINTS', 'routes'];
                
                configObjects.forEach(obj => {
                    if (window[obj] && typeof window[obj] === 'object') {
                        const configStr = JSON.stringify(window[obj]);
                        // Extract URLs from config objects
                        const urlMatches = configStr.match(/https?:\/\/[^"'\\s]+|\/[a-zA-Z0-9_\/\-\.]+/g);
                        if (urlMatches) {
                            urls.push(...urlMatches);
                        }
                    }
                });
                
                // Check window properties for URLs
                for (let prop in window) {
                    try {
                        if (typeof window[prop] === 'string' && 
                            (window[prop].startsWith('/') || window[prop].startsWith('http'))) {
                            urls.push(window[prop]);
                        }
                    } catch(e) {
                        // Skip restricted properties
                    }
                }
                
                return urls;
            }
            """)
            
            discovered_links.update(global_urls)
            
            return discovered_links
            
        except Exception as e:
            print(f"Error extracting JavaScript links: {e}")
            return set()
    
    def _extract_links_from_js_content(self, js_content: str) -> set:
        """Extract links from JavaScript content using advanced patterns."""
        links = set()
        
        # Comprehensive JavaScript URL patterns
        js_patterns = [
            # API calls and AJAX requests
            r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.(?:get|post|put|delete|patch|head|options)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'ajax\s*\(\s*[{]?[^}]*[\'"`]?url[\'"`]?\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
            r'XMLHttpRequest.*open\s*\([^,]*,\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # Framework-specific patterns
            r'axios\.[a-z]+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\$\.(?:get|post|ajax)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # URL assignments and variables
            r'(?:url|URL|endpoint|href|src)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'location\.(?:href|assign|replace)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'window\.open\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # Router and navigation patterns
            r'(?:router|navigate|redirect|push|replace)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'(?:route|path)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # Import and require statements
            r'import\s+.*from\s+[\'"`]([^\'"`]+)[\'"`]',
            r'require\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # WebSocket and event source URLs
            r'WebSocket\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'EventSource\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # Configuration and base URLs
            r'(?:baseURL|base_url|apiUrl|api_url|serverUrl|server_url)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # String literals that look like URLs or paths
            r'[\'"`](/(?:api|admin|user|auth|login|register|dashboard|panel|manage|config|debug|test|dev|staging|prod|upload|download|file|image|asset|static|public|private|secure|\.well-known)/[^\'"`]*)[\'"`]',
            r'[\'"`](https?://[^\'"`]+)[\'"`]',
            r'[\'"`](/[a-zA-Z0-9_/\-\.]{3,})[\'"`]',  # Relative paths
            
            # File extensions of interest
            r'[\'"`]([^\'"`]*\.(?:json|xml|txt|log|bak|sql|zip|tar|gz|pdf|doc|xls|csv))[\'"`]',
            
            # Template and dynamic URLs
            r'[\'"`]([^\'"`]*\$\{[^}]+\}[^\'"`]*)[\'"`]',  # Template literals
            r'[\'"`]([^\'"`]*%[sd][^\'"`]*)[\'"`]',  # Printf-style templates
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match else ""
                
                if match and len(match) > 2:
                    # Convert relative URLs to absolute
                    absolute_url = self._make_absolute_url(match)
                    if absolute_url:
                        links.add(absolute_url)
        
        return links
    
    def _extract_css_links(self) -> set:
        """Extract URLs from CSS files and inline styles."""
        try:
            discovered_links = set()
            
            # Get all CSS sources
            css_sources = self.page.evaluate("""
            () => {
                const styles = [];
                
                // External stylesheets
                document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
                    if (link.href) {
                        styles.push({type: 'external', href: link.href, content: null});
                    }
                });
                
                // Inline styles
                document.querySelectorAll('style').forEach(style => {
                    if (style.textContent) {
                        styles.push({type: 'inline', href: null, content: style.textContent});
                    }
                });
                
                return styles;
            }
            """)
            
            for css_source in css_sources:
                if css_source['type'] == 'external':
                    # Add the CSS file URL itself
                    discovered_links.add(css_source['href'])
                    
                    # Fetch and analyze external CSS content
                    try:
                        response = requests.get(css_source['href'], timeout=5)
                        if response.status_code == 200:
                            css_links = self._extract_links_from_css_content(response.text)
                            discovered_links.update(css_links)
                    except:
                        continue
                        
                elif css_source['type'] == 'inline' and css_source['content']:
                    css_links = self._extract_links_from_css_content(css_source['content'])
                    discovered_links.update(css_links)
            
            return discovered_links
            
        except Exception as e:
            print(f"Error extracting CSS links: {e}")
            return set()
    
    def _extract_links_from_css_content(self, css_content: str) -> set:
        """Extract URLs from CSS content."""
        links = set()
        
        css_patterns = [
            r'url\s*\(\s*[\'"]?([^\'")]+)[\'"]?\s*\)',
            r'@import\s+[\'"]([^\'";]+)[\'"]',
            r'@import\s+url\s*\(\s*[\'"]?([^\'")]+)[\'"]?\s*\)',
        ]
        
        for pattern in css_patterns:
            matches = re.findall(pattern, css_content, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith('data:'):
                    absolute_url = self._make_absolute_url(match)
                    if absolute_url:
                        links.add(absolute_url)
        
        return links
    
    def _extract_comment_links(self) -> set:
        """Extract URLs from HTML comments."""
        try:
            discovered_links = set()
            
            html_content = self.page.content()
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all comments
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            
            for comment in comments:
                comment_text = str(comment)
                
                # Extract URLs from comments using patterns
                comment_patterns = [
                    r'https?://[^\s<>"\']+',
                    r'/[a-zA-Z0-9_/\-\.]+',
                    r'(?:TODO|FIXME|NOTE|HACK).*?(?:https?://[^\s]+|/[a-zA-Z0-9_/\-\.]+)',
                ]
                
                for pattern in comment_patterns:
                    matches = re.findall(pattern, comment_text, re.IGNORECASE)
                    for match in matches:
                        absolute_url = self._make_absolute_url(match)
                        if absolute_url:
                            discovered_links.add(absolute_url)
            
            return discovered_links
            
        except Exception as e:
            print(f"Error extracting comment links: {e}")
            return set()
    
    def _extract_data_attribute_links(self) -> set:
        """Extract URLs from data attributes."""
        try:
            discovered_links = set()
            
            data_attrs_js = """
            () => {
                const urls = [];
                
                // Common data attributes that might contain URLs
                const dataAttrs = [
                    'data-url', 'data-href', 'data-src', 'data-action', 'data-endpoint',
                    'data-api', 'data-target', 'data-link', 'data-path', 'data-route'
                ];
                
                dataAttrs.forEach(attr => {
                    document.querySelectorAll(`[${attr}]`).forEach(element => {
                        const value = element.getAttribute(attr);
                        if (value && (value.startsWith('/') || value.startsWith('http'))) {
                            urls.push(value);
                        }
                    });
                });
                
                // Also check any data-* attribute for URL patterns
                document.querySelectorAll('[data-*]').forEach(element => {
                    Array.from(element.attributes).forEach(attr => {
                        if (attr.name.startsWith('data-') && attr.value) {
                            const value = attr.value;
                            if (value.startsWith('/') || value.startsWith('http')) {
                                urls.push(value);
                            }
                        }
                    });
                });
                
                return urls;
            }
            """
            
            data_urls = self.page.evaluate(data_attrs_js)
            
            for url in data_urls:
                absolute_url = self._make_absolute_url(url)
                if absolute_url:
                    discovered_links.add(absolute_url)
            
            return discovered_links
            
        except Exception as e:
            print(f"Error extracting data attribute links: {e}")
            return set()
    
    def _extract_form_endpoints(self) -> set:
        """Extract endpoints from forms and form-related JavaScript."""
        try:
            discovered_links = set()
            
            # Form actions
            for form in self.forms:
                if form.get('action'):
                    absolute_url = self._make_absolute_url(form['action'])
                    if absolute_url:
                        discovered_links.add(absolute_url)
            
            # Form submission handlers in JavaScript
            form_js = self.page.evaluate("""
            () => {
                const urls = [];
                
                // Look for form submission event handlers
                document.querySelectorAll('form').forEach(form => {
                    // Check for data attributes
                    ['data-action', 'data-submit-url', 'data-endpoint'].forEach(attr => {
                        const value = form.getAttribute(attr);
                        if (value) urls.push(value);
                    });
                });
                
                return urls;
            }
            """)
            
            for url in form_js:
                absolute_url = self._make_absolute_url(url)
                if absolute_url:
                    discovered_links.add(absolute_url)
            
            return discovered_links
            
        except Exception as e:
            print(f"Error extracting form endpoints: {e}")
            return set()
    
    def _extract_sourcemap_links(self) -> set:
        """Extract source map and webpack-related links."""
        try:
            discovered_links = set()
            
            sourcemap_js = """
            () => {
                const urls = [];
                
                // Look for source map comments in script tags
                document.querySelectorAll('script').forEach(script => {
                    if (script.textContent) {
                        const content = script.textContent;
                        
                        // Source map comments
                        const sourcemapMatches = content.match(/\/\/[@#]\\s*sourceMappingURL=([^\\s]+)/g);
                        if (sourcemapMatches) {
                            sourcemapMatches.forEach(match => {
                                const url = match.split('=')[1];
                                if (url) urls.push(url.trim());
                            });
                        }
                        
                        // Webpack chunk loading patterns
                        const webpackMatches = content.match(/["']([^"']*\\.(?:js|css|map)(?:\\?[^"']*)?["']])/g);
                        if (webpackMatches) {
                            webpackMatches.forEach(match => {
                                const cleaned = match.replace(/['"]/g, '');
                                if (cleaned) urls.push(cleaned);
                            });
                        }
                    }
                });
                
                return urls;
            }
            """
            
            sourcemap_urls = self.page.evaluate(sourcemap_js)
            
            for url in sourcemap_urls:
                absolute_url = self._make_absolute_url(url)
                if absolute_url:
                    discovered_links.add(absolute_url)
            
            return discovered_links
            
        except Exception as e:
            print(f"Error extracting sourcemap links: {e}")
            return set()
    
    def _is_valid_link(self, link: str) -> bool:
        """Check if a link is valid for security testing."""
        if not link or not isinstance(link, str):
            return False
        
        # Skip common non-HTTP protocols and invalid URLs
        skip_prefixes = ['javascript:', 'mailto:', 'tel:', 'ftp:', 'file:', '#', 'data:']
        return not any(link.startswith(prefix) for prefix in skip_prefixes)
    
    def _make_absolute_url(self, url: str) -> str:
        """Convert relative URL to absolute URL."""
        if not url:
            return ""
        
        try:
            if url.startswith('http'):
                return url
            elif url.startswith('//'):
                scheme = urlparse(self.current_url).scheme
                return f"{scheme}:{url}"
            elif url.startswith('/'):
                base = f"{urlparse(self.current_url).scheme}://{urlparse(self.current_url).netloc}"
                return urljoin(base, url)
            else:
                return urljoin(self.current_url, url)
        except:
            return ""
    
    def _structure_discovered_links(self, discovered_links: set) -> List[Dict]:
        """Structure discovered links with metadata for penetration testing."""
        structured_links = []
        
        for link in discovered_links:
            if not link:
                continue
                
            # Categorize link for penetration testing
            category = self._categorize_link(link)
            priority = self._assess_link_priority(link, category)
            
            structured_links.append({
                'url': link,
                'category': category,
                'priority': priority,
                'potential_attacks': self._suggest_attacks(link, category)
            })
        
        # Sort by priority and limit results
        structured_links.sort(key=lambda x: {'high': 3, 'medium': 2, 'low': 1}[x['priority']], reverse=True)
        
        return structured_links[:50]  # Limit to top 50 links
    
    def _categorize_link(self, url: str) -> str:
        """Categorize link based on URL patterns."""
        url_lower = url.lower()
        
        if any(word in url_lower for word in ['/admin', '/manage', '/dashboard', '/panel']):
            return 'admin'
        elif any(word in url_lower for word in ['/api/', '/rest/', '/graphql', '.json', '.xml']):
            return 'api'
        elif any(word in url_lower for word in ['/login', '/auth', '/signin', '/register']):
            return 'authentication'
        elif any(word in url_lower for word in ['/upload', '/file', '/download']):
            return 'file_handling'
        elif any(word in url_lower for word in ['/debug', '/test', '/dev', '/staging']):
            return 'development'
        elif any(ext in url_lower for ext in ['.bak', '.old', '.tmp', '.log', '.sql']):
            return 'sensitive_files'
        elif any(word in url_lower for word in ['/user', '/profile', '/account']):
            return 'user_area'
        else:
            return 'general'
    
    def _assess_link_priority(self, url: str, category: str) -> str:
        """Assess penetration testing priority of a link."""
        high_priority_categories = ['admin', 'development', 'sensitive_files', 'api']
        medium_priority_categories = ['authentication', 'file_handling', 'user_area']
        
        if category in high_priority_categories:
            return 'high'
        elif category in medium_priority_categories:
            return 'medium'
        else:
            return 'low'
    
    def _suggest_attacks(self, url: str, category: str) -> List[str]:
        """Suggest relevant attack types for a link."""
        attacks = []
        url_lower = url.lower()
        
        # Default attacks for all URLs
        attacks.extend(['xss', 'csrf'])
        
        # Category-specific attacks
        if category == 'api':
            attacks.extend(['sqli', 'idor', 'api_abuse', 'nosqli'])
        elif category == 'authentication':
            attacks.extend(['brute_force', 'sqli', 'bypass'])
        elif category == 'file_handling':
            attacks.extend(['lfi', 'rfi', 'file_upload', 'path_traversal'])
        elif category == 'admin':
            attacks.extend(['privilege_escalation', 'idor', 'sqli'])
        elif category == 'development':
            attacks.extend(['info_disclosure', 'debug_access', 'source_disclosure'])
        
        # Parameter-based attacks
        if '?' in url:
            attacks.extend(['parameter_pollution', 'sqli', 'xss'])
        
        return list(set(attacks))  # Remove duplicates
    
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
                            value: field.type !== 'password' ? (field.value || '') : ''
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
            
            for form in raw_forms:
                action = form.get('action', '')
                
                # Convert relative action URLs to absolute
                if action and not action.startswith('http'):
                    action = urljoin(self.current_url, action)
                
                self.forms.append({
                    'action': action,
                    'method': form.get('method', 'GET').upper(),
                    'enctype': form.get('enctype', ''),
                    'id': form.get('id', ''),
                    'class': form.get('class', ''),
                    'fields': form.get('fields', [])
                })
            
        except Exception as e:
            print(f"Error extracting forms: {str(e)}")
            self.forms = []
    
    def _extract_sensitive_strings(self):
        """Extract sensitive strings from page content."""
        try:
            # Get page text and HTML
            page_text = self.page.evaluate("() => document.body.textContent || ''")
            html_source = self.page.content()
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
            
            # Look for file extensions of interest
            file_patterns = [
                r'\.[a-zA-Z0-9]+\.(bak|backup|old|tmp|log|config|conf|ini|env)',
                r'\.git\b', r'\.svn\b', r'\.env\b', r'config\.[a-zA-Z]+',
                r'\.htaccess\b', r'web\.config\b'
            ]
            
            for pattern in file_patterns:
                matches = re.findall(pattern, combined_content, re.IGNORECASE)
                for match in matches:
                    sensitive_findings.add(match)
            
            self.sensitive_strings = list(sensitive_findings)[:30]
            
        except Exception as e:
            print(f"Error extracting sensitive strings: {str(e)}")
            self.sensitive_strings = []
    
    def _extract_api_calls(self):
        """Extract API endpoints from JavaScript and HTML."""
        try:
            api_endpoints = set()
            
            # Get all script content
            scripts_content = self.page.evaluate("""
            () => {
                const scripts = [];
                document.querySelectorAll('script').forEach(script => {
                    if (script.textContent) {
                        scripts.push(script.textContent);
                    }
                    if (script.src) {
                        scripts.push('EXTERNAL_SCRIPT: ' + script.src);
                    }
                });
                return scripts.join(' ');
            }
            """)
            
            # Enhanced API patterns
            api_call_patterns = [
                r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\.(?:get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'ajax\s*\(\s*[{]?[^}]*[\'"`]?url[\'"`]?\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
                r'axios\.[a-z]+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'[\'"`](/api/[a-zA-Z0-9_/\-\.]+)[\'"`]',
                r'[\'"`]([^\'"`]*\.json)[\'"`]',
                r'[\'"`]([^\'"`]*graphql[^\'"`]*)[\'"`]',
            ]
            
            for pattern in api_call_patterns:
                matches = re.findall(pattern, scripts_content, re.IGNORECASE)
                for match in matches:
                    if match.startswith('/') or match.startswith('http'):
                        api_endpoints.add(match)
            
            # Get HTML attributes
            html_content = self.page.content()
            html_patterns = [
                r'data-url\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
                r'data-api\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
                r'action\s*=\s*[\'"`]([^\'"`]*api[^\'"`]*)[\'"`]',
            ]
            
            for pattern in html_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if '/api/' in match or match.endswith('.json') or 'graphql' in match:
                        api_endpoints.add(match)
            
            # Convert to list with method detection
            self.api_calls = []
            for endpoint in list(api_endpoints)[:20]:
                if endpoint.startswith('/'):
                    endpoint = urljoin(self.current_url, endpoint)
                
                # Simple method detection
                method = 'GET'
                if any(word in endpoint.lower() for word in ['create', 'add', 'register']):
                    method = 'POST'
                elif any(word in endpoint.lower() for word in ['update', 'edit']):
                    method = 'PUT'
                elif any(word in endpoint.lower() for word in ['delete', 'remove']):
                    method = 'DELETE'
                
                self.api_calls.append({
                    'endpoint': endpoint,
                    'method': method,
                    'source': 'javascript_analysis'
                })
            
        except Exception as e:
            print(f"Error extracting API calls: {str(e)}")
            self.api_calls = []
    
    def _extract_security_headers(self):
        """Extract security-related HTTP headers."""
        try:
            response = requests.get(self.current_url, timeout=10)
            headers = response.headers
            
            security_header_names = [
                'strict-transport-security', 'content-security-policy',
                'x-frame-options', 'x-content-type-options', 'x-xss-protection',
                'referrer-policy', 'permissions-policy'
            ]
            
            self.security_headers = {}
            for header in security_header_names:
                if header in headers:
                    self.security_headers[header] = headers[header]
            
            # Check for information disclosure headers
            disclosure_headers = ['server', 'x-powered-by', 'x-aspnet-version']
            for header in disclosure_headers:
                if header in headers:
                    self.security_headers[f"{header}_disclosure"] = headers[header]
            
        except Exception as e:
            print(f"Error extracting security headers: {str(e)}")
            self.security_headers = {}
    
    def _extract_cookies_info(self):
        """Extract cookie information."""
        try:
            response = requests.get(self.current_url, timeout=10)
            cookies = response.cookies
            
            self.cookies_info = {
                'total_cookies': len(cookies),
                'secure_cookies': 0,
                'httponly_cookies': 0,
                'insecure_cookies': []
            }
            
            for cookie in cookies:
                if cookie.secure:
                    self.cookies_info['secure_cookies'] += 1
                if 'HttpOnly' in str(cookie):
                    self.cookies_info['httponly_cookies'] += 1
                
                if not cookie.secure or 'HttpOnly' not in str(cookie):
                    self.cookies_info['insecure_cookies'].append({
                        'name': cookie.name,
                        'secure': cookie.secure,
                        'httponly': 'HttpOnly' in str(cookie)
                    })
            
        except Exception as e:
            print(f"Error extracting cookies: {str(e)}")
            self.cookies_info = {}
    
    # Advanced reconnaissance methods for penetration testing
    
    def _discover_hidden_endpoints(self):
        """Discover hidden endpoints valuable for penetration testing."""
        try:
            print("Discovering hidden endpoints...")
            
            discovered_endpoints = set()
            page_content = self.page.content()
            
            # Extract endpoints using advanced patterns
            for pattern in self.endpoint_patterns:
                matches = re.findall(pattern, page_content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match else ""
                    if match:
                        discovered_endpoints.add(match)
            
            # Look for endpoints in comments (often forgotten by developers)
            soup = BeautifulSoup(page_content, 'html.parser')
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            
            for comment in comments:
                comment_text = str(comment)
                # Look for URLs in comments
                url_matches = re.findall(r'(/[a-zA-Z0-9_/\-\.]+)', comment_text)
                for url in url_matches:
                    if any(keyword in url.lower() for keyword in ['api', 'admin', 'test', 'debug', 'dev']):
                        discovered_endpoints.add(url)
            
            # Convert to absolute URLs
            base_url = f"{urlparse(self.current_url).scheme}://{urlparse(self.current_url).netloc}"
            
            self.hidden_endpoints = []
            for endpoint in discovered_endpoints:
                if endpoint.startswith('/'):
                    full_url = urljoin(base_url, endpoint)
                elif endpoint.startswith('http'):
                    full_url = endpoint
                else:
                    continue
                
                # Categorize endpoint for pentest planning
                category = 'general'
                if any(word in endpoint.lower() for word in ['admin', 'manage', 'dashboard']):
                    category = 'admin'
                elif any(word in endpoint.lower() for word in ['api', 'rest', 'graphql']):
                    category = 'api'
                elif any(word in endpoint.lower() for word in ['debug', 'test', 'dev']):
                    category = 'development'
                elif any(ext in endpoint.lower() for ext in ['.bak', '.old', '.tmp', '.log']):
                    category = 'sensitive_files'
                
                self.hidden_endpoints.append({
                    'url': full_url,
                    'category': category,
                    'priority': 'high' if category in ['admin', 'development'] else 'medium'
                })
            
            # Remove duplicates and limit results
            seen_urls = set()
            unique_endpoints = []
            for endpoint in self.hidden_endpoints:
                if endpoint['url'] not in seen_urls:
                    seen_urls.add(endpoint['url'])
                    unique_endpoints.append(endpoint)
            
            self.hidden_endpoints = unique_endpoints[:30]
            print(f"Discovered {len(self.hidden_endpoints)} hidden endpoints")
            
        except Exception as e:
            print(f"Error discovering hidden endpoints: {str(e)}")
            self.hidden_endpoints = []
    
    def _detect_technology_stack(self):
        """Detect technology stack for targeted exploit selection."""
        try:
            print("Detecting technology stack...")
            
            # Get response headers for technology detection
            response = requests.get(self.current_url, timeout=10)
            headers = response.headers
            content = response.text
            
            self.technology_stack = {
                'web_server': [],
                'programming_language': [],
                'frameworks': [],
                'databases': [],
                'cloud_services': []
            }
            
            # Web server detection (critical for exploit selection)
            server_indicators = {
                'nginx': [r'nginx', r'server:\s*nginx'],
                'apache': [r'apache', r'server:\s*apache'],
                'iis': [r'iis', r'server:\s*microsoft-iis'],
                'tomcat': [r'tomcat', r'server:\s*tomcat'],
                'jetty': [r'jetty', r'server:\s*jetty']
            }
            
            combined_text = str(headers) + content[:5000]  # First 5KB for efficiency
            
            for server, patterns in server_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, combined_text, re.IGNORECASE):
                        self.technology_stack['web_server'].append(server)
                        break
            
            # Programming language detection (for targeted payloads)
            lang_indicators = {
                'php': [r'\.php', r'x-powered-by.*php', r'phpsessid'],
                'python': [r'django', r'flask', r'pyramid'],
                'nodejs': [r'express', r'x-powered-by.*express'],
                'java': [r'jsessionid', r'\.jsp', r'\.do\b'],
                'dotnet': [r'\.aspx', r'asp\.net', r'x-aspnet-version'],
                'ruby': [r'rails', r'ruby']
            }
            
            for lang, patterns in lang_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, combined_text, re.IGNORECASE):
                        self.technology_stack['programming_language'].append(lang)
                        break
            
            # Framework detection (for specific vulnerabilities)
            framework_indicators = {
                'wordpress': [r'wp-content', r'wp-includes'],
                'drupal': [r'drupal'],
                'joomla': [r'joomla'],
                'react': [r'react', r'__react'],
                'angular': [r'angular', r'ng-version'],
                'vue': [r'vue\.js', r'__vue__'],
                'jquery': [r'jquery']
            }
            
            for framework, patterns in framework_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, combined_text, re.IGNORECASE):
                        self.technology_stack['frameworks'].append(framework)
                        break
            
            # Database hints (for SQL injection targeting)
            db_indicators = {
                'mysql': [r'mysql', r'phpmyadmin'],
                'postgresql': [r'postgres', r'pgadmin'],
                'mongodb': [r'mongodb', r'mongo'],
                'redis': [r'redis'],
                'oracle': [r'oracle'],
                'mssql': [r'microsoft.*sql', r'mssql']
            }
            
            for db, patterns in db_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, combined_text, re.IGNORECASE):
                        self.technology_stack['databases'].append(db)
                        break
            
            # Cloud service detection (for cloud-specific attacks)
            cloud_indicators = {
                'aws': [r'amazonaws', r'awselb', r's3\.amazonaws'],
                'azure': [r'azure', r'azurewebsites'],
                'gcp': [r'googleusercontent', r'appspot'],
                'cloudflare': [r'cloudflare', r'cf-ray']
            }
            
            for cloud, patterns in cloud_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, combined_text, re.IGNORECASE):
                        self.technology_stack['cloud_services'].append(cloud)
                        break
            
            print("Technology stack detection completed")
            
        except Exception as e:
            print(f"Error detecting technology stack: {str(e)}")
            self.technology_stack = {}
    
    def _enumerate_directories(self):
        """Enumerate potential directory paths for fuzzing."""
        try:
            print("Enumerating directory paths...")
            
            discovered_paths = set()
            
            # Extract paths from all discovered links
            for link in self.links:
                parsed = urlparse(link['url'])
                path_parts = parsed.path.split('/')
                
                # Build directory paths
                current_path = ""
                for part in path_parts[:-1]:  # Exclude filename
                    if part:
                        current_path += f"/{part}"
                        discovered_paths.add(current_path)
            
            # Extract paths from API calls
            for api in self.api_calls:
                parsed = urlparse(api['endpoint'])
                path_parts = parsed.path.split('/')
                
                current_path = ""
                for part in path_parts[:-1]:
                    if part:
                        current_path += f"/{part}"
                        discovered_paths.add(current_path)
            
            # Common directory patterns based on discovered technology
            common_paths = [
                '/admin', '/api', '/backup', '/config', '/debug', '/dev',
                '/files', '/images', '/includes', '/js', '/css', '/uploads'
            ]
            
            # Add technology-specific paths
            if 'wordpress' in str(self.technology_stack.get('frameworks', [])):
                common_paths.extend(['/wp-admin', '/wp-content', '/wp-includes'])
            
            if 'drupal' in str(self.technology_stack.get('frameworks', [])):
                common_paths.extend(['/sites', '/modules', '/themes'])
            
            discovered_paths.update(common_paths)
            
            self.directory_paths = list(discovered_paths)[:20]  # Limit for efficiency
            print(f"Enumerated {len(self.directory_paths)} directory paths")
            
        except Exception as e:
            print(f"Error enumerating directories: {str(e)}")
            self.directory_paths = []
    
    def _analyze_parameters(self):
        """Analyze parameters for injection testing candidates."""
        try:
            print("Analyzing parameters for injection testing...")
            
            parameter_candidates = {}
            
            # Extract parameters from links
            for link in self.links:
                parsed = urlparse(link['url'])
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name in params.keys():
                        if param_name.lower() in self.vulnerable_params:
                            parameter_candidates[param_name] = {
                                'urls': parameter_candidates.get(param_name, {}).get('urls', []) + [link['url']],
                                'priority': 'high' if param_name in ['id', 'file', 'path', 'cmd'] else 'medium',
                                'injection_types': self._get_injection_types(param_name)
                            }
            
            # Extract parameters from forms
            for form in self.forms:
                for field in form['fields']:
                    field_name = field.get('name', '')
                    if field_name and field_name.lower() in self.vulnerable_params:
                        parameter_candidates[field_name] = {
                            'forms': parameter_candidates.get(field_name, {}).get('forms', []) + [form['action']],
                            'priority': 'high' if field.get('type') in ['text', 'search'] else 'medium',
                            'injection_types': self._get_injection_types(field_name)
                        }
            
            self.parameter_candidates = parameter_candidates
            print(f"Identified {len(self.parameter_candidates)} parameter candidates")
            
        except Exception as e:
            print(f"Error analyzing parameters: {str(e)}")
            self.parameter_candidates = {}
    
    def _get_injection_types(self, param_name: str) -> List[str]:
        """Determine likely injection types based on parameter name."""
        injection_types = ['xss']  # Default to XSS testing
        
        param_lower = param_name.lower()
        
        if param_lower in ['id', 'user_id', 'userid']:
            injection_types.extend(['sqli', 'nosqli'])
        elif param_lower in ['file', 'path', 'dir', 'include']:
            injection_types.extend(['lfi', 'rfi', 'path_traversal'])
        elif param_lower in ['cmd', 'exec', 'command']:
            injection_types.extend(['command_injection'])
        elif param_lower in ['callback', 'jsonp']:
            injection_types.extend(['jsonp_injection'])
        elif param_lower in ['redirect', 'url', 'next']:
            injection_types.extend(['open_redirect'])
        
        return injection_types
    
    def _detect_error_patterns(self):
        """Detect error patterns that might reveal information."""
        try:
            print("Detecting error patterns...")
            
            # Try to trigger common error conditions
            test_urls = [
                self.current_url + "?id='",  # SQL error
                self.current_url + "?file=../../../etc/passwd",  # Path traversal
                self.current_url + "?page=nonexistent",  # File not found
            ]
            
            self.error_pages = []
            
            for test_url in test_urls:
                try:
                    response = requests.get(test_url, timeout=5)
                    content = response.text
                    
                    # Look for error patterns
                    error_patterns = [
                        r'SQL.*error',
                        r'MySQL.*error',
                        r'PostgreSQL.*error',
                        r'Oracle.*error',
                        r'Warning.*include',
                        r'Fatal error',
                        r'Stack trace',
                        r'Exception.*at line',
                        r'Internal Server Error'
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            self.error_pages.append({
                                'url': test_url,
                                'error_type': pattern,
                                'status_code': response.status_code
                            })
                            break
                
                except:
                    continue
            
            print(f"Detected {len(self.error_pages)} error patterns")
            
        except Exception as e:
            print(f"Error detecting error patterns: {str(e)}")
            self.error_pages = []
    
    def _format_page_data(self) -> str:
        """Format all collected data into a comprehensive penetration testing report."""
        try:
            # Format basic data
            links_str = [f"'{link['url']}'" for link in self.links[:15]]
            
            forms_str = []
            for form in self.forms:
                form_fields = [field['name'] for field in form['fields'] if field['name']]
                forms_str.append(f"{{'action': '{form['action']}', 'method': '{form['method']}', 'fields': {form_fields}}}")
            
            api_calls_str = [f"'{api['endpoint']}'" for api in self.api_calls[:15]]
            
            # Format advanced reconnaissance data
            hidden_endpoints_str = [f"'{ep['url']}' ({ep['category']})" for ep in self.hidden_endpoints[:10]]
            
            tech_summary = f"""
Technology Stack Detected:
- Web Server: {self.technology_stack.get('web_server', [])}
- Programming Language: {self.technology_stack.get('programming_language', [])}
- Frameworks: {self.technology_stack.get('frameworks', [])}
- Databases: {self.technology_stack.get('databases', [])}
- Cloud Services: {self.technology_stack.get('cloud_services', [])}"""
            
            pentest_targets = f"""
Penetration Testing Targets:
- High Priority Endpoints: {[ep['url'] for ep in self.hidden_endpoints if ep['priority'] == 'high'][:5]}
- Parameter Injection Candidates: {list(self.parameter_candidates.keys())[:10]}
- Directory Enumeration Targets: {self.directory_paths[:10]}
- Error-Prone URLs: {len(self.error_pages)} found"""
            
            # Security summary
            security_score = len(self.security_headers) * 10  # Simple scoring
            
            formatted_data = f"""=== PENETRATION TESTING RECONNAISSANCE REPORT ===

Summarized HTML:
{self.html_content}

BASIC PAGE DATA:
- Links: [{', '.join(links_str)}]
- Forms: [{', '.join(forms_str)}]
- Sensitive Strings: {self.sensitive_strings[:20]}
- API Endpoints: [{', '.join(api_calls_str)}]

ADVANCED RECONNAISSANCE:
- Hidden Endpoints: [{', '.join(hidden_endpoints_str)}]
{tech_summary}
{pentest_targets}

SECURITY ANALYSIS:
- Security Headers Present: {list(self.security_headers.keys())}
- Security Score: {security_score}/100
- Cookies: {self.cookies_info.get('total_cookies', 0)} total, {self.cookies_info.get('secure_cookies', 0)} secure
- Information Disclosure: {len([k for k in self.security_headers.keys() if 'disclosure' in k])} issues

REQUEST/RESPONSE DATA:
- Request: GET {self.current_url}
- Response: Status: 200, Title: '{self.page.title()}'

=== END PENETRATION TESTING REPORT ==="""

            return formatted_data
            
        except Exception as e:
            print(f"Error formatting page data: {str(e)}")
            return self._get_fallback_data()
    
    def _get_fallback_data(self) -> str:
        """Return fallback data if extraction fails."""
        return f"""=== FALLBACK PENETRATION TESTING REPORT ===

Summarized HTML:
<html><body>Error extracting page data from {self.current_url}</body></html>

BASIC PAGE DATA:
- Links: []
- Forms: []
- Sensitive Strings: []
- API Endpoints: []

ADVANCED RECONNAISSANCE:
- Hidden Endpoints: []
- Technology Detection: Failed
- Parameter Analysis: Failed

SECURITY ANALYSIS:
- Security Headers: None detected
- Security Score: 0/100
- Information Disclosure: Failed to analyze

REQUEST/RESPONSE DATA:
- Request: GET {self.current_url}
- Response: Status: unknown

=== END FALLBACK REPORT ==="""


# Enhanced testing example
if __name__ == "__main__":
    import sys
    
    # Test URL
    starting_url = "https://httpbin.org/forms/post"
    
    try:
        # Initialize WebProxy
        proxy = WebProxy(starting_url)
        
        # Create browser instance
        browser, context, page, playwright = proxy.create_proxy()
        
        try:
            # Navigate to the URL
            page.goto(starting_url, wait_until="networkidle")
            
            # Initialize enhanced PageDataExtractor
            extractor = PageDataExtractor(page)
            
            # Extract comprehensive page data
            print("Starting enhanced penetration testing reconnaissance...")
            page_data = extractor.extract_page_data()
            
            # Print the extracted data
            print("\n" + "="*80)
            print("ENHANCED PENETRATION TESTING RECONNAISSANCE RESULTS")
            print("="*80)
            print(page_data)
            
            # Print detailed summary for penetration testing
            print("\n" + "="*80)
            print("PENETRATION TESTING SUMMARY")
            print("="*80)
            print(f"Links Found: {len(extractor.links)}")
            print(f"Forms Found: {len(extractor.forms)}")
            print(f"API Endpoints: {len(extractor.api_calls)}")
            print(f"Hidden Endpoints: {len(extractor.hidden_endpoints)}")
            print(f"Sensitive Strings: {len(extractor.sensitive_strings)}")
            print(f"Security Headers: {len(extractor.security_headers)}")
            print(f"Parameter Candidates: {len(extractor.parameter_candidates)}")
            print(f"Directory Paths: {len(extractor.directory_paths)}")
            print(f"Error Pages: {len(extractor.error_pages)}")
            print(f"Technology Stack Items: {sum(len(v) for v in extractor.technology_stack.values())}")
            
            # Show high-priority targets
            high_priority_endpoints = [ep for ep in extractor.hidden_endpoints if ep['priority'] == 'high']
            if high_priority_endpoints:
                print(f"\nHigh Priority Targets for Manual Testing:")
                for ep in high_priority_endpoints[:5]:
                    print(f"  - {ep['url']} ({ep['category']})")
            
        finally:
            # Clean up browser resources
            context.close()
            browser.close()
            playwright.stop()
            print("\nBrowser resources cleaned up successfully")
            
    except Exception as e:
        print(f"Error during testing: {str(e)}", file=sys.stderr)
        sys.exit(1)

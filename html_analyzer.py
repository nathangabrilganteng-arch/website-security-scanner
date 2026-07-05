"""
HTML Analysis Module - Checks HTML structure, metadata, links, etc.
"""

import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse

class HTMLAnalyzer:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        
    def analyze(self):
        """Analyze HTML content"""
        results = {
            'url': self.target,
            'html_version': 'unknown',
            'metadata': {},
            'links': {},
            'images': {},
            'favicon': None,
            'robots_txt': None,
            'sitemap_xml': None,
            'security_txt': None,
            'broken_links': [],
            'html_validated': False,
            'validation_errors': []
        }
        
        try:
            response = requests.get(self.target, timeout=10, headers={'User-Agent': self.config.get('user_agent', 'Mozilla/5.0')})
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # HTML version
            results['html_version'] = self.detect_html_version(soup)
            
            # Metadata
            results['metadata'] = self.extract_metadata(soup)
            
            # Links
            results['links'] = self.analyze_links(soup, response.url)
            
            # Images
            results['images'] = self.analyze_images(soup, response.url)
            
            # Favicon
            results['favicon'] = self.find_favicon(soup, response.url)
            
            # robots.txt
            results['robots_txt'] = self.check_robots_txt(response.url)
            
            # sitemap.xml
            results['sitemap_xml'] = self.check_sitemap_xml(response.url)
            
            # security.txt
            results['security_txt'] = self.check_security_txt(response.url)
            
            # Broken links check
            results['broken_links'] = self.check_broken_links(soup, response.url)
            
            # HTML validation (basic)
            results['validation_errors'] = self.validate_html(soup)
            results['html_validated'] = len(results['validation_errors']) == 0
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def detect_html_version(self, soup):
        """Detect HTML version"""
        doctype = soup.find('!DOCTYPE')
        if doctype:
            if 'html' in doctype.lower():
                if 'xhtml' in doctype.lower():
                    return 'XHTML 1.0'
                elif 'html5' in doctype.lower():
                    return 'HTML5'
                else:
                    return 'HTML 4.01'
        return 'Unknown'
    
    def extract_metadata(self, soup):
        """Extract metadata from HTML"""
        metadata = {}
        
        # Title
        title_tag = soup.find('title')
        if title_tag:
            metadata['title'] = title_tag.string.strip() if title_tag.string else ''
        
        # Meta tags
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            property_name = meta.get('property', '').lower()
            content = meta.get('content', '')
            
            if name:
                metadata[name] = content
            elif property_name.startswith('og:'):
                metadata[property_name] = content
            elif property_name == 'charset':
                metadata['charset'] = content
        
        return metadata
    
    def analyze_links(self, soup, base_url):
        """Analyze links on the page"""
        links = {
            'internal': [],
            'external': [],
            'total': 0
        }
        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href:
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                
                if parsed.netloc and parsed.netloc not in urlparse(base_url).netloc:
                    links['external'].append(full_url)
                else:
                    links['internal'].append(full_url)
        
        links['total'] = len(links['internal']) + len(links['external'])
        return links
    
    def analyze_images(self, soup, base_url):
        """Analyze images on the page"""
        images = {
            'total': 0,
            'with_alt': 0,
            'without_alt': 0,
            'alt_texts': []
        }
        
        for img in soup.find_all('img'):
            images['total'] += 1
            alt = img.get('alt', '')
            if alt:
                images['with_alt'] += 1
                images['alt_texts'].append(alt)
            else:
                images['without_alt'] += 1
        
        return images
    
    def find_favicon(self, soup, base_url):
        """Find favicon URL"""
        favicon = None
        
        # Check link tags
        for link in soup.find_all('link'):
            rel = link.get('rel', [])
            if isinstance(rel, list):
                if 'icon' in rel or 'shortcut icon' in rel:
                    href = link.get('href')
                    if href:
                        favicon = urljoin(base_url, href)
                        break
            elif rel in ['icon', 'shortcut icon']:
                href = link.get('href')
                if href:
                    favicon = urljoin(base_url, href)
                    break
        
        # Default favicon location
        if not favicon:
            favicon = urljoin(base_url, '/favicon.ico')
        
        return favicon
    
    def check_robots_txt(self, base_url):
        """Check robots.txt"""
        try:
            parsed = urlparse(base_url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            response = requests.get(robots_url, timeout=5)
            if response.status_code == 200:
                return {
                    'exists': True,
                    'content': response.text[:500]  # First 500 chars
                }
            return {'exists': False}
        except:
            return {'exists': False, 'error': 'Cannot fetch robots.txt'}
    
    def check_sitemap_xml(self, base_url):
        """Check sitemap.xml"""
        try:
            parsed = urlparse(base_url)
            sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
            response = requests.get(sitemap_url, timeout=5)
            if response.status_code == 200:
                return {
                    'exists': True,
                    'url': sitemap_url
                }
            return {'exists': False}
        except:
            return {'exists': False, 'error': 'Cannot fetch sitemap.xml'}
    
    def check_security_txt(self, base_url):
        """Check security.txt (RFC 9116)"""
        try:
            parsed = urlparse(base_url)
            security_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt"
            response = requests.get(security_url, timeout=5)
            if response.status_code == 200:
                return {
                    'exists': True,
                    'content': response.text[:500]
                }
            return {'exists': False}
        except:
            return {'exists': False, 'error': 'Cannot fetch security.txt'}
    
    def check_broken_links(self, soup, base_url):
        """Check for broken links (limited to a reasonable number)"""
        broken_links = []
        # Check only first 20 internal links
        links_to_check = []
        for link in soup.find_all('a', href=True)[:20]:
            href = link.get('href')
            if href and not href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.netloc in urlparse(base_url).netloc or not parsed.netloc:
                    links_to_check.append(full_url)
        
        # Check each link
        for link in links_to_check[:10]:  # Check only first 10
            try:
                resp = requests.head(link, timeout=5, allow_redirects=True)
                if resp.status_code >= 400:
                    broken_links.append({
                        'url': link,
                        'status_code': resp.status_code
                    })
            except:
                broken_links.append({
                    'url': link,
                    'status_code': 'connection_error'
                })
        
        return broken_links
    
    def validate_html(self, soup):
        """Basic HTML validation"""
        errors = []
        
        # Check for unclosed tags
        tags = soup.find_all()
        open_tags = {}
        for tag in tags:
            if not tag.find_all(recursive=False):
                # Leaf node
                if tag.name not in ['br', 'hr', 'img', 'input', 'meta', 'link']:
                    # Check if it's closed
                    if not tag.find_parent(lambda x: x.name == tag.name):
                        errors.append(f"Possible unclosed tag: <{tag.name}>")
        
        # Check for duplicate IDs
        ids = {}
        for tag in tags:
            if tag.get('id'):
                id_val = tag.get('id')
                if id_val in ids:
                    errors.append(f"Duplicate ID: {id_val}")
                else:
                    ids[id_val] = True
        
        # Check for empty alt text
        for img in soup.find_all('img'):
            if not img.get('alt'):
                errors.append(f"Image missing alt attribute: {img.get('src', 'unknown')}")
        
        return errors[:20]  # Limit to 20 errors
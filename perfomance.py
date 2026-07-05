"""
Performance Analysis Module
"""

import requests
import time
from urllib.parse import urlparse

class PerformanceAnalyzer:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        
    def analyze(self):
        """Analyze performance metrics"""
        results = {
            'page_size': 0,
            'page_size_kb': 0,
            'load_time': 0,
            'time_to_first_byte': 0,
            'status_code': 0,
            'redirect_count': 0,
            'resource_stats': {
                'images': 0,
                'css': 0,
                'javascript': 0,
                'total_requests': 0
            },
            'recommendations': []
        }
        
        try:
            # Measure load time
            start_time = time.time()
            response = requests.get(self.target, headers={'User-Agent': self.config.get('user_agent', 'Mozilla/5.0')})
            end_time = time.time()
            
            results['load_time'] = end_time - start_time
            results['status_code'] = response.status_code
            results['redirect_count'] = len(response.history)
            
            # Page size
            content = response.content
            results['page_size'] = len(content)
            results['page_size_kb'] = len(content) / 1024
            
            # TTFB
            if response.history:
                # Use first request in history
                results['time_to_first_byte'] = response.history[0].elapsed.total_seconds()
            else:
                results['time_to_first_byte'] = response.elapsed.total_seconds()
            
            # Parse HTML for resource stats
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            # Count images
            results['resource_stats']['images'] = len(soup.find_all('img'))
            
            # Count CSS
            results['resource_stats']['css'] = len(soup.find_all('link', {'rel': 'stylesheet'}))
            
            # Count JavaScript
            results['resource_stats']['javascript'] = len(soup.find_all('script'))
            
            # Total requests (approximate)
            results['resource_stats']['total_requests'] = (
                results['resource_stats']['images'] +
                results['resource_stats']['css'] +
                results['resource_stats']['javascript'] +
                1  # HTML itself
            )
            
            # Performance recommendations
            if results['page_size_kb'] > 1000:
                results['recommendations'].append("Page is large (>1MB), consider optimizing resources")
            
            if results['load_time'] > 3:
                results['recommendations'].append(f"Load time is {results['load_time']:.2f}s, consider improving")
            
            if results['resource_stats']['images'] > 50:
                results['recommendations'].append("Many images found, consider lazy loading")
            
            # HTTP version detection
            if hasattr(response.raw, '_connection'):
                http_version = response.raw._connection.sock.getsockopt(0, 0, 0)
                # This is simplified, real detection would be more complex
                results['http_version'] = response.raw.version
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
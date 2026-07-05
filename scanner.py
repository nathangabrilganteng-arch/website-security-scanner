#!/usr/bin/env python3
"""
Website Security Scanner - A comprehensive security audit tool
Author: Security Audit Tool
Version: 1.0.0
"""

import sys
import os
import argparse
import json
import yaml
from datetime import datetime
from colorama import init, Fore, Style
import logging
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# Import modules
from modules.security_headers import SecurityHeadersAnalyzer
from modules.ssl_tls import SSLTLSInspector
from modules.dns_whois import DNSWhoisChecker
from modules.html_analyzer import HTMLAnalyzer
from modules.performance import PerformanceAnalyzer
from modules.network_scanner import NetworkScanner
from modules.utils import Utils

class WebsiteSecurityScanner:
    def __init__(self, target, config_file='config.yaml'):
        self.target = target
        self.config = self.load_config(config_file)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'modules': {}
        }
        self.setup_logging()
        
    def load_config(self, config_file):
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # Default configuration
            return {
                'scan_timeout': 10,
                'max_redirects': 5,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'follow_redirects': True,
                'verify_ssl': True,
                'threads': 4,
                'export_formats': ['json', 'html']
            }
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_file = f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        os.makedirs('logs', exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def banner(self):
        """Display application banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║     {Fore.YELLOW}Website Security Scanner v1.0.0{Fore.CYAN}                      ║
║     {Fore.GREEN}Comprehensive Security Audit Tool{Fore.CYAN}                   ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def run_security_headers_scan(self):
        """Run security headers analysis"""
        print(f"\n{Fore.BLUE}[*] Analyzing Security Headers...")
        analyzer = SecurityHeadersAnalyzer(self.target, self.config)
        return analyzer.analyze()
    
    def run_ssl_tls_scan(self):
        """Run SSL/TLS inspection"""
        print(f"\n{Fore.BLUE}[*] Inspecting SSL/TLS Configuration...")
        inspector = SSLTLSInspector(self.target, self.config)
        return inspector.inspect()
    
    def run_dns_whois_scan(self):
        """Run DNS and WHOIS checking"""
        print(f"\n{Fore.BLUE}[*] Checking DNS and WHOIS Information...")
        checker = DNSWhoisChecker(self.target, self.config)
        return checker.check()
    
    def run_html_scan(self):
        """Run HTML analysis"""
        print(f"\n{Fore.BLUE}[*] Analyzing HTML Content...")
        analyzer = HTMLAnalyzer(self.target, self.config)
        return analyzer.analyze()
    
    def run_performance_scan(self):
        """Run performance analysis"""
        print(f"\n{Fore.BLUE}[*] Analyzing Performance...")
        analyzer = PerformanceAnalyzer(self.target, self.config)
        return analyzer.analyze()
    
    def run_network_scan(self):
        """Run network diagnostics (Wi-Fi features)"""
        if self.config.get('enable_network_diagnostics', True):
            print(f"\n{Fore.BLUE}[*] Running Network Diagnostics...")
            scanner = NetworkScanner(self.config)
            return scanner.diagnose()
        return None
    
    def calculate_security_score(self):
        """Calculate overall security score"""
        score = 0
        recommendations = []
        
        # Security Headers Score
        if 'security_headers' in self.results['modules']:
            header_results = self.results['modules']['security_headers']
            if header_results.get('hsts_enabled'):
                score += 10
            else:
                recommendations.append("Enable HSTS to enforce HTTPS")
            
            if header_results.get('csp_present'):
                score += 10
            else:
                recommendations.append("Implement Content Security Policy")
            
            # Add more scoring logic...
        
        # SSL/TLS Score
        if 'ssl_tls' in self.results['modules']:
            ssl_results = self.results['modules']['ssl_tls']
            if ssl_results.get('valid_certificate'):
                score += 15
            else:
                recommendations.append("Fix SSL/TLS certificate issues")
            
            if ssl_results.get('tls_version') in ['TLS 1.3', 'TLS 1.2']:
                score += 10
            else:
                recommendations.append("Upgrade to TLS 1.2 or 1.3")
        
        # DNS/WHOIS Score
        if 'dns_whois' in self.results['modules']:
            whois = self.results['modules']['dns_whois']
            if whois.get('domain_expiring_soon', False):
                recommendations.append(f"Domain expires on {whois.get('expiration_date', 'unknown')}")
        
        # Score normalization
        score = min(score, 100)
        
        return {
            'score': score,
            'grade': self.get_grade(score),
            'recommendations': recommendations
        }
    
    def get_grade(self, score):
        """Get letter grade based on score"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def run_full_scan(self):
        """Execute all scanning modules"""
        self.banner()
        
        print(f"\n{Fore.GREEN}[+] Target: {self.target}")
        print(f"[+] Starting comprehensive security audit...")
        
        # Progress bar
        modules = [
            'security_headers',
            'ssl_tls',
            'dns_whois',
            'html',
            'performance',
            'network'
        ]
        
        with tqdm(total=len(modules), desc="Scanning Progress", 
                 bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
            
            # Security Headers
            self.results['modules']['security_headers'] = self.run_security_headers_scan()
            pbar.update(1)
            
            # SSL/TLS
            self.results['modules']['ssl_tls'] = self.run_ssl_tls_scan()
            pbar.update(1)
            
            # DNS/WHOIS
            self.results['modules']['dns_whois'] = self.run_dns_whois_scan()
            pbar.update(1)
            
            # HTML
            self.results['modules']['html'] = self.run_html_scan()
            pbar.update(1)
            
            # Performance
            self.results['modules']['performance'] = self.run_performance_scan()
            pbar.update(1)
            
            # Network
            self.results['modules']['network'] = self.run_network_scan()
            pbar.update(1)
        
        # Calculate security score
        score_result = self.calculate_security_score()
        self.results['security_score'] = score_result
        
        # Display summary
        self.display_summary(score_result)
        
        # Export results
        self.export_results()
        
        return self.results
    
    def display_summary(self, score_result):
        """Display scan summary"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║              {Fore.YELLOW}SCAN SUMMARY{Fore.CYAN}                                     ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")
        
        # Security Score
        score = score_result['score']
        grade = score_result['grade']
        
        if grade == 'A':
            color = Fore.GREEN
        elif grade in ['B', 'C']:
            color = Fore.YELLOW
        else:
            color = Fore.RED
        
        print(f"\n{color}[+] Security Score: {score}/100 ({grade})")
        
        # Recommendations
        if score_result['recommendations']:
            print(f"\n{Fore.YELLOW}[!] Recommendations:")
            for rec in score_result['recommendations']:
                print(f"  - {rec}")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical issues found!")
        
        # Quick stats
        print(f"\n{Fore.CYAN}Quick Stats:")
        headers = self.results['modules'].get('security_headers', {})
        ssl = self.results['modules'].get('ssl_tls', {})
        
        print(f"  - HTTPS: {'✓' if ssl.get('https_enabled') else '✗'}")
        print(f"  - HSTS: {'✓' if headers.get('hsts_enabled') else '✗'}")
        print(f"  - CSP: {'✓' if headers.get('csp_present') else '✗'}")
        print(f"  - Valid SSL: {'✓' if ssl.get('valid_certificate') else '✗'}")
        
        print(f"\n{Fore.GREEN}[+] Report saved to: reports/")
    
    def export_results(self):
        """Export results to various formats"""
        os.makedirs('reports', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
        
        # JSON export
        if 'json' in self.config.get('export_formats', []):
            json_file = f"reports/{domain}_{timestamp}.json"
            with open(json_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            self.logger.info(f"JSON report saved: {json_file}")
        
        # HTML export
        if 'html' in self.config.get('export_formats', []):
            html_file = f"reports/{domain}_{timestamp}.html"
            self.export_html_report(html_file)
            self.logger.info(f"HTML report saved: {html_file}")
    
    def export_html_report(self, filename):
        """Export results as HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Audit Report - {{ target }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }
                .score { font-size: 48px; text-align: center; padding: 20px; margin: 20px 0; }
                .grade-A { color: #27ae60; }
                .grade-B { color: #f39c12; }
                .grade-C { color: #f1c40f; }
                .grade-D { color: #e67e22; }
                .grade-F { color: #e74c3c; }
                .section { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; }
                .badge-success { background: #27ae60; }
                .badge-danger { background: #e74c3c; }
                .badge-warning { background: #f39c12; }
                .badge-info { background: #3498db; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background: #34495e; color: white; }
                tr:hover { background: #f5f5f5; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Website Security Audit Report</h1>
                    <p>Target: {{ target }}</p>
                    <p>Scan Date: {{ timestamp }}</p>
                </div>
                
                <div class="score grade-{{ grade }}">
                    Security Score: {{ score }}/100 ({{ grade }})
                </div>
                
                <div class="section">
                    <h2>Security Headers</h2>
                    <table>
                        <tr><th>Header</th><th>Status</th></tr>
                        {% for key, value in headers.items() %}
                        <tr>
                            <td>{{ key }}</td>
                            <td>
                                <span class="badge {% if value %}badge-success{% else %}badge-danger{% endif %}">
                                    {% if value %}✓ Present{% else %}✗ Missing{% endif %}
                                </span>
                            </td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                
                <div class="section">
                    <h2>Recommendations</h2>
                    <ul>
                        {% for rec in recommendations %}
                        <li>{{ rec }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
        </body>
        </html>
        """
        
        try:
            from jinja2 import Template
            template = Template(html_template)
            
            html_content = template.render(
                target=self.target,
                timestamp=self.results['timestamp'],
                score=self.results['security_score']['score'],
                grade=self.results['security_score']['grade'],
                headers=self.results['modules'].get('security_headers', {}),
                recommendations=self.results['security_score']['recommendations']
            )
            
            with open(filename, 'w') as f:
                f.write(html_content)
        except ImportError:
            self.logger.warning("Jinja2 not installed, skipping HTML export")

def main():
    parser = argparse.ArgumentParser(description='Website Security Scanner')
    parser.add_argument('target', help='Target domain or URL to scan')
    parser.add_argument('--config', default='config.yaml', help='Configuration file')
    parser.add_argument('--skip-network', action='store_true', help='Skip network diagnostics')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', 
                       help='Export format')
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'https://' + args.target
    
    scanner = WebsiteSecurityScanner(args.target, args.config)
    
    # Update config
    if args.skip_network:
        scanner.config['enable_network_diagnostics'] = False
    
    if args.format != 'both':
        scanner.config['export_formats'] = [args.format]
    
    # Run scan
    try:
        scanner.run_full_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}")
        logging.error(f"Scan error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
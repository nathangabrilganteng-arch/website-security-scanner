
#!/usr/bin/env python3
"""
Website Security Scanner - Main Entry Point
"""

import sys
import os
import argparse
import yaml
import json
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm
import time

# Import modules
from src.security_headers import SecurityHeadersAnalyzer
from src.ssl_tls import SSLTLSInspector
from src.dns_whois import DNSWhoisChecker
from src.html_analyzer import HTMLAnalyzer
from src.performance import PerformanceAnalyzer
from src.network_scanner import NetworkScanner
from src.gps_scanner import GPSScanner
from src.utils import Utils

init(autoreset=True)

class WebsiteSecurityScanner:
    def __init__(self, config_path='config.yaml'):
        self.config = self.load_config(config_path)
        self.results = {}
        self.target = None
        self.utils = Utils()
        
    def load_config(self, config_path):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"{Fore.RED}Error loading config: {e}")
            return {}
    
    def banner(self):
        """Display banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
{Fore.CYAN}║     {Fore.YELLOW}Website Security Scanner v1.0.0{Fore.CYAN}                         ║
{Fore.CYAN}║     {Fore.GREEN}Comprehensive Security Audit & GPS Location Tool{Fore.CYAN}       ║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def scan_website(self, target):
        """Scan a website with all modules"""
        self.target = target
        print(f"\n{Fore.GREEN}[+] Target: {target}")
        print(f"{Fore.GREEN}[+] Starting comprehensive security audit...\n")
        
        modules = self.config.get('modules', {})
        total_modules = sum(1 for v in modules.values() if v)
        
        # Progress bar
        progress = tqdm(total=total_modules, desc="Scanning Progress", ncols=80)
        
        # Run modules
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'modules': {}
        }
        
        # Security Headers
        if modules.get('security_headers', True):
            headers_analyzer = SecurityHeadersAnalyzer(target, self.config)
            results['modules']['security_headers'] = headers_analyzer.analyze()
            progress.update(1)
            time.sleep(0.5)
        
        # SSL/TLS
        if modules.get('ssl_tls', True):
            ssl_analyzer = SSLTLSInspector(target, self.config)
            results['modules']['ssl_tls'] = ssl_analyzer.inspect()
            progress.update(1)
            time.sleep(0.5)
        
        # DNS/WHOIS
        if modules.get('dns_whois', True):
            dns_analyzer = DNSWhoisChecker(target, self.config)
            results['modules']['dns_whois'] = dns_analyzer.check()
            progress.update(1)
            time.sleep(0.5)
        
        # HTML Analysis
        if modules.get('html', True):
            html_analyzer = HTMLAnalyzer(target, self.config)
            results['modules']['html'] = html_analyzer.analyze()
            progress.update(1)
            time.sleep(0.5)
        
        # Performance
        if modules.get('performance', True):
            perf_analyzer = PerformanceAnalyzer(target, self.config)
            results['modules']['performance'] = perf_analyzer.analyze()
            progress.update(1)
            time.sleep(0.5)
        
        # Network
        if modules.get('network', True):
            network_scanner = NetworkScanner(self.config)
            results['modules']['network'] = network_scanner.diagnose()
            progress.update(1)
            time.sleep(0.5)
        
        progress.close()
        
        # GPS Location Scan
        print(f"\n{Fore.BLUE}[+] Running GPS Location Scan...")
        gps_scanner = GPSScanner(self.config)
        results['modules']['gps_location'] = gps_scanner.get_target_location_from_website(target)
        
        # Calculate score
        results['score'] = self.calculate_score(results)
        results['grade'] = self.get_grade(results['score'])
        
        self.results = results
        
        # Display results
        self.display_summary(results)
        
        # Save report
        self.save_report(results)
        
        return results
    
    def calculate_score(self, results):
        """Calculate security score"""
        score = 0
        
        # Security Headers
        if 'security_headers' in results.get('modules', {}):
            headers = results['modules']['security_headers']
            if headers.get('hsts_enabled'):
                score += 20
            if headers.get('csp_present'):
                score += 20
            if headers.get('x_frame_options'):
                score += 15
            if headers.get('x_content_type_options'):
                score += 15
            if headers.get('referrer_policy'):
                score += 10
            if headers.get('permissions_policy'):
                score += 10
            if headers.get('cookies'):
                secure_cookies = sum(1 for c in headers['cookies'] if c.get('secure'))
                score += min(10, secure_cookies * 2)
        
        # SSL/TLS
        if 'ssl_tls' in results.get('modules', {}):
            ssl = results['modules']['ssl_tls']
            if ssl.get('valid_certificate'):
                score += 25
            if ssl.get('tls_version') in ['TLSv1.2', 'TLSv1.3']:
                score += 15
        
        # Score from DNS/WHOIS
        if 'dns_whois' in results.get('modules', {}):
            dns = results['modules']['dns_whois']
            if dns.get('has_mx_records'):
                score += 5
            if dns.get('has_spf'):
                score += 10
            if dns.get('has_dkim'):
                score += 10
        
        return min(100, score)
    
    def get_grade(self, score):
        """Convert score to grade"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        elif score >= 40:
            return 'E'
        else:
            return 'F'
    
    def display_summary(self, results):
        """Display scan summary"""
        print(f"\n{Fore.YELLOW}╔══════════════════════════════════════════════════════════════╗")
        print(f"{Fore.YELLOW}║              SCAN SUMMARY                                     ║")
        print(f"{Fore.YELLOW}╚══════════════════════════════════════════════════════════════╝")
        
        score = results.get('score', 0)
        grade = results.get('grade', 'F')
        color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 60 else Fore.RED
        
        print(f"\n{color}[+] Security Score: {score}/100 ({grade})")
        
        # GPS Location Display
        if 'gps_location' in results.get('modules', {}):
            gps = results['modules']['gps_location']
            if gps.get('ip_geolocation'):
                geo = gps['ip_geolocation']
                if geo.get('latitude') and geo.get('longitude'):
                    print(f"\n{Fore.CYAN}📍 GPS Location:")
                    print(f"  {Fore.GREEN}Latitude: {geo['latitude']}")
                    print(f"  {Fore.GREEN}Longitude: {geo['longitude']}")
                    print(f"  {Fore.BLUE}Google Maps: https://maps.google.com/?q={geo['latitude']},{geo['longitude']}")
                    if geo.get('city'):
                        print(f"  {Fore.GREEN}Location: {geo.get('city', '')}, {geo.get('country', '')}")
                    if geo.get('isp'):
                        print(f"  {Fore.BLUE}ISP: {geo['isp']}")
        
        # Recommendations
        recommendations = self.generate_recommendations(results)
        if recommendations:
            print(f"\n{Fore.YELLOW}[!] Recommendations:")
            for rec in recommendations[:5]:
                print(f"  - {rec}")
        
        # Quick Stats
        print(f"\n{Fore.CYAN}Quick Stats:")
        headers = results.get('modules', {}).get('security_headers', {})
        print(f"  {'✓' if headers.get('hsts_enabled') else '✗'} HSTS")
        print(f"  {'✓' if headers.get('csp_present') else '✗'} CSP")
        print(f"  {'✓' if headers.get('x_frame_options') else '✗'} X-Frame-Options")
        
        ssl = results.get('modules', {}).get('ssl_tls', {})
        print(f"  {'✓' if ssl.get('valid_certificate') else '✗'} Valid SSL")
    
    def generate_recommendations(self, results):
        """Generate security recommendations"""
        recommendations = []
        
        headers = results.get('modules', {}).get('security_headers', {})
        if not headers.get('hsts_enabled'):
            recommendations.append("Enable HSTS to enforce HTTPS")
        if not headers.get('csp_present'):
            recommendations.append("Implement Content Security Policy")
        if not headers.get('x_frame_options'):
            recommendations.append("Add X-Frame-Options to prevent clickjacking")
        if not headers.get('x_content_type_options'):
            recommendations.append("Add X-Content-Type-Options: nosniff")
        if not headers.get('referrer_policy'):
            recommendations.append("Set Referrer-Policy header")
        
        ssl = results.get('modules', {}).get('ssl_tls', {})
        if not ssl.get('valid_certificate'):
            recommendations.append("Install valid SSL certificate")
        if ssl.get('tls_version') in ['TLSv1.0', 'TLSv1.1']:
            recommendations.append("Upgrade to TLS 1.2 or 1.3")
        
        return recommendations
    
    def save_report(self, results):
        """Save report to file"""
        export_formats = self.config.get('export_formats', ['json', 'html'])
        
        if not os.path.exists('reports'):
            os.makedirs('reports')
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = results['target'].replace('https://', '').replace('http://', '').replace('/', '_')
        base_filename = f"reports/{domain}_{timestamp}"
        
        # JSON
        if 'json' in export_formats:
            with open(f"{base_filename}.json", 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"{Fore.GREEN}[+] JSON report saved to: {base_filename}.json")
        
        # HTML
        if 'html' in export_formats:
            html_content = self.generate_html_report(results)
            with open(f"{base_filename}.html", 'w') as f:
                f.write(html_content)
            print(f"{Fore.GREEN}[+] HTML report saved to: {base_filename}.html")
        
        # Text
        text_report = self.generate_text_report(results)
        with open(f"{base_filename}.txt", 'w') as f:
            f.write(text_report)
        print(f"{Fore.GREEN}[+] Text report saved to: {base_filename}.txt")
        
        # GPS Report
        if 'gps_location' in results.get('modules', {}):
            gps_scanner = GPSScanner(self.config)
            gps_report = gps_scanner.location_report(results['modules']['gps_location'])
            with open(f"{base_filename}_gps.txt", 'w') as f:
                f.write(gps_report)
            print(f"{Fore.GREEN}[+] GPS report saved to: {base_filename}_gps.txt")
    
    def generate_html_report(self, results):
        """Generate HTML report"""
        # Simple HTML template - can be enhanced
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .score {{ font-size: 48px; text-align: center; padding: 20px; }}
                .grade {{ font-size: 72px; text-align: center; padding: 10px; }}
                .section {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
                .positive {{ color: green; }}
                .negative {{ color: red; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #2c3e50; color: white; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Website Security Scan Report</h1>
                    <p>Target: {results['target']}</p>
                    <p>Scan Date: {results['timestamp']}</p>
                </div>
                
                <div class="score">
                    <h2>Security Score: {results['score']}/100</h2>
                    <div class="grade">Grade: {results['grade']}</div>
                </div>
        """
        
        # Add GPS Location Section
        if 'gps_location' in results.get('modules', {}):
            gps = results['modules']['gps_location']
            if gps.get('ip_geolocation'):
                geo = gps['ip_geolocation']
                html += f"""
                <div class="section">
                    <h2>📍 GPS Location Information</h2>
                    <table>
                        <tr><th>Property</th><th>Value</th></tr>
                        <tr><td>Latitude</td><td>{geo.get('latitude', 'N/A')}</td></tr>
                        <tr><td>Longitude</td><td>{geo.get('longitude', 'N/A')}</td></tr>
                        <tr><td>City</td><td>{geo.get('city', 'N/A')}</td></tr>
                        <tr><td>Country</td><td>{geo.get('country', 'N/A')}</td></tr>
                        <tr><td>ISP</td><td>{geo.get('isp', 'N/A')}</td></tr>
                        <tr><td>Google Maps</td><td><a href='https://maps.google.com/?q={geo.get('latitude', '')},{geo.get('longitude', '')}'>View on Map</a></td></tr>
                    </table>
                </div>
                """
        
        html += """
            </div>
        </body>
        </html>
        """
        return html
    
    def generate_text_report(self, results):
        """Generate text report"""
        report = []
        report.append("="*60)
        report.append("WEBSITE SECURITY SCAN REPORT")
        report.append("="*60)
        report.append(f"Target: {results['target']}")
        report.append(f"Scan Date: {results['timestamp']}")
        report.append(f"Score: {results['score']}/100 (Grade: {results['grade']})")
        report.append("="*60)
        
        # Add GPS info
        if 'gps_location' in results.get('modules', {}):
            gps = results['modules']['gps_location']
            if gps.get('ip_geolocation'):
                geo = gps['ip_geolocation']
                report.append("\n📍 GPS LOCATION:")
                if geo.get('latitude') and geo.get('longitude'):
                    report.append(f"  Coordinates: {geo['latitude']}, {geo['longitude']}")
                    report.append(f"  Google Maps: https://maps.google.com/?q={geo['latitude']},{geo['longitude']}")
                if geo.get('city'):
                    report.append(f"  City: {geo['city']}")
                if geo.get('country'):
                    report.append(f"  Country: {geo['country']}")
                if geo.get('isp'):
                    report.append(f"  ISP: {geo['isp']}")
        
        return "\n".join(report)

def setup_hound():
    """Setup Hound for GPS tracking"""
    print(f"{Fore.BLUE}[+] Setting up Hound GPS tracker...")
    
    # Create hound directory if not exists
    if not os.path.exists('hound'):
        os.makedirs('hound')
        os.makedirs('hound/reports')
    
    # Create basic index.php
    index_php = """<?php
// Hound - GPS Location Tracker
$ip = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$data = array(
    'ip' => $ip,
    'user_agent' => $user_agent,
    'timestamp' => date('Y-m-d H:i:s')
);

// Get geolocation from IP
$geo = file_get_contents("http://ip-api.com/json/$ip");
if ($geo) {
    $geo_data = json_decode($geo, true);
    $data['location'] = $geo_data;
}

// Save to file
$log_file = 'reports/' . date('Y-m-d') . '.log';
file_put_contents($log_file, json_encode($data) . "\\n", FILE_APPEND);

// Return response
header('Content-Type: application/json');
echo json_encode($data);
?>
"""
    with open('hound/index.php', 'w') as f:
        f.write(index_php)
    
    # Create HTML payload
    payload_html = """<!DOCTYPE html>
<html>
<head>
    <title>Location Tracker</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; background: #0a0a0a; color: #00ff00; }
        .container { max-width: 600px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #00ff00; }
        .status { color: #00ff00; font-size: 24px; }
        .loading { font-size: 48px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h1>📍 Location Tracker</h1>
        <div class="status">
            <div class="loading">🔄</div>
            <p>Getting your location...</p>
            <p id="status-text">Please allow location access</p>
        </div>
        <div id="location-info"></div>
    </div>
    <script>
        // Get GPS Location
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                function(position) {
                    const lat = position.coords.latitude;
                    const lng = position.coords.longitude;
                    document.getElementById('status-text').innerHTML = '📍 Location captured!';
                    document.getElementById('location-info').innerHTML = 
                        '<p>Latitude: ' + lat + '</p>' +
                        '<p>Longitude: ' + lng + '</p>' +
                        '<p><a href="https://maps.google.com/?q=' + lat + ',' + lng + '" target="_blank">View on Google Maps</a></p>';
                    
                    // Send to server
                    fetch('index.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({lat: lat, lng: lng})
                    });
                },
                function(error) {
                    document.getElementById('status-text').innerHTML = '❌ Error: ' + error.message;
                }
            );
        } else {
            document.getElementById('status-text').innerHTML = '❌ Geolocation not supported';
        }
    </script>
</body>
</html>"""
    with open('hound/payload.html', 'w') as f:
        f.write(payload_html)
    
    print(f"{Fore.GREEN}[+] Hound setup complete!")
    print(f"{Fore.CYAN}   - PHP backend: hound/index.php")
    print(f"{Fore.CYAN}   - HTML payload: hound/payload.html")
    print(f"{Fore.YELLOW}   - To use: Upload payload.html to a web server or share the link")
    print(f"{Fore.YELLOW}   - Location data saved to: hound/reports/")

def main():
    parser = argparse.ArgumentParser(description='Website Security Scanner with GPS Location Tracking')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-c', '--config', default='config.yaml', help='Config file path')
    parser.add_argument('--gps', action='store_true', help='Enabdef setup_hound():
    """Setup Hound for GPS tracking"""
    print(f"{Fore.BLUE}[+] Setting up Hound GPS tracker...")
    
    if not os.path.exists('hound'):
        os.makedirs('hound')
        os.makedirs('hound/reports')
    
    # Create index.php
    index_php = """<?php
$ip = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$data = array(
    'ip' => $ip,
    'user_agent' => $user_agent,
    'timestamp' => date('Y-m-d H:i:s')
);

$geo = file_get_contents("http://ip-api.com/json/$ip");
if ($geo) {
    $geo_data = json_decode($geo, true);
    $data['location'] = $geo_data;
}

$log_file = 'reports/' . date('Y-m-d') . '.log';
file_put_contents($log_file, json_encode($data) . "\\n", FILE_APPEND);

header('Content-Type: application/json');
echo json_encode($data);
?>
"""
    with open('hound/index.php', 'w') as f:
        f.write(index_php)
    
    # Create payload.html
    payload_html = """<!DOCTYPE html>
<html>
<head>
    <title>Location Tracker</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; background: #0a0a0a; color: #00ff00; }
        .container { max-width: 600px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #00ff00; }
        .status { color: #00ff00; font-size: 24px; }
        .loading { font-size: 48px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h1>📍 Location Tracker</h1>
        <div class="status">
            <div class="loading">🔄</div>
            <p>Getting your location...</p>
            <p id="status-text">Please allow location access</p>
        </div>
        <div id="location-info"></div>
    </div>
    <script>
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                function(position) {
                    const lat = position.coords.latitude;
                    const lng = position.coords.longitude;
                    document.getElementById('status-text').innerHTML = '📍 Location captured!';
                    document.getElementById('location-info').innerHTML = 
                        '<p>Latitude: ' + lat + '</p>' +
                        '<p>Longitude: ' + lng + '</p>' +
                        '<p><a href="https://maps.google.com/?q=' + lat + ',' + lng + '" target="_blank">View on Google Maps</a></p>';
                    
                    fetch('index.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({lat: lat, lng: lng})
                    });
                },
                function(error) {
                    document.getElementById('status-text').innerHTML = '❌ Error: ' + error.message;
                }
            );
        } else {
            document.getElementById('status-text').innerHTML = '❌ Geolocation not supported';
        }
    </script>
</body>
</html>"""
    with open('hound/payload.html', 'w') as f:
        f.write(payload_html)
    
    print(f"{Fore.GREEN}[+] Hound setup complete!")
    print(f"{Fore.CYAN}   - PHP backend: hound/index.php")
    print(f"{Fore.CYAN}   - HTML payload: hound/payload.html")
    print(f"{Fore.YELLOW}   - To use: Upload payload.html to a web server or share the link")
    print(f"{Fore.YELLOW}   - Location data saved to: hound/reports/")

def main():
    parser = argparse.ArgumentParser(description='Website Security Scanner with GPS Location Tracking')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-c', '--config', default='config.yaml', help='Config file path')
    parser.add_argument('--gps', action='store_true', help='Enable GPS location scanning')
    parser.add_argument('--setup-hound', action='store_true', help='Setup Hound GPS tracker')
    parser.add_argument('--list-modules', action='store_true', help='List available modules')
    
    args = parser.parse_args()
    
    scanner = WebsiteSecurityScanner(args.config)
    scanner.banner()
    
    if args.setup_hound:
        setup_hound()
        return
    
    if args.list_modules:
        print(f"\n{Fore.CYAN}Available Modules:")
        modules = scanner.config.get('modules', {})
        for module, enabled in modules.items():
            status = f"{Fore.GREEN}✓" if enabled else f"{Fore.RED}✗"
            print(f"  {status} {module}")
        return
    
    if not args.url:
        print(f"{Fore.RED}Error: Please specify a URL with -u or --url")
        print(f"{Fore.YELLOW}Usage: python main.py -u https://example.com")
        return
    
    # Run scan
    results = scanner.scan_website(args.url)
    
    # GPS only mode
    if args.gps:
        print(f"\n{Fore.BLUE}[+] Running GPS Location Scan only...")
        gps_scanner = GPSScanner(scanner.config)
        gps_results = gps_scanner.get_target_location_from_website(args.url)
        print(gps_scanner.location_report(gps_results))

if __name__ == "__main__":
    main()
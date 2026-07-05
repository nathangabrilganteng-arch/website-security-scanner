# Website Security Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)]()
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)]()
[![CI](https://github.com/yourusername/website-security-scanner/workflows/CI/badge.svg)](https://github.com/yourusername/website-security-scanner/actions)
A comprehensive security audit tool for websites, built in Python.

## ✨ Features

### Security Headers Analysis
- HSTS (HTTP Strict Transport Security)
- CSP (Content Security Policy)
- X-Frame-Options, X-Content-Type-Options
- Referrer-Policy, Permissions-Policy
- CORS headers

### SSL/TLS Inspection
- Certificate validation
- TLS version detection
- Certificate expiration check
- Weak cipher detection

### DNS & WHOIS
- DNS record lookup (A, AAAA, MX, NS, TXT, CNAME)
- WHOIS information
- Domain expiration check

### HTML Analysis
- HTML version detection
- Metadata extraction
- Link analysis (internal/external)
- Image analysis (alt attributes)
- Favicon detection
- robots.txt, sitemap.xml, security.txt
- Broken link detection
- Basic HTML validation

### Performance Analysis
- Page load time
- Time to first byte
- Page size
- Resource counting
- Performance recommendations

### Network Diagnostics
- SSID detection
- IP address, Gateway, DNS servers
- Latency test, Speed test
- Signal strength (Linux)

### Reporting
- Security score (0-100)
- Grade (A-F)
- Detailed recommendations
- JSON & HTML export
- Colorful CLI output

## 📦 Installation

### Linux / Termux

```bash
# Update packages
sudo apt update && sudo apt upgrade
sudo apt install python3 python3-pip git nmap whois openssl

# Clone repository
git clone https://github.com/yourusername/website-security-scanner.git
cd website-security-scanner

# Install dependencies
pip3 install -r requirements.txt
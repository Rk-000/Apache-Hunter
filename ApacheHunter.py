#!/usr/bin/env python3
"""
ApacheHunter - Advanced Apache Server Scanner
Developed by Rownok Ahmed Khan
GitHub: https://github.com/Rk-000
"""

import requests
import argparse
import sys
import re
import hashlib
from colorama import init, Fore, Style
from fake_useragent import UserAgent
import urllib3
from bs4 import BeautifulSoup
import json

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Banner
BANNER = f"""
{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   {Fore.YELLOW}█████╗ ██████╗  █████╗  ██████╗██╗  ██╗███████╗{Fore.CYAN}       ║
    ║   {Fore.YELLOW}██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝{Fore.CYAN}       ║
    ║   {Fore.YELLOW}██████║██████╔╝███████║██║     ███████║█████╗  {Fore.CYAN}       ║
    ║   {Fore.YELLOW}██╔══██║██╔═══╝ ██╔══██║██║     ██╔══██║██╔══╝  {Fore.CYAN}       ║
    ║   {Fore.YELLOW}██║  ██║██║     ██║  ██║╚██████╗██║  ██║███████╗{Fore.CYAN}       ║
    ║   {Fore.YELLOW}╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝{Fore.CYAN}       ║
    ║                                                          ║
    ║              {Fore.GREEN}Advanced Apache Scanner{Fore.CYAN}                    ║
    ║         {Fore.WHITE}Like Wappalyzer - But Better{Fore.CYAN}                     ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.MAGENTA}Developed by Rownok Ahmed Khan{Style.RESET_ALL}
{Fore.BLUE}GitHub: https://github.com/Rk-000{Style.RESET_ALL}
{Fore.YELLOW}Version: 2.0 - Enhanced Detection{Style.RESET_ALL}

"""

class ApacheHunterEnhanced:
    def __init__(self):
        self.ua = UserAgent()
        self.session = requests.Session()
        self.results = []
        
        # Apache signatures for detection
        self.apache_signatures = [
            r'apache', r'apache/?[\d\.]*', r'Apache(?:[^a-zA-Z]|\Z)',
            'Apache-Handler', 'mod_', '.htaccess'
        ]
        
        # Apache version patterns
        self.version_patterns = [
            r'Apache(?:-[\w]+)?/(\d+\.\d+(?:\.\d+)?)',
            r'Apache\/(\d+\.\d+(?:\.\d+)?)',
            r'Server: Apache\/(\d+\.\d+(?:\.\d+)?)',
            r'<meta name="generator" content="Apache (.*?)"',
            r'Apache/(\d+\.\d+(?:\.\d+)?)',
            r'apache/(\d+\.\d+(?:\.\d+)?)'
        ]
        
        # Apache Answer specific signatures
        self.answer_signatures = [
            'Apache Answer',
            'answer.apache.org',
            'powered by Apache Answer',
            'answer-dev',
            'Answer Community',
            '/static/answer/',
            'answer.js',
            'answer.css'
        ]
        
        # Common paths to check
        self.common_paths = [
            '/',
            '/version',
            '/about',
            '/changelog',
            '/CHANGELOG',
            '/VERSION',
            '/api/version',
            '/.well-known/',
            '/server-status',
            '/server-info',
            '/info.php',
            '/phpinfo.php',
            '/wp-content/',
            '/wp-includes/',
            '/admin',
            '/login',
            '/questions',
            '/questions/ask',
            '/users',
            '/tags',
            '/badges',
            '/help',
            '/community',
            '/forum',
            '/discussions'
        ]

    def get_headers(self, custom_ua=None):
        """Generate realistic browser headers"""
        return {
            'User-Agent': custom_ua if custom_ua else self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }

    def check_server_headers(self, response):
        """Extensive header analysis"""
        findings = {
            'is_apache': False,
            'version': None,
            'confidence': 0,
            'evidence': []
        }
        
        headers_to_check = ['Server', 'X-Powered-By', 'Via', 'X-Aspnet-Version', 
                           'X-AspNet-Version', 'X-Generator', 'X-Drupal-Cache',
                           'X-Drupal-Dynamic-Cache', 'X-Varnish', 'X-Varnish-Cache']
        
        for header in headers_to_check:
            if header in response.headers:
                value = response.headers[header]
                findings['evidence'].append(f"{header}: {value}")
                
                # Check for Apache in headers
                if re.search(r'apache', value, re.I):
                    findings['is_apache'] = True
                    findings['confidence'] += 30
                    
                    # Extract version
                    for pattern in self.version_patterns:
                        match = re.search(pattern, value, re.I)
                        if match:
                            findings['version'] = match.group(1)
                            findings['confidence'] += 50
                            break
        
        return findings

    def check_page_content(self, response):
        """Deep page content analysis"""
        findings = {
            'is_apache': False,
            'is_answer': False,
            'version': None,
            'confidence': 0,
            'evidence': []
        }
        
        if not response.text:
            return findings
            
        text = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check meta tags
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            content = meta_generator['content']
            findings['evidence'].append(f"Meta generator: {content}")
            if 'apache' in content.lower():
                findings['is_apache'] = True
                findings['confidence'] += 40
                # Try to extract version
                for pattern in self.version_patterns:
                    match = re.search(pattern, content, re.I)
                    if match:
                        findings['version'] = match.group(1)
                        findings['confidence'] += 30
        
        # Check for Apache Answer signatures
        for sig in self.answer_signatures:
            if sig.lower() in text:
                findings['is_answer'] = True
                findings['evidence'].append(f"Found Apache Answer signature: {sig}")
                findings['confidence'] += 50
        
        # Check for Apache default pages
        apache_defaults = [
            'it works!', 'apache2 default page', 'apache default page',
            'welcome to apache', 'apache is functioning normally'
        ]
        for default in apache_defaults:
            if default in text:
                findings['is_apache'] = True
                findings['evidence'].append(f"Found Apache default page text: {default}")
                findings['confidence'] += 60
        
        # Check for common Apache paths in links
        for link in soup.find_all('link'):
            if link.get('href') and 'apache' in link['href'].lower():
                findings['is_apache'] = True
                findings['evidence'].append(f"Apache reference in link: {link['href']}")
                findings['confidence'] += 20
        
        # Check scripts
        for script in soup.find_all('script'):
            if script.get('src') and 'apache' in script['src'].lower():
                findings['is_apache'] = True
                findings['evidence'].append(f"Apache reference in script: {script['src']}")
                findings['confidence'] += 20
        
        return findings

    def probe_paths(self, base_url):
        """Probe common paths for version disclosure"""
        findings = {
            'is_apache': False,
            'version': None,
            'confidence': 0,
            'evidence': []
        }
        
        for path in self.common_paths:
            try:
                url = base_url.rstrip('/') + path
                response = self.session.get(
                    url,
                    headers=self.get_headers(),
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    # Check response for Apache signs
                    if 'apache' in response.text.lower():
                        findings['is_apache'] = True
                        findings['evidence'].append(f"Apache reference in {path}")
                        findings['confidence'] += 15
                    
                    # Look for version in text
                    for pattern in self.version_patterns:
                        matches = re.findall(pattern, response.text, re.I)
                        if matches:
                            findings['version'] = matches[0]
                            findings['evidence'].append(f"Version found in {path}: {matches[0]}")
                            findings['confidence'] += 40
                            
            except:
                continue
                
        return findings

    def check_apache_modules(self, response):
        """Check for Apache module signatures"""
        findings = {
            'detected': [],
            'confidence': 0
        }
        
        module_signatures = {
            'mod_ssl': 'SSL',
            'mod_rewrite': 'Rewrite',
            'mod_deflate': 'gzip',
            'mod_security': 'ModSecurity',
            'mod_headers': 'Header',
            'mod_proxy': 'Proxy'
        }
        
        text = response.text
        headers = str(response.headers)
        
        for module, signature in module_signatures.items():
            if signature.lower() in text.lower() or signature in headers:
                findings['detected'].append(module)
                findings['confidence'] += 10
                
        return findings

    def scan_target(self, url):
        """Complete scan of a single target"""
        print(f"\n{Fore.CYAN}[*] Scanning: {url}{Style.RESET_ALL}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        result = {
            'url': url,
            'is_apache': False,
            'is_answer': False,
            'version': None,
            'vulnerable': False,
            'confidence': 0,
            'evidence': [],
            'headers': {},
            'status_code': None
        }
        
        try:
            # Initial request
            response = self.session.get(
                url,
                headers=self.get_headers(),
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)
            
            # Method 1: Header Analysis
            header_findings = self.check_server_headers(response)
            if header_findings['is_apache']:
                result['is_apache'] = True
                result['confidence'] += header_findings['confidence']
                result['evidence'].extend(header_findings['evidence'])
                if header_findings['version']:
                    result['version'] = header_findings['version']
            
            # Method 2: Page Content Analysis
            content_findings = self.check_page_content(response)
            if content_findings['is_apache']:
                result['is_apache'] = True
                result['confidence'] += content_findings['confidence']
                result['evidence'].extend(content_findings['evidence'])
                if content_findings['version']:
                    result['version'] = content_findings['version']
            if content_findings['is_answer']:
                result['is_answer'] = True
                result['evidence'].append("Confirmed Apache Answer installation")
            
            # Method 3: Module Detection
            module_findings = self.check_apache_modules(response)
            if module_findings['detected']:
                result['evidence'].append(f"Apache modules detected: {', '.join(module_findings['detected'])}")
                result['confidence'] += module_findings['confidence']
            
            # Method 4: Path Probing
            path_findings = self.probe_paths(url)
            if path_findings['is_apache']:
                result['is_apache'] = True
                result['confidence'] += path_findings['confidence']
                result['evidence'].extend(path_findings['evidence'])
                if path_findings['version']:
                    result['version'] = path_findings['version']
            
            # Determine vulnerability
            if result['version']:
                result['vulnerable'] = self.is_vulnerable(result['version'])
            
            # Print results
            self.print_results(result)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)[:50]}{Style.RESET_ALL}")
            result['error'] = str(e)
        
        self.results.append(result)
        return result

    def is_vulnerable(self, version):
        """Check if version is vulnerable to CVE-2024-22393"""
        try:
            parts = version.split('.')
            if len(parts) >= 2:
                major = int(parts[0])
                minor = int(parts[1])
                patch = int(parts[2]) if len(parts) > 2 else 0
                
                if major == 1:
                    if minor < 2:
                        return True
                    elif minor == 2 and patch <= 1:
                        return True
            return False
        except:
            return False

    def print_results(self, result):
        """Print formatted results"""
        if 'error' in result:
            return
            
        # Status emoji
        status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if result['status_code'] == 200 else f"{Fore.YELLOW}!{Style.RESET_ALL}"
        
        print(f"{status} {Fore.WHITE}{result['url']}{Style.RESET_ALL}")
        print(f"  ├─ Status: {result['status_code']}")
        
        # Apache detection
        if result['is_apache']:
            apache_status = f"{Fore.GREEN}✓ YES{Style.RESET_ALL}"
        else:
            apache_status = f"{Fore.RED}✗ NO{Style.RESET_ALL}"
        print(f"  ├─ Apache: {apache_status}")
        
        # Version
        if result['version']:
            if result['vulnerable']:
                version_color = Fore.RED
                vuln_text = f"{Fore.RED}⚠ VULNERABLE{Style.RESET_ALL}"
            else:
                version_color = Fore.GREEN
                vuln_text = f"{Fore.GREEN}✓ PATCHED{Style.RESET_ALL}"
            print(f"  ├─ Version: {version_color}{result['version']}{Style.RESET_ALL}")
            print(f"  ├─ Status: {vuln_text}")
        else:
            print(f"  ├─ Version: {Fore.YELLOW}Unknown (try manual Wappalyzer){Style.RESET_ALL}")
        
        # Apache Answer
        if result.get('is_answer'):
            print(f"  ├─ {Fore.CYAN}✓ Apache Answer Detected{Style.RESET_ALL}")
        
        # Confidence
        confidence_color = Fore.GREEN if result['confidence'] > 70 else Fore.YELLOW if result['confidence'] > 40 else Fore.RED
        print(f"  ├─ Confidence: {confidence_color}{result['confidence']}%{Style.RESET_ALL}")
        
        # Evidence (show top 3)
        if result['evidence']:
            print(f"  └─ Evidence:")
            for i, evidence in enumerate(result['evidence'][:3]):
                print(f"     • {evidence}")
            if len(result['evidence']) > 3:
                print(f"     • ... and {len(result['evidence'])-3} more")

    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        total = len(self.results)
        apache = sum(1 for r in self.results if r.get('is_apache'))
        answer = sum(1 for r in self.results if r.get('is_answer'))
        vulnerable = sum(1 for r in self.results if r.get('vulnerable'))
        
        print(f"Total targets: {total}")
        print(f"Apache servers: {Fore.GREEN if apache else ''}{apache}{Style.RESET_ALL}")
        print(f"Apache Answer: {Fore.CYAN}{answer}{Style.RESET_ALL}")
        print(f"Vulnerable: {Fore.RED if vulnerable else ''}{vulnerable}{Style.RESET_ALL}")
        
        if vulnerable > 0:
            print(f"\n{Fore.RED}⚠ VULNERABLE TARGETS:{Style.RESET_ALL}")
            for r in self.results:
                if r.get('vulnerable'):
                    print(f"  • {r['url']} - Apache/{r['version']}")

def main():
    parser = argparse.ArgumentParser(description='ApacheHunter - Advanced Apache Scanner')
    parser.add_argument('-f', '--file', required=True, help='File containing targets')
    parser.add_argument('--delay', type=float, default=1, help='Delay between scans')
    
    args = parser.parse_args()
    
    print(BANNER)
    
    # Load targets
    try:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found: {args.file}{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.CYAN}[*] Loaded {len(targets)} targets{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Using enhanced detection (like Wappalyzer){Style.RESET_ALL}")
    
    scanner = ApacheHunterEnhanced()
    
    try:
        for target in targets:
            scanner.scan_target(target)
            if args.delay > 0:
                import time
                time.sleep(args.delay)
        
        scanner.print_summary()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted{Style.RESET_ALL}")
        scanner.print_summary()

if __name__ == "__main__":
    main()
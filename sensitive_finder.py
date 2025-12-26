import os
import stat
import csv
import time
import sys

# 1. Configuration - Enhanced Detection Database
# Added Cloud, Database, and SSH related secrets for better coverage
SENSITIVE_FILES = [
    ".env", "config.txt", "password.txt", "credentials", "backup", 
    "db_backup.sql", "id_rsa", "id_dsa", ".ssh", "settings.py", 
    "web.config", ".htaccess", "database.yml"
]

KEYWORDS = [
    # General Authentication Secrets
    "password", "secret", "api_key", "token", "access_key", "admin", "key",
    # Infrastructure & Cloud Providers (AWS, Azure, GCP)
    "aws_access_key_id", "aws_secret_access_key", "gcp_api_key", "azure_storage_key",
    # Database Connection Strings & Credentials
    "mongodb+srv", "db_password", "db_user", "postgres_password", "mysql_pwd",
    # Payment Gateways & Bearer Tokens
    "stripe_secret", "sk_live", "jwt_secret", "bearer_token", "auth_token",
    # Cryptographic Keys & Internal Secrets
    "begin rsa private key", "ssh_key", "client_secret"
]

# 2. Argument Handling - Fetching target path from Terminal
# Defaulting to 'test_env' if no path is provided via command line
if len(sys.argv) > 1:
    SCAN_PATH = sys.argv[1]
else:
    SCAN_PATH = "test_env"

REPORT_FILE = "vulnerability_report.csv"

def start_monitoring():
    print(f"\n🚀 Secret-Sniffer-Pro: Advanced Security Monitor Started!")
    print(f"📂 Monitoring Target: {os.path.abspath(SCAN_PATH)}")
    print(f"💡 Press Ctrl + C to stop the monitor.\n")
    
    while True:
        results = []
        found_any = False
        
        # Iterating through all directories and sub-directories
        for root, dirs, files in os.walk(SCAN_PATH):
            for file in files:
                path = os.path.join(root, file)
                found_keywords = []
                
                # Logic A: Validating sensitive filenames
                is_sensitive_name = any(sf in file.lower() for sf in SENSITIVE_FILES)
                
                # Logic B: Deep content inspection for hardcoded secrets
                try:
                    with open(path, 'r', errors='ignore') as f:
                        content = f.read().lower()
                        for key in KEYWORDS:
                            if key in content:
                                found_keywords.append(key)
                except:
                    # Skipping files that cannot be read (e.g., system or binary files)
                    continue

                # Risk evaluation and reporting logic
                if is_sensitive_name or found_keywords:
                    found_any = True
                    file_stat = os.stat(path)
                    # Checking if the file has world-readable permissions
                    world_readable = "YES" if bool(file_stat.st_mode & stat.S_IROTH) else "NO"
                    
                    # Risk Classification: Combining keyword presence and file visibility
                    risk = "CRITICAL" if found_keywords and world_readable == "YES" else "HIGH"
                    detected_info = f"Keywords: {', '.join(found_keywords)}" if found_keywords else "Sensitive Filename"
                    
                    results.append([path, file, world_readable, risk, detected_info])

        # Logging results into a CSV Audit Report
        if found_any:
            with open(REPORT_FILE, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["File Path", "File Name", "World Readable", "Risk Level", "Detected Info"])
                writer.writerows(results)
            print(f"[{time.strftime('%H:%M:%S')}] ⚠️  Security Risk Detected! {len(results)} files found. Report updated.")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] ✅  System Secure. No sensitive data found.")

        # Monitoring frequency: 10-second refresh interval
        time.sleep(10)

if __name__ == "__main__":
    try:
        start_monitoring()
    except KeyboardInterrupt:
        # Graceful exit on user interruption
        print("\n\n🛑 Monitor stopped by user. Goodbye!")

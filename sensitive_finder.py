import os
import re
import sys
import stat
import csv
import json
import math
import time
import queue
import threading
import argparse
import requests  # Naya feature: API verification ke liye
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk

# Optional Git support
try:
    from git import Repo
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

# ================= COLORS =================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ================= SMART FILTERS =================
FALSE_POSITIVE_KEYWORDS = ['integrity', 'sha256', 'sha512', 'checksum', 'nonce', 'version', 'subresource']

# ================= MODERN 2026 PATTERNS =================
PATTERNS = {
    "AWS Access Key": r"(AKIA|ASIA|AIDA|ANPA|AROA)[A-Z0-9]{16}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36,255}",
    "Google API": r"AIza[0-9A-Za-z-_]{35}",
    "Hardcoded Secret": r"(?i)(password|api_key|secret|token|auth|bearer)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
}

ENTROPY_CONTEXT = re.compile(r"(key|token|secret|auth|bearer|credential)", re.I)
ENTROPY_REGEX = re.compile(r"[A-Za-z0-9+/=_-]{24,}")

IGNORE_FILE = ".secsnifferignore"
IGNORE_FOLDERS = {'.git', 'node_modules', 'venv', '__pycache__'}

# ================= NEW: VALIDATOR LOGIC =================
class Validator:
    @staticmethod
    def check_google(key):
        url = f"https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=100x100&key={key}"
        try:
            r = requests.get(url, timeout=5)
            return "🟢 ACTIVE" if r.status_code == 200 else "🔴 EXPIRED"
        except: return "🟡 UNKNOWN"

    @staticmethod
    def check_github(token):
        headers = {"Authorization": f"token {token}"}
        try:
            r = requests.get("https://api.github.com/user", headers=headers, timeout=5)
            return "🟢 ACTIVE" if r.status_code == 200 else "🔴 EXPIRED"
        except: return "🟡 UNKNOWN"

# ================= UTILS =================
def get_banner():
    return f"""{Colors.YELLOW}{Colors.BOLD}
**********************************************************
* ███████╗███████╗ ██████╗       ██████╗██████╗  ██████╗ *
* ██╔════╝██╔════╝██╔════╝       ██╔════╝██╔══██╗██╔═══██╗*
* ███████╗█████╗  ██║            ██║     ██████╔╝██║   ██║*
* ╚════██║██╔══╝  ██║            ██║     ██╔══██╗██║   ██║*
* ███████║███████╗╚██████╗       ╚██████╗██║  ██║╚██████╔╝*
* SEC-SNIFFER PRO                                        *
**********************************************************
{Colors.END}"""

def shannon_entropy(s):
    if not s: return 0
    entropy = 0
    for c in set(s):
        p = s.count(c) / len(s)
        entropy -= p * math.log2(p)
    return entropy

def mask_secret(s):
    return s[:4] + "****" + s[-4:] if len(s) > 10 else "****"

def load_ignore_list(root):
    ignore = set()
    path = os.path.join(root, IGNORE_FILE)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f: ignore.add(line.strip())
    return ignore

# ================= SCANNER ENGINE =================
class Scanner:
    def __init__(self, target, log_queue=None, progress_callback=None):
        self.target = target
        self.log_queue = log_queue
        self.ignore = load_ignore_list(target)
        self.results = []
        self.progress_callback = progress_callback
        self.total_files = 0
        self.scanned_files = 0

    def log(self, msg):
        if self.log_queue: self.log_queue.put(msg)
        else: print(msg)

    def is_false_positive(self, content):
        content_lower = content.lower()
        return any(word in content_lower for word in FALSE_POSITIVE_KEYWORDS)

    def permission_info(self, path):
        try:
            st = os.stat(path)
            return {
                "world_readable": bool(st.st_mode & stat.S_IROTH),
                "group_writable": bool(st.st_mode & stat.S_IWGRP)
            }
        except: return {"world_readable": False, "group_writable": False}

    def remediation(self, secret_type):
        return {
            "AWS Access Key": "Rotate via IAM and move to Secrets Manager",
            "GitHub Token": "Revoke token immediately and check repository permissions",
            "Hardcoded Secret": "Move to encrypted .env file or Vault",
            "High Entropy Secret": "Verify if this is an Encryption Key; if valid hash, move to config",
            "Git History Leak": "Use 'git filter-repo' to remove from history"
        }.get(secret_type, "Secure the secret immediately")

    def scan_content(self, content, source_name, line_num=1):
        if self.is_false_positive(content):
            return

        for name, reg in PATTERNS.items():
            m = re.search(reg, content)
            if m:
                found_secret = m.group(0)
                status = "⚠️ UNVERIFIED"
                
                # Naya Feature: Verification Logic
                if name == "Google API": status = Validator.check_google(found_secret)
                elif name == "GitHub Token": status = Validator.check_github(found_secret)

                risk = "HIGH"
                if "ACTIVE" in status: risk = "CRITICAL"
                elif "EXPIRED" in status: risk = "LOW"
                
                if os.path.exists(source_name):
                    perms = self.permission_info(source_name)
                    if perms["world_readable"] and risk != "LOW": risk = "CRITICAL"
                
                self.results.append({
                    "file": source_name, "line": line_num, "type": name,
                    "secret": mask_secret(found_secret), "status": status,
                    "risk": risk, "fix": self.remediation(name)
                })

        if ENTROPY_CONTEXT.search(content):
            for chunk in ENTROPY_REGEX.findall(content):
                if shannon_entropy(chunk) > 4.5:
                    self.results.append({
                        "file": source_name, "line": line_num, "type": "High Entropy Secret",
                        "secret": mask_secret(chunk), "status": "⚠️ UNVERIFIED", "risk": "HIGH",
                        "fix": self.remediation("High Entropy Secret")
                    })

    def scan_file(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for ln, line in enumerate(f, 1):
                    self.scan_content(line, path, ln)
            self.scanned_files += 1
            if self.progress_callback:
                self.progress_callback(self.scanned_files, self.total_files)
        except: pass

    def scan_git_history(self):
        if not GIT_AVAILABLE:
            self.log("⚠️ GitPython not installed. Skipping History scan.")
            return
        try:
            repo = Repo(self.target)
            self.log("📜 Git History Scan: Analyzing last 5 commits...")
            for commit in repo.iter_commits(max_count=5):
                for parent in commit.parents:
                    diffs = parent.diff(commit)
                    for d in diffs:
                        if d.b_blob:
                            content = d.b_blob.data_stream.read().decode('utf-8', errors='ignore')
                            self.scan_content(content, f"GIT-COMMIT:{commit.hexsha[:7]} ({d.b_path})")
        except: self.log("⚠️ Not a git repository.")

    def scan_directory(self):
        self.log("🔍 Scanning filesystem...")
        file_list = []
        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in IGNORE_FOLDERS]
            for file in files:
                path = os.path.join(root, file)
                if not any(i in path for i in self.ignore):
                    file_list.append(path)
                    self.total_files += 1
        
        with ThreadPoolExecutor(max_workers=8) as exe:
            for p in file_list: exe.submit(self.scan_file, p)
        
        self.scan_git_history()

# ================= REPORTER =================
class Reporter:
    @staticmethod
    def save(results):
        if not results: return
        with open("security_report.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=results[0].keys())
            w.writeheader()
            w.writerows(results)

        rows = ""
        for r in results:
            badge_color = "#ff4d4d" if r['risk'] == "CRITICAL" else "#ffa500"
            if r['risk'] == "LOW": badge_color = "#4CAF50"
            rows += f"<tr><td><span class='badge' style='background:{badge_color}; color:white; padding:5px; border-radius:4px;'>{r['risk']}</span></td><td>{r['file']}</td><td>{r['line']}</td><td>{r['type']}</td><td><code>{r['secret']}</code></td><td>{r['status']}</td><td>{r['fix']}</td></tr>"

        html = f"""<html><head><title>SEC-SNIFFER Report</title><style>body{{background:#111; color:#eee; font-family:sans-serif;}} table{{width:100%; border-collapse:collapse;}} th,td{{padding:10px; border:1px solid #333; text-align:left;}} th{{background:#222; color:#00ff00;}}</style></head>
        <body><h1>SEC-SNIFFER PRO | Security Audit</h1><p>Time: {time.ctime()}</p><table><thead><tr><th>Risk</th><th>File</th><th>Line</th><th>Type</th><th>Secret</th><th>Status</th><th>Fix</th></tr></thead><tbody>{rows}</tbody></table></body></html>"""
        with open("security_dashboard.html", "w", encoding="utf-8") as f: f.write(html)

# ================= GUI =================
class SecSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SEC-SNIFFER PRO")
        self.root.geometry("1000x750")
        self.queue = queue.Queue()
        tk.Label(root, text="SEC-SNIFFER PRO", font=("Arial", 24), fg="#00ff00").pack(pady=10)
        
        # Security Philosophy Quote
        tk.Label(root, text='"Better to flag 10 safe things than to miss 1 dangerous secret."', font=("Arial", 10, "italic"), fg="#888").pack()

        self.path = tk.Entry(root, width=80)
        self.path.pack(pady=5)
        tk.Button(root, text="Browse", command=self.browse).pack(pady=5)
        tk.Button(root, text="Start Scan", command=self.start_scan, bg="#27ae60", fg="white").pack(pady=5)
        self.progress = ttk.Progressbar(root, length=800, mode='determinate')
        self.progress.pack(pady=10)
        self.log = scrolledtext.ScrolledText(root, height=25, bg="#111", fg="#00ff00")
        self.log.pack(fill=tk.BOTH, expand=True)
        self.root.after(100, self.process_queue)

    def browse(self):
        p = filedialog.askdirectory()
        if p: self.path.delete(0, tk.END); self.path.insert(0, p)

    def start_scan(self):
        target = self.path.get()
        if not os.path.exists(target): return
        print(get_banner())
        def worker():
            scanner = Scanner(target, self.queue, lambda s, t: self.update_progress(s, t))
            scanner.scan_directory()
            Reporter.save(scanner.results)
            self.queue.put(f"✅ Found {len(scanner.results)} secrets. Report saved.")
        threading.Thread(target=worker, daemon=True).start()

    def update_progress(self, s, t):
        self.progress['maximum'] = t
        self.progress['value'] = s

    def process_queue(self):
        while not self.queue.empty():
            msg = self.queue.get()
            self.log.insert(tk.END, msg + "\n"); self.log.see(tk.END)
        self.root.after(100, self.process_queue)

# ================= CLI =================
def run_cli(target):
    print(get_banner())
    scanner = Scanner(target)
    scanner.scan_directory()
    Reporter.save(scanner.results)
    for r in scanner.results:
        print(f"[{r['risk']}] {r['type']} - {r['status']} - {r['file']}:{r['line']}")
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SEC-SNIFFER PRO")
    parser.add_argument("--path", type=str, help="Path to scan")
    parser.add_argument("--no-gui", action="store_true", help="Run without GUI")
    args = parser.parse_args()
    if args.no_gui and args.path: run_cli(args.path)
    else:
        root = tk.Tk()
        app = SecSnifferGUI(root)
        root.mainloop()

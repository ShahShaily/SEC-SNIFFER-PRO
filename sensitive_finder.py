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

# ================= ASCII BANNER =================
def get_banner():
    return f"""{Colors.YELLOW}{Colors.BOLD}
**********************************************************
* ███████╗███████╗ ██████╗       ██████╗██████╗  ██████╗ *
* ██╔════╝██╔════╝██╔════╝      ██╔════╝██╔══██╗██╔═══██╗*
* ███████╗█████╗  ██║           ██║     ██████╔╝██║   ██║*
* ╚════██║██╔══╝  ██║           ██║     ██╔══██╗██║   ██║*
* ███████║███████╗╚██████╗      ╚██████╗██║  ██║╚██████╔╝*
* SEC-SNIFFER PRO                         *
**********************************************************
{Colors.END}"""

# ================= CONFIG =================
PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "Google API": r"AIza[0-9A-Za-z-_]{35}",
    "Hardcoded Secret": r"(?i)(password|api_key|secret|token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
}

ENTROPY_CONTEXT = re.compile(r"(key|token|secret|auth|bearer)", re.I)
ENTROPY_REGEX = re.compile(r"[A-Za-z0-9+/=_-]{24,}")

IGNORE_FILE = ".secsnifferignore"

# ================= UTILS =================
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

# ================= SCANNER =================
class Scanner:
    def __init__(self, target, log_queue, progress_callback=None):
        self.target = target
        self.log_queue = log_queue
        self.ignore = load_ignore_list(target)
        self.results = []
        self.progress_callback = progress_callback
        self.total_files = 0
        self.scanned_files = 0

    def log(self, msg):
        self.log_queue.put(msg)

    def permission_info(self, path):
        st = os.stat(path)
        return {
            "world_readable": bool(st.st_mode & stat.S_IROTH),
            "group_writable": bool(st.st_mode & stat.S_IWGRP),
            "executable": bool(st.st_mode & stat.S_IXUSR)
        }

    def remediation(self, secret_type):
        return {
            "AWS Key": "Rotate via IAM and move to Secrets Manager",
            "GitHub Token": "Revoke token immediately",
            "Hardcoded Secret": "Move to .env file",
            "High Entropy Secret": "Store in secure vault",
            "Git History Leak": "Rewrite git history"
        }.get(secret_type, "Secure the secret")

    def scan_file(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for ln, line in enumerate(f, 1):
                    for name, reg in PATTERNS.items():
                        m = re.search(reg, line)
                        if m:
                            perms = self.permission_info(path)
                            self.results.append({
                                "file": path, "line": ln, "type": name,
                                "secret": mask_secret(m.group(0)),
                                "risk": "CRITICAL" if perms["world_readable"] else "HIGH",
                                "fix": self.remediation(name)
                            })
                    if ENTROPY_CONTEXT.search(line):
                        for chunk in ENTROPY_REGEX.findall(line):
                            if shannon_entropy(chunk) > 4.5:
                                self.results.append({
                                    "file": path, "line": ln, "type": "High Entropy Secret",
                                    "secret": mask_secret(chunk), "risk": "HIGH",
                                    "fix": self.remediation("High Entropy Secret")
                                })
            self.scanned_files += 1
            if self.progress_callback:
                self.progress_callback(self.scanned_files, self.total_files)
        except: pass

    def scan_directory(self):
        self.log("🔍 Scanning filesystem...")
        file_list = []
        for root, _, files in os.walk(self.target):
            for file in files:
                path = os.path.join(root, file)
                if not any(i in path for i in self.ignore):
                    file_list.append(path)
                    self.total_files += 1
        with ThreadPoolExecutor(max_workers=8) as exe:
            for p in file_list: exe.submit(self.scan_file, p)

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
            rows += f"""
            <tr>
                <td><span class="badge" style="background-color: {badge_color};">{r['risk']}</span></td>
                <td>{r['file']}</td>
                <td style="color: #ffcc00; font-weight: bold;">{r['line']}</td>
                <td style="color: #00ff00;">{r['type']}</td>
                <td style="font-family: monospace;">{r['secret']}</td>
                <td style="font-style: italic; color: #aaa;">{r['fix']}</td>
            </tr>"""

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SEC-SNIFFER PRO Report</title>
            <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
            <style>
                body {{ background-color: #111; color: #e0e0e0; font-family: sans-serif; padding: 30px; }}
                h1 {{ color: #00ff00; border-bottom: 2px solid #00ff00; }}
                table {{ background: #1a1a1a; }}
                .badge {{ padding: 4px 8px; border-radius: 4px; color: white; }}
            </style>
            <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
            <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
            <script>$(document).ready(function(){{ $('table').DataTable(); }});</script>
        </head>
        <body>
            <h1>SEC-SNIFFER PRO | Security Audit</h1>
            <p>Vulnerabilities: {len(results)} | Time: {time.strftime('%H:%M:%S')}</p>
            <table>
                <thead><tr><th>Risk</th><th>File</th><th>Line</th><th>Type</th><th>Secret</th><th>Fix</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </body>
        </html>"""
        with open("security_dashboard.html", "w", encoding="utf-8") as f: f.write(html)

# ================= GUI =================
class SecSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SEC-SNIFFER PRO")
        self.root.geometry("1000x750")
        self.queue = queue.Queue()
        tk.Label(root, text="SEC-SNIFFER PRO", font=("Arial", 24), fg="#00ff00").pack(pady=10)
        self.path = tk.Entry(root, width=80)
        self.path.pack(pady=5)
        tk.Button(root, text="Browse", command=self.browse).pack(pady=5)
        tk.Button(root, text="Start Scan", command=self.start_scan, bg="#27ae60", fg="white").pack(pady=5)
        self.progress = ttk.Progressbar(root, length=800, mode='determinate')
        self.progress.pack(pady=10)
        self.log = scrolledtext.ScrolledText(root, height=25)
        self.log.pack(fill=tk.BOTH, expand=True)
        self.root.after(100, self.process_queue)

    def browse(self):
        p = filedialog.askdirectory()
        if p: self.path.delete(0, tk.END); self.path.insert(0, p)

    def start_scan(self):
        target = self.path.get()
        if not os.path.exists(target): return
        self.log.insert(tk.END, "🚀 Scanning... Check terminal for banner.\n")
        print(get_banner())
        def worker():
            scanner = Scanner(target, self.queue, lambda s, t: self.update_progress(s, t))
            scanner.scan_directory()
            Reporter.save(scanner.results)
            self.queue.put(f"✅ Found {len(scanner.results)} secrets. Report saved.")
            if any(r['risk'] == "CRITICAL" for r in scanner.results):
                messagebox.showwarning("CRITICAL", "Critical leaks detected!")
        threading.Thread(target=worker, daemon=True).start()

    def update_progress(self, s, t):
        self.progress['maximum'] = t
        self.progress['value'] = s

    def process_queue(self):
        while not self.queue.empty():
            msg = self.queue.get()
            self.log.insert(tk.END, msg + "\n"); self.log.see(tk.END)
        self.root.after(100, self.process_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecSnifferGUI(root)
    root.mainloop()

import os
import re
import stat
import json
import time
import csv
import sys
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

# --- Colors for Terminal ---
class Colors:
    RED, GREEN, YELLOW, BLUE, BOLD, END = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[1m', '\033[0m'

# --- Patterns ---
PATTERNS = {
    "AWS_Access_Key": r"AKIA[0-9A-Z]{16}",
    "Google_API_Key": r"AIza[0-9A-Za-z-_]{35}",
    "Github_Token": r"ghp_[a-zA-Z0-9]{36}",
    "Hardcoded_Secret": r"(?i)(password|api_key|secret|token)[\s:=]+['\"]([0-9a-zA-Z]{8,})['\"]"
}
IGNORE_WORDS = ["your_password", "example_key", "placeholder"]

# --- ASCII Banner ---
def get_banner():
    return f"""{Colors.YELLOW}{Colors.BOLD}
    **********************************************************
    * ███████╗███████╗ ██████╗      ██████╗██████╗  ██████╗ *
    * ██╔════╝██╔════╝██╔════╝     ██╔════╝██╔══██╗██╔═══██╗*
    * ███████╗█████╗  ██║          ██║     ██████╔╝██║   ██║*
    * ╚════██║██╔══╝  ██║          ██║     ██╔══██╗██║   ██║*
    * ███████║███████╗╚██████╗     ╚██████╗██║  ██║╚██████╔╝*
    * V.2.5 - ENTERPRISE SEC-PRO MONITOR (GUI + ALARM + CSV) *
    **********************************************************{Colors.END}"""

class SecProApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ SEC-SNIFFER PRO - Professional Suite")
        self.root.geometry("900x700")
        self.root.configure(bg="#1a1a1a")
        self.is_running = False
        
        # UI Elements
        tk.Label(root, text="SEC-SNIFFER PRO v2.5", font=("Arial", 25, "bold"), fg="#4caf50", bg="#1a1a1a").pack(pady=10)
        self.path_entry = tk.Entry(root, width=65, font=("Consolas", 10))
        self.path_entry.pack(pady=5)
        tk.Button(root, text="📁 BROWSE TARGET", command=self.browse, bg="#333", fg="white").pack(pady=5)
        
        btn_frame = tk.Frame(root, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        self.start_btn = tk.Button(btn_frame, text="▶ START MONITOR", bg="#27ae60", fg="white", width=15, command=self.start_thread)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk.Button(btn_frame, text="🛑 STOP", bg="#c0392b", fg="white", width=15, command=self.stop_scan)
        self.stop_btn.pack(side=tk.LEFT)
        
        self.log_area = scrolledtext.ScrolledText(root, width=100, height=25, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(pady=10, padx=10)

    def browse(self):
        folder = filedialog.askdirectory()
        if folder:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, folder)

    def log(self, msg, color=Colors.END):
        ts = time.strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_area.see(tk.END)
        print(f"{color}[{ts}] {msg}{Colors.END}")

    def start_thread(self):
        if not self.is_running:
            self.is_running = True
            threading.Thread(target=self.scan_logic, daemon=True).start()

    def stop_scan(self):
        self.is_running = False
        self.log("🛑 Monitor Stopped.", Colors.YELLOW)

    def scan_logic(self):
        target = self.path_entry.get()
        if not target or not os.path.exists(target):
            messagebox.showerror("Error", "Invalid Folder!")
            self.is_running = False
            return
        
        print(get_banner()) 
        self.log(f"🚀 Monitor Active: {target}", Colors.BLUE)
        
        while self.is_running:
            findings = []
            for root, dirs, files in os.walk(target):
                if not self.is_running: break
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules']]
                for file in files:
                    if file.endswith(('.png', '.jpg', '.zip')): continue
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', errors='ignore', encoding='utf-8') as f:
                            for ln, line in enumerate(f, 1):
                                for name, reg in PATTERNS.items():
                                    if re.search(reg, line):
                                        # Filtering Ignore Words
                                        if not any(w in line.lower() for w in IGNORE_WORDS):
                                            risk = "CRITICAL" if bool(os.stat(path).st_mode & stat.S_IROTH) else "HIGH"
                                            findings.append({"file": path, "line_no": ln, "type": name, "risk": risk, "context": line.strip()[:80]})
                    except: pass
            
            if findings:
                self.save_all(findings)
                self.log(f"🚨 ALERT: {len(findings)} Issues Found!", Colors.RED)
                if sys.platform == "win32":
                    import winsound
                    winsound.Beep(1000, 500)
            else:
                self.log("✅ System Secure. Monitoring...", Colors.GREEN)
            
            time.sleep(10)

    def save_all(self, findings):
        ts = time.ctime()
        try:
            # CSV with UTF-8 encoding
            with open("security_report.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=findings[0].keys())
                w.writeheader()
                w.writerows(findings)
            
            # JSON with UTF-8 encoding
            with open("security_report.json", "w", encoding="utf-8") as f:
                json.dump({"time": ts, "data": findings}, f, indent=4)
            
            # HTML Dashboard with UTF-8 encoding to fix UnicodeEncodeError
            rows = "".join([f"<tr><td>{f['risk']}</td><td>{f['file']}</td><td>{f['type']}</td></tr>" for f in findings])
            with open("security_dashboard.html", "w", encoding="utf-8") as f:
                f.write(f"<html><body style='background:#121212;color:white;'><h1>SEC-PRO DASHBOARD</h1><p>Last Update: {ts}</p><table border='1' style='width:100%; border-collapse: collapse;'><thead><tr><th>RISK</th><th>LOCATION</th><th>TYPE</th></tr></thead><tbody>{rows}</tbody></table></body></html>")
        
        except Exception as e:
            print(f"Error saving reports: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecProApp(root)
    root.mainloop()


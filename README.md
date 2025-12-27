# 🛡️ SEC-SNIFFER PRO
**"High-Precision Real-time Secret Scanner & Security Auditor Tool"**

SEC-SNIFFER PRO is a powerful Static Application Security Testing (SAST) tool developed in Python. It is designed to help developers and security auditors identify sensitive information such as API Keys, Credentials, and Tokens hidden within source code in real-time.

## 🌟 Key Features

* **🔍 Pattern-Based Detection:** Uses optimized Regular Expressions (Regex) to accurately detect AWS Keys, GitHub Tokens, Google API keys, and other private credentials.
* **⚡ Performance Optimized:** Intelligently skips heavy metadata and dependency folders like `node_modules`, `.git`, and media assets to ensure lightning-fast scanning.
* **🛰️ Live File-System Monitoring:** Features a 'Watchdog' logic that monitors your project directory. It automatically re-scans any file within seconds of it being saved.
* **📉 False Positive Mitigation:** Implements a smart filtering layer to ignore dummy data (e.g., 'example_password') and common placeholders.
* **🔔 Instant Audio Alerts:** Triggers a **Windows Beep (Audio Alert)** the moment a critical security leak is detected.
* **📊 Professional Reporting:** Generates comprehensive and clean reports in **HTML Dashboard**, **CSV**, and **JSON** formats for easy auditing.
* **🖥️ Responsive GUI:** A clean, multi-threaded Tkinter-based interface that ensures the tool remains responsive during background operations.

## 🛠️ Technical Stack

* **Language:** Python 3.x
* **GUI Framework:** Tkinter (Multi-threaded architecture)
* **Monitoring Logic:** Real-time directory polling
* **Detection Engine:** Regular Expressions (Regex)
* **Data Export:** JSON, CSV, and Dynamic HTML templates

## 🚀 How to Use

1. **Clone the Repository:**
   git clone [https://github.com/ShahShaily/SEC-SNIFFER-PRO.git](https://github.com/ShahShaily/SEC-SNIFFER-PRO.git)
2. **Launch the Application:**
   python sensitive_finder.py
3. **Operation**:
   Click the 'Browse' button to select your target project folder.
   Click 'Start Monitor' to begin the security audit.
   The tool will run in the background. If a secret is saved in any file, you will hear a Beep Alert instantly!
   **Why SEC-SNIFFER PRO?**
*  Real-time Feedback: Unlike traditional scanners that run once, this tool monitors your work as you code.
*  Developer Friendly: Designed to be lightweight and easy to use without complex command-line arguments.
*  Detailed Audits: Provides exact line numbers and file paths in professional HTML reports.
  **Disclaimer**
*  This project is intended for educational purposes and authorized security auditing only. Always obtain explicit permission before scanning third-party repositories.

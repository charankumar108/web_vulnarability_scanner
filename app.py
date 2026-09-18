import os
import io
import textwrap
import socket
import time
import datetime
from urllib.parse import urlparse
from flask import Flask, render_template, request, send_file, jsonify
import requests
import urllib3
from fpdf import FPDF

# Suppress insecure request warnings if scanning internal/self-signed targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "vuln-scanner-prod-key-default")

def sanitize_pdf_text(text):
    """Sanitizes text to prevent FPDF unicode character encoding errors."""
    if not text:
        return ""
    replacements = {
        "\u2018": "'", "\u2019": "'", "\u201a": "'",
        "\u201c": '"', "\u201d": '"', "\u201e": '"',
        "\u2013": "-", "\u2014": "-", "\u2026": "...",
        "\u2022": "*", "\xa0": " "
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)
    return text.encode("latin-1", "replace").decode("latin-1")


class RealTimeScanner:
    def __init__(self, target_url):
        target_url = (target_url or "").strip()
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "http://" + target_url
        self.target_url = target_url
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 VulScan/1.0"
        })

    def run_live_scan(self):
        self.site_details = {"ip_address": "Unknown", "response_time": "Unknown", "server": "Unknown", "technology": "Unknown"}
        try:
            parsed = urlparse(self.target_url)
            if parsed.hostname:
                self.site_details["ip_address"] = socket.gethostbyname(parsed.hostname)
        except Exception:
            pass

        # Initial baseline connection check
        initial_res = None
        try:
            start_t = time.time()
            initial_res = self.session.get(self.target_url, timeout=5, verify=False)
            end_t = time.time()
            self.site_details["response_time"] = f"{round((end_t - start_t) * 1000)} ms"
            self.site_details["server"] = initial_res.headers.get("Server", "Unknown")
            self.site_details["technology"] = initial_res.headers.get("X-Powered-By", "Unknown")
        except requests.exceptions.RequestException as e:
            self.findings.append({
                "vulnerability": "Target Unreachable",
                "severity": "Critical",
                "description": f"Could not establish connection to the remote target: {e}"
            })
            return {"findings": self.findings, "site_details": self.site_details}

        # 1. REAL-TIME HEADER ANALYSIS
        try:
            headers = initial_res.headers
            security_headers = {
                "X-Frame-Options": ("Low", "Missing protection against Clickjacking attacks."),
                "Content-Security-Policy": ("Medium", "Missing Content-Security-Policy (CSP) headers.")
            }
            for h, (sev, desc) in security_headers.items():
                if h not in headers:
                    self.findings.append({"vulnerability": f"Missing {h} Header", "severity": sev, "description": desc})
        except Exception:
            pass

        # 2. REAL-TIME SQL INJECTION CHECK
        try:
            sqli_url = f"{self.target_url}?id='"
            sqli_res = self.session.get(sqli_url, timeout=4, verify=False)
            body_lower = sqli_res.text.lower()
            if "sql syntax" in body_lower or "mysql" in body_lower or "mariadb" in body_lower or "syntax error" in body_lower:
                self.findings.append({
                    "vulnerability": "SQL Injection Detected",
                    "severity": "High",
                    "description": "The application returned a raw database driver exception layout upon payload parsing."
                })
        except requests.exceptions.RequestException:
            pass

        # 3. REAL-TIME REFLECTED XSS CHECK
        try:
            xss_payload = "<script>alert(1)</script>"
            xss_url = f"{self.target_url}?q={xss_payload}"
            xss_res = self.session.get(xss_url, timeout=4, verify=False)
            if xss_payload in xss_res.text:
                self.findings.append({
                    "vulnerability": "Reflected Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "description": "The payload executable element reflected back dynamically inside the HTML framework context."
                })
        except requests.exceptions.RequestException:
            pass

        # 4. REAL-TIME EXPOSED DIRECTORIES CHECK
        common_dirs = ["/admin", "/backup", "/config", "/.git/"]
        for d in common_dirs:
            try:
                dir_url = self.target_url.rstrip("/") + d
                dir_res = self.session.get(dir_url, timeout=4, verify=False)
                if dir_res.status_code == 200:
                    self.findings.append({
                        "vulnerability": f"Exposed Directory: {d}",
                        "severity": "Medium",
                        "description": f"Sensitive directory {d} might be publicly accessible."
                    })
            except requests.exceptions.RequestException:
                pass

        return {"findings": self.findings, "site_details": self.site_details}

scan_history = []

@app.route("/health")
def health():
    """Health check endpoint for cloud platforms and load balancers."""
    return jsonify({"status": "ok", "timestamp": datetime.datetime.now().isoformat()}), 200

@app.route("/", methods=["GET", "POST"])
def main():
    results, target = None, None
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    scan_id = -1
    if request.method == "POST":
        target = (request.form.get("url") or "").strip()
        if not target:
            target = "http://127.0.0.1:8080"
        scanner = RealTimeScanner(target)
        scan_result = scanner.run_live_scan()
        results = scan_result["findings"]
        site_details = scan_result["site_details"]
        for r in results:
            sev = r.get("severity", "Low")
            if sev in stats:
                stats[sev] += 1
            else:
                stats["Low"] += 1
        
        scan_id = len(scan_history)
        scan_history.append({
            "id": scan_id,
            "target": target,
            "results": results,
            "site_details": site_details,
            "stats": stats,
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    return render_template("index.html", results=results, target=target, stats=stats, scan_id=scan_id)

@app.route("/history")
def history():
    return render_template("history.html", history=scan_history)

@app.route("/export_pdf/<int:scan_id>")
def export_pdf(scan_id):
    if scan_id < 0 or scan_id >= len(scan_history):
        return "Scan not found", 404
        
    scan = scan_history[scan_id]
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Helvetica", style="B", size=24)
    pdf.set_text_color(0, 73, 101) # Dark blue/primary
    pdf.cell(0, 15, txt="Vul Scan | Security Report", align="C")
    pdf.ln(15)
    
    # Meta Info
    pdf.set_font("Helvetica", size=11)
    
    # Left column for scan info
    target_clean = sanitize_pdf_text(scan['target'])
    time_clean = sanitize_pdf_text(scan['time'])
    pdf.cell(0, 8, txt=f"Scan Date/Time: {time_clean}", ln=True)
    pdf.cell(0, 8, txt=f"Target Site: {target_clean}", ln=True)
    pdf.cell(0, 8, txt="Scan Status: COMPLETED", ln=True)
    
    # Right column (or just print below) for site details
    sd = scan.get('site_details', {})
    pdf.ln(4)
    pdf.set_font("Helvetica", style="B", size=11)
    pdf.cell(0, 8, txt="Site Infrastructure Details:", ln=True)
    pdf.set_font("Helvetica", size=11)
    pdf.cell(0, 8, txt=f"IP Address: {sanitize_pdf_text(str(sd.get('ip_address', 'Unknown')))}", ln=True)
    pdf.cell(0, 8, txt=f"Response Time: {sanitize_pdf_text(str(sd.get('response_time', 'Unknown')))}", ln=True)
    pdf.cell(0, 8, txt=f"Server: {sanitize_pdf_text(str(sd.get('server', 'Unknown')))}", ln=True)
    pdf.cell(0, 8, txt=f"Technology: {sanitize_pdf_text(str(sd.get('technology', 'Unknown')))}", ln=True)
    
    pdf.ln(6)
    total_findings = len(scan['results'])
    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 8, txt=f"Total Vulnerabilities Found: {total_findings}", ln=True)
    pdf.ln(4)
    
    # Disclaimer
    pdf.set_font("Helvetica", style="I", size=10)
    pdf.set_text_color(120, 120, 120)
    disclaimer = "CONFIDENTIALITY NOTICE: This document contains sensitive information regarding the security posture of the target system. It is intended solely for authorized personnel. The findings presented are the result of an automated scan and should be manually verified by a security professional."
    lines = textwrap.wrap(disclaimer, width=95)
    for line in lines:
        pdf.cell(0, 5, txt=line, align="C", ln=True)
    pdf.ln(10)
    pdf.set_text_color(0, 0, 0)
    
    # Executive Summary
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(0, 10, txt="1. Executive Summary", ln=True)
    
    pdf.set_font("Helvetica", size=12)
    stats = scan['stats']
    pdf.cell(0, 8, txt=f"Critical: {stats['Critical']} | High: {stats['High']} | Medium: {stats['Medium']} | Low: {stats['Low']}", ln=True)
    pdf.ln(10)
    
    # Findings
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(0, 10, txt="2. Detailed Findings", ln=True)
    pdf.ln(5)
    
    for idx, f in enumerate(scan['results']):
        sev = str(f.get('severity', 'LOW')).upper()
        vuln_name = sanitize_pdf_text(str(f.get('vulnerability', 'Unknown Vulnerability')))
        pdf.set_font("Helvetica", style='B', size=12)
        lines = textwrap.wrap(f"Finding #{idx+1}: {vuln_name} [{sev}]", width=85)
        for line in lines:
            pdf.cell(0, 8, txt=line, ln=True)
        
        pdf.set_font("Helvetica", size=11)
        desc = sanitize_pdf_text(str(f.get('description', '')))
        lines = textwrap.wrap(f"Description: {desc}", width=95)
        for line in lines:
            pdf.cell(0, 6, txt=line, ln=True)
            
        if 'impact' in f and f['impact']:
            pdf.ln(2)
            pdf.set_font("Helvetica", style='B', size=11)
            pdf.cell(0, 6, txt="Business & Security Impact:", ln=True)
            pdf.set_font("Helvetica", size=11)
            lines = textwrap.wrap(sanitize_pdf_text(str(f['impact'])), width=95)
            for line in lines:
                pdf.cell(0, 6, txt=line, ln=True)
                
        if 'remediation' in f and f['remediation']:
            pdf.ln(2)
            pdf.set_font("Helvetica", style='I', size=11)
            rem = sanitize_pdf_text(str(f['remediation']))
            lines = textwrap.wrap(f"Recommended Remediation: {rem}", width=95)
            for line in lines:
                pdf.cell(0, 6, txt=line, ln=True)
        pdf.ln(8)
        
    pdf_bytes = bytes(pdf.output())
    return send_file(io.BytesIO(pdf_bytes), download_name=f"scan_report_{scan_id}.pdf", as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() in ("true", "1")
    app.run(host="0.0.0.0", port=port, debug=debug)
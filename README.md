# Web Application Vulnerability Scanner

## Overview
The Web Application Vulnerability Scanner is a security tool developed to identify common web vulnerabilities. It serves as an academic project to enhance understanding of web security and provide practical experience in vulnerability detection.

## Features
- **SQL Injection Detection**: Injects SQL statements into input fields to analyze responses and identify potential SQL syntax errors or exposed database logs.
- **Cross-Site Scripting (XSS) Detection**: Tests for Reflected XSS vulnerabilities by injecting scripts into input vectors and verifying if the payload is reflected back dynamically within the HTML framework context.
- **Insecure Server Configurations & Exposed Directories**: Analyzes HTTP headers to check for missing security measures (e.g., CSP, X-Frame-Options) and scans for common exposed directories like `/admin`, `/backup`, `/config`, and `/.git/`.
- **Report Generation**: Automatically generates detailed structural reports (`Vulnerability_Scan_Report.txt`) containing the findings, severity levels, and remediation recommendations.

## Setup & Installation

### Requirements
- Python 3.7+
- Recommended OS: Windows, Linux, or macOS

### Installation
1. Clone or download this project.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *Note: If `requests` is unavailable, the CLI scanner includes a fallback that utilizes the built-in `urllib`.*

## Usage

### 1. Live Interactive Web UI
A modern web interface is provided for easy usage. To start the scanner UI:
```bash
python app.py
```
Then navigate to `http://localhost:5000` in your web browser. Enter the target URL and launch the live audit.

### 2. Command Line Interface (CLI)
You can use the vulnerability scanner directly from the terminal against any target URL:
```bash
python scanner.py "http://example.com"
```
This will run the full suite of checks and output a `Vulnerability_Scan_Report.txt` file in the same directory.

### 3. Simulation & Grading Mode
The project comes with a built-in "dummy" lab target to demonstrate functionality safely without attacking real systems. 
To start the vulnerable target lab, run:
```bash
python target_app.py
```
This starts the dummy target on `http://localhost:8080`.
You can then run `python scanner.py` with no arguments, and it will automatically execute a mock simulation showing how the scanner detects vulnerabilities.

## Disclaimer
This project is built for educational and ethical hacking purposes. Only scan applications and networks for which you have explicit permission.
"# web_vulnarability_scanner"  

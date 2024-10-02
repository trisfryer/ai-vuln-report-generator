# AI-Powered Vulnerability Scanner and Report Generator

A Python tool that automates vulnerability scanning of a target host using various tools and generates a comprehensive vulnerability report leveraging OpenAI's GPT-4 model.

## Overview

This tool automates the process of scanning a target host for vulnerabilities and generates a detailed report using AI. It integrates traditional scanning tools with OpenAI's GPT-4 to analyze scan results and present findings in a professional report format.

## Features

- Automated Scanning: Runs multiple vulnerability scanning tools against a target host.
  - Nmap: For network scanning and service enumeration.
  - Nikto: For web server scanning.
  - WhatWeb: For website fingerprinting.
  - Gobuster: For directory and file brute-forcing.
  - testssl.sh: For SSL/TLS scanning (if SSL is detected).
- AI-Powered Analysis: Uses OpenAI's GPT-4 API to analyze raw scan outputs and extract vulnerabilities.
- Comprehensive Reports: Generates detailed vulnerability reports in Markdown format, including an overview, detailed findings, and remediation recommendations.
- Error Handling: Robust error handling and logging mechanisms.
- Debugging Support: Saves intermediate data and logs for troubleshooting.

## Prerequisites

- Python: Python 3.6 or higher.
- Tools: Ensure the following tools are installed and accessible in your PATH:
  - nmap
  - nikto
  - whatweb
  - gobuster
  - testssl.sh (or modify the script to use sslscan if preferred)
- Python Packages: Install required Python packages using pip.
- OpenAI API Key: An API key for OpenAI's GPT-4 model.

## Installation

1. Clone the Repository:

```
git clone https://github.com/exampleuser/ai-vuln-report-generator.git
cd ai-vuln-report-generator
```

2. Install Python Dependencies:

   It's recommended to use a virtual environment.

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Install Scanning Tools:

   Install the required scanning tools if not already installed.

- Nmap:

```
sudo apt-get install nmap
```

- Nikto:

```
sudo apt-get install nikto
```

- WhatWeb:

```
sudo apt-get install whatweb
```

- Gobuster:

```
sudo apt-get install gobuster
```

- testssl.sh:

```
# Navigate to your preferred directory for tools
cd /opt
sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git
# Ensure testssl.sh is executable
sudo chmod +x /opt/testssl.sh/testssl.sh
# Add testssl.sh to your PATH or modify the script to point to its location
```

5. Set OpenAI API Key:

Obtain your API key from OpenAI and set it as an environment variable.

```
export OPENAI_API_KEY='your-api-key-here'
```

## Usage

Run the script with the target host as an argument.

```
python3 gen_report.py <target_host>
```

Replace <target_host> with the IP address or domain name of the target you have permission to scan.

The script will perform the following steps:

1. Run Nmap Scan: Scans the target host to detect open ports and services.
2. Conditional Scans:
   - If port 443 (HTTPS) is open or SSL is detected, it runs SSLScan using testssl.sh.
   - If port 80 (HTTP) is open or a web server is detected, it runs Nikto, WhatWeb, and Gobuster.
3. Collect Raw Data: Gathers raw outputs from the scanning tools.
4. AI Analysis: Sends the raw data to GPT-4 to extract vulnerabilities and generate the report.
5. Generate Report: Saves the comprehensive vulnerability report in Markdown format.

The report will be saved as vulnerability*report*<target_host>.md.

![Screenshot of the code output after successfuling running a scan and generating report](/images/script.png)

### Configuration

- Script Files:
  - gen_report.py: The main script to run the scans and generate the report.
  - vulnerability_scanner.py: The library module containing all the functions and classes related to scanning and report generation.
- Tool Paths: If any tools are installed in non-standard locations, update the paths in vulnerability_scanner.py.
- Gobuster Wordlist: Ensure the wordlist path in vulnerability_scanner.py points to a valid wordlist on your system.
- OpenAI Model: The script uses the GPT-4 model by default. Ensure your API key has access to GPT-4.
- Token Limits: Be mindful of the token limits for the GPT-4 model (8,192 tokens). The script includes mechanisms to manage token usage.

### Example Output

Two examples of generated reports can be found in the examples directory. The reports include:

- Overview: A summary of the overall security posture.
- Vulnerability Findings: A detailed table of vulnerabilities with their impact (rating and description), likelihood (rating and description), and remediation steps.

The two scans were run against [HackTheBox SolarLab](https://app.hackthebox.com/machines/SolarLab) ([vulnerability_report_solarlab.htb.md](Examples/vulnerability_report_solarlab.htb.md) and [HackTheBox Sea](https://app.hackthebox.com/machines/Sea) ([vulnerability_report_10.10.11.28.md](Examples/vulnerability_report_10.10.11.28.md)

## Notes

- Permissions: Ensure you have legal authorization to scan the target host. Unauthorized scanning is illegal and unethical.
- OpenAI API Costs: Using the GPT-4 API incurs costs. Monitor your usage and set up billing limits as necessary.
- Error Handling: Logs are saved in the debug_data directory to help troubleshoot any issues.
- Debug Data: Intermediate data and GPT-4 responses are saved for debugging purposes.
- Customizable Prompts: The script uses prompts designed to extract detailed vulnerability information. You can adjust the prompts in vulnerability_scanner.py if needed.
- Modifying the Script: Feel free to customize the script to suit your needs, such as adding more scanning tools or adjusting the report format.

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. Unauthorized use of this tool to scan systems without explicit permission is illegal and unethical.

The developers are not responsible for any misuse of this tool. Always ensure you have proper authorization before conducting any scans.

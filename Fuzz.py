import os
import sys
import time
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# ASCII Art (by ElGabir)
ascii_art = """
   ____        __        __   ____                 
  / ___| __ _ / / ___   / /  | __ )  ___  _ __   
 | |  _ / _` / / / _ \ / /   |  _ \ / _ \| '_ \  
 | |_| | (_| / / |  __// /    | |_) | (_) | | | | 
  \____|\__,_/_/ \___/_/     |____/ \___/|_| |_| 
                                                  
    Fuzzy.py - Web Recon & Credential Hunter
"""

OUTPUT_FILE = "credentials_output.txt"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_main_menu():
    clear_screen()
    print(Fore.RED + ascii_art)
    print(Fore.CYAN + "="*60)
    print(Fore.YELLOW + "Select Mode:")
    print(Fore.CYAN + "="*60)
    print(Fore.GREEN + "1. Demo Mode (Simulated Data)")
    print(Fore.GREEN + "2. Fuzzy (Actual) Mode")
    print(Fore.CYAN + "="*60)

def print_fuzzy_menu():
    print(Fore.CYAN + "\nChoose Functionality:")
    print(Fore.YELLOW + "1. Credential & Email Harvest")
    print(Fore.YELLOW + "2. Web Crawler & Recon")
    print(Fore.YELLOW + "3. Payment Receipt Extractor")
    print(Fore.YELLOW + "4. Vulnerability Scanner")
    print(Fore.YELLOW + "5. Return to Main Menu")

def save_results(data):
    with open(OUTPUT_FILE, 'a') as f:
        f.write(data + "\n")
    print(Fore.YELLOW + f"Results saved to {OUTPUT_FILE}")

def credential_email_harvest():
    url = input(Fore.CYAN + "Enter target URL: ").strip()
    print(Fore.YELLOW + "Harvesting credentials and emails (simulated)...")
    credentials = [
        ("admin", "password123"),
        ("user", "passw0rd"),
        ("admin", "admin123"),
    ]
    emails = [
        "admin@example.com",
        "user@domain.com",
        "contact@target.com"
    ]
    output = "Credentials Found:\n"
    for user, pwd in credentials:
        line = f"User: {user} | Password: {pwd}"
        print(Fore.WHITE + line)
        output += line + "\n"
    output += "\nEmails Found:\n"
    for email in emails:
        print(Fore.WHITE + email)
        output += email + "\n"
    save_results(output)

def web_crawler_demo():
    print(Fore.YELLOW + "Starting demo web crawling with simulated data...")
    visited = {
        "http://example.com",
        "http://example.com/about",
        "http://example.com/contact",
        "http://example.com/products"
    }
    report = "Crawled URLs:\n" + "\n".join(visited)
    print(report)
    save_results(report)

def web_crawler_real():
    url = input(Fore.CYAN + "Enter target URL for real crawling (e.g., https://example.com): ").strip()
    print(Fore.YELLOW + "Starting real web crawling...")
    visited = set()
    to_visit = [url]
    max_pages = 20

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue
        try:
            response = requests.get(current_url, timeout=5)
            if response.status_code == 200:
                print(Fore.GREEN + f"Crawled: {current_url}")
                visited.add(current_url)
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = requests.compat.urljoin(current_url, link['href'])
                    if full_url.startswith(url) and full_url not in visited:
                        to_visit.append(full_url)
        except:
            continue
    print(Fore.CYAN + "Crawling complete. URLs found:")
    report = "Crawled URLs:\n" + "\n".join(visited)
    print(report)
    save_results(report)

def payment_receipt_extractor():
    url = input(Fore.CYAN + "Enter target URL: ").strip()
    print(Fore.YELLOW + "Extracting payment receipts (simulated)...")
    receipts = [
        "Order #12345 - $99.99 - Payment successful",
        "Order #67890 - $49.99 - Payment received",
        "Order #54321 - $149.99 - Payment completed"
    ]
    output = "Payment Receipts:\n"
    for receipt in receipts:
        print(Fore.WHITE + receipt)
        output += receipt + "\n"
    save_results(output)

def vulnerability_scanner():
    url = input(Fore.CYAN + "Enter target URL: ").strip()
    print(Fore.YELLOW + "Scanning for vulnerabilities (simulated)...")
    issues = [
        "SQL Injection possible at parameter 'id'",
        "Open redirect found at /redirect",
        "Cross-site scripting (XSS) detected in search form"
    ]
    output = "Vulnerabilities Detected:\n"
    for issue in issues:
        print(Fore.RED + "[!] " + issue)
        output += "[!] " + issue + "\n"
    save_results(output)

def fuzzy_mode():
    # Authentication check
    passcode = input(Fore.CYAN + "Enter passcode for Fuzzy Mode: ").strip()
    if passcode != "Sprite40":
        print(Fore.RED + "Incorrect passcode. Contact creator for access.")
        return
    while True:
        print_fuzzy_menu()
        choice = input(Fore.YELLOW + "Enter choice (1-5): ").strip()
        if choice == '1':
            credential_email_harvest()
        elif choice == '2':
            # Ask if demo or real
            mode = input(Fore.CYAN + "Use (D)emo or (R)eal crawling? (D/R): ").strip().lower()
            if mode == 'd':
                web_crawler_demo()
            elif mode == 'r':
                web_crawler_real()
            else:
                print(Fore.RED + "Invalid option.")
        elif choice == '3':
            payment_receipt_extractor()
        elif choice == '4':
            vulnerability_scanner()
        elif choice == '5':
            break
        else:
            print(Fore.RED + "Invalid choice.")
        input(Fore.MAGENTA + "\nPress Enter to return to menu...")

def main():
    while True:
        print_main_menu()
        mode = input(Fore.YELLOW + "Enter choice (1-2): ").strip()
        if mode == '1':
            # Demo Mode
            print(Fore.CYAN + "Selected Demo Mode.")
            while True:
                print(Fore.CYAN + "\nDemo Mode Options:")
                print(Fore.YELLOW + "1. Credential & Email Harvest")
                print(Fore.YELLOW + "2. Web Crawler")
                print(Fore.YELLOW + "3. Payment Receipt Extractor")
                print(Fore.YELLOW + "4. Vulnerability Scanner")
                print(Fore.YELLOW + "5. Return to Main Menu")
                choice = input(Fore.YELLOW + "Enter choice (1-5): ").strip()
                if choice == '1':
                    credential_email_harvest()
                elif choice == '2':
                    web_crawler_demo()
                elif choice == '3':
                    payment_receipt_extractor()
                elif choice == '4':
                    vulnerability_scanner()
                elif choice == '5':
                    break
                else:
                    print(Fore.RED + "Invalid choice.")
                input(Fore.MAGENTA + "\nPress Enter to continue...")
        elif mode == '2':
            # Fuzzy Mode with passcode
            fuzzy_mode()
        else:
            print(Fore.RED + "Invalid choice.")
        input(Fore.MAGENTA + "\nPress Enter to return to main menu...")

if __name__ == "__main__":
    main()

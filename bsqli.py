import requests
import concurrent.futures
import time
import os
from urllib.parse import urlparse, parse_qs
import logging
import argparse

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger()

# Configuration
TIMEOUT = 15  # Max response wait time
DELAY_THRESHOLD = 10  # If >=10s, considered vulnerable
MAX_THREADS = 3  # Max number of concurrent threads

def load_payloads(payload_file):
    """
    Loads payloads from a text file.

    Args:
        payload_file (str): Path to the payload file.

    Returns:
        list: List of loaded payloads.
    """
    if not os.path.exists(payload_file):
        log.error(f"The payload file '{payload_file}' does not exist.")
        exit(1)
    
    with open(payload_file, "r", encoding="utf-8") as f:
        payloads = [line.strip() for line in f.readlines() if line.strip()]
    
    log.info(f"Loaded {len(payloads)} payloads from '{payload_file}'.")
    return payloads

def inject_sql_payload(url, payloads):
    """
    Injects SQLi payloads into the URL by modifying its parameters.

    Args:
        url (str): The original URL.
        payloads (list): List of SQLi payloads to inject.

    Returns:
        list: A list of new URLs with injected payloads.
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    if not query_params:
        return [url]  # Do nothing if no parameters

    modified_urls = []
    for param, values in query_params.items():
        for value in values:
            for payload in payloads:
                new_query_params = query_params.copy()
                new_query_params[param] = [value + payload]  # Inject payload directly
                new_query = "&".join(f"{k}={v[0]}" for k, v in new_query_params.items())
                new_url = parsed_url._replace(query=new_query).geturl()
                modified_urls.append(new_url)
    
    return modified_urls

def process_urls(input_file, payload_file, output_file):
    """
    Reads a file with URLs, injects SQLi payloads into parameters, and writes the modified URLs.

    Args:
        input_file (str): File containing the URLs.
        payload_file (str): File with SQLi payloads.
        output_file (str): Output file for the modified URLs.
    """
    if not os.path.exists(input_file):
        log.error(f"The input file '{input_file}' does not exist.")
        exit(1)

    payloads = load_payloads(payload_file)

    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f.readlines() if line.strip()]

    modified_urls = []
    for url in urls:
        log.info(f"Processing URL: {url}")
        new_urls = inject_sql_payload(url, payloads)
        modified_urls.extend(new_urls)

    with open(output_file, "w", encoding="utf-8") as f:
        for url in modified_urls:
            f.write(url + "\n")
            log.info(f"Modified URL: {url}")

    log.info(f"Modified URLs saved to: {output_file}")

def banner():
    """Displays the banner."""
    ascii_banner = r"""
  ____   _____  ____  _      _____               
 |  _ \ / ____|/ __ \| |    |_   _|    _     _   
 | |_) | (___ | |  | | |      | |    _| |_ _| |_ 
 |  _ < \___ \| |  | | |      | |   |_   _|_   _|
 | |_) |____) | |__| | |____ _| |_    |_|   |_|  
 |____/|_____/ \___\_\______|_____|              


                    By b3pwn3d
    """
    print(f"\033[1;34m{ascii_banner}\033[0m")

def test_sqli(url):
    """
    Makes a request to the URL and measures response time to detect Blind SQLi.

    Args:
        url (str): URL to test.

    Returns:
        str or None: Vulnerable URL if detected, else None.
    """
    headers = {"User-Agent": "SQLi Tester"}

    try:
        start_time = time.time()
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        response_time = time.time() - start_time

        if response_time >= DELAY_THRESHOLD:
            print(f"\033[92m[+] SQLi Found: {url} - Response Time: {response_time:.2f}s\033[0m")
            return url
        else:
            print(f"\033[91m[-] Not Vulnerable: {url} - Response Time: {response_time:.2f}s\033[0m")

    except requests.Timeout:
        print(f"\033[93m[!] Timeout (> {TIMEOUT}s): {url}\033[0m")

    except requests.RequestException as e:
        print(f"\033[91m[ERROR] {url}: {str(e)}\033[0m")

    return None

def process_file(file):
    """
    Reads a URL file, tests each URL, and saves vulnerable ones.

    Args:
        file (str): Path to the file.
    """
    print(f"\n\033[94m[INFO] Processing: {file}\033[0m")

    try:
        with open(file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]

        vulnerable_urls = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            results = executor.map(test_sqli, urls)

        vulnerable_urls = [url for url in results if url]

        if vulnerable_urls:
            with open("vulnerable_urls.txt", "a", encoding="utf-8") as f:
                for url in vulnerable_urls:
                    f.write(url + "\n")
            print(f"\033[92m[✔] {len(vulnerable_urls)} Vulnerable URLs saved to 'vulnerable_urls.txt'\033[0m")
        else:
            print("\033[91m[✗] No vulnerable URLs found in this file.\033[0m")
    except FileNotFoundError:
        print(f"\033[91m[ERROR] File '{file}' not found.\033[0m")

def second():
    """
    Prompts user for file paths and processes each one.
    """
    banner()
    files_input = input("\033[94m[INFO] Enter the path(s) of the URL file(s) (comma separated if multiple): \033[0m")
    files = [file.strip() for file in files_input.split(',')]

    for file in files:
        process_file(file)

def main():
    parser = argparse.ArgumentParser(description="Inject SQLi payloads into URL parameters")
    parser.add_argument("-i", "--input", help="Input file with URLs", required=True)
    parser.add_argument("-p", "--payloads", help="Input file with SQLi payloads", required=True)
    parser.add_argument("-o", "--output", help="Output file for modified URLs", required=True)
    
    args = parser.parse_args()

    process_urls(args.input, args.payloads, args.output)
    second()

if __name__ == "__main__":
    main()

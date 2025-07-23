# BSQLI++  Advanced Blind SQL Injection Tester
# BSQLI++ is an enhanced and more robust version of the original Blind SQL Injection testing tool developed by LostSec.
The original tool had two major limitations:

Freezing on timeouts: If a URL didn’t respond, the tool would hang indefinitely.

Naive payload injection: It appended all payloads to the end of the URL, without considering query parameters.

BSQLI++ solves these issues by introducing a smarter and more reliable testing approach:

Timeout handling: The tool never freezes when a URL is unreachable or too slow, thanks to a strict timeout mechanism.

Smarter payload injection: Payloads are injected directly into each query parameter of the URL, instead of just being appended at the end. This results in a more accurate and effective detection of vulnerabilities.

# Key Features
Advanced injection logic: Automatically parses URL parameters and injects payloads individually.

Time-based Blind SQLi detection: Identifies potential vulnerabilities based on server response delays.

Multi-threaded execution: Tests multiple URLs concurrently for faster scanning.

Robust error handling: Prevents freezing or getting stuck on slow/unreachable URLs.

Detailed logging: Generates a list of vulnerable URLs in vulnerable_urls.txt.

## Usage

python3 bsqli++.py -i target_urls.txt -p payloads.txt -o modified_urls.txt
## Arguments:

-i / --input: Path to the file containing target URLs.

-p / --payloads: Path to the file containing SQLi payloads.

-o / --output: Output file where the modified URLs (with payloads) will be saved.



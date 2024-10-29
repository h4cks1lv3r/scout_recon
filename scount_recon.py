
#!/usr/bin/env python3

import os
import sys
import shutil
import argparse
import subprocess
from datetime import datetime

VERSION = "1.0"
SCAN_DIR = None

def log(level, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        log("ERROR", f"Command failed: {command}")
        log("ERROR", str(e))

def check_requirements():
    tools = ["subfinder", "amass", "httpx", "waybackurls", "katana", "ffuf"]
    missing_tools = []

    for tool in tools:
        if not shutil.which(tool):
            missing_tools.append(tool)

    if missing_tools:
        log("ERROR", f"Missing required tools: {', '.join(missing_tools)}")
        log("ERROR", "Please install all required tools before running the script.")
        sys.exit(1)
    else:
        log("SUCCESS", "All required tools are available")

def setup_directories(domain):
    global SCAN_DIR
    base_dir = os.path.join(os.getcwd(), "scans", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    SCAN_DIR = os.path.join(base_dir, timestamp)

    # Create directory structure
    directories = [
        os.path.join(SCAN_DIR, d)
        for d in [
            "subdomains",
            "wayback_data",
            "crawled_urls",
            "content_discovery",
            "reports",
        ]
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def enumerate_subdomains(domain, aggressive_mode):
    log("INFO", "Starting subdomain enumeration...")
    subdomains_dir = os.path.join(SCAN_DIR, "subdomains")
    raw_subdomains = os.path.join(subdomains_dir, "raw_subdomains.txt")
    unique_subdomains = os.path.join(subdomains_dir, "unique_subdomains.txt")

    # Run subfinder
    os.system(f"subfinder -d {domain} > {raw_subdomains}")

    # Run amass
    if aggressive_mode:
        os.system(f"amass enum -d {domain} > {raw_subdomains}.amass")
    else:
        os.system(f"amass enum -passive -d {domain} > {raw_subdomains}.amass")

    # Combine amass results if they exist
    if os.path.exists(f"{raw_subdomains}.amass"):
        with open(f"{raw_subdomains}.amass", 'r') as amass_file:
            with open(raw_subdomains, 'a') as raw_file:
                raw_file.write(amass_file.read())

    # Remove duplicates and save to unique_subdomains.txt
    if os.path.isfile(raw_subdomains):
        with open(raw_subdomains) as raw, open(unique_subdomains, "w") as unique:
            unique_domains = set(raw.read().splitlines())
            unique.write("\n".join(sorted(unique_domains)))

        subdomains_count = len(unique_domains)
        log("SUCCESS", f"Found {subdomains_count} unique subdomains")
        log("SUCCESS", f"Results saved to {unique_subdomains}")
        return unique_subdomains
    else:
        log("WARN", "No subdomains found")
        return None

def probe_live_hosts(subdomains_file, aggressive_mode):
    if not subdomains_file or not os.path.isfile(subdomains_file):
        log("WARN", "No subdomains file for probing")
        return None

    log("INFO", "Probing for live hosts...")
    live_hosts_file = os.path.join(SCAN_DIR, "subdomains", "live_hosts.txt")

    if aggressive_mode:
        os.system(f"httpx -l {subdomains_file} -silent -t 100 -o {live_hosts_file}")
    else:
        os.system(f"httpx -l {subdomains_file} -silent -t 50 -o {live_hosts_file}")

    if os.path.isfile(live_hosts_file) and os.path.getsize(live_hosts_file) > 0:
        hosts_count = sum(1 for _ in open(live_hosts_file))
        log("SUCCESS", f"Found {hosts_count} live hosts")
        log("SUCCESS", f"Results saved to {live_hosts_file}")
        return live_hosts_file
    else:
        log("WARN", "No live hosts found")
        return None

def fetch_wayback_data(subdomains_file):
    if not subdomains_file or not os.path.isfile(subdomains_file):
        log("WARN", "No subdomains file for wayback data collection")
        return None

    log("INFO", "Fetching URLs from Wayback Machine...")
    wayback_dir = os.path.join(SCAN_DIR, "wayback_data")
    wayback_file = os.path.join(wayback_dir, "waybackurls.txt")

    with open(subdomains_file) as f:
        domains = f.read().splitlines()

    for domain in domains:
        os.system(f"waybackurls {domain} > {wayback_file}")

    if os.path.isfile(wayback_file) and os.path.getsize(wayback_file) > 0:
        urls_count = sum(1 for _ in open(wayback_file))
        log("SUCCESS", f"Found {urls_count} URLs in Wayback Machine")
        log("SUCCESS", f"Results saved to {wayback_file}")
        return wayback_file
    else:
        log("WARN", "No wayback URLs found")
        return None

def combine_urls(live_hosts_file, wayback_file):
    combined_urls = set()

    if live_hosts_file and os.path.isfile(live_hosts_file):
        with open(live_hosts_file) as f:
            combined_urls.update(f.read().splitlines())

    if wayback_file and os.path.isfile(wayback_file):
        with open(wayback_file) as f:
            combined_urls.update(f.read().splitlines())

    if not combined_urls:
        log("WARN", "No URLs to combine")
        return None

    combined_file = os.path.join(SCAN_DIR, "combined_urls.txt")
    with open(combined_file, "w") as f:
        f.write("\n".join(sorted(combined_urls)))

    log("SUCCESS", f"Combined URLs saved to {combined_file}")
    return combined_file

def crawl_urls(urls_file, aggressive_mode):
    if not os.path.isfile(urls_file) or os.path.getsize(urls_file) == 0:
        log("WARN", "No URLs to crawl")
        return

    if not shutil.which("katana"):
        log("WARN", "Katana not found, skipping crawling.")
        return

    log("INFO", "Crawling URLs with Katana... This may take some time.")
    crawled_dir = os.path.join(SCAN_DIR, "crawled_urls")
    os.makedirs(crawled_dir, exist_ok=True)
    katana_output_file = os.path.join(crawled_dir, "katana_output.txt")

    if aggressive_mode:
        katana_cmd = (
            f"katana -list {urls_file} -silent -timeout 20 -d 10 -c 100 -o {katana_output_file}"
        )
    else:
        katana_cmd = f"katana -list {urls_file} -silent -timeout 10 -d 2 -c 20 -o {katana_output_file}"

    run_command(katana_cmd)

    if os.path.isfile(katana_output_file) and os.path.getsize(katana_output_file) > 0:
        crawled_urls_count = sum(1 for _ in open(katana_output_file))
        log("SUCCESS", f"Crawled URLs found: {crawled_urls_count}")
        log("SUCCESS", f"Crawled URLs saved to {katana_output_file}")
    else:
        log("WARN", "No URLs crawled.")

def run_ffuf(urls_file, aggressive_mode, wordlist_dir):
    if not os.path.isfile(urls_file) or os.path.getsize(urls_file) == 0:
        log("WARN", "No URLs for content discovery")
        return

    if not shutil.which("ffuf"):
        log("WARN", "ffuf not found, skipping content discovery.")
        return

    log("INFO", "Running content discovery with ffuf...")
    ffuf_dir = os.path.join(SCAN_DIR, "content_discovery")
    os.makedirs(ffuf_dir, exist_ok=True)

    # Default wordlist paths
    if aggressive_mode:
        default_wordlist = "/usr/share/wordlists/dirb/big.txt"
    else:
        default_wordlist = "/usr/share/wordlists/dirb/common.txt"

    # Check if custom wordlist exists, otherwise use default
    if os.path.isfile(os.path.join(wordlist_dir, "directory-list-2.3-medium.txt")):
        wordlist = os.path.join(wordlist_dir, "directory-list-2.3-medium.txt")
    else:
        wordlist = default_wordlist
        log("INFO", f"Using default wordlist: {default_wordlist}")

    if not os.path.isfile(wordlist):
        log("ERROR", f"Wordlist not found at {wordlist}")
        return

    # Prepare URLs for ffuf
    with open(urls_file, "r") as f:
        urls = f.read().splitlines()

    # Run ffuf on each URL
    for url in urls:
        url_sanitized = url.replace("://", "_").replace("/", "_").replace(":", "_")
        output_file = os.path.join(ffuf_dir, f"{url_sanitized}_ffuf.txt")

        if aggressive_mode:
            ffuf_cmd = (
                f"ffuf -w {wordlist} -u {url}/FUZZ -t 100 -ac -o {output_file} -of csv -s"
            )
        else:
            ffuf_cmd = (
                f"ffuf -w {wordlist} -u {url}/FUZZ -t 20 -ac -o {output_file} -of csv -s"
            )

        run_command(ffuf_cmd)
        if os.path.isfile(output_file) and os.path.getsize(output_file) > 0:
            log("INFO", f"Content discovery results for {url} saved to {output_file}")
        else:
            log("WARN", f"No content discovered for {url}")

    log("SUCCESS", "Content discovery with ffuf completed.")

def generate_report():
    log("INFO", "Generating summary report...")
    report_file = os.path.join(SCAN_DIR, "reports", "summary_report.md")
    with open(report_file, "w") as report:
        report.write(f"# Reconnaissance Summary Report\n\n")
        report.write(f"**Scan Directory:** {SCAN_DIR}\n\n")

        # Subdomains
        subdomains_file = os.path.join(SCAN_DIR, "subdomains", "unique_subdomains.txt")
        subdomains_count = sum(1 for _ in open(subdomains_file)) if os.path.isfile(subdomains_file) else 0
        report.write(f"## Subdomain Enumeration\n")
        report.write(f"**Unique Subdomains Found:** {subdomains_count}\n\n")

        # Wayback Data
        wayback_file = os.path.join(SCAN_DIR, "wayback_data", "waybackurls.txt")
        wayback_count = sum(1 for _ in open(wayback_file)) if os.path.isfile(wayback_file) else 0
        report.write(f"## Wayback Machine Data\n")
        report.write(f"**URLs Found in Wayback Machine:** {wayback_count}\n\n")

        # Live Hosts
        live_hosts_file = os.path.join(SCAN_DIR, "subdomains", "live_hosts.txt")
        live_hosts_count = sum(1 for _ in open(live_hosts_file)) if os.path.isfile(live_hosts_file) else 0
        report.write(f"## Live Hosts\n")
        report.write(f"**Live Hosts Found:** {live_hosts_count}\n\n")

        # Crawled URLs
        katana_output_file = os.path.join(SCAN_DIR, "crawled_urls", "katana_output.txt")
        crawled_urls_count = sum(1 for _ in open(katana_output_file)) if os.path.isfile(katana_output_file) else 0
        report.write(f"## Crawled URLs\n")
        report.write(f"**Crawled URLs Found:** {crawled_urls_count}\n\n")

        # Content Discovery
        ffuf_dir = os.path.join(SCAN_DIR, "content_discovery")
        ffuf_files = [
            f for f in os.listdir(ffuf_dir) if os.path.isfile(os.path.join(ffuf_dir, f))
        ] if os.path.isdir(ffuf_dir) else []
        content_discovery_count = len(ffuf_files)
        report.write(f"## Content Discovery\n")
        report.write(f"**ffuf Scans Completed:** {content_discovery_count}\n\n")

    log("SUCCESS", f"Report generated: {report_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Scout Recon - A multi-tool reconnaissance automation script"
    )
    parser.add_argument("-d", "--domain", help="Target domain to scan", required=True)
    parser.add_argument(
        "-a",
        "--aggressive",
        help="Enable aggressive scanning (maximum depth and threads)",
        action="store_true",
    )
    parser.add_argument(
        "-w",
        "--wordlist-dir",
        help="Specify custom wordlist directory",
        default="/usr/share/wordlists",
    )
    parser.add_argument(
        "-v", "--version", help="Show version information", action="store_true"
    )

    args = parser.parse_args()

    if args.version:
        print(f"Scout Recon v{VERSION}")
        sys.exit(0)

    domain = args.domain.strip()
    aggressive_mode = args.aggressive
    wordlist_dir = args.wordlist_dir.strip()

    print("===========================")
    print(f"Scout Recon v{VERSION}")
    print("===========================")

    setup_directories(domain)
    log("INFO", f"Initialized scan for {domain}")
    log("INFO", f"Scan directory: {SCAN_DIR}")

    check_requirements()

    # Run all reconnaissance modules
    subdomains_file = enumerate_subdomains(domain, aggressive_mode
        subdomains_file = enumerate_subdomains(domain, aggressive_mode)  
    live_hosts_file = probe_live_hosts(subdomains_file, aggressive_mode)  
    wayback_file = fetch_wayback_data(subdomains_file)  
    combined_urls_file = combine_urls(live_hosts_file, wayback_file)  
    
    if combined_urls_file:  
        crawl_urls(combined_urls_file, aggressive_mode)  
        run_ffuf(combined_urls_file, aggressive_mode, wordlist_dir)  
    
    generate_report()  
    log("SUCCESS", "Reconnaissance completed!")  

if __name__ == "__main__":  
    main()

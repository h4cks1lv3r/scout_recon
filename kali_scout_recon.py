#!/usr/bin/env python3

import os
import sys
import shutil
import argparse
import subprocess
from datetime import datetime

VERSION = "1.1"
SCAN_DIR = None

CONFIG = {
    "aggressive": {"httpx_threads": 100, "katana_depth": 10},
    "default": {"httpx_threads": 50, "katana_depth": 2},
}

def log(level, message):
    levels = {
        "INFO": "\033[94mINFO\033[0m",
        "SUCCESS": "\033[92mSUCCESS\033[0m",
        "ERROR": "\033[91mERROR\033[0m",
        "WARN": "\033[93mWARN\033[0m",
    }
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{levels.get(level, level)}] {message}")

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        log("ERROR", f"Command failed: {command}")
        log("ERROR", str(e))

def check_requirements():
    tools = {
        "subfinder": "apt install subfinder",
        "amass": "apt install amass",
        "httpx": "apt install httpx",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "katana": "go install github.com/projectdiscovery/katana@latest",
        "ffuf": "apt install ffuf",
    }
    missing_tools = {tool: cmd for tool, cmd in tools.items() if not shutil.which(tool)}

    if missing_tools:
        for tool, cmd in missing_tools.items():
            log("ERROR", f"{tool} not found. Install with: {cmd}")
        sys.exit(1)
    else:
        log("SUCCESS", "All required tools are available")

def setup_directories(domain):
    global SCAN_DIR
    base_dir = os.path.join(os.getcwd(), "scans", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    SCAN_DIR = os.path.join(base_dir, timestamp)

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
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as e:
            log("ERROR", f"Failed to create directory {directory}: {str(e)}")
            sys.exit(1)

def read_lines(file_path):
    if os.path.isfile(file_path):
        with open(file_path, "r") as f:
            return f.read().splitlines()
    return []

def write_lines(file_path, lines):
    with open(file_path, "w") as f:
        f.write("\n".join(lines))

def enumerate_subdomains(domain, aggressive_mode):
    log("INFO", "Starting subdomain enumeration...")
    subdomains_dir = os.path.join(SCAN_DIR, "subdomains")
    raw_subdomains = os.path.join(subdomains_dir, "raw_subdomains.txt")
    unique_subdomains = os.path.join(subdomains_dir, "unique_subdomains.txt")

    run_command(f"subfinder -d {domain} -o {raw_subdomains}")
    if aggressive_mode:
        run_command(f"amass enum -d {domain} -o {raw_subdomains}.amass")
    else:
        run_command(f"amass enum -passive -d {domain} -o {raw_subdomains}.amass")

    if os.path.exists(f"{raw_subdomains}.amass"):
        write_lines(raw_subdomains, read_lines(raw_subdomains) + read_lines(f"{raw_subdomains}.amass"))

    unique_domains = sorted(set(read_lines(raw_subdomains)))
    write_lines(unique_subdomains, unique_domains)

    if unique_domains:
        log("SUCCESS", f"Found {len(unique_domains)} unique subdomains")
        log("SUCCESS", f"Results saved to {unique_subdomains}")
        return unique_subdomains
    else:
        log("WARN", "No subdomains found")
        return None

def probe_live_hosts(subdomains_file, aggressive_mode):
    if not subdomains_file:
        log("WARN", "No subdomains file for probing")
        return None

    log("INFO", "Probing for live hosts...")
    live_hosts_file = os.path.join(SCAN_DIR, "subdomains", "live_hosts.txt")
    threads = CONFIG["aggressive" if aggressive_mode else "default"]["httpx_threads"]
    run_command(f"httpx -l {subdomains_file} -silent -t {threads} -o {live_hosts_file}")

    if os.path.isfile(live_hosts_file) and os.path.getsize(live_hosts_file) > 0:
        hosts_count = len(read_lines(live_hosts_file))
        log("SUCCESS", f"Found {hosts_count} live hosts")
        log("SUCCESS", f"Results saved to {live_hosts_file}")
        return live_hosts_file
    else:
        log("WARN", "No live hosts found")
        return None

def fetch_wayback_data(subdomains_file):
    if not subdomains_file:
        log("WARN", "No subdomains file for wayback data collection")
        return None

    log("INFO", "Fetching URLs from Wayback Machine...")
    wayback_file = os.path.join(SCAN_DIR, "wayback_data", "waybackurls.txt")

    for domain in read_lines(subdomains_file):
        run_command(f"waybackurls {domain} >> {wayback_file}")

    if os.path.isfile(wayback_file) and os.path.getsize(wayback_file) > 0:
        urls_count = len(read_lines(wayback_file))
        log("SUCCESS", f"Found {urls_count} URLs in Wayback Machine")
        log("SUCCESS", f"Results saved to {wayback_file}")
        return wayback_file
    else:
        log("WARN", "No wayback URLs found")
        return None

def combine_urls(live_hosts_file, wayback_file):
    combined_urls = set(read_lines(live_hosts_file) + read_lines(wayback_file))

    if not combined_urls:
        log("WARN", "No URLs to combine")
        return None

    combined_file = os.path.join(SCAN_DIR, "combined_urls.txt")
    write_lines(combined_file, sorted(combined_urls))
    log("SUCCESS", f"Combined URLs saved to {combined_file}")
    return combined_file

def generate_report():
    log("INFO", "Generating summary report...")
    report_file = os.path.join(SCAN_DIR, "reports", "summary_report.md")
    with open(report_file, "w") as report:
        report.write(f"# Reconnaissance Summary Report\n\n")
        report.write(f"**Scan Directory:** {SCAN_DIR}\n\n")
        subdomains_file = os.path.join(SCAN_DIR, "subdomains", "unique_subdomains.txt")
        subdomains_count = len(read_lines(subdomains_file)) if os.path.isfile(subdomains_file) else 0
        report.write(f"## Subdomain Enumeration\n**Unique Subdomains Found:** {subdomains_count}\n\n")
        wayback_file = os.path.join(SCAN_DIR, "wayback_data", "waybackurls.txt")
        wayback_count = len(read_lines(wayback_file)) if os.path.isfile(wayback_file) else 0
        report.write(f"## Wayback Machine Data\n**URLs Found in Wayback Machine:** {wayback_count}\n\n")
        live_hosts_file = os.path.join(SCAN_DIR, "subdomains", "live_hosts.txt")
        live_hosts_count = len(read_lines(live_hosts_file)) if os.path.isfile(live_hosts_file) else 0
        report.write(f"## Live Hosts\n**Live Hosts Found:** {live_hosts_count}\n\n")

    log("SUCCESS", f"Report generated: {report_file}")

def main():
    parser = argparse.ArgumentParser(description="Scout Recon - A multi-tool reconnaissance automation script")
    parser.add_argument("-d", "--domain", help="Target domain to scan", required=True)
    parser.add_argument("-a", "--aggressive", help="Enable aggressive scanning", action="store_true")
    args = parser.parse_args()

    domain = args.domain.strip()
    aggressive_mode = args.aggressive

    print(f"Scout Recon v{VERSION}")
    setup_directories(domain)
    log("INFO", f"Initialized scan for {domain}")
    log("INFO", f"Scan directory: {SCAN_DIR}")

    check_requirements()

    subdomains_file = enumerate_subdomains(domain, aggressive_mode)
    live_hosts_file = probe_live_hosts(subdomains_file, aggressive_mode)
    wayback_file = fetch_wayback_data(subdomains_file)
    combined_urls_file = combine_urls(live_hosts_file, wayback_file)

    generate_report()
    log("SUCCESS", "Reconnaissance completed!")

if __name__ == "__main__":
    main()

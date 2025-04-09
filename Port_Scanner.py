import shodan
import json
import argparse
import socket
import threading
from datetime import datetime
import os
from dotenv import load_dotenv
from colorama import Fore, Style, init

# Load .env variables
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# Initialize colorama
init(autoreset=True)

open_ports = []
lock = threading.Lock()

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def ensure_results_folder():
    if not os.path.exists("results"):
        os.makedirs("results")

def scan_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = grab_banner(ip, port)
        with lock:
            open_ports.append((port, banner))
            print(f"{Fore.GREEN}[+] Port {port} is open {Fore.YELLOW}| Banner: {banner or 'No banner'}{Style.RESET_ALL}")
        s.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

def run_scanner(target, port_range):
    try:
        start_port, end_port = map(int, port_range.split('-'))
    except ValueError:
        print(f"{Fore.RED}[-] Invalid port range format. Use format like 20-80.{Style.RESET_ALL}")
        return target


    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\n{Fore.CYAN}[*] Starting scan on {target} from port {start_port} to {end_port}...\n")

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n{Fore.CYAN}[*] Total open ports found: {len(open_ports)}{Style.RESET_ALL}")
    return target

def verify_shodan_key(api_key):
    try:
        api = shodan.Shodan(api_key)
        api.info()
        return True
    except shodan.APIError as e:
        print(f"{Fore.RED}[!] Shodan API error: {e}{Style.RESET_ALL}")
        return False

def get_shodan_info(api_key, ip):
    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)

        print(f"\n{Fore.MAGENTA}[SHODAN DATA] for {ip}:{Style.RESET_ALL}")
        print(f"IP: {host['ip_str']}")
        print(f"Organization: {host.get('org', 'N/A')}")
        print(f"Operating System: {host.get('os', 'N/A')}")
        print(f"Location: {host.get('city', 'N/A')}, {host.get('country_name', 'N/A')}")
        print(f"Hostnames: {', '.join(host.get('hostnames', [])) or 'N/A'}")
        print(f"Ports: {host.get('ports', 'N/A')}")
        print(f"Vulnerabilities: {host.get('vulns', 'None')}")
    except shodan.APIError as e:
        print(f"{Fore.RED}[!] Shodan API error: {e}{Style.RESET_ALL}")

def save_results_txt(target, prefix):
    ensure_results_folder()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"results/{prefix}_scan_log_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write(f"Scan results for {target} on {datetime.now()}\n")
        f.write("-" * 50 + "\n")
        for port, banner in sorted(open_ports):
            f.write(f"Port {port} open | Banner: {banner or 'N/A'}\n")
    print(f"{Fore.GREEN}[✓] Scan log saved to: {Fore.YELLOW}{filename}")

def save_results_json(target, prefix):
    ensure_results_folder()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"results/{prefix}_scan_results_{timestamp}.json"

    result_data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "open_ports": [{"port": port, "banner": banner or "N/A"} for port, banner in sorted(open_ports)]
    }

    with open(filename, "w") as json_file:
        json.dump(result_data, json_file, indent=4)
    print(f"{Fore.GREEN}[✓] JSON results saved to: {Fore.YELLOW}{filename}")

def parse_args():
    parser = argparse.ArgumentParser(description="🔥 Python Port Scanner with Banner Grabbing + Shodan Integration")
    parser.add_argument("--target", "-t", required=True, help="Target IP address or domain")
    parser.add_argument("--ports", "-p", required=True, help="Port range to scan (e.g., 20-80)")
    parser.add_argument("--json", action="store_true", help="Save results in JSON format")
    parser.add_argument("--shodan", action="store_true", help="Use Shodan API to fetch additional host info")
    parser.add_argument("--output", help="Custom filename prefix (default: 'scan')", default="scan")
    return parser.parse_args()

# Final execution
if __name__ == "__main__":
    args = parse_args()
    scanned_target = run_scanner(args.target, args.ports)

    save_results_txt(scanned_target, args.output)
    if args.json:
        save_results_json(scanned_target, args.output)

    if args.shodan:
        if SHODAN_API_KEY and verify_shodan_key(SHODAN_API_KEY):
            get_shodan_info(SHODAN_API_KEY, args.target)
        else:
            print(f"{Fore.YELLOW}[!] Shodan key missing or invalid. Skipping Shodan lookup.{Style.RESET_ALL}")

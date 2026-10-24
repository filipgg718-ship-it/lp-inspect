#!/usr/bin/env python3
"""L/P INSPECT — lightweight, authorized network inspection toolkit."""
import argparse
import concurrent.futures
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
from datetime import datetime

BANNER = r"""
 _      /|  INSPECT
| |    / |  NETWORK INTELLIGENCE

┌────────────────────────────────────────────┐
│  L/P INSPECT  //  NETWORK AUDIT            │
└────────────────────────────────────────────┘
 HOST DISCOVERY • SERVICE CHECKS • OS HINTS
 AUTHORIZED SECURITY TESTING ONLY
"""

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
                 3306, 3389, 5432, 5900, 8080, 8443]

def tcp_check(host, port, timeout):
    """Attempt a TCP connection; does not exploit or authenticate to the service."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((str(host), port))
            if result == 0:
                service = socket.getservbyport(port, "tcp") if port < 1024 else "unknown"
                return {"port": port, "state": "open", "service_hint": service}
    except (OSError, OverflowError):
        pass
    return None

def scan_host(host, ports, timeout, workers):
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(tcp_check, host, port, timeout) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    found.sort(key=lambda item: item["port"])
    return {"ip": str(host), "open_ports": found, "reachable": bool(found)}

def run_nmap(host, timeout=20):
    """Optional, non-exploitative Nmap OS/service fingerprinting."""
    nmap = shutil.which("nmap")
    if not nmap:
        return {"available": False, "note": "Nmap not installed; OS fingerprint unavailable."}
    try:
        # -sT uses TCP connect scans; -sV probes service versions; -O may require elevated privileges.
        # No NSE scripts or exploit checks are run.
        proc = subprocess.run(
            [nmap, "-sT", "-sV", "-O", "--osscan-guess", "--host-timeout",
             f"{timeout}s", str(host)],
            capture_output=True, text=True, timeout=timeout + 5, check=False
        )
        return {"available": True, "returncode": proc.returncode,
                "output": proc.stdout[-12000:], "errors": proc.stderr[-2000:]}
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": True, "error": str(exc)}

def main():
    parser = argparse.ArgumentParser(
        description="L/P INSPECT — authorized network inventory and basic service inspection."
    )
    parser.add_argument("target", help="IPv4 address or CIDR range, e.g. 192.168.1.10 or 192.168.1.0/24")
    parser.add_argument("--ports", help="Comma-separated TCP ports (default: common ports)")
    parser.add_argument("--timeout", type=float, default=0.5, help="TCP timeout in seconds (default: 0.5)")
    parser.add_argument("--workers", type=int, default=32, help="Concurrent checks (default: 32; max: 128)")
    parser.add_argument("--nmap-os", action="store_true", help="Run optional Nmap service/OS fingerprinting per discovered host")
    parser.add_argument("--json", dest="json_path", help="Save results as JSON")
    args = parser.parse_args()

    print(BANNER)
    try:
        network = ipaddress.ip_network(args.target, strict=False)
        if network.version != 4:
            parser.error("This starter version supports IPv4 targets only.")
        if network.num_addresses > 256:
            parser.error("Range is larger than 256 addresses. Use a smaller authorized subnet.")
        ports = [int(p.strip()) for p in args.ports.split(",")] if args.ports else COMMON_PORTS
        if not ports or any(p < 1 or p > 65535 for p in ports):
            parser.error("Ports must be between 1 and 65535.")
        if args.timeout <= 0 or not (1 <= args.workers <= 128):
            parser.error("Timeout must be positive and workers must be between 1 and 128.")
    except ValueError as exc:
        parser.error(str(exc))

    print(f"Target: {network}")
    print("Only scan networks/devices you own or have explicit permission to test.")
    answer = input("Do you have authorization to scan this target? Type YES to continue: ").strip()
    if answer != "YES":
        print("Cancelled.")
        return 1

    hosts = list(network.hosts()) if network.prefixlen < 31 else list(network)
    results = []
    print(f"\nChecking {len(hosts)} host(s), TCP ports: {','.join(map(str, ports))}\n")
    for host in hosts:
        result = scan_host(host, ports, args.timeout, min(args.workers, 128))
        if result["reachable"]:
            print(f"[+] {host}")
            for item in result["open_ports"]:
                print(f"    {item['port']:>5}/tcp open  ({item['service_hint']})")
            if args.nmap_os:
                result["nmap"] = run_nmap(host)
                if result["nmap"].get("available") and result["nmap"].get("output"):
                    print("    Nmap fingerprint saved in report.")
                elif result["nmap"].get("note"):
                    print(f"    {result['nmap']['note']}")
            results.append(result)
    report = {
        "tool": "L/P INSPECT",
        "timestamp": datetime.now().astimezone().isoformat(),
        "target": str(network),
        "method": "TCP connect checks; no exploitation or authentication attempts",
        "hosts_with_open_ports": results,
    }
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"\nReport written to {args.json_path}")
    print(f"\nFinished. Hosts with open checked ports: {len(results)}")
    print("Note: no open ports does not prove a host is offline.")
    return 0

if __name__ == "__main__":
    sys.exit(main())

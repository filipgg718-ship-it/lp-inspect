# L/P INSPECT

**Lightweight network inventory and service inspection for Termux, Linux, and Windows.**

L/P INSPECT is a small Python CLI for authorized network audits. It checks selected TCP ports, reports open services, optionally invokes Nmap for service/OS fingerprinting, and exports JSON reports.

> Use only on devices and networks you own or have explicit permission to test. This tool does not exploit devices, bypass authentication, or attempt takeover.

## Features

- IPv4 host/range input (up to 256 addresses per run)
- TCP connect checks for common ports or a custom port list
- Optional Nmap service and OS fingerprinting
- JSON report export
- Python standard library for the basic scan; no pip packages required
- Optional Wireshark/TShark workflow described below

## Requirements

- Python 3.9+
- Optional: Nmap for OS/service fingerprinting
- Optional: Wireshark or `tshark` for packet capture and analysis

##Kali(debian)
sudo apt update
sudo apt install -y git python3 nmap tshark

git clone https://github.com/filipgg718-ship-it/lp-inspect.git
cd lp-inspect

avaliable options:
python3 lp_inspect.py --help
Run it on your local network
ip -br addr
ip route



## Termux quick start

Install Termux from a trusted source such as F-Droid or the official Termux GitHub releases, then:

```bash
pkg update
pkg install python nmap
```

Download or clone this repository:

```bash
git clone https://github.com/YOUR-USERNAME/lp-inspect.git
cd lp-inspect
python lp_inspect.py --help
```

Run against your own LAN subnet (replace the example with your actual authorized subnet):

```bash
python lp_inspect.py 192.168.1.0/24
```

Scan custom ports and save a report:

```bash
python lp_inspect.py 192.168.1.0/24 --ports 22,53,80,443,445,3389 --json report.json
```

Optional Nmap fingerprints:

```bash
python lp_inspect.py 192.168.1.25 --nmap-os --json host-report.json
```

OS detection can require elevated privileges and may not work from every Android/Termux environment. Android restrictions also limit packet capture and low-level network access on unrooted devices.

## Windows

Install Python 3.9+ and optionally Nmap, then run from PowerShell:

```powershell
py .\lp_inspect.py 192.168.1.0/24
```

## Wireshark / TShark

L/P INSPECT does not bundle Wireshark. Wireshark is a separate packet analyzer and its capture drivers/permissions are platform-specific. On a desktop where TShark is installed, you can inspect a capture file with:

```bash
tshark -r capture.pcapng
tshark -r capture.pcapng -Y "dns || tcp.flags.syn == 1"
```

On Android/Termux, live capture may be unavailable without root or a compatible capture method. You can analyze a `.pcap`/`.pcapng` file copied from a system where capture is permitted.

## Scope and limitations

- This is a basic inventory tool, not a full vulnerability scanner.
- Open ports and version strings alone do not prove a vulnerability.
- Nmap output is a fingerprint estimate, not a guarantee of the device's OS.
- The script does not perform exploit checks, credential attacks, stealth, persistence, or remote command execution.
- A timeout or no open ports does not prove a device is offline.

## Roadmap

- [ ] Terminal color theme and interactive menu
- [ ] MAC/vendor lookup where platform support permits
- [ ] CVE matching against a maintained vulnerability feed
- [ ] HTML report output
- [ ] Optional TShark integration for existing capture files

## License

MIT — see `LICENSE`.

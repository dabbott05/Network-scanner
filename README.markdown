# Network Scanner

A Python-based network scanner that monitors a local network for devices using ARP requests. It detects new devices by comparing their IP and MAC addresses against a stored list, logging results to a file and console. Supports configurable scan intervals and subnets, with persistent device logging via JSON.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/dabbott05/network-scanner.git
   cd network-scanner
   ```
2. Install dependencies:
   ```bash
   pip install scapy netifaces
   ```
3. For Windows, install [npcap](https://nmap.org/npcap/).

## Usage

Run with `sudo` (Linux/macOS) or as Administrator (Windows) due to raw socket requirements.

- Default scan (auto-detects subnet, scans every 5 minutes):
  ```bash
  sudo python network_scanner.py
  ```
- Custom subnet:
  ```bash
  sudo python network_scanner.py --subnet 192.168.1.0/24
  ```
- Custom interval (e.g., every 60 seconds):
  ```bash
  sudo python network_scanner.py --interval 60
  ```

Logs are saved to `network_scanner.log` and shown in the console. New devices are stored in `known_devices.json`.

## Requirements

- Python 3.6+
- `scapy` (`pip install scapy`)
- `netifaces` (`pip install netifaces`)
- Root/admin privileges

## Notes

- **Permissions**: Requires `sudo` or Administrator rights for ARP scanning.
- **Ethics**: Only scan networks you own or have permission to scan.
- **Logs**: View `network_scanner.log` for scan details and new device alerts.

## TODO

- **Detect wether the devices are ethernet or wireless**
- **Name the devices for better readability**

## License

MIT License

import scapy.all as scapy
import netifaces
import json
import argparse
import time
import logging
import sys
import os

def setup_logging():
    # set up the logging configuration
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("network_scanner.log"), # network_scanner.log is the log file
            logging.StreamHandler(sys.stdout)
        ]
    )

def get_network_info():
    # get the IP and subnet of the network
    try:
        # get default interface
        interfaces = netifaces.interfaces()
        for iface in interfaces: # loop through the interfaces (eth0, wlan0, etc)
            addrs = netifaces.ifaddresses(iface) #get addresses
            if netifaces.AF_INET in addrs: # check for IPv4
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get("addr") # get IP
                    netmask = addr.get("netmask") # get subnet mask
                    if ip and netmask and not ip.startswith("127."): # No loopback
                        return ip, netmask
        raise Exception("No valid network interface found")
    except Exception as e:
        logging.error(f"Error getting network info: {e}")
        sys.exit(1)

def calculate_subnet(ip, netmask):
    # calculates the subnet in CIDR notation
    try:
        from ipaddress import ip_network, ip_address
        ip = ip_address(ip) # create IP object
        mask = sum(bin(int(x)).count("1") for x in netmask.split(".")) # calculate CIDR mask
        network = ip_network(f"{ip}/{mask}", strict=False) #create network object
        return str(network)
    except Exception as e:
        logging.error(f"Error calculating subnet: {e}")
        sys.exit(1)

def scan_network(subnet):
    # use ARP requests to scan the network for devices
    try:
        arp_request = scapy.ARP(pdst=subnet) #OSI layer 3
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # OSI layer 2
        arp_request_broadcast = broadcast / arp_request # combines the ethernet frame and ARP request into a single packet
        
        # send ARP request and get responses
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        devices = [] # where we store found devices
        for sent, received in answered_list:
            devices.append({"ip": received.psrc, "mac": received.hwsrc}) # psrc is the IP address, hwsrc is the MAC address
        return devices
    except PermissionError:
        logging.error("Permission denied: Run this script with sudo/admin privileges")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error scanning network: {e}")
        return []

def load_known_devices(filename="known_devices.json"):
    # load known devices from JSON file
    try:
        if os.path.exists(filename):
            with open(filename, "r") as f:
                return json.load(f)
        return []
    except Exception as e:
        logging.error(f"Error loading known devices: {e}")
        return []

def save_known_devices(devices, filename="known_devices.json"):
    # saves known devices to JSON file
    try:
        with open(filename, "w") as f:
            json.dump(devices, f, indent=4) #indent=4 for prettier prints
    except Exception as e:
        logging.error(f"Error saving known devices: {e}")

def detect_new_devices(current_devices, known_devices):
    # compares current devices to the known devices to single them out
    known_set = {(d["ip"], d["mac"]) for d in known_devices}
    current_set = {(d["ip"], d["mac"]) for d in current_devices}
    new_devices = [d for d in current_devices if (d["ip"], d["mac"]) not in known_set]
    return new_devices

def parse_args():
    # parse command line arguments
    parser = argparse.ArgumentParser(description="Network scanner to detect new devices")
    parser.add_argument("--interval", type=int, default=300, help="Scan interval in seconds (default: 300)")
    parser.add_argument("--subnet", type=str, help="Subnet to scan (e.g., 192.168.1.0/24)")
    return parser.parse_args()

def main():
    setup_logging()
    args = parse_args()
    
    # get network info if subnet not provided
    subnet = args.subnet
    if not subnet:
        ip, netmask = get_network_info()
        subnet = calculate_subnet(ip, netmask)
    
    logging.info(f"Starting network scanner on subnet {subnet} with interval {args.interval} seconds")
    
    # load known devices
    known_devices = load_known_devices()
    
    while True:
        try:
            # scan the network
            current_devices = scan_network(subnet)
            logging.info(f"Found {len(current_devices)} devices")
            
            # detect new devices
            new_devices = detect_new_devices(current_devices, known_devices)
            if new_devices:
                logging.info(f"New devices detected: {len(new_devices)}")
                for device in new_devices:
                    logging.info(f"New device: IP={device['ip']}, MAC={device['mac']}")
                    known_devices.append(device)
                save_known_devices(known_devices)

            time.sleep(args.interval)
        except KeyboardInterrupt:
            logging.info("Shutting down...")
            break

if __name__ == "__main__":
    main()
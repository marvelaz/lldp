import paramiko
import time
import json
from typing import List, Dict

def get_device_hostname(host: str, username: str, password: str, port: int = 22) -> str:
    """
    Connect to FortiSwitch via SSH and retrieve the device hostname
    Returns the actual hostname of the device
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the device
        ssh.connect(host, port=port, username=username, password=password)

        # Get an interactive shell
        shell = ssh.invoke_shell()

        # Send command to get system status (which includes hostname)
        shell.send('get system status\n')
        time.sleep(2)  # Wait for command to execute

        # Read the output
        output = ""
        while shell.recv_ready():
            output += shell.recv(4096).decode('utf-8')
            time.sleep(0.5)

        # Parse hostname from output
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('Hostname:'):
                hostname = line.split(':', 1)[1].strip()
                return hostname

        # Fallback to IP-based name if hostname not found
        return f"device-{host.replace('.', '-')}"

    except Exception as e:
        print(f"Failed to get hostname from {host}: {e}")
        return f"device-{host.replace('.', '-')}"
    finally:
        ssh.close()

def get_lldp_neighbors(host: str, username: str, password: str, port: int = 22) -> List[Dict]:
    """
    Connect to FortiSwitch via SSH and retrieve LLDP neighbors using the supported command
    Returns a list of dictionaries with neighbor info (filtered to exclude invalid entries)
    """
    # Initialize SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    neighbors = []

    try:
        # Connect to the device
        ssh.connect(host, port=port, username=username, password=password)

        # Get an interactive shell
        shell = ssh.invoke_shell()

        # Send command to get LLDP neighbors
        shell.send('get switch lldp neighbors-summary\n')
        time.sleep(2)  # Wait for command to execute

        # Read the output
        output = ""
        while shell.recv_ready():
            output += shell.recv(4096).decode('utf-8')
            time.sleep(0.5)

        # Parse the output
        data_started = False
        for line in output.split('\n'):
            line = line.strip()

            # Skip empty lines and header lines
            if not line:
                continue

            # Detect when the actual data starts (after the header line with "Portname")
            if line.startswith('Portname') or line.startswith('____'):
                data_started = True
                continue

            # Skip lines before data starts and after the command prompt
            if not data_started or line.startswith('US') and line.endswith('#'):
                continue

            # Split line into parts, handling multiple spaces
            parts = [p for p in line.split(' ') if p]

            # Valid neighbor entry has at least 7 parts and the port starts with "port"
            if len(parts) >= 7 and parts[0].startswith('port'):
                # Filter out invalid entries where neighbor_device is '-'
                if parts[2] == '-':
                    continue

                neighbor = {
                    'local_port': parts[0],
                    'status': parts[1],
                    'neighbor_device': parts[2],
                    'ttl': parts[3],
                    'capability': parts[4],
                    'med_type': parts[5],
                    'neighbor_port': parts[6]
                }
                neighbors.append(neighbor)

        return neighbors

    finally:
        ssh.close()

def save_to_json(data: List[Dict], filename: str = 'lldp_neighbors.json'):
    """Save LLDP neighbor data to JSON file"""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

# Example usage
if __name__ == "__main__":
    switch_ip = "192.168.1.1"
    username = "admin"
    password = "yourpassword"

    # Get hostname first
    hostname = get_device_hostname(switch_ip, username, password)
    print(f"Device hostname: {hostname}")

    lldp_neighbors = get_lldp_neighbors(switch_ip, username, password)

    # Save to JSON file
    save_to_json(lldp_neighbors)

    print(f"Found {len(lldp_neighbors)} valid LLDP neighbors. Saved to lldp_neighbors.json")
    print("Sample neighbor:", json.dumps(lldp_neighbors[0], indent=2) if lldp_neighbors else "No neighbors found")

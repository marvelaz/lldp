import requests
import json
import logging
import concurrent.futures
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

class NetBoxAPI:
    """Optimized NetBox API client with concurrent fetching capabilities"""

    def __init__(self, base_url: str, token: str, site_filter: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.site_filter = site_filter

        # Create optimized session with connection pooling and retries
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        self.session.verify = False

        # Add retry strategy and connection pooling
        retry_strategy = Retry(total=3, backoff_factor=0.3)
        adapter = HTTPAdapter(
            max_retries=retry_strategy, 
            pool_connections=10, 
            pool_maxsize=10
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make a request to NetBox API"""
        url = urljoin(f"{self.base_url}/", f"api/{endpoint.lstrip('/')}")

        # Add site filter to params if specified
        if params is None:
            params = {}

        if self.site_filter and 'site' not in params:
            params['site'] = self.site_filter

        try:
            logger.debug(f"NetBox API request: {url} with params: {params}")
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"NetBox API request failed: {e}")
            raise

    def _fetch_page(self, endpoint: str, offset: int, limit: int = 50, 
                   extra_params: Optional[Dict] = None) -> Dict:
        """Fetch a single page of results"""
        params = {
            "offset": offset,
            "limit": limit,
        }

        # Add extra parameters (like filters)
        if extra_params:
            params.update(extra_params)

        # Add site filter if specified
        if self.site_filter and 'site' not in params:
            params['site'] = self.site_filter

        return self._make_request(endpoint, params)

    def get_all_pages_concurrent(self, endpoint: str, params: Optional[Dict] = None, 
                               max_workers: int = 5, limit: int = 50) -> List[Dict]:
        """
        Fetch all pages concurrently for maximum efficiency

        Args:
            endpoint: API endpoint to fetch from
            params: Additional parameters for filtering
            max_workers: Number of concurrent threads
            limit: Items per page

        Returns:
            List of all results from all pages
        """
        params = params or {}

        # Get total count first
        first_response = self._fetch_page(endpoint, 0, 1, params)
        total_count = first_response["count"]

        if total_count == 0:
            return []

        # Generate all offsets for concurrent fetching
        offsets = list(range(0, total_count, limit))
        all_results = []

        # Use ThreadPoolExecutor for concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all page requests
            futures = [
                executor.submit(self._fetch_page, endpoint, offset, limit, params) 
                for offset in offsets
            ]

            # Collect results as they complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    data = future.result()
                    all_results.extend(data.get("results", []))
                except Exception as e:
                    logger.error(f"Error fetching page: {e}")
                    continue

        logger.info(f"Fetched {len(all_results)} items from {endpoint} using {len(offsets)} concurrent requests")
        return all_results

    def get_all_pages(self, endpoint: str, params: Optional[Dict] = None) -> List[Dict]:
        """
        Fetch all pages - uses concurrent method for better performance
        Kept for backward compatibility
        """
        return self.get_all_pages_concurrent(endpoint, params)

def get_device_hostname_from_fortinet(host: str, username: str, password: str, port: int = 22) -> str:
    """
    Get the actual hostname from a Fortinet device using SSH
    This is imported from python_lldp_neigh.py functionality
    """
    import paramiko
    import time

    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to device
        ssh.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False
        )

        # Create shell session
        shell = ssh.invoke_shell()
        time.sleep(1)

        # Clear any initial output
        shell.recv(1024)

        # Send command to get hostname
        shell.send('get system status\n')
        time.sleep(2)

        # Read output
        output = shell.recv(4096).decode('utf-8')

        # Parse hostname from output
        for line in output.split('\n'):
            if 'Hostname:' in line:
                hostname = line.split('Hostname:')[1].strip()
                logger.debug(f"Retrieved hostname '{hostname}' from device {host}")
                ssh.close()
                return hostname

        # If hostname not found in expected format, try alternative
        for line in output.split('\n'):
            if line.strip() and not line.startswith('get ') and not line.startswith('#'):
                # Sometimes the hostname appears in the prompt
                if '#' in line:
                    potential_hostname = line.split('#')[0].strip()
                    if potential_hostname and len(potential_hostname) > 0:
                        logger.debug(f"Retrieved hostname '{potential_hostname}' from prompt for device {host}")
                        ssh.close()
                        return potential_hostname

        ssh.close()

        # Fallback: use IP-based hostname
        fallback_hostname = f'device-{host.replace(".", "-")}'
        logger.warning(f"Could not parse hostname from device {host}, using fallback: {fallback_hostname}")
        return fallback_hostname

    except Exception as e:
        logger.error(f"Failed to get hostname from device {host}: {e}")
        # Fallback: use IP-based hostname
        fallback_hostname = f'device-{host.replace(".", "-")}'
        logger.warning(f"Using fallback hostname for {host}: {fallback_hostname}")
        return fallback_hostname

def get_allowed_hostnames_from_config(device_config_string: str, username: str, password: str, port: int = 22) -> Set[str]:
    """Get actual device hostnames from configuration string by querying each device"""
    hostnames = set()

    if not device_config_string:
        logger.warning("No device configuration provided")
        return hostnames

    device_ips = [ip.strip() for ip in device_config_string.split(',') if ip.strip()]
    logger.info(f"Resolving hostnames for {len(device_ips)} devices...")

    for ip in device_ips:
        try:
            hostname = get_device_hostname_from_fortinet(ip, username, password, port)
            hostnames.add(hostname)
            logger.info(f"Device {ip} -> hostname: {hostname}")
        except Exception as e:
            logger.error(f"Failed to resolve hostname for {ip}: {e}")
            # Add IP-based fallback
            fallback = f'device-{ip.replace(".", "-")}'
            hostnames.add(fallback)
            logger.warning(f"Using fallback hostname for {ip}: {fallback}")

    logger.info(f"Resolved {len(hostnames)} device hostnames: {hostnames}")
    return hostnames

def filter_cables_efficiently(cables: List[Dict], allowed_devices: Optional[Set[str]] = None) -> List[Dict]:
    """
    Efficiently filter cables with optimized logic from the second script

    Args:
        cables: List of cable dictionaries from NetBox API
        allowed_devices: Set of device hostnames to filter by (optional)

    Returns:
        Filtered list of cables
    """
    filtered_cables = []

    for cable in cables:
        try:
            # Filter 1: Skip cables with empty or excluded types
            cable_type = cable.get("type", "")
            if not cable_type or cable_type in ("console", "power"):
                continue

            # Filter 2: Only connected status (server-side filtering preferred)
            status = cable.get('status', {})
            if isinstance(status, dict):
                status_label = status.get('label', '').lower()
            else:
                status_label = str(status).lower()

            if status_label != 'connected':
                continue

            # Filter 3: Device filtering if specified
            if allowed_devices:
                cable_involves_our_devices = False

                # Check A terminations
                a_terminations = cable.get('a_terminations', [])
                for a_term in a_terminations:
                    device_info = a_term.get('object', {}).get('device', {})
                    if device_info:
                        device_name = device_info.get('name', '')
                        if device_name in allowed_devices:
                            cable_involves_our_devices = True
                            break

                # Check B terminations if not found in A
                if not cable_involves_our_devices:
                    b_terminations = cable.get('b_terminations', [])
                    for b_term in b_terminations:
                        device_info = b_term.get('object', {}).get('device', {})
                        if device_info:
                            device_name = device_info.get('name', '')
                            if device_name in allowed_devices:
                                cable_involves_our_devices = True
                                break

                if not cable_involves_our_devices:
                    continue

            # Cable passed all filters
            filtered_cables.append(cable)

        except Exception as e:
            logger.warning(f"Error filtering cable {cable.get('id', 'unknown')}: {e}")
            continue

    logger.info(f"Filtered {len(cables)} cables down to {len(filtered_cables)} relevant cables")
    return filtered_cables

def get_netbox_sites(netbox_url: str, netbox_token: str) -> List[Dict]:
    """Fetch all sites from NetBox using concurrent requests"""
    if not netbox_url or not netbox_token:
        logger.warning("NetBox URL or token not configured")
        return []

    try:
        api = NetBoxAPI(netbox_url, netbox_token)
        sites = api.get_all_pages_concurrent('dcim/sites/')
        logger.info(f"Fetched {len(sites)} sites from NetBox")
        return sites
    except Exception as e:
        logger.error(f"Failed to fetch sites from NetBox: {e}")
        return []

def get_netbox_devices(netbox_url: str, netbox_token: str, site_filter: Optional[str] = None) -> List[Dict]:
    """Fetch devices from NetBox using concurrent requests"""
    if not netbox_url or not netbox_token:
        logger.warning("NetBox URL or token not configured")
        return []

    try:
        api = NetBoxAPI(netbox_url, netbox_token, site_filter)
        devices = api.get_all_pages_concurrent('dcim/devices/')

        if site_filter:
            logger.info(f"Fetched {len(devices)} devices from NetBox for site '{site_filter}'")
        else:
            logger.info(f"Fetched {len(devices)} devices from NetBox (all sites)")
        return devices
    except Exception as e:
        logger.error(f"Failed to fetch devices from NetBox: {e}")
        return []

def get_netbox_cables(netbox_url: str, netbox_token: str, site_filter: Optional[str] = None, 
                     allowed_devices: Optional[Set[str]] = None) -> List[Dict]:
    """
    Fetch cables from NetBox with optimized concurrent requests and efficient filtering

    Args:
        netbox_url: NetBox base URL
        netbox_token: NetBox API token
        site_filter: Site name or slug to filter by (optional)
        allowed_devices: Set of device hostnames to filter by (optional)

    Returns:
        List of filtered cable dictionaries
    """
    if not netbox_url or not netbox_token:
        logger.warning("NetBox URL or token not configured")
        return []

    try:
        api = NetBoxAPI(netbox_url, netbox_token, site_filter)

        # Server-side filtering parameters for better performance
        filter_params = {
            "status": "connected",  # Filter connected cables on server side
        }

        # Fetch all cables with concurrent requests and server-side filtering
        all_cables = api.get_all_pages_concurrent('dcim/cables/', filter_params)

        if site_filter:
            logger.info(f"Fetched {len(all_cables)} raw cables from NetBox for site '{site_filter}'")
        else:
            logger.info(f"Fetched {len(all_cables)} raw cables from NetBox (all sites)")

        # Apply efficient client-side filtering
        filtered_cables = filter_cables_efficiently(all_cables, allowed_devices)

        return filtered_cables

    except Exception as e:
        logger.error(f"Failed to fetch cables from NetBox: {e}")
        return []

def get_netbox_connections(netbox_url: str, netbox_token: str, site_filter: Optional[str] = None,
                          device_config_string: Optional[str] = None, device_username: Optional[str] = None,
                          device_password: Optional[str] = None, device_port: int = 22) -> List[Dict]:
    """
    Fetch and process NetBox topology connections with optimized performance

    Returns validated connection data in standardized format
    """
    # Resolve actual hostnames from device IPs if provided
    allowed_devices = None
    if device_config_string and device_username and device_password:
        allowed_devices = get_allowed_hostnames_from_config(
            device_config_string, device_username, device_password, device_port
        )
        logger.info(f"Filtering NetBox connections for resolved hostnames: {allowed_devices}")
    elif device_config_string:
        logger.warning("Device config provided but missing credentials - cannot resolve hostnames")

    # Fetch filtered cables with optimized concurrent requests
    cables = get_netbox_cables(netbox_url, netbox_token, site_filter, allowed_devices)
    connections = []

    for cable in cables:
        try:
            # Extract connection information from cable
            a_terminations = cable.get('a_terminations', [])
            b_terminations = cable.get('b_terminations', [])

            # Process each A-B termination pair
            for a_term in a_terminations:
                if not isinstance(a_term, dict):
                    continue
                for b_term in b_terminations:
                    if not isinstance(b_term, dict):
                        continue

                    # Extract device and interface information
                    a_device = None
                    a_interface = None
                    b_device = None
                    b_interface = None

                    # Handle different termination types efficiently
                    termination_types = ['dcim.interface', 'dcim.frontport', 'dcim.rearport']

                    if a_term.get('object_type') in termination_types:
                        a_device = a_term.get('object', {}).get('device', {}).get('name')
                        a_interface = a_term.get('object', {}).get('name')

                    if b_term.get('object_type') in termination_types:
                        b_device = b_term.get('object', {}).get('device', {}).get('name')
                        b_interface = b_term.get('object', {}).get('name')

                    # Only add valid connections with both devices and interfaces
                    if all([a_device, a_interface, b_device, b_interface]):
                        connection = {
                            'device_a': a_device,
                            'interface_a': a_interface,
                            'device_b': b_device,
                            'interface_b': b_interface,
                            'cable_id': cable.get('id'),
                            'cable_label': cable.get('label', ''),
                            'cable_type': cable.get('type', {}).get('label', 'Unknown'),
                            'status': cable.get('status', {}).get('label', 'Unknown')
                        }
                        connections.append(connection)

        except Exception as e:
            logger.warning(f"Failed to process cable {cable.get('id', 'unknown')}: {e}")
            continue

    # Log summary
    filter_description = []
    if site_filter:
        filter_description.append(f"site '{site_filter}'")
    if allowed_devices:
        filter_description.append(f"devices {allowed_devices}")

    if filter_description:
        logger.info(f"Processed {len(connections)} valid connections from NetBox cables for {' and '.join(filter_description)}")
    else:
        logger.info(f"Processed {len(connections)} valid connections from NetBox cables (no filters applied)")

    return connections

def compare_lldp_netbox_topology(lldp_neighbors: List[Dict], netbox_connections: List[Dict]) -> Dict:
    """Compare LLDP discovered topology with NetBox documented topology"""

    # Normalize LLDP connections to bidirectional pairs
    lldp_connections = set()
    for neighbor in lldp_neighbors:
        # Create normalized connection tuples (sorted to handle bidirectional)
        conn1 = (neighbor['local_device'], neighbor['local_interface'], 
                neighbor['remote_device'], neighbor['remote_interface'])
        conn2 = (neighbor['remote_device'], neighbor['remote_interface'],
                neighbor['local_device'], neighbor['local_interface'])
        lldp_connections.add(tuple(sorted([conn1, conn2])))

    # Normalize NetBox connections to bidirectional pairs
    netbox_connections_set = set()
    for conn in netbox_connections:
        conn1 = (conn['device_a'], conn['interface_a'], 
                conn['device_b'], conn['interface_b'])
        conn2 = (conn['device_b'], conn['interface_b'],
                conn['device_a'], conn['interface_a'])
        netbox_connections_set.add(tuple(sorted([conn1, conn2])))

    # Find differences
    missing_in_netbox = []
    missing_in_lldp = []
    matching_connections = []

    # Convert back to comparable format for detailed analysis
    lldp_simple = set()
    netbox_simple = set()

    for neighbor in lldp_neighbors:
        lldp_simple.add((neighbor['local_device'], neighbor['local_interface'], 
                        neighbor['remote_device'], neighbor['remote_interface']))

    for conn in netbox_connections:
        netbox_simple.add((conn['device_a'], conn['interface_a'], 
                          conn['device_b'], conn['interface_b']))
        # Add reverse direction
        netbox_simple.add((conn['device_b'], conn['interface_b'],
                          conn['device_a'], conn['interface_a']))

    # Find connections in LLDP but not in NetBox
    for lldp_conn in lldp_simple:
        if lldp_conn not in netbox_simple:
            missing_in_netbox.append({
                'local_device': lldp_conn[0],
                'local_interface': lldp_conn[1],
                'remote_device': lldp_conn[2],
                'remote_interface': lldp_conn[3],
                'source': 'lldp_only'
            })

    # Find connections in NetBox but not in LLDP
    for netbox_conn in netbox_simple:
        if netbox_conn not in lldp_simple:
            missing_in_lldp.append({
                'local_device': netbox_conn[0],
                'local_interface': netbox_conn[1],
                'remote_device': netbox_conn[2],
                'remote_interface': netbox_conn[3],
                'source': 'netbox_only'
            })

    # Find matching connections
    for lldp_conn in lldp_simple:
        if lldp_conn in netbox_simple:
            matching_connections.append({
                'local_device': lldp_conn[0],
                'local_interface': lldp_conn[1],
                'remote_device': lldp_conn[2],
                'remote_interface': lldp_conn[3],
                'source': 'both'
            })

    comparison_result = {
        'lldp_count': len(lldp_neighbors),
        'netbox_count': len(netbox_connections),
        'matching_count': len(matching_connections),
        'missing_in_netbox': missing_in_netbox,
        'missing_in_lldp': missing_in_lldp,
        'matching_connections': matching_connections,
        'mismatch_count': len(missing_in_netbox) + len(missing_in_lldp)
    }

    logger.info(f"Topology comparison: {len(lldp_neighbors)} LLDP, {len(netbox_connections)} NetBox, "
               f"{len(matching_connections)} matching, {comparison_result['mismatch_count']} mismatches")

    return comparison_result

def save_comparison_to_json(comparison_result: Dict, filename: str = 'topology_comparison.json'):
    """Save topology comparison results to JSON file"""
    with open(filename, 'w') as f:
        json.dump(comparison_result, f, indent=2, default=str)

# Example usage
if __name__ == "__main__":
    # Example configuration
    netbox_url = "https://netbox.cselab.io"
    netbox_token = "xxxxxxxx"
    site_filter = "datacenter-1"  # Optional: filter by site
    device_config = "192.168.1.10,192.168.1.11,192.168.1.12"  # Device IPs from config
    device_username = "admin"
    device_password = "password"

    # List available sites
    sites = get_netbox_sites(netbox_url, netbox_token)
    print(f"Available sites: {[site['name'] for site in sites]}")

    # Fetch NetBox data (with hostname resolution and filtering)
    devices = get_netbox_devices(netbox_url, netbox_token, site_filter)
    connections = get_netbox_connections(
        netbox_url, netbox_token, site_filter, 
        device_config, device_username, device_password
    )

    print(f"Found {len(devices)} devices and {len(connections)} connections in NetBox")
    if site_filter:
        print(f"Filtered by site: {site_filter}")
    if device_config:
        print(f"Filtered by resolved hostnames from device IPs: {device_config}")

    # Example LLDP data (would come from your LLDP collection)
    example_lldp = [
        {
            'local_device': 'switch01',
            'local_interface': 'port1',
            'remote_device': 'switch02',
            'remote_interface': 'port1'
        }
    ]

    # Compare topologies
    comparison = compare_lldp_netbox_topology(example_lldp, connections)

    # Save results
    save_comparison_to_json(comparison)

    print(f"Comparison complete: {comparison['mismatch_count']} mismatches found")

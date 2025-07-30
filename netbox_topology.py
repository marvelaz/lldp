import requests
import json
import logging
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class NetBoxAPI:
    """NetBox API client for fetching topology data"""

    def __init__(self, base_url: str, token: str, site_filter: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.site_filter = site_filter
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        # Disable SSL verification for self-signed certificates
        self.session.verify = False

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
            response = self.session.get(url, params=params, verify=False)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"NetBox API request failed: {e}")
            raise

    def get_all_pages(self, endpoint: str, params: Optional[Dict] = None) -> List[Dict]:
        """Fetch all pages of results from a paginated NetBox API endpoint"""
        all_results = []
        params = params or {}

        # Add site filter if specified and not already in params
        if self.site_filter and 'site' not in params:
            params['site'] = self.site_filter

        while True:
            data = self._make_request(endpoint, params)
            all_results.extend(data.get('results', []))

            # Check if there's a next page
            if not data.get('next'):
                break

            # Extract offset from next URL for pagination
            next_url = data['next']
            if 'offset=' in next_url:
                offset = next_url.split('offset=')[1].split('&')[0]
                params['offset'] = offset
            else:
                break

        return all_results

def get_device_names_from_config(device_config_string: str) -> Set[str]:
    """
    Extract device names/IPs from configuration string

    Args:
        device_config_string: Comma-separated string of device IPs from config

    Returns:
        Set of device identifiers (IPs and potentially hostnames)
    """
    device_identifiers = set()

    if device_config_string:
        device_ips = device_config_string.split(',')
        for ip in device_ips:
            ip = ip.strip()
            if ip:
                device_identifiers.add(ip)
                # Also add IP-based hostname format for matching
                device_identifiers.add(f'device-{ip.replace(".", "-")}')

    return device_identifiers

def filter_netbox_cables(cables: List[Dict], allowed_devices: Set[str]) -> List[Dict]:
    """
    Filter NetBox cables based on status, type, and device involvement

    Args:
        cables: List of cable dictionaries from NetBox API
        allowed_devices: Set of device names/IPs that we want to monitor

    Returns:
        Filtered list of cables
    """
    filtered_cables = []

    for cable in cables:
        try:
            # Filter 1: Only "connected" status cables
            status = cable.get('status', {})
            if isinstance(status, dict):
                status_label = status.get('label', '').lower()
            else:
                status_label = str(status).lower()

            if status_label != 'connected':
                logger.debug(f"Skipping cable {cable.get('id')} - status: {status_label}")
                continue

            # Filter 2: Exclude POWER and CONSOLE cables
            cable_type = cable.get('type', {})
            if isinstance(cable_type, dict):
                type_label = cable_type.get('label', '').lower()
            else:
                type_label = str(cable_type).lower()

            if type_label in ('power', 'console'):
                logger.debug(f"Skipping cable {cable.get('id')} - type: {type_label}")
                continue

            # Filter 3: Only cables involving our monitored devices
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

            # Check B terminations if not already found
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
                logger.debug(f"Skipping cable {cable.get('id')} - doesn't involve monitored devices")
                continue

            # Cable passed all filters
            filtered_cables.append(cable)

        except Exception as e:
            logger.warning(f"Error filtering cable {cable.get('id', 'unknown')}: {e}")
            continue

    logger.info(f"Filtered {len(cables)} cables down to {len(filtered_cables)} relevant cables")
    return filtered_cables

def get_netbox_sites(netbox_url: str, netbox_token: str) -> List[Dict]:
    """
    Fetch all sites from NetBox
    Returns a list of site dictionaries
    """
    if not netbox_url or not netbox_token:
        logger.warning("NetBox URL or token not configured")
        return []

    try:
        api = NetBoxAPI(netbox_url, netbox_token)

        # Fetch all sites (no site filter for this call)
        sites = api.get_all_pages('dcim/sites/')

        logger.info(f"Fetched {len(sites)} sites from NetBox")
        return sites

    except Exception as e:
        logger.error(f"Failed to fetch sites from NetBox: {e}")
        return []

def get_netbox_devices(netbox_url: str, netbox_token: str, site_filter: Optional[str] = None) -> List[Dict]:
    """
    Fetch devices from NetBox, optionally filtered by site

    Args:
        netbox_url: NetBox base URL
        netbox_token: NetBox API token
        site_filter: Site name or slug to filter by (optional)

    Returns:
        List of device dictionaries
    """
    if not netbox_url or not netbox_token:
        logger.warning("NetBox URL or token not configured")
        return []

    try:
        api = NetBoxAPI(netbox_url, netbox_token, site_filter)

        # Fetch devices (site filter applied automatically if specified)
        devices = api.get_all_pages('dcim/devices/')

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
    Fetch cables (connections) from NetBox with comprehensive filtering

    Args:
        netbox_url: NetBox base URL
        netbox_token: NetBox API token
        site_filter: Site name or slug to filter by (optional)
        allowed_devices: Set of device names/IPs to filter by (optional)

    Returns:
        List of filtered cable dictionaries representing physical connections
    """
    if not netbox_url or not netbox_token:
        logger.warning("NetBox URL or token not configured")
        return []

    try:
        api = NetBoxAPI(netbox_url, netbox_token, site_filter)

        # Fetch all cables (site filter applied automatically if specified)
        all_cables = api.get_all_pages('dcim/cables/')

        if site_filter:
            logger.info(f"Fetched {len(all_cables)} raw cables from NetBox for site '{site_filter}'")
        else:
            logger.info(f"Fetched {len(all_cables)} raw cables from NetBox (all sites)")

        # Apply additional filtering if allowed_devices is provided
        if allowed_devices:
            filtered_cables = filter_netbox_cables(all_cables, allowed_devices)
        else:
            # Still apply status and type filtering even without device filtering
            filtered_cables = []
            for cable in all_cables:
                try:
                    # Filter by status
                    status = cable.get('status', {})
                    if isinstance(status, dict):
                        status_label = status.get('label', '').lower()
                    else:
                        status_label = str(status).lower()

                    if status_label != 'connected':
                        continue

                    # Filter by type
                    cable_type = cable.get('type', {})
                    if isinstance(cable_type, dict):
                        type_label = cable_type.get('label', '').lower()
                    else:
                        type_label = str(cable_type).lower()

                    if type_label in ('power', 'console'):
                        continue

                    filtered_cables.append(cable)

                except Exception as e:
                    logger.warning(f"Error filtering cable {cable.get('id', 'unknown')}: {e}")
                    continue

        logger.info(f"After filtering: {len(filtered_cables)} relevant cables")
        return filtered_cables

    except Exception as e:
        logger.error(f"Failed to fetch cables from NetBox: {e}")
        return []

def get_netbox_connections(netbox_url: str, netbox_token: str, site_filter: Optional[str] = None,
                          device_config_string: Optional[str] = None) -> List[Dict]:
    """
    Fetch and process NetBox topology connections with comprehensive filtering

    Args:
        netbox_url: NetBox base URL
        netbox_token: NetBox API token
        site_filter: Site name or slug to filter by (optional)
        device_config_string: Comma-separated string of device IPs from config (optional)

    Returns:
        List of connection dictionaries in a standardized format
    """
    # Parse allowed devices from config if provided
    allowed_devices = None
    if device_config_string:
        allowed_devices = get_device_names_from_config(device_config_string)
        logger.info(f"Filtering NetBox connections for devices: {allowed_devices}")

    # Fetch filtered cables
    cables = get_netbox_cables(netbox_url, netbox_token, site_filter, allowed_devices)
    connections = []

    for cable in cables:
        try:
            # Extract connection information from cable
            a_terminations = cable.get('a_terminations', [])
            b_terminations = cable.get('b_terminations', [])

            # Process each A-B termination pair
            for a_term in a_terminations:
                for b_term in b_terminations:
                    # Extract device and interface information
                    a_device = None
                    a_interface = None
                    b_device = None
                    b_interface = None

                    # Handle different termination types (interfaces, front ports, etc.)
                    if a_term.get('object_type') == 'dcim.interface':
                        a_device = a_term.get('object', {}).get('device', {}).get('name')
                        a_interface = a_term.get('object', {}).get('name')
                    elif a_term.get('object_type') == 'dcim.frontport':
                        a_device = a_term.get('object', {}).get('device', {}).get('name')
                        a_interface = a_term.get('object', {}).get('name')
                    elif a_term.get('object_type') == 'dcim.rearport':
                        a_device = a_term.get('object', {}).get('device', {}).get('name')
                        a_interface = a_term.get('object', {}).get('name')

                    if b_term.get('object_type') == 'dcim.interface':
                        b_device = b_term.get('object', {}).get('device', {}).get('name')
                        b_interface = b_term.get('object', {}).get('name')
                    elif b_term.get('object_type') == 'dcim.frontport':
                        b_device = b_term.get('object', {}).get('device', {}).get('name')
                        b_interface = b_term.get('object', {}).get('name')
                    elif b_term.get('object_type') == 'dcim.rearport':
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

    if site_filter and device_config_string:
        logger.info(f"Processed {len(connections)} valid connections from NetBox cables for site '{site_filter}' and specified devices")
    elif site_filter:
        logger.info(f"Processed {len(connections)} valid connections from NetBox cables for site '{site_filter}'")
    elif device_config_string:
        logger.info(f"Processed {len(connections)} valid connections from NetBox cables for specified devices")
    else:
        logger.info(f"Processed {len(connections)} valid connections from NetBox cables (all sites and devices)")

    return connections

def compare_lldp_netbox_topology(lldp_neighbors: List[Dict], netbox_connections: List[Dict]) -> Dict:
    """
    Compare LLDP discovered topology with NetBox documented topology

    Args:
        lldp_neighbors: List of LLDP neighbor dictionaries with keys:
                       ['local_device', 'local_interface', 'remote_device', 'remote_interface']
        netbox_connections: List of NetBox connection dictionaries with keys:
                           ['device_a', 'interface_a', 'device_b', 'interface_b']

    Returns:
        Dictionary with comparison results
    """

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
    netbox_url = "https://netbox.example.com"
    netbox_token = "your-netbox-token"
    site_filter = "datacenter-1"  # Optional: filter by site
    device_config = "192.168.1.10,192.168.1.11,192.168.1.12"  # Optional: filter by devices

    # List available sites
    sites = get_netbox_sites(netbox_url, netbox_token)
    print(f"Available sites: {[site['name'] for site in sites]}")

    # Fetch NetBox data (with optional site and device filtering)
    devices = get_netbox_devices(netbox_url, netbox_token, site_filter)
    connections = get_netbox_connections(netbox_url, netbox_token, site_filter, device_config)

    print(f"Found {len(devices)} devices and {len(connections)} connections in NetBox")
    if site_filter:
        print(f"Filtered by site: {site_filter}")
    if device_config:
        print(f"Filtered by devices: {device_config}")

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

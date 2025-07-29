import requests
import json
import logging
from typing import List, Dict, Optional
from urllib.parse import urljoin

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

def get_netbox_cables(netbox_url: str, netbox_token: str, site_filter: Optional[str] = None) -> List[Dict]:
    """
    Fetch cables (connections) from NetBox, optionally filtered by site

    Args:
        netbox_url: NetBox base URL
        netbox_token: NetBox API token
        site_filter: Site name or slug to filter by (optional)

    Returns:
        List of cable dictionaries representing physical connections
    """
    if not netbox_url or not netbox_token:
        logger.warning("NetBox URL or token not configured")
        return []

    try:
        api = NetBoxAPI(netbox_url, netbox_token, site_filter)

        # Fetch cables (site filter applied automatically if specified)
        cables = api.get_all_pages('dcim/cables/')

        if site_filter:
            logger.info(f"Fetched {len(cables)} cables from NetBox for site '{site_filter}'")
        else:
            logger.info(f"Fetched {len(cables)} cables from NetBox (all sites)")
        return cables

    except Exception as e:
        logger.error(f"Failed to fetch cables from NetBox: {e}")
        return []

def get_netbox_connections(netbox_url: str, netbox_token: str, site_filter: Optional[str] = None) -> List[Dict]:
    """
    Fetch and process NetBox topology connections, optionally filtered by site

    Args:
        netbox_url: NetBox base URL
        netbox_token: NetBox API token
        site_filter: Site name or slug to filter by (optional)

    Returns:
        List of connection dictionaries in a standardized format
    """
    cables = get_netbox_cables(netbox_url, netbox_token, site_filter)
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

                    if b_term.get('object_type') == 'dcim.interface':
                        b_device = b_term.get('object', {}).get('device', {}).get('name')
                        b_interface = b_term.get('object', {}).get('name')
                    elif b_term.get('object_type') == 'dcim.frontport':
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
                            'status': cable.get('status', {}).get('label', 'Unknown')
                        }
                        connections.append(connection)

        except Exception as e:
            logger.warning(f"Failed to process cable {cable.get('id', 'unknown')}: {e}")
            continue

    if site_filter:
        logger.info(f"Processed {len(connections)} valid connections from NetBox cables for site '{site_filter}'")
    else:
        logger.info(f"Processed {len(connections)} valid connections from NetBox cables (all sites)")
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

    # List available sites
    sites = get_netbox_sites(netbox_url, netbox_token)
    print(f"Available sites: {[site['name'] for site in sites]}")

    # Fetch NetBox data (with optional site filter)
    devices = get_netbox_devices(netbox_url, netbox_token, site_filter)
    connections = get_netbox_connections(netbox_url, netbox_token, site_filter)

    print(f"Found {len(devices)} devices and {len(connections)} connections in NetBox")
    if site_filter:
        print(f"Filtered by site: {site_filter}")

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

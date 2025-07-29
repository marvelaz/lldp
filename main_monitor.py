#!/usr/bin/env python3
"""
Fortinet Topology Monitor - Main Application with NetBox Integration
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import List, Dict
import aiosqlite
from pathlib import Path

from config import settings
from models import LLDPNeighborRaw, LLDPNeighbor, NetworkConnection, TopologyDifference
from python_lldp_neigh import get_lldp_neighbors, get_device_hostname
from netbox_topology import get_netbox_connections, compare_lldp_netbox_topology

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(settings.log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FortinetTopologyMonitor:
    def __init__(self):
        self.db_path = settings.database_path
        self.devices = self._parse_devices()
        self.consecutive_mismatches = 0

    def _parse_devices(self) -> List[Dict[str, str]]:
        """Parse device list from configuration and get actual hostnames"""
        device_ips = settings.fgt_devices.split(',')
        devices = []
        
        for ip in device_ips:
            ip = ip.strip()
            try:
                # Get the actual hostname from the device
                hostname = get_device_hostname(
                    host=ip,
                    username=settings.fgt_username,
                    password=settings.fgt_password,
                    port=settings.fgt_port
                )
                logger.info(f"Retrieved hostname '{hostname}' for device {ip}")
            except Exception as e:
                logger.warning(f"Failed to get hostname for {ip}, using IP-based name: {e}")
                hostname = f'device-{ip.replace(".", "-")}'
            
            devices.append({
                'ip': ip,
                'username': settings.fgt_username,
                'password': settings.fgt_password,
                'port': settings.fgt_port,
                'name': hostname
            })
        return devices

    async def initialize(self):
        """Initialize the monitor and database"""
        logger.info("Initializing Fortinet Topology Monitor...")

        # Create directories
        Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
        Path(settings.log_file).parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        await self._initialize_database()
        logger.info(f"Monitor initialized with {len(self.devices)} devices")

    async def _initialize_database(self):
        """Create database tables if they don't exist"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    name TEXT PRIMARY KEY,
                    ip_address TEXT,
                    device_type TEXT,
                    serial_number TEXT,
                    firmware_version TEXT,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS lldp_neighbors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    local_device TEXT,
                    local_interface TEXT,
                    remote_device TEXT,
                    remote_interface TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT,
                    ttl TEXT,
                    capability TEXT
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    device_a TEXT,
                    port_a TEXT,
                    device_b TEXT,
                    port_b TEXT,
                    source TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    PRIMARY KEY (device_a, port_a, device_b, port_b)
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS topology_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    lldp_count INTEGER,
                    netbox_count INTEGER,
                    mismatch_count INTEGER,
                    device_count INTEGER
                )
            """)

            # New table for storing topology comparison results
            await db.execute("""
                CREATE TABLE IF NOT EXISTS topology_mismatches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    check_id INTEGER,
                    local_device TEXT,
                    local_interface TEXT,
                    remote_device TEXT,
                    remote_interface TEXT,
                    mismatch_type TEXT,
                    source TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (check_id) REFERENCES topology_checks (id)
                )
            """)

            await db.commit()
            logger.info("Database initialized successfully")

    async def collect_lldp_neighbors(self) -> List[LLDPNeighbor]:
        """Collect LLDP neighbors from all configured devices"""
        all_neighbors = []

        for device in self.devices:
            try:
                logger.info(f"Collecting LLDP neighbors from {device['name']} ({device['ip']})")

                # Use the existing function to get raw LLDP data
                raw_neighbors_data = get_lldp_neighbors(
                    host=device['ip'],
                    username=device['username'],
                    password=device['password'],
                    port=device['port']
                )

                # Convert to Pydantic models
                valid_neighbors = 0
                for raw_data in raw_neighbors_data:
                    try:
                        raw_neighbor = LLDPNeighborRaw(**raw_data)
                        neighbor = LLDPNeighbor.from_raw(raw_neighbor, device['name'])
                        all_neighbors.append(neighbor)
                        valid_neighbors += 1
                    except Exception as e:
                        logger.error(f"Failed to parse neighbor data: {e}")
                        continue

                logger.info(f"Collected {valid_neighbors} valid neighbors from {device['name']} (filtered out invalid entries)")

            except Exception as e:
                logger.error(f"Failed to collect from {device['name']}: {e}")
                continue

        logger.info(f"Total valid LLDP neighbors collected: {len(all_neighbors)}")
        return all_neighbors

    async def collect_netbox_topology(self) -> List[Dict]:
        """Collect topology data from NetBox"""
        if not settings.netbox_url or not settings.netbox_token:
            logger.warning("NetBox integration not configured, skipping NetBox data collection")
            return []

        try:
            logger.info("Collecting topology data from NetBox...")
            
            # Run NetBox API calls in executor to avoid blocking
            loop = asyncio.get_event_loop()
            netbox_connections = await loop.run_in_executor(
                None, 
                get_netbox_connections, 
                settings.netbox_url, 
                settings.netbox_token
            )
            
            logger.info(f"Collected {len(netbox_connections)} connections from NetBox")
            return netbox_connections
            
        except Exception as e:
            logger.error(f"Failed to collect NetBox topology: {e}")
            return []

    async def compare_topologies(self, lldp_neighbors: List[LLDPNeighbor], netbox_connections: List[Dict]) -> Dict:
        """Compare LLDP and NetBox topologies"""
        if not netbox_connections:
            logger.info("No NetBox data available for comparison")
            return {
                'lldp_count': len(lldp_neighbors),
                'netbox_count': 0,
                'matching_count': 0,
                'missing_in_netbox': [],
                'missing_in_lldp': [],
                'matching_connections': [],
                'mismatch_count': 0
            }

        # Convert LLDPNeighbor objects to dictionaries for comparison
        lldp_dicts = []
        for neighbor in lldp_neighbors:
            lldp_dicts.append({
                'local_device': neighbor.local_device,
                'local_interface': neighbor.local_interface,
                'remote_device': neighbor.remote_device,
                'remote_interface': neighbor.remote_interface
            })

        # Run comparison in executor to avoid blocking
        loop = asyncio.get_event_loop()
        comparison_result = await loop.run_in_executor(
            None,
            compare_lldp_netbox_topology,
            lldp_dicts,
            netbox_connections
        )

        return comparison_result

    async def save_matching_connections(self, comparison_result: Dict):
        """Save matching connections to a JSON file in the log directory"""
        try:
            # Get the log file directory
            log_file_path = Path(settings.log_file)
            log_directory = log_file_path.parent
            
            # Create filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            matches_filename = f"matching_connections_{timestamp}.json"
            matches_filepath = log_directory / matches_filename
            
            # Prepare data to save
            matches_data = {
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_matches": comparison_result['matching_count'],
                    "lldp_count": comparison_result['lldp_count'],
                    "netbox_count": comparison_result['netbox_count'],
                    "mismatch_count": comparison_result['mismatch_count']
                },
                "matching_connections": comparison_result['matching_connections']
            }
            
            # Save to file
            with open(matches_filepath, 'w') as f:
                json.dump(matches_data, f, indent=2, default=str)
            
            logger.info(f"Saved {comparison_result['matching_count']} matching connections to {matches_filepath}")
            
            # Also save latest matches (overwrite each time)
            latest_matches_filepath = log_directory / "latest_matching_connections.json"
            with open(latest_matches_filepath, 'w') as f:
                json.dump(matches_data, f, indent=2, default=str)
            
            logger.info(f"Updated latest matching connections file: {latest_matches_filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save matching connections to file: {e}")

    async def store_topology_comparison(self, check_id: int, comparison_result: Dict):
        """Store topology comparison results in database"""
        async with aiosqlite.connect(self.db_path) as db:
            # Clear old mismatches for this check
            await db.execute('DELETE FROM topology_mismatches WHERE check_id = ?', (check_id,))

            # Store missing in NetBox
            for mismatch in comparison_result.get('missing_in_netbox', []):
                await db.execute("""
                    INSERT INTO topology_mismatches 
                    (check_id, local_device, local_interface, remote_device, remote_interface, mismatch_type, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    check_id,
                    mismatch['local_device'],
                    mismatch['local_interface'],
                    mismatch['remote_device'],
                    mismatch['remote_interface'],
                    'missing_in_netbox',
                    mismatch['source']
                ))

            # Store missing in LLDP
            for mismatch in comparison_result.get('missing_in_lldp', []):
                await db.execute("""
                    INSERT INTO topology_mismatches 
                    (check_id, local_device, local_interface, remote_device, remote_interface, mismatch_type, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    check_id,
                    mismatch['local_device'],
                    mismatch['local_interface'],
                    mismatch['remote_device'],
                    mismatch['remote_interface'],
                    'missing_in_lldp',
                    mismatch['source']
                ))

            await db.commit()
            logger.info(f"Stored {comparison_result['mismatch_count']} topology mismatches for check {check_id}")

    async def store_lldp_neighbors(self, neighbors: List[LLDPNeighbor]):
        """Store LLDP neighbors in database"""
        async with aiosqlite.connect(self.db_path) as db:
            # Clear old data
            await db.execute('DELETE FROM lldp_neighbors')

            # Insert new data
            for neighbor in neighbors:
                await db.execute("""
                    INSERT INTO lldp_neighbors 
                    (local_device, local_interface, remote_device, remote_interface, discovered_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    neighbor.local_device,
                    neighbor.local_interface,
                    neighbor.remote_device,
                    neighbor.remote_interface,
                    neighbor.discovered_at
                ))

            await db.commit()
            logger.info(f"Stored {len(neighbors)} LLDP neighbors in database")

    async def get_topology_history(self, days: int = 7) -> List[Dict]:
        """Get topology check history"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(f"""
                SELECT * FROM topology_checks 
                WHERE timestamp >= datetime('now', '-{days} days')
                ORDER BY timestamp DESC
            """)

            rows = await cursor.fetchall()
            columns = [description[0] for description in cursor.description]

            return [dict(zip(columns, row)) for row in rows]

    async def get_recent_mismatches(self, check_id: int = None, limit: int = 100) -> List[Dict]:
        """Get recent topology mismatches"""
        async with aiosqlite.connect(self.db_path) as db:
            if check_id:
                cursor = await db.execute("""
                    SELECT * FROM topology_mismatches 
                    WHERE check_id = ?
                    ORDER BY discovered_at DESC
                    LIMIT ?
                """, (check_id, limit))
            else:
                cursor = await db.execute("""
                    SELECT * FROM topology_mismatches 
                    ORDER BY discovered_at DESC
                    LIMIT ?
                """, (limit,))

            rows = await cursor.fetchall()
            columns = [description[0] for description in cursor.description]

            return [dict(zip(columns, row)) for row in rows]

    async def run_monitoring_cycle(self):
        """Execute one monitoring cycle with NetBox comparison"""
        try:
            logger.info("Starting monitoring cycle...")

            # Collect LLDP data
            lldp_neighbors = await self.collect_lldp_neighbors()

            # Store LLDP data in database
            await self.store_lldp_neighbors(lldp_neighbors)

            # Collect NetBox topology data
            netbox_connections = await self.collect_netbox_topology()

            # Compare topologies
            comparison_result = await self.compare_topologies(lldp_neighbors, netbox_connections)

            # Save matching connections to file in log directory
            await self.save_matching_connections(comparison_result)

            # Record the check in database
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    INSERT INTO topology_checks 
                    (timestamp, lldp_count, netbox_count, mismatch_count, device_count)
                    VALUES (datetime('now'), ?, ?, ?, ?)
                """, (
                    comparison_result['lldp_count'],
                    comparison_result['netbox_count'],
                    comparison_result['mismatch_count'],
                    len(self.devices)
                ))
                await db.commit()
                
                # Get the check ID for storing mismatches
                check_id = cursor.lastrowid

            # Store detailed mismatch information
            await self.store_topology_comparison(check_id, comparison_result)

            # Log summary
            logger.info(f"Monitoring cycle completed:")
            logger.info(f"  - LLDP neighbors: {comparison_result['lldp_count']}")
            logger.info(f"  - NetBox connections: {comparison_result['netbox_count']}")
            logger.info(f"  - Matching connections: {comparison_result['matching_count']}")
            logger.info(f"  - Mismatches: {comparison_result['mismatch_count']}")

            # Handle consecutive mismatches for alerting
            if comparison_result['mismatch_count'] > 0:
                self.consecutive_mismatches += 1
                logger.warning(f"Topology mismatches detected ({self.consecutive_mismatches} consecutive)")
                
                if self.consecutive_mismatches >= settings.alert_threshold:
                    logger.error(f"Alert threshold reached: {self.consecutive_mismatches} consecutive mismatches")
                    # Here you could trigger email alerts or other notifications
            else:
                self.consecutive_mismatches = 0

        except Exception as e:
            logger.error(f"Monitoring cycle failed: {e}")
            raise

    async def run_periodically(self):
        """Run monitoring on a schedule"""
        await self.initialize()

        logger.info(f"Starting periodic monitoring every {settings.monitor_interval_minutes} minutes")

        while True:
            try:
                await self.run_monitoring_cycle()
                await asyncio.sleep(settings.monitor_interval_minutes * 60)
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Monitoring cycle failed: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying

    async def shutdown(self):
        """Clean shutdown"""
        logger.info("Shutting down monitor...")

async def main():
    """Main entry point"""
    monitor = FortinetTopologyMonitor()

    try:
        await monitor.run_periodically()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        await monitor.shutdown()

if __name__ == "__main__":
    asyncio.run(main())

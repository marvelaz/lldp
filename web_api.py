#!/usr/bin/env python3
"""
Fortinet Topology Monitor - Web API
FastAPI web server for topology visualization and monitoring
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pathlib import Path

import aiosqlite
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Import our configuration and models
from config import settings
from models import LLDPNeighbor, NetworkConnection, TopologyCheck
from main_monitor import FortinetTopologyMonitor

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

# FastAPI app
app = FastAPI(
    title="Fortinet Topology Monitor",
    description="Network topology monitoring and visualization for Fortinet devices",
    version="1.0.0"
)

# Global monitor instance
monitor: Optional[FortinetTopologyMonitor] = None

# Response models
class TopologyStats(BaseModel):
    total_devices: int
    total_connections: int
    last_update: Optional[datetime]
    lldp_neighbors: int

class DeviceInfo(BaseModel):
    name: str
    ip_address: str
    device_type: str
    last_seen: Optional[datetime]
    neighbor_count: int

class ConnectionInfo(BaseModel):
    device_a: str
    port_a: str
    device_b: str
    port_b: str
    source: str
    last_seen: datetime

@app.on_event("startup")
async def startup_event():
    """Initialize the monitor on startup"""
    global monitor
    logger.info("Starting Fortinet Topology Monitor Web API...")

    try:
        # Create directories
        Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
        Path(settings.log_file).parent.mkdir(parents=True, exist_ok=True)

        # Initialize monitor
        monitor = FortinetTopologyMonitor()
        await monitor.initialize()

        logger.info("Web API started successfully")

    except Exception as e:
        logger.error(f"Failed to start web API: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Clean shutdown"""
    global monitor
    if monitor:
        await monitor.shutdown()
    logger.info("Web API shut down")

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serve the main dashboard HTML"""
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Fortinet Network Topology</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); flex: 1; }
        .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        #cy { width: 100%; height: 600px; border: 1px solid #ddd; border-radius: 8px; background: white; }
        .controls { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .btn { background-color: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin-right: 10px; }
        .btn:hover { background-color: #2980b9; }
        .status { padding: 10px; border-radius: 4px; margin-bottom: 10px; }
        .status.success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.23.0/cytoscape.min.js"></script>
</head>
<body>
    <div class="header">
        <h1>🌐 Fortinet Network Topology Monitor</h1>
        <p>Real-time network topology visualization and monitoring</p>
    </div>

    <div class="stats" id="stats">
        <div class="stat-card">
            <div class="stat-value" id="device-count">-</div>
            <div class="stat-label">Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="connection-count">-</div>
            <div class="stat-label">Connections</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="neighbor-count">-</div>
            <div class="stat-label">LLDP Neighbors</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="last-update">-</div>
            <div class="stat-label">Last Update</div>
        </div>
    </div>

    <div class="controls">
        <button class="btn" onclick="refreshTopology()">🔄 Refresh</button>
        <button class="btn" onclick="runDiscovery()">🔍 Run Discovery</button>
        <button class="btn" onclick="exportData()">📥 Export Data</button>
        <div id="status-message"></div>
    </div>

    <div id="cy"></div>

    <script>
        let cy;

        async function loadTopology() {
            try {
                const response = await fetch('/api/topology');
                const data = await response.json();

                if (cy) {
                    cy.destroy();
                }

                cy = cytoscape({
                    container: document.getElementById('cy'),
                    elements: data.elements || [],
                    style: [
                        {
                            selector: 'node',
                            style: {
                                'label': 'data(label)',
                                'text-valign': 'center',
                                'text-halign': 'center',
                                'width': 60,
                                'height': 60,
                                'font-size': '12px',
                                'text-wrap': 'wrap',
                                'text-max-width': '80px'
                            }
                        },
                        {
                            selector: 'edge',
                            style: {
                                'label': 'data(label)',
                                'curve-style': 'bezier',
                                'target-arrow-shape': 'triangle',
                                'width': 2,
                                'font-size': '10px',
                                'text-rotation': 'autorotate'
                            }
                        },
                        {
                            selector: '.fortigate',
                            style: { 
                                'shape': 'rectangle',
                                'background-color': '#e74c3c'
                            }
                        },
                        {
                            selector: '.fortiswitch',
                            style: { 
                                'shape': 'diamond',
                                'background-color': '#2ecc71'
                            }
                        },
                        {
                            selector: '.fortiap',
                            style: { 
                                'shape': 'ellipse',
                                'background-color': '#3498db'
                            }
                        },
                        {
                            selector: '.other',
                            style: { 
                                'shape': 'hexagon',
                                'background-color': '#95a5a6'
                            }
                        },
                        {
                            selector: '.lldp',
                            style: { 
                                'line-color': '#3498db',
                                'target-arrow-color': '#3498db'
                            }
                        }
                    ],
                    layout: {
                        name: 'cose',
                        idealEdgeLength: 100,
                        nodeOverlap: 20,
                        refresh: 20,
                        fit: true,
                        padding: 30,
                        randomize: false,
                        componentSpacing: 100,
                        nodeRepulsion: 40000,
                        edgeElasticity: 100,
                        nestingFactor: 5,
                        gravity: 80,
                        numIter: 1000,
                        initialTemp: 200,
                        coolingFactor: 0.95,
                        minTemp: 1.0
                    }
                });

                showStatus('Topology loaded successfully', 'success');

            } catch (error) {
                console.error('Failed to load topology:', error);
                showStatus('Failed to load topology: ' + error.message, 'error');
            }
        }

        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();

                document.getElementById('device-count').textContent = stats.total_devices;
                document.getElementById('connection-count').textContent = stats.total_connections;
                document.getElementById('neighbor-count').textContent = stats.lldp_neighbors;

                if (stats.last_update) {
                    const lastUpdate = new Date(stats.last_update);
                    document.getElementById('last-update').textContent = lastUpdate.toLocaleTimeString();
                } else {
                    document.getElementById('last-update').textContent = 'Never';
                }

            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }

        async function refreshTopology() {
            showStatus('Refreshing topology...', 'success');
            await loadTopology();
            await loadStats();
        }

        async function runDiscovery() {
            try {
                showStatus('Running network discovery...', 'success');
                const response = await fetch('/api/discover', { method: 'POST' });
                const result = await response.json();

                if (response.ok) {
                    showStatus('Discovery completed: ' + result.neighbors_found + ' neighbors found', 'success');
                    setTimeout(() => {
                        refreshTopology();
                    }, 2000);
                } else {
                    showStatus('Discovery failed: ' + result.detail, 'error');
                }
            } catch (error) {
                showStatus('Discovery failed: ' + error.message, 'error');
            }
        }

        async function exportData() {
            try {
                const response = await fetch('/api/export');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'topology_data.json';
                a.click();
                window.URL.revokeObjectURL(url);
                showStatus('Data exported successfully', 'success');
            } catch (error) {
                showStatus('Export failed: ' + error.message, 'error');
            }
        }

        function showStatus(message, type) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.innerHTML = '<div class="status ' + type + '">' + message + '</div>';
            setTimeout(() => {
                statusDiv.innerHTML = '';
            }, 5000);
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            loadTopology();
            loadStats();

            // Auto-refresh every 30 seconds
            setInterval(() => {
                loadStats();
            }, 30000);
        });
    </script>
</body>
</html>"""
    return html_content

@app.get("/api/stats")
async def get_stats():
    """Get topology statistics"""
    try:
        async with aiosqlite.connect(settings.database_path) as db:
            # Get device count
            cursor = await db.execute("SELECT COUNT(DISTINCT local_device) FROM lldp_neighbors")
            device_count = (await cursor.fetchone())[0]

            # Get connection count
            cursor = await db.execute("SELECT COUNT(*) FROM lldp_neighbors")
            neighbor_count = (await cursor.fetchone())[0]

            # Get last update
            cursor = await db.execute("SELECT MAX(timestamp) FROM topology_checks")
            last_update_row = await cursor.fetchone()
            last_update = last_update_row[0] if last_update_row[0] else None

            return TopologyStats(
                total_devices=device_count,
                total_connections=neighbor_count,
                last_update=datetime.fromisoformat(last_update) if last_update else None,
                lldp_neighbors=neighbor_count
            )

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/topology")
async def get_topology():
    """Get topology data for visualization"""
    try:
        async with aiosqlite.connect(settings.database_path) as db:
            # Get all LLDP neighbors
            cursor = await db.execute("""
                SELECT local_device, local_interface, remote_device, remote_interface
                FROM lldp_neighbors
            """)
            neighbors = await cursor.fetchall()

            # Build Cytoscape elements
            nodes = {}
            edges = []

            for local_dev, local_int, remote_dev, remote_int in neighbors:
                # Add nodes
                if local_dev not in nodes:
                    nodes[local_dev] = {
                        'data': {
                            'id': local_dev,
                            'label': local_dev
                        },
                        'classes': 'fortiswitch'  # Default class
                    }

                if remote_dev not in nodes:
                    nodes[remote_dev] = {
                        'data': {
                            'id': remote_dev,
                            'label': remote_dev
                        },
                        'classes': 'other'  # Default class for remote devices
                    }

                # Add edge
                edge_id = f"{local_dev}_{local_int}_{remote_dev}_{remote_int}"
                edges.append({
                    'data': {
                        'id': edge_id,
                        'source': local_dev,
                        'target': remote_dev,
                        'label': f"{local_int} → {remote_int}"
                    },
                    'classes': 'lldp'
                })

            elements = list(nodes.values()) + edges

            return {
                'elements': elements,
                'stats': {
                    'nodes': len(nodes),
                    'edges': len(edges)
                }
            }

    except Exception as e:
        logger.error(f"Failed to get topology: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/discover")
async def run_discovery(background_tasks: BackgroundTasks):
    """Trigger network discovery"""
    global monitor

    if not monitor:
        raise HTTPException(status_code=500, detail="Monitor not initialized")

    try:
        # Run discovery in background
        background_tasks.add_task(monitor.run_monitoring_cycle)

        return {
            "message": "Discovery started",
            "status": "running"
        }

    except Exception as e:
        logger.error(f"Failed to start discovery: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/devices")
async def get_devices():
    """Get list of all devices"""
    try:
        async with aiosqlite.connect(settings.database_path) as db:
            cursor = await db.execute("""
                SELECT 
                    local_device as name,
                    COUNT(*) as neighbor_count,
                    MAX(discovered_at) as last_seen
                FROM lldp_neighbors 
                GROUP BY local_device
            """)

            devices = []
            for row in await cursor.fetchall():
                devices.append(DeviceInfo(
                    name=row[0],
                    ip_address="Unknown",  # Would need device registry
                    device_type="fortiswitch",
                    last_seen=datetime.fromisoformat(row[2]) if row[2] else None,
                    neighbor_count=row[1]
                ))

            return devices

    except Exception as e:
        logger.error(f"Failed to get devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/connections")
async def get_connections():
    """Get list of all connections"""
    try:
        async with aiosqlite.connect(settings.database_path) as db:
            cursor = await db.execute("""
                SELECT local_device, local_interface, remote_device, remote_interface, discovered_at
                FROM lldp_neighbors
                ORDER BY discovered_at DESC
            """)

            connections = []
            for row in await cursor.fetchall():
                connections.append(ConnectionInfo(
                    device_a=row[0],
                    port_a=row[1],
                    device_b=row[2],
                    port_b=row[3],
                    source="lldp",
                    last_seen=datetime.fromisoformat(row[4]) if row[4] else datetime.utcnow()
                ))

            return connections

    except Exception as e:
        logger.error(f"Failed to get connections: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/export")
async def export_data():
    """Export topology data as JSON"""
    try:
        async with aiosqlite.connect(settings.database_path) as db:
            # Get all data
            cursor = await db.execute("SELECT * FROM lldp_neighbors")
            neighbors = await cursor.fetchall()

            cursor = await db.execute("SELECT * FROM topology_checks")
            checks = await cursor.fetchall()

            export_data = {
                "export_time": datetime.utcnow().isoformat(),
                "lldp_neighbors": [
                    {
                        "local_device": row[1],
                        "local_interface": row[2],
                        "remote_device": row[3],
                        "remote_interface": row[4],
                        "discovered_at": row[5]
                    }
                    for row in neighbors
                ],
                "topology_checks": [
                    {
                        "timestamp": row[1],
                        "lldp_count": row[2],
                        "netbox_count": row[3],
                        "mismatch_count": row[4],
                        "device_count": row[5]
                    }
                    for row in checks
                ]
            }

            return JSONResponse(
                content=export_data,
                headers={"Content-Disposition": "attachment; filename=topology_data.json"}
            )

    except Exception as e:
        logger.error(f"Failed to export data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": settings.database_path,
        "monitor_interval": settings.monitor_interval_minutes
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

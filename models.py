from datetime import datetime
from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field, validator

class DeviceType(str, Enum):
    FORTIGATE = "fortigate"
    FORTISWITCH = "fortiswitch"
    FORTIAP = "fortiap"
    OTHER = "other"

class Interface(BaseModel):
    name: str
    description: Optional[str] = None
    mac_address: Optional[str] = None
    speed: Optional[int] = None  # in Mbps
    duplex: Optional[str] = None  # full/half/auto
    status: Optional[str] = None  # up/down

class Device(BaseModel):
    name: str
    ip_address: str
    device_type: DeviceType
    serial_number: Optional[str] = None
    firmware_version: Optional[str] = None
    interfaces: List[Interface] = []

# Updated model to match your actual JSON structure
class LLDPNeighborRaw(BaseModel):
    """Raw LLDP neighbor data as collected from FortiSwitch"""
    local_port: str
    status: str
    neighbor_device: str
    ttl: str
    capability: str
    med_type: str
    neighbor_port: str

class LLDPNeighbor(BaseModel):
    """Processed LLDP neighbor for internal use"""
    local_device: str
    local_interface: str
    remote_device: str
    remote_interface: str
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    @classmethod
    def from_raw(cls, raw: LLDPNeighborRaw, local_device: str):
        """Convert raw LLDP data to processed format"""
        return cls(
            local_device=local_device,
            local_interface=raw.local_port,
            remote_device=raw.neighbor_device,
            remote_interface=raw.neighbor_port,
        )

class NetworkConnection(BaseModel):
    device_a: str
    port_a: str
    device_b: str
    port_b: str
    source: str = Field(..., description="lldp or netbox")
    first_seen: datetime
    last_seen: datetime

    @validator('device_a', 'device_b', pre=True)
    def lowercase_hostnames(cls, v):
        return v.lower()

    @validator('port_a', 'port_b', pre=True)
    def normalize_interface_names(cls, v):
        # Standardize interface names (e.g., "port1" -> "port1", "1/0/1" -> "port1.0.1")
        return v.replace("/", ".").replace(" ", "").lower()

class TopologyDifference(BaseModel):
    missing_in_netbox: List[NetworkConnection] = []
    missing_in_lldp: List[NetworkConnection] = []
    mismatched_ports: List[NetworkConnection] = []

class TopologyCheck(BaseModel):
    """Database model for topology check results"""
    id: Optional[int] = None
    timestamp: datetime
    lldp_count: int
    netbox_count: int
    mismatch_count: int

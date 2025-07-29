#!/usr/bin/env python3
"""
Test script to validate Pydantic models against actual JSON data
"""

import json
from typing import List
from models import LLDPNeighborRaw, LLDPNeighbor
from config import settings

def test_json_compatibility():
    """Test if our models can parse the actual JSON data"""
    print("🧪 Testing JSON compatibility with Pydantic models...")

    try:
        # Load the actual JSON data
        with open('lldp_neighbors.json', 'r') as f:
            raw_data = json.load(f)

        print(f"📄 Loaded {len(raw_data)} records from lldp_neighbors.json")

        # Test parsing with LLDPNeighborRaw model
        parsed_neighbors = []
        for i, neighbor_data in enumerate(raw_data):
            try:
                neighbor = LLDPNeighborRaw(**neighbor_data)
                parsed_neighbors.append(neighbor)
                print(f"✅ Record {i+1}: {neighbor.local_port} -> {neighbor.neighbor_device}:{neighbor.neighbor_port}")
            except Exception as e:
                print(f"❌ Record {i+1} failed: {e}")
                return False

        print(f"\n🎉 Successfully parsed all {len(parsed_neighbors)} LLDP neighbor records!")

        # Test conversion to internal format
        print("\n🔄 Testing conversion to internal format...")
        local_device_name = "TEST-SWITCH"  # This would come from device config

        internal_neighbors = []
        for raw_neighbor in parsed_neighbors[:3]:  # Test first 3
            internal = LLDPNeighbor.from_raw(raw_neighbor, local_device_name)
            internal_neighbors.append(internal)
            print(f"✅ Converted: {internal.local_device}:{internal.local_interface} -> {internal.remote_device}:{internal.remote_interface}")

        print("\n✅ All model validations passed!")
        return True

    except FileNotFoundError:
        print("❌ lldp_neighbors.json not found!")
        return False
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        return False

def test_config_loading():
    """Test if configuration loads properly"""
    print("\n🔧 Testing configuration loading...")

    try:
        print(f"Database path: {settings.database_path}")
        print(f"Monitor interval: {settings.monitor_interval_minutes} minutes")
        print(f"Alert threshold: {settings.alert_threshold}")
        print(f"FortiGate devices: {settings.fgt_devices}")
        print(f"FortiGate username: {settings.fgt_username}")
        print(f"Email enabled: {settings.email_enabled}")
        print(f"Log level: {settings.log_level}")
        print(f"Log file: {settings.log_file}")

        # Test backward compatibility
        print("\n🔄 Testing backward compatibility...")
        print(f"settings.database.path: {settings.database.path}")
        print(f"settings.monitoring.interval_minutes: {settings.monitoring.interval_minutes}")
        print(f"settings.fortigate.devices: {settings.fortigate.devices}")
        print(f"settings.email.enabled: {settings.email.enabled}")
        print(f"settings.logging.level: {settings.logging.level}")

        print("✅ Configuration loaded successfully!")
        return True

    except Exception as e:
        print(f"❌ Configuration loading failed: {e}")
        print("💡 Make sure you have a .env file with all required variables")
        return False

def test_device_parsing():
    """Test device parsing from configuration"""
    print("\n📱 Testing device parsing...")

    try:
        from main_monitor import FortinetTopologyMonitor

        monitor = FortinetTopologyMonitor()
        devices = monitor.devices

        print(f"Found {len(devices)} configured devices:")
        for i, device in enumerate(devices, 1):
            print(f"  {i}. {device['name']} ({device['ip']}) - Port: {device['port']}")

        if len(devices) > 0:
            print("✅ Device parsing successful!")
            return True
        else:
            print("❌ No devices found - check FGT_DEVICES in .env")
            return False

    except Exception as e:
        print(f"❌ Device parsing failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Fortinet Topology Monitor - Validation Tests")
    print("=" * 50)

    # Test configuration first
    config_ok = test_config_loading()

    # Test device parsing
    device_ok = test_device_parsing()

    # Test JSON parsing
    json_ok = test_json_compatibility()

    print("\n" + "=" * 50)
    if config_ok and device_ok and json_ok:
        print("🎉 All tests passed! Your setup is ready.")
        print("\n💡 Next steps:")
        print("  1. Run './run.sh' and choose option 1 for web dashboard")
        print("  2. Or choose option 2 for CLI monitoring")
        exit(0)
    else:
        print("❌ Some tests failed. Please fix the issues above.")
        exit(1)

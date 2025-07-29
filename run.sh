#!/bin/bash

# Fortinet Topology Monitor - Local Development Run Script

set -e  # Exit on any error

echo "🚀 Starting Fortinet Topology Monitor (Local Development Mode)"
echo "================================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check Python version
print_header "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
print_status "Found Python $PYTHON_VERSION"

# Check if Python version is 3.8 or higher
if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
    print_status "Python version is compatible"
else
    print_error "Python 3.8 or higher is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment if it doesn't exist
print_header "Setting up virtual environment..."
if [ ! -d "venv" ]; then
    print_status "Creating virtual environment..."
    python3 -m venv venv
    print_status "Virtual environment created successfully"
else
    print_status "Virtual environment already exists"
fi

# Activate virtual environment
print_header "Activating virtual environment..."
source venv/bin/activate

# Verify we're in the virtual environment
if [[ "$VIRTUAL_ENV" != "" ]]; then
    print_status "Virtual environment activated: $VIRTUAL_ENV"
else
    print_error "Failed to activate virtual environment"
    exit 1
fi

# Upgrade pip
print_header "Upgrading pip..."
#pip install --upgrade pip

# Install dependencies
print_header "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_status "Dependencies installed successfully"
else
    print_error "requirements.txt not found!"
    exit 1
fi

# Check if .env file exists
print_header "Checking configuration..."
if [ ! -f ".env" ]; then
    print_warning "No .env file found. Creating from template..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
        print_status "Created .env file from template"
        echo ""
        print_warning "⚠️  IMPORTANT: Please edit the .env file with your configuration!"
        print_warning "   Required settings:"
        print_warning "   - NETBOX_URL and NETBOX_TOKEN (if using Netbox)"
        print_warning "   - Email settings (if using email alerts)"
        print_warning "   - Device credentials (will be added to services.py)"
        echo ""
        read -p "Press Enter to continue after editing .env file, or Ctrl+C to exit..."
    else
        print_error ".env.example template not found!"
        exit 1
    fi
else
    print_status "Configuration file (.env) found"
fi

# Check if required JSON data file exists
print_header "Checking data files..."
if [ ! -f "lldp_neighbors.json" ]; then
    print_warning "lldp_neighbors.json not found. This is needed for validation tests."
    print_warning "You can skip validation tests if you don't have sample data yet."
fi

# Create necessary directories
print_header "Creating directories..."
mkdir -p logs
mkdir -p data
print_status "Created logs and data directories"

# Run validation tests if data file exists
if [ -f "lldp_neighbors.json" ]; then
    print_header "Running validation tests..."
    if python test_validation.py; then
        print_status "✅ Validation tests passed!"
    else
        print_error "❌ Validation tests failed!"
        echo ""
        print_warning "You can still continue, but there might be configuration issues."
        read -p "Continue anyway? (y/N): " continue_choice
        if [[ ! "$continue_choice" =~ ^[Yy]$ ]]; then
            print_status "Exiting. Please fix the issues and try again."
            exit 1
        fi
    fi
else
    print_warning "Skipping validation tests (no sample data file)"
fi

# Show menu for run mode
echo ""
print_header "Select run mode:"
echo "1) 🌐 Web API Server with Dashboard (Recommended)"
echo "2) 🔄 CLI Monitor Only (Background monitoring)"
echo "3) 🧪 Run validation tests only"
echo "4) 🛠️  Interactive Python shell (for debugging)"
echo "5) 📊 Show system status"
echo ""

read -p "Enter choice (1-5): " choice

case $choice in
    1)
        print_header "Starting Web API Server with Dashboard..."
        print_status "Dashboard will be available at: http://localhost:8000/dashboard"
        print_status "API documentation at: http://localhost:8000/docs"
        print_status "Press Ctrl+C to stop the server"
        echo ""
        python web_api.py
        ;;
    2)
        print_header "Starting CLI Monitor..."
        print_status "Monitor will run in the background. Check logs/topology_monitor.log for output"
        print_status "Press Ctrl+C to stop the monitor"
        echo ""
        python main_monitor.py
        ;;
    3)
        print_header "Running validation tests..."
        if [ -f "lldp_neighbors.json" ]; then
            python test_validation.py
        else
            print_error "lldp_neighbors.json not found. Cannot run validation tests."
            exit 1
        fi
        ;;
    4)
        print_header "Starting interactive Python shell..."
        print_status "All modules are available for import. Try:"
        print_status "  from models import *"
        print_status "  from services import *"
        print_status "  from config import settings"
        echo ""
        python -i -c "
import sys
sys.path.append('.')
print('Fortinet Topology Monitor - Interactive Shell')
print('All modules available for import')
"
        ;;
    5)
        print_header "System Status Check..."
        python -c "
import asyncio
from main_monitor import FortinetTopologyMonitor
from config import settings

async def show_status():
    try:
        monitor = FortinetTopologyMonitor()
        await monitor.initialize()

        print('\n📊 System Status:')
        print(f'  Database Path: {settings.database.path}')
        print(f'  Monitoring Interval: {settings.monitoring.interval_minutes} minutes')
        print(f'  Alert Threshold: {settings.monitoring.alert_threshold}')
        print(f'  Devices Configured: {len(monitor.devices)}')

        if monitor.devices:
            print('\n📱 Configured Devices:')
            for device in monitor.devices:
                print(f'  - {device.name} ({device.ip_address}) - {device.device_type.value}')

        # Check database
        history = await monitor.repository.get_topology_history(days=1)
        print(f'\n📈 Recent Checks: {len(history)} in last 24 hours')

        await monitor.shutdown()
        print('\n✅ System status check completed')

    except Exception as e:
        print(f'\n❌ Status check failed: {e}')

asyncio.run(show_status())
"
        ;;
    *)
        print_error "Invalid choice. Exiting."
        exit 1
        ;;
esac

print_status "\nExiting Fortinet Topology Monitor"

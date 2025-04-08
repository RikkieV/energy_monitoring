#!/bin/bash

# Create directory structure
mkdir -p energy_monitoring/static energy_monitoring/templates
cd energy_monitoring

# Create Dockerfile
cat << 'EOF' > Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies for building Python packages
RUN apt-get update && apt-get install -y \
    openssl \
    gcc \
    python3-dev \
    libffi-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Ensure pip is installed and up-to-date
RUN python -m ensurepip --upgrade \
    && python -m pip install --upgrade pip

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Debug: Verify each package installation individually
RUN python -c "import requests" && echo "requests OK" || echo "requests failed"
RUN python -c "import pymodbus" && echo "pymodbus OK" || echo "pymodbus failed"
RUN python -c "import serial" && echo "pyserial OK" || echo "pyserial failed"
RUN python -c "import influxdb_client" && echo "influxdb_client OK" || echo "influxdb_client failed"
RUN python -c "import tapo" && echo "tapo OK" || echo "tapo failed"
RUN python -c "import flask" && echo "flask OK" || echo "flask failed"

# Corrected verification step
RUN python -c "import requests, pymodbus, serial, influxdb_client, tapo, flask" || exit 1

COPY app.py energy_monitoring.py config_utility.py web_config.py ./
COPY static/ ./static/
COPY templates/ ./templates/

RUN touch devices.json && \
    chown root:root devices.json && \
    chmod 600 devices.json

CMD ["python", "energy_monitoring.py"]
EOF

# Create docker-compose.yml
cat << 'EOF' > docker-compose.yml
version: '3.8'

services:
  traefik:
    image: traefik:latest
    command:
      - "--api"
      - "--providers.docker=true"
      - "--providers.docker.exposedByDefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entryPoints.web.http.redirections.entryPoint.to=websecure"
      - "--entryPoints.web.http.redirections.entryPoint.scheme=https"
      - "--certificatesResolvers.myresolver.acme.httpChallenge=true"
      - "--certificatesResolvers.myresolver.acme.httpChallenge.entryPoint=web"
      - "--certificatesResolvers.myresolver.acme.email=admin@${DOMAIN}"
      - "--certificatesResolvers.myresolver.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - ./letsencrypt:/letsencrypt
      - /var/run/docker.sock:/var/run/docker.sock:ro
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.api.rule=Host(`${DOMAIN}`) && PathPrefix(`/dashboard`)"
      - "traefik.http.routers.api.entrypoints=websecure"
      - "traefik.http.routers.api.tls=true"
      - "traefik.http.routers.api.tls.certresolver=myresolver"
      - "traefik.http.routers.api.service=api@internal"
      - "traefik.http.routers.api.middlewares=auth"
      - "traefik.http.middlewares.auth.basicauth.users=admin:$apr1$YOUR_HASH_HERE"
    networks:
      - energy-net

  app:
    build: .
    volumes:
      - ./devices.json:/app/devices.json
      - ./energy_monitoring.log:/app/energy_monitoring.log
    environment:
      - PYTHONUNBUFFERED=1
    depends_on:
      - influxdb
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`${DOMAIN}`)"
      - "traefik.http.routers.app.entrypoints=websecure"
      - "traefik.http.routers.app.tls=true"
      - "traefik.http.routers.app.tls.certresolver=myresolver"
      - "traefik.http.services.app.loadbalancer.server.port=5000"
    networks:
      - energy-net

  web_config:
    build: .
    command: ["python", "web_config.py"]
    volumes:
      - ./devices.json:/app/devices.json
    ports:
      - "5001:5001"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.web_config.rule=Host(`${DOMAIN}`) && PathPrefix(`/config`)"
      - "traefik.http.routers.web_config.entrypoints=websecure"
      - "traefik.http.routers.web_config.tls=true"
      - "traefik.http.routers.web_config.tls.certresolver=myresolver"
      - "traefik.http.middlewares.web_config-stripprefix.stripprefix.prefixes=/config"
      - "traefik.http.routers.web_config.middlewares=web_config-stripprefix"
      - "traefik.http.services.web_config.loadbalancer.server.port=5001"
    networks:
      - energy-net

  influxdb:
    image: influxdb:2.7
    volumes:
      - influxdb-data:/var/lib/influxdb2
    environment:
      - DOCKER_INFLUXDB_INIT_MODE=setup
      - DOCKER_INFLUXDB_INIT_USERNAME=${INFLUXDB_USERNAME}
      - DOCKER_INFLUXDB_INIT_PASSWORD=${INFLUXDB_PASSWORD}
      - DOCKER_INFLUXDB_INIT_ORG=${INFLUXDB_ORG}
      - DOCKER_INFLUXDB_INIT_BUCKET=${INFLUXDB_BUCKET}
      - DOCKER_INFLUXDB_INIT_ADMIN_TOKEN=${INFLUXDB_TOKEN}
    ports:
      - "8086:8086"
    networks:
      - energy-net

  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana-data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_USER=${GRAFANA_USERNAME}
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.grafana.rule=Host(`${DOMAIN}`) && PathPrefix(`/grafana`)"
      - "traefik.http.routers.grafana.entrypoints=websecure"
      - "traefik.http.routers.grafana.tls=true"
      - "traefik.http.routers.grafana.tls.certresolver=myresolver"
      - "traefik.http.middlewares.grafana-stripprefix.stripprefix.prefixes=/grafana"
      - "traefik.http.routers.grafana.middlewares=grafana-stripprefix"
      - "traefik.http.services.grafana.loadbalancer.server.port=3000"
    networks:
      - energy-net

volumes:
  influxdb-data:
  grafana-data:
  letsencrypt:

networks:
  energy-net:
    driver: bridge
EOF

# Create setup_docker.sh
cat << 'EOF' > setup_docker.sh
#!/bin/bash

set -e

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install a package if not already installed
install_package() {
    local package=$1
    if ! dpkg -l | grep -q " $package "; then
        echo "Installing $package..."
        sudo apt-get install -y "$package"
    else
        echo "$package is already installed."
    fi
}

echo "Starting setup process for Energy Monitoring System on Raspberry Pi 5..."

# Update package list
echo "Updating package list..."
sudo apt-get update

# Install essential system dependencies
echo "Installing system dependencies..."
install_package "curl"
install_package "apt-transport-https"
install_package "ca-certificates"
install_package "software-properties-common"
install_package "python3"
install_package "python3-pip"
install_package "python3-venv"
install_package "python3-dev"
install_package "gcc"
install_package "jq"
install_package "apache2-utils"  # For htpasswd

# Install Docker if not present
if ! command_exists docker; then
    echo "Installing Docker for ARM64..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo systemctl enable docker
    sudo systemctl start docker
    sudo usermod -aG docker $USER
    rm get-docker.sh
else
    echo "Docker is already installed."
fi

# Install Docker Compose if not present
if ! command_exists docker-compose; then
    echo "Installing Docker Compose for ARM64..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
else
    echo "Docker Compose is already installed."
fi

# Create and activate a virtual environment
echo "Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

# Ensure pip is installed and up-to-date within the venv
echo "Ensuring pip is installed and up-to-date in virtual environment..."
python -m ensurepip --upgrade
python -m pip install --upgrade pip

# Install Python dependencies in the virtual environment
echo "Installing Python dependencies in virtual environment..."
if [ -f "requirements.txt" ]; then
    python -m pip install -r requirements.txt
else
    echo "Creating and installing requirements.txt..."
    cat << REQEOF > requirements.txt
requests
pymodbus>=3.0.0
pyserial
influxdb-client
tapo
flask
REQEOF
    python -m pip install -r requirements.txt
fi

# Verify key dependencies are installed in venv
echo "Verifying installed dependencies in venv..."
for pkg in requests pymodbus pyserial influxdb_client tapo flask; do
    if python -c "import $pkg" 2>/dev/null; then
        echo "$pkg is installed in venv."
    else
        echo "Error: $pkg is not installed in venv. Installing now..."
        python -m pip install "$pkg"
    fi
done

# Prompt for domain name
echo "Please enter your domain name (e.g., example.com):"
read DOMAIN
if [ -z "$DOMAIN" ]; then
    echo "Domain name cannot be empty. Exiting."
    exit 1
fi

# Prompt for Traefik dashboard password
echo "Please enter a password for the Traefik dashboard (username: admin):"
read -s TRAEFIK_PASSWORD
if [ -z "$TRAEFIK_PASSWORD" ]; then
    echo "Password cannot be empty. Exiting."
    exit 1
fi

# Generate Traefik password hash
TRAEFIK_HASH=$(htpasswd -nb admin "$TRAEFIK_PASSWORD" | sed 's/\//\\\//g')
echo "Generated Traefik password hash: $TRAEFIK_HASH"

# Update docker-compose.yml with the hash
if [ -f "docker-compose.yml" ]; then
    sed -i "s/admin:\$apr1\$YOUR_HASH_HERE/$TRAEFIK_HASH/" docker-compose.yml
    echo "Updated docker-compose.yml with Traefik password hash."
else
    echo "Error: docker-compose.yml not found. Please ensure it exists before running this script."
    exit 1
fi

# Run CLI configuration utility within the virtual environment
echo "Running CLI configuration utility to generate initial devices.json..."
python config_utility.py

# Deactivate virtual environment
deactivate

# Set permissions for devices.json
echo "Setting permissions for devices.json..."
sudo chown root:root devices.json
sudo chmod 600 devices.json

# Create .env file
echo "Creating .env file with configuration..."
cat << EOF > .env
DOMAIN=$DOMAIN
INFLUXDB_USERNAME=$(jq -r '.database.username' devices.json)
INFLUXDB_PASSWORD=$(jq -r '.database.password' devices.json)
INFLUXDB_ORG=$(jq -r '.database.org' devices.json)
INFLUXDB_BUCKET=$(jq -r '.database.bucket' devices.json)
INFLUXDB_TOKEN=$(jq -r '.database.token' devices.json)
GRAFANA_USERNAME=$(jq -r '.security.grafana_username' devices.json)
GRAFANA_PASSWORD=$(jq -r '.security.grafana_password' devices.json)
EOF

# Build and start Docker Compose services
echo "Building and starting Docker Compose services..."
docker-compose up -d --build

# Wait for Traefik to obtain certificates
echo "Waiting for Traefik to obtain certificates (this may take a moment)..."
sleep 20
docker-compose logs traefik

# Display setup completion message
echo "Setup complete!"
echo "Energy Flow Diagram: https://$DOMAIN"
echo "Grafana: https://$DOMAIN/grafana (login: $(jq -r '.security.grafana_username' devices.json)/$(jq -r '.security.grafana_password' devices.json))"
echo "Web Config Utility: https://$DOMAIN/config"
echo "Traefik Dashboard: https://$DOMAIN/dashboard (login: admin/<your_password>)"
echo "InfluxDB: http://localhost:8086"
echo "Check container status: docker-compose ps"

echo "You can now access the web configuration utility at https://$DOMAIN/config to further customize settings."
echo "Note: If using serial devices, ensure they are mapped in docker-compose.yml (e.g., /dev/ttyUSB0)."
EOF

# Create requirements.txt
cat << 'EOF' > requirements.txt
requests
pymodbus>=3.0.0
pyserial
influxdb-client
tapo
flask
EOF

# Create app.py
cat << 'EOF' > app.py
from flask import Flask, jsonify, request
import json
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_config():
    with open("devices.json", "r") as f:
        return json.load(f)

@app.route('/energy-data', methods=['GET'])
def get_energy_data():
    config = load_config()
    api_key = config["security"]["flask_api_key"]
    if request.headers.get("X-API-Key") != api_key:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"message": "Energy data endpoint (placeholder)"}), 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
EOF

# Create energy_monitoring.py
cat << 'EOF' > energy_monitoring.py
import json
import time
import logging
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_config():
    with open("devices.json", "r") as f:
        return json.load(f)

def monitor_energy():
    config = load_config()
    logger.info("Starting energy monitoring...")
    while True:
        for device in config["devices"]:
            if device["communication"]["type"] == "modbus_tcp":
                try:
                    client = ModbusTcpClient(device["communication"]["ip"], port=device["communication"]["port"])
                    if client.connect():
                        logger.info(f"Connected to {device['name']} ({device['vendor']})")
                        client.close()
                    else:
                        logger.warning(f"Failed to connect to {device['name']}")
                except Exception as e:
                    logger.error(f"Error with {device['name']}: {str(e)}")
            else:
                logger.info(f"Monitoring {device['name']} ({device['vendor']}) - Placeholder")
        time.sleep(config["visualization"]["update_interval"])

if __name__ == "__main__":
    monitor_energy()
EOF

# Create config_utility.py
cat << 'EOF' > config_utility.py
import json
import os
import secrets
import requests
import subprocess
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, BucketRetentionRules
from influxdb_client.client.write_api import SYNCHRONOUS
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SMA_REGISTERS = {
    "SMA": {"power": 30775, "energy": 30529},
    "SMA_EVCharger": {"power": 30775, "energy": 30529},
    "SMA_Tripower_Battery": {"power": 30845, "energy": 30847, "soc": 30865, "temperature": 30867},
    "DTS353F": {"power": 0, "energy": 256}
}

VENDORS = {
    "SolarEdge": {"comm_type": "api", "default_group": "PV"},
    "SMA": {"comm_type": "modbus_tcp", "default_group": "PV"},
    "Growatt": {"comm_type": "modbus_tcp", "default_group": "PV"},
    "Enphase": {"comm_type": "api", "default_group": "PV"},
    "Soladin600": {"comm_type": "serial", "default_group": "PV"},
    "DSMR": {"comm_type": "serial", "default_group": "Meter"},
    "SMA_EVCharger": {"comm_type": "modbus_tcp", "default_group": "EV"},
    "Bender_CC613": {"comm_type": "modbus_tcp", "default_group": "EV"},
    "Alfen_EVCharger": {"comm_type": "modbus_tcp", "default_group": "EV"},
    "AlphaInnotec": {"comm_type": "modbus_tcp", "default_group": "Heatpump"},
    "Shelly": {"comm_type": "api", "default_group": "Consumer"},
    "Tapo": {"comm_type": "api", "default_group": "Consumer"},
    "SMA_Tripower_Battery": {"comm_type": "modbus_tcp", "default_group": "Battery"},
    "DTS353F": {"comm_type": "modbus_rtu_over_tcp", "default_group": "Meter"}
}

GROUPS = ["PV", "Battery", "EV", "Heatpump", "Meter", "Consumer"]

def get_user_input(prompt, default=None):
    value = input(f"{prompt} [{'default' if default is None else default}]: ").strip()
    return value if value else default

def configure_database(existing_config=None):
    print("\nConfiguring InfluxDB Database")
    default_config = existing_config or {
        "url": "http://influxdb:8086",
        "token": secrets.token_hex(16),
        "org": "energy_org",
        "bucket": "energy_data",
        "username": "admin",
        "password": "admin1234"
    }
    url = get_user_input("InfluxDB URL", default_config["url"])
    username = get_user_input("InfluxDB Username", default_config["username"])
    password = get_user_input("InfluxDB Password", default_config["password"])
    token = get_user_input("InfluxDB Token", default_config["token"])
    org = get_user_input("InfluxDB Org", default_config["org"])
    bucket = get_user_input("InfluxDB Bucket", default_config["bucket"])
    return {"url": url, "username": username, "password": password, "token": token, "org": org, "bucket": bucket}

def configure_visualization(existing_config=None):
    print("\nConfiguring Visualization Settings")
    default_interval = existing_config.get("update_interval", 5) if existing_config else 5
    update_interval = int(get_user_input("Energy flow diagram update interval (seconds)", default_interval))
    return {"update_interval": update_interval}

def configure_security(existing_config=None):
    print("\nConfiguring Security Settings")
    default_config = existing_config or {
        "grafana_username": "admin",
        "grafana_password": "admin1234",
        "flask_api_key": secrets.token_hex(16)
    }
    grafana_username = get_user_input("Grafana Username", default_config["grafana_username"])
    grafana_password = get_user_input("Grafana Password", default_config["grafana_password"])
    flask_api_key = get_user_input("Flask API Key", default_config["flask_api_key"])
    return {"grafana_username": grafana_username, "grafana_password": grafana_password, "flask_api_key": flask_api_key}

def configure_device(index, existing_device=None):
    print(f"\nConfiguring Device {index + 1}")
    default_name = existing_device["name"] if existing_device else f"Device_{index + 1}"
    name = get_user_input("Device name", default_name)
    
    print("Available vendors:", ", ".join(VENDORS.keys()))
    default_vendor = existing_device["vendor"] if existing_device else "SMA"
    vendor = get_user_input("Vendor", default_vendor)
    if vendor not in VENDORS:
        print(f"Unsupported vendor. Using SMA as default.")
        vendor = "SMA"
    
    default_group = existing_device["group"] if existing_device else VENDORS[vendor]["default_group"]
    group = get_user_input(f"Group (default: {VENDORS[vendor]['default_group']})", default_group)
    if group not in GROUPS:
        print(f"Unsupported group. Using {VENDORS[vendor]['default_group']} as default.")
        group = VENDORS[vendor]["default_group"]
    
    default_interval = existing_device.get("interval", 10) if existing_device else 10
    interval = int(get_user_input("Measurement interval (seconds)", default_interval))
    
    comm_type = VENDORS[vendor]["comm_type"]
    comm = {"type": comm_type}
    existing_comm = existing_device["communication"] if existing_device else {}
    
    if comm_type == "modbus_tcp":
        comm["ip"] = get_user_input("IP address", existing_comm.get("ip", "192.168.1.100"))
        comm["port"] = int(get_user_input("Port", existing_comm.get("port", "502")))
        comm["slave_id"] = int(get_user_input("Slave ID", existing_comm.get("slave_id", "3")))
        comm["registers"] = SMA_REGISTERS.get(vendor, {"power": 0, "energy": 0}).copy()
        if vendor == "SMA_Tripower_Battery":
            comm["registers"]["soc"] = 30865
            comm["registers"]["temperature"] = 30867
        existing_regs = existing_comm.get("registers", {})
        for reg in comm["registers"]:
            comm["registers"][reg] = int(get_user_input(f"{reg.capitalize()} register", existing_regs.get(reg, comm["registers"][reg])))
    
    elif comm_type == "modbus_rtu_over_tcp":
        comm["ip"] = get_user_input("Moxa NPort IP address", existing_comm.get("ip", "192.168.1.200"))
        comm["port"] = int(get_user_input("Moxa NPort TCP port", existing_comm.get("port", "4001")))
        comm["slave_id"] = int(get_user_input("Slave ID", existing_comm.get("slave_id", "1")))
        comm["baudrate"] = int(get_user_input("Baudrate", existing_comm.get("baudrate", "9600")))
        comm["parity"] = get_user_input("Parity (N/E/O)", existing_comm.get("parity", "N"))
        comm["stopbits"] = int(get_user_input("Stop bits", existing_comm.get("stopbits", "1")))
        comm["timeout"] = float(get_user_input("Timeout (seconds)", existing_comm.get("timeout", "1")))
        comm["registers"] = SMA_REGISTERS.get(vendor, {"power": 0, "energy": 256}).copy()
        existing_regs = existing_comm.get("registers", {})
        for reg in comm["registers"]:
            comm["registers"][reg] = int(get_user_input(f"{reg.capitalize()} register", existing_regs.get(reg, comm["registers"][reg])))
    
    elif comm_type == "api" and vendor == "SolarEdge":
        comm["url"] = existing_comm.get("url", "https://monitoringapi.solaredge.com/site/{site_id}/overview")
        comm["api_key"] = get_user_input("API key", existing_comm.get("api_key", "your_solaredge_key"))
        comm["site_id"] = get_user_input("Site ID", existing_comm.get("site_id", "your_site_id"))
        comm["timeout"] = int(get_user_input("Timeout (seconds)", existing_comm.get("timeout", "5")))
    
    return {"name": name, "vendor": vendor, "group": group, "interval": interval, "communication": comm}

def manage_devices(devices):
    while True:
        print(f"\nCurrent devices ({len(devices)}):")
        for i, dev in enumerate(devices):
            print(f"{i + 1}. {dev['name']} ({dev['vendor']}, {dev['group']}, Interval: {dev['interval']}s)")
        print("\nDevice Management Options:")
        print("1. Add a device")
        print("2. Edit a device")
        print("3. Remove a device")
        print("4. Back to main menu")
        choice = get_user_input("Select an option (1-4)", "4")
        
        if choice == "1":
            devices.append(configure_device(len(devices)))
        elif choice == "2":
            index = int(get_user_input("Device number to edit (1-based)", "1")) - 1
            if 0 <= index < len(devices):
                devices[index] = configure_device(index, devices[index])
            else:
                print("Invalid device number.")
        elif choice == "3":
            index = int(get_user_input("Device number to remove (1-based)", "1")) - 1
            if 0 <= index < len(devices):
                devices.pop(index)
            else:
                print("Invalid device number.")
        elif choice == "4":
            break
        else:
            print("Invalid option. Please try again.")
    return devices

def check_status(config):
    print("\nChecking Status of Components...")
    try:
        db_config = config["database"]
        client = InfluxDBClient(url=db_config["url"], token=db_config["token"], org=db_config["org"])
        health = client.health()
        if health.status == "pass":
            logger.info(f"InfluxDB at {db_config['url']} is reachable and healthy.")
        else:
            logger.warning(f"InfluxDB at {db_config['url']} is reachable but unhealthy: {health.message}")
    except Exception as e:
        logger.error(f"InfluxDB at {db_config['url']} is not reachable: {str(e)}")
    
    try:
        security_config = config["security"]
        response = requests.get("http://app:5000/energy-data", headers={"X-API-Key": security_config["flask_api_key"]}, timeout=5)
        if response.status_code == 200:
            logger.info("Flask API at http://app:5000/energy-data is reachable and authenticated.")
        elif response.status_code == 401:
            logger.info("Flask API at http://app:5000/energy-data is reachable but API key is invalid.")
        else:
            logger.warning(f"Flask API at http://app:5000/energy-data returned unexpected status: {response.status_code}")
    except Exception as e:
        logger.error(f"Flask API at http://app:5000/energy-data is not reachable: {str(e)}")
    
    try:
        grafana_config = config["security"]
        response = requests.get(f"http://grafana:3000/api/health", auth=(grafana_config["grafana_username"], grafana_config["grafana_password"]), timeout=5)
        if response.status_code == 200:
            logger.info("Grafana at http://grafana:3000 is reachable and authenticated.")
        else:
            logger.warning(f"Grafana at http://grafana:3000 returned unexpected status: {response.status_code}")
    except Exception as e:
        logger.error(f"Grafana at http://grafana:3000 is not reachable: {str(e)}")
    
    devices = config.get("devices", [])
    if not devices:
        logger.info("No devices configured to check.")
    for i, device in enumerate(devices):
        print(f"\nChecking Device {i + 1}: {device['name']} ({device['vendor']})")
        comm = device["communication"]
        if comm["type"] == "modbus_tcp":
            try:
                client = ModbusTcpClient(comm["ip"], port=comm["port"])
                if client.connect():
                    logger.info(f"Device {device['name']} at {comm['ip']}:{comm['port']} (Modbus TCP) is reachable.")
                    client.close()
                else:
                    logger.warning(f"Device {device['name']} at {comm['ip']}:{comm['port']} (Modbus TCP) connection failed.")
            except Exception as e:
                logger.error(f"Device {device['name']} at {comm['ip']}:{comm['port']} (Modbus TCP) is not reachable: {str(e)}")
        elif comm["type"] == "api" and device["vendor"] == "SolarEdge":
            try:
                url = comm["url"].format(site_id=comm["site_id"])
                response = requests.get(url, params={"api_key": comm["api_key"]}, timeout=comm["timeout"])
                if response.status_code == 200:
                    logger.info(f"Device {device['name']} at {url} (SolarEdge API) is reachable.")
                else:
                    logger.warning(f"Device {device['name']} at {url} (SolarEdge API) returned status: {response.status_code}")
            except Exception as e:
                logger.error(f"Device {device['name']} at {url} (SolarEdge API) is not reachable: {str(e)}")
        else:
            logger.info(f"Device {device['name']} ({comm['type']}) status check not implemented yet.")

def manage_docker_containers():
    print("\nDocker Container Management")
    print("1. Start containers")
    print("2. Stop containers")
    print("3. Update containers (pull and recreate)")
    print("4. Back to main menu")
    choice = get_user_input("Select an option (1-4)", "4")
    
    if choice == "1":
        try:
            subprocess.run(["docker-compose", "up", "-d"], check=True)
            logger.info("Docker containers started successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start Docker containers: {str(e)}")
    elif choice == "2":
        try:
            subprocess.run(["docker-compose", "down"], check=True)
            logger.info("Docker containers stopped successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop Docker containers: {str(e)}")
    elif choice == "3":
        try:
            subprocess.run(["docker-compose", "pull"], check=True)
            subprocess.run(["docker-compose", "up", "-d", "--force-recreate"], check=True)
            logger.info("Docker containers updated and restarted successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update Docker containers: {str(e)}")
    elif choice == "4":
        return
    else:
        print("Invalid option. Please try again.")

def database_maintenance(config):
    print("\nDatabase Maintenance")
    print("1. Clear bucket (delete all data)")
    print("2. Backup bucket")
    print("3. Back to main menu")
    choice = get_user_input("Select an option (1-3)", "3")
    
    db_config = config["database"]
    client = InfluxDBClient(url=db_config["url"], token=db_config["token"], org=db_config["org"])
    buckets_api = client.buckets_api()
    bucket_name = db_config["bucket"]
    
    if choice == "1":
        confirm = get_user_input(f"Are you sure you want to clear bucket '{bucket_name}'? (y/n)", "n").lower()
        if confirm == "y":
            try:
                bucket = buckets_api.find_bucket_by_name(bucket_name)
                if bucket:
                    buckets_api.delete_bucket(bucket)
                    buckets_api.create_bucket(bucket_name=bucket_name, org_id=client.orgs_api().find_organizations(org=db_config["org"])[0].id)
                    logger.info(f"Bucket '{bucket_name}' cleared successfully.")
                else:
                    logger.warning(f"Bucket '{bucket_name}' not found.")
            except Exception as e:
                logger.error(f"Failed to clear bucket '{bucket_name}': {str(e)}")
    elif choice == "2":
        backup_path = get_user_input("Enter backup file path", f"{bucket_name}_backup.jsonl")
        try:
            query = f'from(bucket:"{bucket_name}") |> range(start: -10y)'
            result = client.query_api().query(query=query)
            with open(backup_path, "w") as f:
                for table in result:
                    for record in table.records:
                        f.write(json.dumps(record.values) + "\n")
            logger.info(f"Bucket '{bucket_name}' backed up to '{backup_path}' successfully.")
        except Exception as e:
            logger.error(f"Failed to backup bucket '{bucket_name}': {str(e)}")
    elif choice == "3":
        return
    else:
        print("Invalid option. Please try again.")

def navigation_menu(config):
    while True:
        print("\nEnergy Monitoring Configuration Utility")
        print("1. Configure Database")
        print("2. Configure Visualization")
        print("3. Configure Security")
        print("4. Manage Devices")
        print("5. Check Status")
        print("6. Manage Docker Containers")
        print("7. Database Maintenance")
        print("8. Save and Exit")
        choice = get_user_input("Select an option (1-8)", "8")
        
        if choice == "1":
            config["database"] = configure_database(config.get("database"))
        elif choice == "2":
            config["visualization"] = configure_visualization(config.get("visualization"))
        elif choice == "3":
            config["security"] = configure_security(config.get("security"))
        elif choice == "4":
            config["devices"] = manage_devices(config.get("devices", []))
        elif choice == "5":
            check_status(config)
        elif choice == "6":
            manage_docker_containers()
        elif choice == "7":
            database_maintenance(config)
        elif choice == "8":
            break
        else:
            print("Invalid option. Please try again.")
    return config

def main():
    print("Energy Monitoring Configuration Utility")
    if os.path.exists("devices.json"):
        edit_existing = get_user_input("Edit existing config? (y/n)", "y").lower() == "y"
        if edit_existing:
            with open("devices.json", "r") as f:
                config = json.load(f)
            config = navigation_menu(config)
        else:
            config = {
                "database": configure_database(),
                "visualization": configure_visualization(),
                "security": configure_security(),
                "devices": []
            }
            config = navigation_menu(config)
    else:
        config = {
            "database": configure_database(),
            "visualization": configure_visualization(),
            "security": configure_security(),
            "devices": []
        }
        config = navigation_menu(config)
    
    with open("devices.json", "w") as f:
        json.dump(config, f, indent=2)
    print("Configuration saved to devices.json")

if __name__ == "__main__":
    main()
EOF

# Create web_config.py
cat << 'EOF' > web_config.py
import json
import os
import secrets
import requests
import subprocess
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, BucketRetentionRules
from influxdb_client.client.write_api import SYNCHRONOUS
from flask import Flask, render_template, request, redirect, url_for, flash
import logging

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SMA_REGISTERS = {
    "SMA": {"power": 30775, "energy": 30529},
    "SMA_EVCharger": {"power": 30775, "energy": 30529},
    "SMA_Tripower_Battery": {"power": 30845, "energy": 30847, "soc": 30865, "temperature": 30867},
    "DTS353F": {"power": 0, "energy": 256}
}

VENDORS = {
    "SolarEdge": {"comm_type": "api", "default_group": "PV"},
    "SMA": {"comm_type": "modbus_tcp", "default_group": "PV"},
    "Growatt": {"comm_type": "modbus_tcp", "default_group": "PV"},
    "Enphase": {"comm_type": "api", "default_group": "PV"},
    "Soladin600": {"comm_type": "serial", "default_group": "PV"},
    "DSMR": {"comm_type": "serial", "default_group": "Meter"},
    "SMA_EVCharger": {"comm_type": "modbus_tcp", "default_group": "EV"},
    "Bender_CC613": {"comm_type": "modbus_tcp", "default_group": "EV"},
    "Alfen_EVCharger": {"comm_type": "modbus_tcp", "default_group": "EV"},
    "AlphaInnotec": {"comm_type": "modbus_tcp", "default_group": "Heatpump"},
    "Shelly": {"comm_type": "api", "default_group": "Consumer"},
    "Tapo": {"comm_type": "api", "default_group": "Consumer"},
    "SMA_Tripower_Battery": {"comm_type": "modbus_tcp", "default_group": "Battery"},
    "DTS353F": {"comm_type": "modbus_rtu_over_tcp", "default_group": "Meter"}
}

GROUPS = ["PV", "Battery", "EV", "Heatpump", "Meter", "Consumer"]

def load_config():
    if os.path.exists("devices.json"):
        with open("devices.json", "r") as f:
            return json.load(f)
    return {
        "database": {"url": "http://influxdb:8086", "token": secrets.token_hex(16), "org": "energy_org", "bucket": "energy_data", "username": "admin", "password": "admin1234"},
        "visualization": {"update_interval": 5},
        "security": {"grafana_username": "admin", "grafana_password": "admin1234", "flask_api_key": secrets.token_hex(16)},
        "devices": []
    }

def save_config(config):
    with open("devices.json", "w") as f:
        json.dump(config, f, indent=2)

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/database', methods=['GET', 'POST'])
def database():
    config = load_config()
    if request.method == 'POST':
        config["database"] = {
            "url": request.form["url"],
            "username": request.form["username"],
            "password": request.form["password"],
            "token": request.form["token"],
            "org": request.form["org"],
            "bucket": request.form["bucket"]
        }
        save_config(config)
        flash("Database configuration saved successfully!")
        return redirect(url_for('index'))
    return render_template('database.html', config=config["database"])

@app.route('/visualization', methods=['GET', 'POST'])
def visualization():
    config = load_config()
    if request.method == 'POST':
        config["visualization"] = {"update_interval": int(request.form["update_interval"])}
        save_config(config)
        flash("Visualization configuration saved successfully!")
        return redirect(url_for('index'))
    return render_template('visualization.html', config=config["visualization"])

@app.route('/security', methods=['GET', 'POST'])
def security():
    config = load_config()
    if request.method == 'POST':
        config["security"] = {
            "grafana_username": request.form["grafana_username"],
            "grafana_password": request.form["grafana_password"],
            "flask_api_key": request.form["flask_api_key"]
        }
        save_config(config)
        flash("Security configuration saved successfully!")
        return redirect(url_for('index'))
    return render_template('security.html', config=config["security"])

@app.route('/devices', methods=['GET', 'POST'])
def devices():
    config = load_config()
    if request.method == 'POST':
        action = request.form.get("action")
        if action == "add":
            comm_type = VENDORS[request.form["vendor"]]["comm_type"]
            comm = {"type": comm_type}
            if comm_type == "modbus_tcp":
                comm.update({
                    "ip": request.form["ip"],
                    "port": int(request.form["port"]),
                    "slave_id": int(request.form["slave_id"]),
                    "registers": {
                        "power": int(request.form["power"]),
                        "energy": int(request.form["energy"])
                    }
                })
                if request.form["vendor"] == "SMA_Tripower_Battery":
                    comm["registers"].update({
                        "soc": int(request.form["soc"]),
                        "temperature": int(request.form["temperature"])
                    })
            elif comm_type == "api" and request.form["vendor"] == "SolarEdge":
                comm.update({
                    "url": request.form["url"],
                    "api_key": request.form["api_key"],
                    "site_id": request.form["site_id"],
                    "timeout": int(request.form["timeout"])
                })
            device = {
                "name": request.form["name"],
                "vendor": request.form["vendor"],
                "group": request.form["group"],
                "interval": int(request.form["interval"]),
                "communication": comm
            }
            config["devices"].append(device)
        elif action == "edit":
            index = int(request.form["index"])
            comm_type = VENDORS[request.form["vendor"]]["comm_type"]
            comm = {"type": comm_type}
            if comm_type == "modbus_tcp":
                comm.update({
                    "ip": request.form["ip"],
                    "port": int(request.form["port"]),
                    "slave_id": int(request.form["slave_id"]),
                    "registers": {
                        "power": int(request.form["power"]),
                        "energy": int(request.form["energy"])
                    }
                })
                if request.form["vendor"] == "SMA_Tripower_Battery":
                    comm["registers"].update({
                        "soc": int(request.form["soc"]),
                        "temperature": int(request.form["temperature"])
                    })
            elif comm_type == "api" and request.form["vendor"] == "SolarEdge":
                comm.update({
                    "url": request.form["url"],
                    "api_key": request.form["api_key"],
                    "site_id": request.form["site_id"],
                    "timeout": int(request.form["timeout"])
                })
            config["devices"][index] = {
                "name": request.form["name"],
                "vendor": request.form["vendor"],
                "group": request.form["group"],
                "interval": int(request.form["interval"]),
                "communication": comm
            }
        elif action == "remove":
            index = int(request.form["index"])
            config["devices"].pop(index)
        save_config(config)
        flash("Device configuration updated successfully!")
        return redirect(url_for('devices'))
    return render_template('devices.html', config=config, vendors=VENDORS.keys(), groups=GROUPS)

@app.route('/status')
def status():
    config = load_config()
    status_messages = []
    try:
        db_config = config["database"]
        client = InfluxDBClient(url=db_config["url"], token=db_config["token"], org=db_config["org"])
        health = client.health()
        if health.status == "pass":
            status_messages.append(f"InfluxDB at {db_config['url']} is reachable and healthy.")
        else:
            status_messages.append(f"InfluxDB at {db_config['url']} is reachable but unhealthy: {health.message}")
    except Exception as e:
        status_messages.append(f"InfluxDB at {db_config['url']} is not reachable: {str(e)}")
    
    try:
        security_config = config["security"]
        response = requests.get("http://app:5000/energy-data", headers={"X-API-Key": security_config["flask_api_key"]}, timeout=5)
        if response.status_code == 200:
            status_messages.append("Flask API at http://app:5000/energy-data is reachable and authenticated.")
        elif response.status_code == 401:
            status_messages.append("Flask API at http://app:5000/energy-data is reachable but API key is invalid.")
        else:
            status_messages.append(f"Flask API at http://app:5000/energy-data returned unexpected status: {response.status_code}")
    except Exception as e:
        status_messages.append(f"Flask API at http://app:5000/energy-data is not reachable: {str(e)}")
    
    try:
        grafana_config = config["security"]
        response = requests.get(f"http://grafana:3000/api/health", auth=(grafana_config["grafana_username"], grafana_config["grafana_password"]), timeout=5)
        if response.status_code == 200:
            status_messages.append("Grafana at http://grafana:3000 is reachable and authenticated.")
        else:
            status_messages.append(f"Grafana at http://grafana:3000 returned unexpected status: {response.status_code}")
    except Exception as e:
        status_messages.append(f"Grafana at http://grafana:3000 is not reachable: {str(e)}")
    
    for i, device in enumerate(config["devices"]):
        comm = device["communication"]
        if comm["type"] == "modbus_tcp":
            try:
                client = ModbusTcpClient(comm["ip"], port=comm["port"])
                if client.connect():
                    status_messages.append(f"Device {device['name']} at {comm['ip']}:{comm['port']} (Modbus TCP) is reachable.")
                    client.close()
                else:
                    status_messages.append(f"Device {device['name']} at {comm['ip']}:{comm['port']} (Modbus TCP) connection failed.")
            except Exception as e:
                status_messages.append(f"Device {device['name']} at {comm['ip']}:{comm['port']} (Modbus TCP) is not reachable: {str(e)}")
        elif comm["type"] == "api" and device["vendor"] == "SolarEdge":
            try:
                url = comm["url"].format(site_id=comm["site_id"])
                response = requests.get(url, params={"api_key": comm["api_key"]}, timeout=comm["timeout"])
                if response.status_code == 200:
                    status_messages.append(f"Device {device['name']} at {url} (SolarEdge API) is reachable.")
                else:
                    status_messages.append(f"Device {device['name']} at {url} (SolarEdge API) returned status: {response.status_code}")
            except Exception as e:
                status_messages.append(f"Device {device['name']} at {url} (SolarEdge API) is not reachable: {str(e)}")
        else:
            status_messages.append(f"Device {device['name']} ({comm['type']}) status check not implemented yet.")
    
    return render_template('status.html', status_messages=status_messages)

@app.route('/docker', methods=['GET', 'POST'])
def docker():
    if request.method == 'POST':
        action = request.form["action"]
        try:
            if action == "start":
                subprocess.run(["docker-compose", "up", "-d"], check=True)
                flash("Docker containers started successfully!")
            elif action == "stop":
                subprocess.run(["docker-compose", "down"], check=True)
                flash("Docker containers stopped successfully!")
            elif action == "update":
                subprocess.run(["docker-compose", "pull"], check=True)
                subprocess.run(["docker-compose", "up", "-d", "--force-recreate"], check=True)
                flash("Docker containers updated and restarted successfully!")
        except subprocess.CalledProcessError as e:
            flash(f"Failed to {action} Docker containers: {str(e)}", "error")
        return redirect(url_for('docker'))
    return render_template('docker.html')

@app.route('/db_maintenance', methods=['GET', 'POST'])
def db_maintenance():
    config = load_config()
    db_config = config["database"]
    client = InfluxDBClient(url=db_config["url"], token=db_config["token"], org=db_config["org"])
    buckets_api = client.buckets_api()
    
    if request.method == 'POST':
        action = request.form["action"]
        if action == "clear":
            try:
                bucket = buckets_api.find_bucket_by_name(db_config["bucket"])
                if bucket:
                    buckets_api.delete_bucket(bucket)
                    buckets_api.create_bucket(bucket_name=db_config["bucket"], org_id=client.orgs_api().find_organizations(org=db_config["org"])[0].id)
                    flash(f"Bucket '{db_config['bucket']}' cleared successfully!")
                else:
                    flash(f"Bucket '{db_config['bucket']}' not found.", "error")
            except Exception as e:
                flash(f"Failed to clear bucket '{db_config['bucket']}': {str(e)}", "error")
        elif action == "backup":
            backup_path = request.form["backup_path"] or f"{db_config['bucket']}_backup.jsonl"
            try:
                query = f'from(bucket:"{db_config["bucket"]}") |> range(start: -10y)'
                result = client.query_api().query(query=query)
                with open(backup_path, "w") as f:
                    for table in result:
                        for record in table.records:
                            f.write(json.dumps(record.values) + "\n")
                flash(f"Bucket '{db_config['bucket']}' backed up to '{backup_path}' successfully!")
            except Exception as e:
                flash(f"Failed to backup bucket '{db_config['bucket']}': {str(e)}", "error")
        return redirect(url_for('db_maintenance'))
    return render_template('db_maintenance.html', bucket=db_config["bucket"])

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)
EOF

# Create templates/base.html
cat << 'EOF' > templates/base.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Energy Monitoring Web Config</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        nav { margin-bottom: 20px; }
        nav a { margin-right: 10px; }
        .message { padding: 10px; margin: 10px 0; }
        .success { background-color: #dff0d8; color: #3c763d; }
        .error { background-color: #f2dede; color: #a94442; }
    </style>
</head>
<body>
    <nav>
        <a href="{{ url_for('index') }}">Home</a>
        <a href="{{ url_for('database') }}">Database</a>
        <a href="{{ url_for('visualization') }}">Visualization</a>
        <a href="{{ url_for('security') }}">Security</a>
        <a href="{{ url_for('devices') }}">Devices</a>
        <a href="{{ url_for('status') }}">Status</a>
        <a href="{{ url_for('docker') }}">Docker</a>
        <a href="{{ url_for('db_maintenance') }}">DB Maintenance</a>
    </nav>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
                <div class="message success">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
</body>
</html>
EOF

# Create templates/database.html
cat << 'EOF' > templates/database.html
{% extends "base.html" %}
{% block content %}
<h2>Configure Database</h2>
<form method="post">
    <label>InfluxDB URL:</label><br>
    <input type="text" name="url" value="{{ config.url }}" required><br><br>
    <label>Username:</label><br>
    <input type="text" name="username" value="{{ config.username }}" required><br><br>
    <label>Password:</label><br>
    <input type="text" name="password" value="{{ config.password }}" required><br><br>
    <label>Token:</label><br>
    <input type="text" name="token" value="{{ config.token }}" required><br><br>
    <label>Org:</label><br>
    <input type="text" name="org" value="{{ config.org }}" required><br><br>
    <label>Bucket:</label><br>
    <input type="text" name="bucket" value="{{ config.bucket }}" required><br><br>
    <input type="submit" value="Save">
</form>
{% endblock %}
EOF

# Create templates/visualization.html
cat << 'EOF' > templates/visualization.html
{% extends "base.html" %}
{% block content %}
<h2>Configure Visualization</h2>
<form method="post">
    <label>Update Interval (seconds):</label><br>
    <input type="number" name="update_interval" value="{{ config.update_interval }}" required><br><br>
    <input type="submit" value="Save">
</form>
{% endblock %}
EOF

# Create templates/security.html
cat << 'EOF' > templates/security.html
{% extends "base.html" %}
{% block content %}
<h2>Configure Security</h2>
<form method="post">
    <label>Grafana Username:</label><br>
    <input type="text" name="grafana_username" value="{{ config.grafana_username }}" required><br><br>
    <label>Grafana Password:</label><br>
    <input type="text" name="grafana_password" value="{{ config.grafana_password }}" required><br><br>
    <label>Flask API Key:</label><br>
    <input type="text" name="flask_api_key" value="{{ config.flask_api_key }}" required><br><br>
    <input type="submit" value="Save">
</form>
{% endblock %}
EOF

# Create templates/devices.html
cat << 'EOF' > templates/devices.html
{% extends "base.html" %}
{% block content %}
<h2>Manage Devices</h2>
<h3>Current Devices</h3>
<ul>
    {% for device in config.devices %}
        <li>{{ device.name }} ({{ device.vendor }}, {{ device.group }}, Interval: {{ device.interval }}s)
            <form method="post" style="display:inline;">
                <input type="hidden" name="action" value="edit">
                <input type="hidden" name="index" value="{{ loop.index0 }}">
                <input type="submit" value="Edit">
            </form>
            <form method="post" style="display:inline;">
                <input type="hidden" name="action" value="remove">
                <input type="hidden" name="index" value="{{ loop.index0 }}">
                <input type="submit" value="Remove" onclick="return confirm('Are you sure?');">
            </form>
        </li>
    {% endfor %}
</ul>

<h3>Add/Edit Device</h3>
<form method="post">
    <input type="hidden" name="action" value="{{ 'edit' if request.args.get('edit') else 'add' }}">
    {% if request.args.get('edit') %}
        <input type="hidden" name="index" value="{{ request.args.get('edit') }}">
        {% set device = config.devices[int(request.args.get('edit'))] %}
    {% endif %}
    <label>Name:</label><br>
    <input type="text" name="name" value="{{ device.name if device else '' }}" required><br><br>
    <label>Vendor:</label><br>
    <select name="vendor" onchange="updateCommFields(this.value)">
        {% for vendor in vendors %}
            <option value="{{ vendor }}" {% if device and device.vendor == vendor %}selected{% endif %}>{{ vendor }}</option>
        {% endfor %}
    </select><br><br>
    <label>Group:</label><br>
    <select name="group">
        {% for group in groups %}
            <option value="{{ group }}" {% if device and device.group == group %}selected{% endif %}>{{ group }}</option>
        {% endfor %}
    </select><br><br>
    <label>Interval (seconds):</label><br>
    <input type="number" name="interval" value="{{ device.interval if device else '10' }}" required><br><br>
    
    <div id="comm_fields">
        {% if device and device.communication.type == 'modbus_tcp' %}
            <label>IP Address:</label><br>
            <input type="text" name="ip" value="{{ device.communication.ip }}" required><br><br>
            <label>Port:</label><br>
            <input type="number" name="port" value="{{ device.communication.port }}" required><br><br>
            <label>Slave ID:</label><br>
            <input type="number" name="slave_id" value="{{ device.communication.slave_id }}" required><br><br>
            <label>Power Register:</label><br>
            <input type="number" name="power" value="{{ device.communication.registers.power }}" required><br><br>
            <label>Energy Register:</label><br>
            <input type="number" name="energy" value="{{ device.communication.registers.energy }}" required><br><br>
            {% if device.vendor == 'SMA_Tripower_Battery' %}
                <label>SoC Register:</label><br>
                <input type="number" name="soc" value="{{ device.communication.registers.soc }}" required><br><br>
                <label>Temperature Register:</label><br>
                <input type="number" name="temperature" value="{{ device.communication.registers.temperature }}" required><br><br>
            {% endif %}
        {% elif device and device.communication.type == 'api' and device.vendor == 'SolarEdge' %}
            <label>URL:</label><br>
            <input type="text" name="url" value="{{ device.communication.url }}" required><br><br>
            <label>API Key:</label><br>
            <input type="text" name="api_key" value="{{ device.communication.api_key }}" required><br><br>
            <label>Site ID:</label><br>
            <input type="text" name="site_id" value="{{ device.communication.site_id }}" required><br><br>
            <label>Timeout (seconds):</label><br>
            <input type="number" name="timeout" value="{{ device.communication.timeout }}" required><br><br>
        {% endif %}
    </div>
    <input type="submit" value="Save">
</form>

<script>
function updateCommFields(vendor) {
    const commFields = document.getElementById('comm_fields');
    commFields.innerHTML = '';
    if (vendor === 'SMA' || vendor === 'SMA_Tripower_Battery' || vendor === 'SMA_EVCharger' || vendor === 'Bender_CC613' || vendor === 'Alfen_EVCharger' || vendor === 'AlphaInnotec') {
        commFields.innerHTML = `
            <label>IP Address:</label><br>
            <input type="text" name="ip" value="192.168.1.100" required><br><br>
            <label>Port:</label><br>
            <input type="number" name="port" value="502" required><br><br>
            <label>Slave ID:</label><br>
            <input type="number" name="slave_id" value="3" required><br><br>
            <label>Power Register:</label><br>
            <input type="number" name="power" value="${vendor === 'SMA_Tripower_Battery' ? '30845' : '30775'}" required><br><br>
            <label>Energy Register:</label><br>
            <input type="number" name="energy" value="${vendor === 'SMA_Tripower_Battery' ? '30847' : '30529'}" required><br><br>
            ${vendor === 'SMA_Tripower_Battery' ? `
                <label>SoC Register:</label><br>
                <input type="number" name="soc" value="30865" required><br><br>
                <label>Temperature Register:</label><br>
                <input type="number" name="temperature" value="30867" required><br><br>
            ` : ''}
        `;
    } else if (vendor === 'SolarEdge') {
        commFields.innerHTML = `
            <label>URL:</label><br>
            <input type="text" name="url" value="https://monitoringapi.solaredge.com/site/{site_id}/overview" required><br><br>
            <label>API Key:</label><br>
            <input type="text" name="api_key" value="your_solaredge_key" required><br><br>
            <label>Site ID:</label><br>
            <input type="text" name="site_id" value="your_site_id" required><br><br>
            <label>Timeout (seconds):</label><br>
            <input type="number" name="timeout" value="5" required><br><br>
        `;
    }
}
</script>
{% endblock %}
EOF

# Create templates/status.html
cat << 'EOF' > templates/status.html
{% extends "base.html" %}
{% block content %}
<h2>Component Status</h2>
<ul>
    {% for message in status_messages %}
        <li>{{ message }}</li>
    {% endfor %}
</ul>
{% endblock %}
EOF

# Create templates/docker.html
cat << 'EOF' > templates/docker.html
{% extends "base.html" %}
{% block content %}
<h2>Manage Docker Containers</h2>
<form method="post">
    <button type="submit" name="action" value="start">Start Containers</button>
    <button type="submit" name="action" value="stop">Stop Containers</button>
    <button type="submit" name="action" value="update">Update Containers</button>
</form>
{% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
        {% for category, message in messages %}
            <div class="message {{ 'success' if category != 'error' else 'error' }}">{{ message }}</div>
        {% endfor %}
    {% endif %}
{% endwith %}
{% endblock %}
EOF

# Create templates/db_maintenance.html
cat << 'EOF' > templates/db_maintenance.html
{% extends "base.html" %}
{% block content %}
<h2>Database Maintenance</h2>
<h3>Bucket: {{ bucket }}</h3>
<form method="post">
    <button type="submit" name="action" value="clear" onclick="return confirm('Are you sure you want to clear the bucket? All data will be lost!');">Clear Bucket</button><br><br>
    <label>Backup File Path:</label><br>
    <input type="text" name="backup_path" placeholder="{{ bucket }}_backup.jsonl"><br><br>
    <button type="submit" name="action" value="backup">Backup Bucket</button>
</form>
{% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
        {% for category, message in messages %}
            <div class="message {{ 'success' if category != 'error' else 'error' }}">{{ message }}</div>
        {% endfor %}
    {% endif %}
{% endwith %}
{% endblock %}
EOF

# Create static/index.html
cat << 'EOF' > static/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Energy Flow Diagram</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="/static/energy_flow.js"></script>
</head>
<body>
    <h1>Energy Flow Diagram</h1>
    <svg width="800" height="600"></svg>
</body>
</html>
EOF

# Create static/energy_flow.js
cat << 'EOF' > static/energy_flow.js
document.addEventListener("DOMContentLoaded", function() {
    const svg = d3.select("svg");
    svg.append("text")
        .attr("x", 400)
        .attr("y", 300)
        .attr("text-anchor", "middle")
        .text("Energy Flow Diagram (Placeholder)");
});
EOF

# Make setup_docker.sh executable
chmod +x setup_docker.sh

echo "Files created successfully in energy_monitoring directory."

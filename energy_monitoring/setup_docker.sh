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

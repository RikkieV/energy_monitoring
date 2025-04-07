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

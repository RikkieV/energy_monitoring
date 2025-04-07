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

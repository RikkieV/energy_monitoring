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

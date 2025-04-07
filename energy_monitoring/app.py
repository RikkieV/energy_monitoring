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

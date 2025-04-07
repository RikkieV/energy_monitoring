FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    openssl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -c "import requests, pymodbus, pyserial, influxdb_client, tapo, flask" || exit 1

COPY app.py energy_monitoring.py config_utility.py web_config.py ./
COPY static/ ./static/
COPY templates/ ./templates/

RUN touch devices.json && \
    chown root:root devices.json && \
    chmod 600 devices.json

CMD ["python", "energy_monitoring.py"]

import os
import requests
import logging
from flask import Flask, request, render_template
from datetime import datetime, timezone
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

LOG_FILE = "logs/gunicorn.log"
LOG_ENV_FILE = "logs/ENV_scanner.log"

webhook_url = ""
# ---------- CAŁĄ ZAWARTOŚĆ STRONY ----------

@app.route("/")
def index():
    return render_template("index.html")

# ---------- POD FUNKCJE ----------
# ---------- Discord alerty ----------
def send_discord_alert(log_line):
    embed = {
        "username": "Promilek.xyz - Scanner Filter",
        "content": "<@615235590044123323>",
        "embeds": [{
            "title": "⚠️ Próba dostępu do Zblacklistowanych plików ⚠",
            "color": 9568256,
            "description": f"Wykryto podejrzaną aktywność:\n`{log_line.strip()}`",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }
    try:
        requests.post(webhook_url, json=embed, timeout=5)
    except Exception as e:
        print(f"Błąd wysyłki na Discord: {e}")

# ---------- Obejście proxy ----------
def get_client_ip():
    if "CF-Connecting-IP" in request.headers:
        return request.headers["CF-Connecting-IP"]
    if "X-Forwarded-For" in request.headers:
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr


app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# ---------- Wzorce detekcji ----------
SUSPICIOUS_PATTERNS = [
    (".env", send_discord_alert),
    (".env.bak", send_discord_alert),
    (".env.backup", send_discord_alert),
    (".env_secret", send_discord_alert),
    ("wp-admin", send_discord_alert),
    ("api", send_discord_alert),
    ("lib", send_discord_alert),
    ("admin", send_discord_alert),
]


# ---------- Konsolowe logi z real IP ----------
@app.after_request
def log_request(response):
    ip = get_client_ip()
    now = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
    method = request.method
    path = request.full_path.rstrip("?")
    protocol = request.environ.get("SERVER_PROTOCOL")
    status = response.status_code

    log_line = f'{ip} - - [{now}] "{method} {path} {protocol}" {status} -\n'

    print(log_line, end="")

    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(log_line)

    path_lower = path.lower()
    for pattern, alert_fn in SUSPICIOUS_PATTERNS:
        if pattern in path_lower:
            with open(LOG_ENV_FILE, "a") as f_alert:
                f_alert.write(log_line)
            alert_fn(log_line)

    return response


# ---------- start ----------
if __name__ == "__main__":
    app.run(debug=True, port=8888, host="0.0.0.0")
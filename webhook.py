import os
import hmac
import hashlib
import subprocess
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables dari .env
load_dotenv()

app = Flask(__name__)

# Ambil Secret dari .env
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

# Logging
logging.basicConfig(level=logging.INFO, filename="/var/www/algoverse/backend/webhook.log",
                    format="%(asctime)s - %(levelname)s - %(message)s")

def verify_signature(payload, signature):
    """ Verifikasi apakah payload berasal dari GitHub dengan HMAC SHA-256 """
    if not GITHUB_WEBHOOK_SECRET:
        logging.error("GITHUB_WEBHOOK_SECRET tidak ditemukan.")
        return False

    computed_signature = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(computed_signature, signature)

@app.route('/webhook', methods=['POST'])
def webhook():
    """ Handle webhook request dari GitHub """
    signature = request.headers.get("X-Hub-Signature-256")
    
    if not signature:
        logging.warning("Permintaan webhook tanpa signature.")
        return jsonify({"error": "Missing signature"}), 400

    # Baca payload request
    payload = request.get_data()

    if not verify_signature(payload, signature):
        logging.warning("Signature tidak valid!")
        return jsonify({"error": "Invalid signature"}), 403

    # Pull latest changes dari GitHub dan restart backend
    try:
        logging.info("Menjalankan git pull & restart backend...")
        result = subprocess.run(
            ["sudo", "-u", "algouser", "git", "pull", "origin", "main"],
            cwd="/var/www/algoverse/backend",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        logging.info(f"Git Pull Output: {result.stdout}")

        restart_result = subprocess.run(
            ["sudo", "systemctl", "restart", "algoverse-backend"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        logging.info(f"Service Restart Output: {restart_result.stdout}")

        return jsonify({"message": "Updated and Restarted"}), 200
    except subprocess.CalledProcessError as e:
        logging.error(f"Webhook gagal: {e.stderr}")
        return jsonify({"error": f"Webhook failed: {e.stderr}"}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=9000, debug=True)

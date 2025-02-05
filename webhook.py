from flask import Flask, request
import os
import subprocess

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    if request.method == 'POST':
        subprocess.run(['git', 'pull', 'origin', 'main'], cwd='/var/www/techlearnix/backend')
        subprocess.run(['source', '/var/www/techlearnix/backend/venv/bin/activate'], shell=True, executable='/bin/bash')  # Aktifkan venv sebelum restart
        subprocess.run(['sudo', 'systemctl', 'restart', 'techlearnix-backend'])
        return 'Updated and Restarted', 200
    return 'Invalid request', 400

if __name__ == '__main__':
    app.run(port=9000)

import os
import logging
import re
from datetime import timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import text
from flask_argon2 import Argon2
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from auth_middleware import admin_required
from models import db, User  # Import dari models.py

# Load environment variables
load_dotenv()

app = Flask(__name__)

# ====================== Konfigurasi Keamanan ======================
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")  # Gunakan ENV untuk keamanan
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)  # Access Token berlaku 15 menit
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)  # Refresh Token berlaku 7 hari

# Inisialisasi database & keamanan
db.init_app(app)
migrate = Migrate(app, db)
argon2 = Argon2(app)
jwt = JWTManager(app)

# CORS Configuration - Hanya frontend yang diizinkan mengakses API
CORS(app, resources={r"/*": {"origins": ["https://app.techlearnix.online"]}})

# Rate Limiting (Mencegah Brute Force & Spam)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "10 per hour"]
)

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ====================== Validasi Input ======================
def validate_user_input(data):
    if not data or 'name' not in data or 'email' not in data:
        return {"error": "Missing name or email"}, 400

    if len(data['name']) > 100 or len(data['email']) > 100:
        return {"error": "Name or email too long"}, 400

    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, data['email']):
        return {"error": "Invalid email format"}, 400

    return None  # Input valid

# ====================== API ROUTES ======================

@app.route("/")
def home():
    return jsonify({"message": "Backend Flask is running!"})

@app.route("/db")
def check_db():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"message": "Database connected successfully!"})
    except Exception as e:
        logging.error(f"Database connection error: {e}")
        return jsonify({"error": "Database connection failed"}), 500

# ====================== API CRUD dengan RBAC & Exception Handling ======================

@app.route('/users', methods=['POST'])
@limiter.limit("5 per minute")
def create_user():
    try:
        data = request.get_json()
        error = validate_user_input(data)
        if error:
            return jsonify(error)

        if 'password' not in data or len(data['password']) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400

        if User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "Email already exists"}), 409

        new_user = User(name=data['name'], email=data['email'], role=data.get("role", "user"))
        new_user.set_password(data['password'])

        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        logging.error(f"Error creating user: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    try:
        users = User.query.all()
        return jsonify({"users": [{"id": u.id, "name": u.name, "email": u.email, "role": u.role} for u in users]})
    except Exception as e:
        logging.error(f"Error retrieving users: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user(user_id):
    try:
        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({"error": "User not found"}), 404

        db.session.delete(target_user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        logging.error(f"Error deleting user {user_id}: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

# ====================== API Authentication ======================

@app.route('/login', methods=['POST'])
@limiter.limit("3 per minute")
def login():
    try:
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()

        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=str(user.id))  # Convert ID to string
            refresh_token = create_refresh_token(identity=str(user.id))  # Convert to string

            return jsonify({
                "access_token": access_token,
                "refresh_token": refresh_token
            }), 200

        return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        logging.error(f"Error during login: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Endpoint untuk memperbarui access token menggunakan refresh token."""
    current_user = get_jwt_identity()  # Tetap string
    new_access_token = create_access_token(identity=current_user)  # Gunakan STRING

    return jsonify({"access_token": new_access_token}), 200

# ====================== Tambahan Protected Routes ======================

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    try:
        current_user = int(get_jwt_identity())
        user = User.query.get(current_user)
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"message": f"Hello {user.name}, you have access!"})
    except Exception as e:
        logging.error(f"Error accessing protected route: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin', methods=['GET'])
@jwt_required()
@admin_required  # Hanya bisa diakses oleh admin
def admin():
    return jsonify({"message": "Welcome, Admin!"})

# ====================== Logging & Error Handling ======================

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Server Error: {error}, route: {request.url}")
    return jsonify({"error": "Internal Server Error"}), 500

@app.errorhandler(404)
def not_found_error(error):
    logging.warning(f"Not Found: {error}, route: {request.url}")
    return jsonify({"error": "Not Found"}), 404

# ========================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

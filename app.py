from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import text
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import re
from auth_middleware import admin_required  # Import middleware untuk RBAC
from models import db, User  # Import dari models.py

app = Flask(__name__)

# ====================== Konfigurasi Keamanan ======================
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://algoverse_user:CQ41-210tu@localhost/algoverse_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'CQ41-210tu'  # Ubah ke env variable di production

# Inisialisasi database & keamanan
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# CORS Configuration - Hanya frontend yang diizinkan mengakses API
CORS(app, resources={r"/*": {"origins": ["https://app.techlearnix.online"]}})

# Rate Limiting (Mencegah Brute Force & Spam)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
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

# ✅ **Route utama**
@app.route("/")
def home():
    return jsonify({"message": "Backend Flask is running!"})

# ✅ **Cek Koneksi Database**
@app.route("/db")
def check_db():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"message": "Database connected successfully!"})
    except Exception as e:
        logging.error(f"Database connection error: {e}")
        return jsonify({"error": "Database connection failed"}), 500

# ====================== API CRUD dengan RBAC & Exception Handling ======================

# ✅ **CREATE User**
@app.route('/users', methods=['POST'])
@limiter.limit("5 per minute")  # Mencegah spam user registration
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

        new_user = User(name=data['name'], email=data['email'])
        new_user.set_password(data['password'])

        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully", "user": {"id": new_user.id, "name": new_user.name, "email": new_user.email}}), 201
    except Exception as e:
        logging.error(f"Error creating user: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

# ✅ **READ All Users (Admin Only)**
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

# ✅ **DELETE User (Admin Only)**
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

# ✅ **Login User & Generate Token**
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Hanya 5 kali percobaan login per menit
def login():
    try:
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()

        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=user.id)
            return jsonify({"access_token": access_token}), 200

        return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        logging.error(f"Error during login: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

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
    app.run(host="0.0.0.0", port=5000, debug=True)

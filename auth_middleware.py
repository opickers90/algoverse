from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from models import User  # Pastikan mengimpor User dari model database

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = User.query.get(get_jwt_identity())
        if not user or user.role != "admin":
            return jsonify({"error": "Admin access required"}), 403  # HTTP 403 Forbidden
        return func(*args, **kwargs)
    return wrapper

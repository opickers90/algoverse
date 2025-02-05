from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# ====================== Model Database ======================
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default="user")  # Role-Based Access Control (RBAC)

    def set_password(self, password):
        from app import bcrypt  # **Hindari circular import dengan in-line import**
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        from app import bcrypt
        return bcrypt.check_password_hash(self.password_hash, password)

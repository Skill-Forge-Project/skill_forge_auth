import app
from flask import Blueprint, request, jsonify
from extensions import db
from models import User
from services import generate_token, generate_refresh_token, internal_only
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token



auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/internal/users/usernames", methods=["GET"])
@internal_only
def get_usernames():
    user_ids = request.json.get("user_ids", [])
    if not user_ids:
        return jsonify({}), 400

    users = User.query.filter(User.id.in_(user_ids)).all()
    return jsonify({user.id: user.username for user in users}), 200


@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")
    username = data.get("username")
    first_name = data.get("firstName")
    last_name = data.get("lastName")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Missing fields"}), 400

    if User.query.filter((User.email == email)).first():
        return jsonify({"message": "User already exists"}), 409

    try:
        user = User(email=email, 
                    username=username, 
                    first_name=first_name, 
                    last_name=last_name, 
                    password=password)
        
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User created successfully", "success": "true"}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.exception("An error occurred during signup")
        return jsonify({"message": "An internal error has occurred"}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        access_token = generate_token(identity=user.id)
        refresh_token = generate_refresh_token(identity=user.id)
        
        user.user_online_status = "Online"
        user.last_seen_date = db.func.current_timestamp()
        db.session.commit()
        
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user.id
        }), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401


@auth_bp.route("/refresh_access_token", methods=["POST"])
@jwt_required(refresh=True)
def refresh_access_token():
    identity = get_jwt_identity()
    new_access_token = generate_token(identity=identity)

    return jsonify({'access_token': new_access_token})


@auth_bp.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    return jsonify({"message": f"Hello user {user_id}, you're authenticated!"}), 200

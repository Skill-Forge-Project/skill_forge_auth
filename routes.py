import app
from flask import Blueprint, request, jsonify
from extensions import db
from models import User
from services import generate_token, generate_refresh_token, internal_only
from flask_jwt_extended import (
    jwt_required, 
    get_jwt_identity, 
    set_access_cookies, 
    set_refresh_cookies, 
    create_access_token,
    unset_jwt_cookies
)
from datetime import timedelta



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

    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid credentials"}), 401
    
    access_token = generate_token(identity=user.id)
    refresh_token = generate_refresh_token(identity=user.id)
    
    response = jsonify({
        "message": "Login successful",
        "user_id": user.id,
    })
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    return response, 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """ Logs out the user by revoking the access and refresh tokens.

    Returns:
        json: _Description of the response_
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user:
        user.user_online_status = "Offline"
        user.last_seen_date = db.func.current_timestamp()
        db.session.commit()
        
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    return response, 200

@auth_bp.route("/refresh_access_token", methods=["POST"])
@jwt_required(refresh=True)
def refresh_access_token():
    """ Refreshes **manually** the access token for the authenticated user.

    Returns:
        json: _Description of the response_
    """
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    response = jsonify({"msg": "Token refreshed"})
    set_access_cookies(response, access_token)
    return response


@auth_bp.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    return jsonify({"message": f"Hello user {user_id}, you're authenticated!"}), 200

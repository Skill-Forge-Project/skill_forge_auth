import datetime, traceback
from flask import Flask, current_app, jsonify, request
from flask_cors import CORS
from config import Config
from extensions import db, jwt, migrate
from jwt import ExpiredSignatureError, InvalidTokenError
from flask_jwt_extended import (
    verify_jwt_in_request,
    get_jwt,
    set_access_cookies,
    get_jwt_identity,
    decode_token,
    create_access_token
)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)

    from routes import auth_bp
    app.register_blueprint(auth_bp)

    with app.app_context():
        db.create_all()
        
    @app.before_request
    def refresh_expired_access_token():
        """ Refreshes the access token if it has expired.

        Returns:
            _type_: _description_
        """
        
        try:
            verify_jwt_in_request(optional=True)
            jwt_data = get_jwt()
            exp_timestamp = jwt_data["exp"]
            now = datetime.datetime.now(datetime.timezone.utc)
            target_timestamp = datetime.datetime.timestamp(now + datetime.timedelta(minutes=1))
            if exp_timestamp < target_timestamp:
                identity = get_jwt_identity()
                new_access_token = create_access_token(identity=identity)
                response = current_app.make_response()
                set_access_cookies(response, new_access_token)
                return response
        except (ExpiredSignatureError, InvalidTokenError) as token_error:
            current_app.logger.warning(
                f"JWT refresh failed for user [{get_jwt_identity()}] at {request.path}: {token_error}"
            )
            response = jsonify({"msg": "Token invalid or expired"})
            response.status_code = 401
            return response
        except Exception as e:
            current_app.logger.error(
                f"Unexpected error during token refresh: {e}\n{traceback.format_exc()}"
            )
            response = jsonify({"msg": "Internal server error"})
            response.status_code = 500
            return response

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)

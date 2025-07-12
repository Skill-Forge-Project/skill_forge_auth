import datetime, traceback
from flask import Flask, current_app, jsonify, g, request
from flask_cors import CORS
from config import Config
from extensions import db, jwt, migrate
from jwt import ExpiredSignatureError, InvalidTokenError
from flask_jwt_extended.exceptions import NoAuthorizationError
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

    CORS(app, supports_credentials=True, origins=["http://localhost:5173"])
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)

    from routes import auth_bp
    app.register_blueprint(auth_bp)

    with app.app_context():
        db.create_all()
        
    
    
    @app.before_request
    def check_access_token():
        """Check if the access token is valid and not expired.

        """
        skip_paths = {"/login", "/me", "/refresh_access_token", "/logout"}

        try:
            verify_jwt_in_request()
            jwt_data = get_jwt()
            exp_timestamp = jwt_data["exp"]
            now = datetime.datetime.now(datetime.timezone.utc)
            target_timestamp = datetime.datetime.timestamp(now + datetime.timedelta(minutes=29))

            if exp_timestamp < target_timestamp:
                g.needs_refresh = True
                g.identity = get_jwt_identity()
        except ExpiredSignatureError:
            g.needs_refresh = True
            g.identity = None  # will be set during refresh
        except Exception:
            g.needs_refresh = False
    
    @app.after_request
    def maybe_refresh_token(response):
        if getattr(g, "needs_refresh", False):
            try:
                # Use refresh token to get new access token
                verify_jwt_in_request(refresh=True)
                identity = get_jwt_identity()
                new_access_token = create_access_token(identity=identity)
                set_access_cookies(response, new_access_token)
                print(f"🔁 Refreshed access token for user: {identity}")
            except Exception as e:
                current_app.logger.warning(f"Failed to refresh token: {e}")
                # Optionally clear cookies or return 401
        return response

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)

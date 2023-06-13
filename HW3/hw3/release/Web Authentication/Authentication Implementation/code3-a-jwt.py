from flask_jwt_extended import JWTManager
from flask import Flask, request, redirect, render_template, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_jwt_extended import create_access_token


# you must already have this line in your project
# you don't have to add it again.
app = Flask(__name__)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this "super secret" with something else!
jwt = JWTManager(app)


# Create a route to authenticate your users and return JWT Token. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/token", methods=["POST"])
def create_token():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    # Query your database for username and password
    user = User.query.filter_by(username=username, password=password).first()
    if user is None:
        # the user was not found on the database
        return "Bad username or password", 401
    
    # create a new token with the user id inside
    access_token = create_access_token(identity=user.id)
    return access_token, 200


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return user.username, 200

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=7777, debug=True)
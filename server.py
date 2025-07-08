from flask import Flask, jsonify, request
import json, os
import bcrypt # type: ignore

app = Flask(__name__)

API_KEY = os.getenv("API_KEY")

if os.path.exists("users.json"):
    with open("users.json") as f:
        passwords = json.load(f)
else:
    passwords = {}


def hash(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()

def check(p, hash):
    return bcrypt.checkpw(p.encode(), hash.encode())

@app.before_request
def is_right_api_key():
    if not request.headers.get("X-API-KEY") == API_KEY:
        return jsonify({"status": "error", "reason": "unauthorized request"}), 401

@app.route("/api/sign-up", methods=["POST"])
def sign_up():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if (not isinstance(username, str)) or (not isinstance(password, str)):
        return jsonify({"status": "error", "reason": "input is not string"})
    if username in passwords:
        return jsonify({"status": "error", "reason": "username already exists"})
    passwords[username] = hash(password)
    with open("users.json", "w") as f:
        json.dump(passwords, f)
    return jsonify({"status": "success"})
        
@app.route("/api/log-in", methods=["POST"])
def log_in():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username in passwords:
        return jsonify({"status": "error", "reason": "no user with this username exists"})
    if check(password, passwords[username]):
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "error", "reason": "password incorrect"})
@app.route("/api/delete", methods=["DELETE"])
def delete():
    data = request.get_json()
    deleted_user = data.get("username")
    if deleted_user in passwords:
        del passwords[deleted_user]
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "error", "reason": "no such user"})
@app.route("/api/list-users", methods=["POST"])
def ls_all():
    return jsonify(passwords)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

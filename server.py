from flask import Flask, jsonify, request
import json, os, dotenv
import bcrypt # type: ignore

dotenv.load_dotenv()
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

def is_right_api_key():
    return request.headers.get("X-API-KEY") == API_KEY
@app.route("/api/sign-up", methods=["POST"])
def sign_up():
    if is_right_api_key():
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
    else:
        return jsonify({"status": "error", "reason": "unauthorized request"}), 401

@app.route("/api/log-in", methods=["POST"])
def log_in():
    if is_right_api_key():
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        if not username in passwords:
            return jsonify({"status": "error", "reason": "no user with this username exists"})
        if check(password, passwords[username]):
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "reason": "password incorrect"})
    else:
        return jsonify({"status": "error", "reason": "unauthorized request"}), 401
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

"""Leaky Notes — a deliberately INSECURE notes API for BE104.

This app works. It also has real security holes on purpose. You will find and
demonstrate them with your own eyes, then fix the same kinds of holes in your
own Recipe Box API.

DO NOT deploy this or reuse its patterns. It exists to be broken.

Two flaws are planted here:
  1. Passwords are stored in PLAINTEXT (Unit 2 finds this before you learn hashing).
  2. Note editing/deleting has NO ownership check — any logged-in user can change
     anyone's notes (Unit 3 finds this before you enforce ownership).
"""

import sqlite3
import os
import jwt
from jwt import ExpiredSignatureError
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, g, jsonify, request
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps


DATABASE = "leaky.db"

app = Flask(__name__)

app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET")

load_dotenv()

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)

    if db is not None:
        db.close()

def current_user_id():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    parts = auth_header.split()
    # Expect exactly: "Bearer <token>"
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]

    try:
        payload = jwt.decode(
            token,
            app.config["JWT_SECRET"],
            algorithms=["HS256"],
        )

    except ExpiredSignatureError:
        # token is valid but past its exp
        return "EXPIRED"
    except jwt.PyJWTError:
        # covers invalid signature, malformed token, expired, etc.
        return None

    sub = payload.get("sub")
    role = payload.get("role")  # 👈 from token

    if sub is None or role is None:
        return None

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        return None

    return {"id": user_id, "role": role}

def require_user(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user = current_user_id()

        # keep EXACT behavior you already had
        if user == "EXPIRED":
            return jsonify({"error": "Token expired, please log in again"}), 401

        if user is None:
            return jsonify({"error": "log in first"}), 401

        # success: store full user dict for the route to use
        g.current_user = user

        # now call the original route function
        return view_func(*args, **kwargs)

    return wrapped_view

@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    password_hash = generate_password_hash(password)
    db = get_db()

    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()

    except sqlite3.IntegrityError:
        return jsonify({"error": "username taken"}), 409

    return jsonify({"message": f"registered {username}"}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    # If either field is missing, treat as bad credentials
    if not username or not password:
        return jsonify({"error": "Username and password combination not found."}), 400

    row = get_db().execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    # Generic failure: unknown user OR wrong password
    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "bad credentials"}), 401
    # Success: create JWT carrying the authenticated identity
    payload = {
        "sub": str(row["id"]),  # user id as STRING
        "username": row["username"],
        "role": row["role"],
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    token = jwt.encode(
        payload,
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )
    # Success: return authenticated identity + token
    return jsonify({
        "user": {
            "id": row["id"],
            "username": row["username"],
        },
        "token": token,
    }), 200

@app.post("/notes")
@require_user
def create_note():
    user = g.current_user      # set by require_user
    user_id = user["id"]

    data = request.get_json(silent=True) or {}

    if not data.get("body"):
        return jsonify({"error": "body required"}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (owner_id, body) VALUES (?, ?)",
        (user_id, data["body"]),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "owner_id": user_id, "body": data["body"]}), 201


@app.get("/notes")
def list_notes():
    rows = get_db().execute("SELECT * FROM notes ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.patch("/notes/<int:note_id>")
@require_user
def edit_note(note_id):
    user = g.current_user
    user_id = user["id"]
    user_role = user["role"]

    data = request.get_json(silent=True) or {}
    db = get_db()

    # 1) Load the note
    note = db.execute(
        "SELECT * FROM notes WHERE id = ?",
        (note_id,),
    ).fetchone()

    # 2) Not found → 404
    if note is None:
        return jsonify({"error": "note not found"}), 404

    # 3) Authorization: owner OR admin
    is_owner = note["owner_id"] == user_id
    is_admin = user_role == "admin"

    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden: not your note"}), 403

    # 4) Allowed → update
    cur = db.execute(
        "UPDATE notes SET body = ? WHERE id = ?",
        (data.get("body", ""), note_id),
    )

    return jsonify({"id": note_id, "body": data.get("body", "")})


@app.delete("/notes/<int:note_id>")
@require_user
def delete_note(note_id):
    user = g.current_user
    user_id = user["id"]
    user_role = user["role"]

    db = get_db()

    # 1) Load the note
    note = db.execute(
        "SELECT * FROM notes WHERE id = ?",
        (note_id,),
    ).fetchone()

    # 2) Not found → 404
    if note is None:
        return jsonify({"error": "note not found"}), 404

    # 3) Authorization: owner OR admin
    is_owner = note["owner_id"] == user_id
    is_admin = user_role == "admin"

    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden: not your note"}), 403

    # 4) Allowed → delete BEFORE returning
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()

    return "", 204


if __name__ == "__main__":
    app.run(debug=True, port=5001)

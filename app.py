import sqlite3
import hashlib
import os
import uuid
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "books.db")

app = Flask(__name__)
CORS(app)

# ── DB ─────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token         TEXT,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS listings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            title        TEXT NOT NULL,
            author       TEXT DEFAULT '',
            subject      TEXT DEFAULT '',
            edition      TEXT DEFAULT '',
            condition    TEXT NOT NULL,
            price        INTEGER NOT NULL,
            description  TEXT DEFAULT '',
            contact_type TEXT NOT NULL,
            contact_info TEXT NOT NULL,
            is_sold      INTEGER DEFAULT 0,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ── Auth helpers ───────────────────────────────────────────────────────────

def hash_password(pw):
    salt = os.urandom(16).hex()
    h = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"{salt}:{h}"

def verify_password(pw, stored):
    try:
        salt, h = stored.split(":", 1)
        return hashlib.sha256((salt + pw).encode()).hexdigest() == h
    except Exception:
        return False

def new_token():
    return uuid.uuid4().hex + uuid.uuid4().hex

def get_user():
    """從 Authorization header 取得目前使用者，無則回傳 None。"""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    conn = get_db()
    row = conn.execute(
        "SELECT id, username FROM users WHERE token = ?", [token]
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def require_user():
    """回傳 (user, None) 或 (None, error_response)。"""
    user = get_user()
    if not user:
        return None, (jsonify({"detail": "請先登入"}), 401)
    return user, None

def check_owner(lid, user_id):
    """確認刊登屬於此使用者，不是則回傳 error response，是則回傳 None。"""
    conn = get_db()
    row = conn.execute("SELECT user_id FROM listings WHERE id = ?", [lid]).fetchone()
    conn.close()
    if not row:
        return jsonify({"detail": "找不到此刊登"}), 404
    if row["user_id"] != user_id:
        return jsonify({"detail": "你沒有權限操作此刊登"}), 403
    return None

# ── Pages ──────────────────────────────────────────────────────────────────

@app.route("/")
def root():
    return send_file("index.html")

# ── Auth routes ────────────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if len(username) < 3 or len(username) > 20:
        return jsonify({"detail": "帳號長度需為 3–20 個字元"}), 400
    if not all(c.isalnum() or c == "_" for c in username):
        return jsonify({"detail": "帳號只能包含英文、數字、底線"}), 400
    if len(password) < 6:
        return jsonify({"detail": "密碼至少需要 6 個字元"}), 400

    token = new_token()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, token) VALUES (?, ?, ?)",
            [username, hash_password(password), token],
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"detail": "此帳號已被使用"}), 400
    finally:
        conn.close()

    return jsonify({"token": token, "username": username})

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    conn = get_db()
    row = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        [username],
    ).fetchone()

    if not row or not verify_password(password, row["password_hash"]):
        conn.close()
        return jsonify({"detail": "帳號或密碼錯誤"}), 401

    token = new_token()
    conn.execute("UPDATE users SET token = ? WHERE id = ?", [token, row["id"]])
    conn.commit()
    conn.close()
    return jsonify({"token": token, "username": row["username"]})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    user, err = require_user()
    if err:
        return err
    conn = get_db()
    conn.execute("UPDATE users SET token = NULL WHERE id = ?", [user["id"]])
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# ── Listings routes ────────────────────────────────────────────────────────

@app.route("/api/listings")
def get_listings():
    search    = request.args.get("search", "")
    subject   = request.args.get("subject", "")
    condition = request.args.get("condition", "")
    mine      = request.args.get("mine", "false").lower() == "true"
    user      = get_user()

    conn = get_db()
    if mine:
        if not user:
            return jsonify([])
        query  = "SELECT l.*, u.username FROM listings l JOIN users u ON l.user_id = u.id WHERE l.user_id = ?"
        params = [user["id"]]
    else:
        query  = "SELECT l.*, u.username FROM listings l JOIN users u ON l.user_id = u.id WHERE l.is_sold = 0"
        params = []

    if search:
        query += " AND (l.title LIKE ? OR l.author LIKE ? OR l.description LIKE ?)"
        params += [f"%{search}%"] * 3
    if subject and subject != "all":
        query += " AND l.subject = ?"
        params.append(subject)
    if condition and condition != "all":
        query += " AND l.condition = ?"
        params.append(condition)

    query += " ORDER BY l.created_at DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()

    items = [dict(r) for r in rows]
    if user:
        for item in items:
            item["is_mine"] = (item["user_id"] == user["id"])
    return jsonify(items)

@app.route("/api/listings/<int:lid>")
def get_listing(lid):
    user = get_user()
    conn = get_db()
    row = conn.execute(
        "SELECT l.*, u.username FROM listings l JOIN users u ON l.user_id = u.id WHERE l.id = ?",
        [lid],
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"detail": "找不到此刊登"}), 404
    result = dict(row)
    if user:
        result["is_mine"] = (result["user_id"] == user["id"])
    return jsonify(result)

@app.route("/api/listings", methods=["POST"])
def create_listing():
    user, err = require_user()
    if err:
        return err

    data         = request.get_json() or {}
    title        = data.get("title", "").strip()
    price        = data.get("price", 0)
    contact_info = data.get("contact_info", "").strip()

    if not title:
        return jsonify({"detail": "書名不能為空"}), 400
    if not isinstance(price, int) or price < 0:
        return jsonify({"detail": "價格不能為負數"}), 400
    if not contact_info:
        return jsonify({"detail": "請填寫聯絡方式"}), 400

    conn = get_db()
    cur = conn.execute("""
        INSERT INTO listings
            (user_id, title, author, subject, edition, condition,
             price, description, contact_type, contact_info)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [user["id"], title,
          data.get("author", "").strip(),
          data.get("subject", ""),
          data.get("edition", "").strip(),
          data.get("condition", "全新"),
          price,
          data.get("description", "").strip(),
          data.get("contact_type", "line"),
          contact_info])
    lid = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({"id": lid})

@app.route("/api/listings/<int:lid>/sold", methods=["POST"])
def mark_sold(lid):
    user, err = require_user()
    if err:
        return err
    owner_err = check_owner(lid, user["id"])
    if owner_err:
        return owner_err
    conn = get_db()
    conn.execute("UPDATE listings SET is_sold = 1 WHERE id = ?", [lid])
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/listings/<int:lid>", methods=["DELETE"])
def delete_listing(lid):
    user, err = require_user()
    if err:
        return err
    owner_err = check_owner(lid, user["id"])
    if owner_err:
        return owner_err
    conn = get_db()
    conn.execute("DELETE FROM listings WHERE id = ?", [lid])
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# ── Run locally ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

import sqlite3
import hashlib
import os
import uuid
import json
from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "books.db")
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
CORS(app)

def save_image(f):
    if not f or f.filename == "":
        return ""
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXT:
        return ""
    fname = uuid.uuid4().hex + "." + ext
    f.save(os.path.join(UPLOAD_FOLDER, fname))
    return fname

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS listings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        author TEXT DEFAULT '',
        subject TEXT DEFAULT '',
        edition TEXT DEFAULT '',
        condition TEXT NOT NULL,
        price INTEGER NOT NULL,
        description TEXT DEFAULT '',
        contact_type TEXT NOT NULL,
        contact_info TEXT NOT NULL,
        is_sold INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id INTEGER NOT NULL,
        buyer_id INTEGER NOT NULL,
        seller_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(listing_id, buyer_id),
        FOREIGN KEY (listing_id) REFERENCES listings(id),
        FOREIGN KEY (buyer_id) REFERENCES users(id),
        FOREIGN KEY (seller_id) REFERENCES users(id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (conversation_id) REFERENCES conversations(id),
        FOREIGN KEY (sender_id) REFERENCES users(id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS favorites (
        user_id INTEGER NOT NULL,
        listing_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, listing_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (listing_id) REFERENCES listings(id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id INTEGER NOT NULL,
        buyer_id INTEGER NOT NULL,
        seller_id INTEGER NOT NULL,
        conv_id INTEGER,
        meet_time TEXT DEFAULT '',
        meet_location TEXT DEFAULT '',
        seller_done INTEGER DEFAULT 0,
        buyer_done INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (listing_id) REFERENCES listings(id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id INTEGER NOT NULL,
        reviewer_id INTEGER NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(listing_id, reviewer_id))""")
    for col in ("image1", "image2", "status", "contacts", "images"):
        try:
            default = "'available'" if col == "status" else "''"
            conn.execute(f"ALTER TABLE listings ADD COLUMN {col} TEXT DEFAULT {default}")
        except Exception:
            pass
    conn.commit()
    conn.close()

init_db()

def hash_password(pw):
    salt = os.urandom(16).hex()
    return salt + ":" + hashlib.sha256((salt + pw).encode()).hexdigest()

def verify_password(pw, stored):
    try:
        salt, h = stored.split(":", 1)
        return hashlib.sha256((salt + pw).encode()).hexdigest() == h
    except Exception:
        return False

def new_token():
    return uuid.uuid4().hex + uuid.uuid4().hex

def get_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    conn = get_db()
    row = conn.execute("SELECT id, username FROM users WHERE token = ?", [token]).fetchone()
    conn.close()
    return dict(row) if row else None

def require_user():
    user = get_user()
    if not user:
        return None, (jsonify({"detail": "請先登入"}), 401)
    return user, None

def check_owner(lid, user_id):
    conn = get_db()
    row = conn.execute("SELECT user_id FROM listings WHERE id = ?", [lid]).fetchone()
    conn.close()
    if not row:
        return jsonify({"detail": "找不到此刊登"}), 404
    if row["user_id"] != user_id:
        return jsonify({"detail": "你沒有權限操作此刊登"}), 403
    return None

@app.route("/")
def root():
    return send_file("index.html")

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ── Auth ───────────────────────────────────────────────────────────────────

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
        conn.execute("INSERT INTO users (username, password_hash, token) VALUES (?, ?, ?)",
                     [username, hash_password(password), token])
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"detail": "此帳號已被使用"}), 400
    finally:
        conn.close()
    return jsonify({"token": token, "username": username})

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    conn = get_db()
    row = conn.execute("SELECT id, username, password_hash FROM users WHERE username = ?",
                       [data.get("username", "").strip()]).fetchone()
    if not row or not verify_password(data.get("password", ""), row["password_hash"]):
        conn.close()
        return jsonify({"detail": "帳號或密碼錯誤"}), 401
    token = new_token()
    conn.execute("UPDATE users SET token = ? WHERE id = ?", [token, row["id"]])
    conn.commit(); conn.close()
    return jsonify({"token": token, "username": row["username"]})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    user, err = require_user()
    if err: return err
    conn = get_db()
    conn.execute("UPDATE users SET token = NULL WHERE id = ?", [user["id"]])
    conn.commit(); conn.close()
    return jsonify({"ok": True})

# ── Listings ───────────────────────────────────────────────────────────────

@app.route("/api/listings")
def get_listings():
    search    = request.args.get("search", "")
    subject   = request.args.get("subject", "")
    condition = request.args.get("condition", "")
    mine      = request.args.get("mine", "false").lower() == "true"
    favs      = request.args.get("favorites", "false").lower() == "true"
    user      = get_user()
    conn = get_db()

    if mine:
        if not user: return jsonify([])
        query = "SELECT l.*, u.username FROM listings l JOIN users u ON l.user_id=u.id WHERE l.user_id=?"
        params = [user["id"]]
    elif favs:
        if not user: return jsonify([])
        query = "SELECT l.*, u.username FROM listings l JOIN users u ON l.user_id=u.id JOIN favorites f ON f.listing_id=l.id WHERE f.user_id=?"
        params = [user["id"]]
    else:
        query = "SELECT l.*, u.username FROM listings l JOIN users u ON l.user_id=u.id WHERE l.is_sold=0"
        params = []

    if search:
        query += " AND (l.title LIKE ? OR l.author LIKE ? OR l.description LIKE ?)"
        params += [f"%{search}%"] * 3
    if subject and subject != "all":
        query += " AND l.subject=?"; params.append(subject)
    if condition and condition != "all":
        query += " AND l.condition=?"; params.append(condition)
    query += " ORDER BY l.created_at DESC"
    rows = conn.execute(query, params).fetchall()

    fav_ids = set()
    if user:
        fav_ids = set(r[0] for r in conn.execute("SELECT listing_id FROM favorites WHERE user_id=?", [user["id"]]).fetchall())
    conn.close()

    items = [dict(r) for r in rows]
    for item in items:
        if user:
            item["is_mine"] = (item["user_id"] == user["id"])
            item["is_favorited"] = (item["id"] in fav_ids)
    return jsonify(items)

@app.route("/api/listings/<int:lid>")
def get_listing(lid):
    user = get_user()
    conn = get_db()
    row = conn.execute("SELECT l.*, u.username FROM listings l JOIN users u ON l.user_id=u.id WHERE l.id=?", [lid]).fetchone()
    conn.close()
    if not row: return jsonify({"detail": "找不到此刊登"}), 404
    result = dict(row)
    if user:
        result["is_mine"] = (result["user_id"] == user["id"])
        conn2 = get_db()
        fav = conn2.execute("SELECT 1 FROM favorites WHERE user_id=? AND listing_id=?", [user["id"], lid]).fetchone()
        conn2.close()
        result["is_favorited"] = bool(fav)
    return jsonify(result)

@app.route("/api/listings", methods=["POST"])
def create_listing():
    user, err = require_user()
    if err: return err
    ct = request.content_type or ""
    if "multipart/form-data" in ct:
        data = request.form
        image1 = save_image(request.files.get("image1"))
        image2 = save_image(request.files.get("image2"))
    else:
        data = request.get_json() or {}
        image1 = image2 = ""
    title = data.get("title", "").strip()
    try: price = int(data.get("price", 0))
    except: price = -1
    if not title: return jsonify({"detail": "書名不能為空"}), 400
    if price < 0: return jsonify({"detail": "價格不能為負數"}), 400
    # Support new multi-contacts JSON field, fallback to single contact_info
    contacts_raw = data.get("contacts", "")
    contact_info = data.get("contact_info", "").strip()
    contact_type = data.get("contact_type", "line")
    if contacts_raw:
        try:
            contacts_list = json.loads(contacts_raw)
            if not contacts_list:
                return jsonify({"detail": "請填寫至少一種聯絡方式"}), 400
            # Also keep legacy fields for backward compat
            contact_type = contacts_list[0].get("type", "line")
            contact_info = contacts_list[0].get("info", "")
        except Exception:
            contacts_raw = ""
    else:
        if not contact_info:
            return jsonify({"detail": "請填寫聯絡方式"}), 400
        contacts_raw = json.dumps([{"type": contact_type, "info": contact_info}], ensure_ascii=False)
    # Handle unlimited images via 'images' field (list of files)
    image_files = request.files.getlist('images') if "multipart/form-data" in ct else []
    saved_imgs = [save_image(f) for f in image_files if f and f.filename]
    saved_imgs = [x for x in saved_imgs if x]
    # Backward compat: also accept old image1/image2
    if not saved_imgs and "multipart/form-data" in ct:
        i1 = save_image(request.files.get('image1'))
        i2 = save_image(request.files.get('image2'))
        if i1: saved_imgs.append(i1)
        if i2: saved_imgs.append(i2)
    images_json = json.dumps(saved_imgs, ensure_ascii=False)
    image1 = saved_imgs[0] if saved_imgs else ""
    image2 = saved_imgs[1] if len(saved_imgs) > 1 else ""
    conn = get_db()
    cur = conn.execute("""INSERT INTO listings
        (user_id,title,author,subject,edition,condition,price,description,contact_type,contact_info,image1,image2,status,contacts,images)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'available',?,?)""",
        [user["id"], title, data.get("author","").strip(), data.get("subject",""),
         data.get("edition","").strip(), data.get("condition","全新"), price,
         data.get("description","").strip(), contact_type, contact_info, image1, image2,
         contacts_raw, images_json])
    lid = cur.lastrowid; conn.commit(); conn.close()
    return jsonify({"id": lid})

@app.route("/api/listings/<int:lid>/sold", methods=["POST"])
def mark_sold(lid):
    user, err = require_user()
    if err: return err
    e = check_owner(lid, user["id"])
    if e: return e
    conn = get_db()
    conn.execute("UPDATE listings SET is_sold=1, status='sold' WHERE id=?", [lid])
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/api/listings/<int:lid>", methods=["DELETE"])
def delete_listing(lid):
    user, err = require_user()
    if err: return err
    e = check_owner(lid, user["id"])
    if e: return e
    conn = get_db()
    conn.execute("DELETE FROM listings WHERE id=?", [lid])
    conn.commit(); conn.close()
    return jsonify({"ok": True})

# ── Favorites ──────────────────────────────────────────────────────────────

@app.route("/api/listings/<int:lid>/favorite", methods=["POST"])
def toggle_favorite(lid):
    user, err = require_user()
    if err: return err
    conn = get_db()
    existing = conn.execute("SELECT 1 FROM favorites WHERE user_id=? AND listing_id=?", [user["id"], lid]).fetchone()
    if existing:
        conn.execute("DELETE FROM favorites WHERE user_id=? AND listing_id=?", [user["id"], lid])
        conn.commit(); conn.close()
        return jsonify({"favorited": False})
    conn.execute("INSERT INTO favorites (user_id, listing_id) VALUES (?,?)", [user["id"], lid])
    conn.commit(); conn.close()
    return jsonify({"favorited": True})

# ── Conversations ──────────────────────────────────────────────────────────

@app.route("/api/conversations")
def list_conversations():
    user, err = require_user()
    if err: return err
    conn = get_db()
    rows = conn.execute("""
        SELECT c.id, c.listing_id, c.buyer_id, c.seller_id,
               l.title AS listing_title,
               ub.username AS buyer_name,
               us.username AS seller_name,
               (SELECT content FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_msg,
               (SELECT created_at FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_at,
               (SELECT COUNT(*) FROM messages WHERE conversation_id=c.id AND is_read=0 AND sender_id!=?) AS unread
        FROM conversations c
        JOIN listings l ON c.listing_id=l.id
        JOIN users ub ON c.buyer_id=ub.id
        JOIN users us ON c.seller_id=us.id
        WHERE c.buyer_id=? OR c.seller_id=?
        ORDER BY last_at DESC""", [user["id"], user["id"], user["id"]]).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["other_name"] = d["seller_name"] if d["buyer_id"] == user["id"] else d["buyer_name"]
        result.append(d)
    return jsonify(result)

@app.route("/api/conversations/unread")
def unread_count():
    user, err = require_user()
    if err: return jsonify({"count": 0})
    conn = get_db()
    row = conn.execute("""SELECT COUNT(*) as cnt FROM messages m
        JOIN conversations c ON m.conversation_id=c.id
        WHERE (c.buyer_id=? OR c.seller_id=?) AND m.sender_id!=? AND m.is_read=0""",
        [user["id"], user["id"], user["id"]]).fetchone()
    conn.close()
    return jsonify({"count": row["cnt"] if row else 0})

@app.route("/api/conversations", methods=["POST"])
def start_conversation():
    user, err = require_user()
    if err: return err
    data = request.get_json() or {}
    lid = data.get("listing_id")
    if not lid: return jsonify({"detail": "缺少 listing_id"}), 400
    conn = get_db()
    listing = conn.execute("SELECT user_id FROM listings WHERE id=?", [lid]).fetchone()
    if not listing: conn.close(); return jsonify({"detail": "找不到此刊登"}), 404
    seller_id = listing["user_id"]
    if seller_id == user["id"]: conn.close(); return jsonify({"detail": "不能向自己發起對話"}), 400
    existing = conn.execute("SELECT id FROM conversations WHERE listing_id=? AND buyer_id=?", [lid, user["id"]]).fetchone()
    if existing: conn.close(); return jsonify({"id": existing["id"]})
    cur = conn.execute("INSERT INTO conversations (listing_id, buyer_id, seller_id) VALUES (?,?,?)", [lid, user["id"], seller_id])
    cid = cur.lastrowid; conn.commit(); conn.close()
    return jsonify({"id": cid})

@app.route("/api/conversations/<int:cid>/messages")
def get_messages(cid):
    user, err = require_user()
    if err: return err
    conn = get_db()
    conv = conn.execute("SELECT * FROM conversations WHERE id=?", [cid]).fetchone()
    if not conv or (conv["buyer_id"] != user["id"] and conv["seller_id"] != user["id"]):
        conn.close(); return jsonify({"detail": "無權限"}), 403
    conn.execute("UPDATE messages SET is_read=1 WHERE conversation_id=? AND sender_id!=?", [cid, user["id"]])
    conn.commit()
    rows = conn.execute("""SELECT m.id, m.sender_id, m.content, m.created_at, u.username AS sender_name
        FROM messages m JOIN users u ON m.sender_id=u.id
        WHERE m.conversation_id=? ORDER BY m.created_at ASC""", [cid]).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/conversations/<int:cid>/messages", methods=["POST"])
def send_message(cid):
    user, err = require_user()
    if err: return err
    conn = get_db()
    conv = conn.execute("SELECT * FROM conversations WHERE id=?", [cid]).fetchone()
    if not conv or (conv["buyer_id"] != user["id"] and conv["seller_id"] != user["id"]):
        conn.close(); return jsonify({"detail": "無權限"}), 403
    data = request.get_json() or {}
    content = data.get("content", "").strip()
    if not content: conn.close(); return jsonify({"detail": "訊息不能為空"}), 400
    conn.execute("INSERT INTO messages (conversation_id, sender_id, content) VALUES (?,?,?)", [cid, user["id"], content])
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/api/conversations/<int:cid>/image", methods=["POST"])
def send_chat_image(cid):
    user, err = require_user()
    if err: return err
    conn = get_db()
    conv = conn.execute("SELECT * FROM conversations WHERE id=?", [cid]).fetchone()
    if not conv or (conv["buyer_id"] != user["id"] and conv["seller_id"] != user["id"]):
        conn.close(); return jsonify({"detail": "無權限"}), 403
    f = request.files.get("image")
    if not f: conn.close(); return jsonify({"detail": "沒有圖片"}), 400
    fname = save_image(f)
    if not fname: conn.close(); return jsonify({"detail": "不支援的格式（請上傳 jpg/png/gif/webp）"}), 400
    content = "__IMG__" + fname
    conn.execute("INSERT INTO messages (conversation_id, sender_id, content) VALUES (?,?,?)", [cid, user["id"], content])
    conn.commit(); conn.close()
    return jsonify({"ok": True, "filename": fname})

# ── Transactions ───────────────────────────────────────────────────────────

@app.route("/api/users/<username>")
def get_user_profile(username):
    viewer = get_user()
    conn = get_db()
    u = conn.execute("SELECT id, username, created_at FROM users WHERE username=?", [username]).fetchone()
    if not u:
        conn.close()
        return jsonify({"detail": "找不到此用戶"}), 404
    uid = u["id"]
    listings = conn.execute(
        "SELECT * FROM listings WHERE user_id=? ORDER BY created_at DESC", [uid]
    ).fetchall()
    items = [dict(r) for r in listings]
    if viewer:
        fav_ids = set(r[0] for r in conn.execute(
            "SELECT listing_id FROM favorites WHERE user_id=?", [viewer["id"]]
        ).fetchall())
        for item in items:
            item["is_favorited"] = (item["id"] in fav_ids)
            item["is_mine"] = (item["user_id"] == viewer["id"])
    total = len(items)
    sold  = sum(1 for i in items if i["is_sold"])
    active = sum(1 for i in items if not i["is_sold"])
    conn.close()
    return jsonify({
        "username": u["username"],
        "created_at": u["created_at"],
        "total": total,
        "sold": sold,
        "active": active,
        "listings": items,
    })

@app.route("/api/listings/<int:lid>/transaction")
def get_transaction(lid):
    user, err = require_user()
    if err: return jsonify(None)
    conn = get_db()
    row = conn.execute("SELECT * FROM transactions WHERE listing_id=?", [lid]).fetchone()
    conn.close()
    if not row: return jsonify(None)
    d = dict(row)
    d["is_buyer"] = (d["buyer_id"] == user["id"])
    d["is_seller"] = (d["seller_id"] == user["id"])
    return jsonify(d)

@app.route("/api/transactions", methods=["POST"])
def propose_meeting():
    user, err = require_user()
    if err: return err
    data = request.get_json() or {}
    lid      = data.get("listing_id")
    conv_id  = data.get("conv_id")
    meet_time = data.get("meet_time", "").strip()
    meet_loc  = data.get("meet_location", "").strip()
    if not meet_time or not meet_loc:
        return jsonify({"detail": "請填寫時間和地點"}), 400
    conn = get_db()
    listing = conn.execute("SELECT user_id FROM listings WHERE id=?", [lid]).fetchone()
    if not listing or listing["user_id"] != user["id"]:
        conn.close(); return jsonify({"detail": "只有賣家才能提議面交"}), 403
    conv = conn.execute("SELECT buyer_id FROM conversations WHERE id=?", [conv_id]).fetchone()
    if not conv: conn.close(); return jsonify({"detail": "找不到對話"}), 404
    buyer_id = conv["buyer_id"]
    existing = conn.execute("SELECT id FROM transactions WHERE listing_id=?", [lid]).fetchone()
    if existing:
        conn.execute("UPDATE transactions SET meet_time=?,meet_location=?,conv_id=?,buyer_id=?,seller_done=0,buyer_done=0 WHERE listing_id=?",
                     [meet_time, meet_loc, conv_id, buyer_id, lid])
        tid = existing["id"]
    else:
        cur = conn.execute("INSERT INTO transactions (listing_id,buyer_id,seller_id,conv_id,meet_time,meet_location) VALUES (?,?,?,?,?,?)",
                           [lid, buyer_id, user["id"], conv_id, meet_time, meet_loc])
        tid = cur.lastrowid
    # Special message
    content = f"__MEET__{meet_time}||{meet_loc}||{tid}"
    conn.execute("INSERT INTO messages (conversation_id, sender_id, content) VALUES (?,?,?)", [conv_id, user["id"], content])
    conn.execute("UPDATE listings SET status='pending' WHERE id=?", [lid])
    conn.commit(); conn.close()
    return jsonify({"id": tid})

@app.route("/api/transactions/<int:tid>/confirm", methods=["POST"])
def confirm_meeting(tid):
    user, err = require_user()
    if err: return err
    conn = get_db()
    txn = conn.execute("SELECT * FROM transactions WHERE id=?", [tid]).fetchone()
    if not txn or txn["buyer_id"] != user["id"]:
        conn.close(); return jsonify({"detail": "無權限"}), 403
    conn.execute("UPDATE listings SET status='reserved' WHERE id=?", [txn["listing_id"]])
    conn.execute("INSERT INTO messages (conversation_id,sender_id,content) VALUES (?,?,?)",
                 [txn["conv_id"], user["id"], "__MEET_CONFIRMED__"])
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/api/transactions/<int:tid>/seller-done", methods=["POST"])
def seller_done(tid):
    user, err = require_user()
    if err: return err
    conn = get_db()
    txn = conn.execute("SELECT * FROM transactions WHERE id=?", [tid]).fetchone()
    if not txn or txn["seller_id"] != user["id"]:
        conn.close(); return jsonify({"detail": "無權限"}), 403
    conn.execute("UPDATE transactions SET seller_done=1 WHERE id=?", [tid])
    txn2 = conn.execute("SELECT buyer_done FROM transactions WHERE id=?", [tid]).fetchone()
    if txn2 and txn2["buyer_done"]:
        conn.execute("UPDATE listings SET is_sold=1, status='sold' WHERE id=?", [txn["listing_id"]])
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/api/transactions/<int:tid>/buyer-done", methods=["POST"])
def buyer_done_route(tid):
    user, err = require_user()
    if err: return err
    conn = get_db()
    txn = conn.execute("SELECT * FROM transactions WHERE id=?", [tid]).fetchone()
    if not txn or txn["buyer_id"] != user["id"]:
        conn.close(); return jsonify({"detail": "無權限"}), 403
    conn.execute("UPDATE transactions SET buyer_done=1 WHERE id=?", [tid])
    txn2 = conn.execute("SELECT seller_done FROM transactions WHERE id=?", [tid]).fetchone()
    if txn2 and txn2["seller_done"]:
        conn.execute("UPDATE listings SET is_sold=1, status='sold' WHERE id=?", [txn["listing_id"]])
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/api/listings/<int:lid>/reviews", methods=["GET"])
def get_reviews(lid):
    conn = get_db()
    rows = conn.execute("""
        SELECT r.rating, r.comment, r.created_at, u.username
        FROM reviews r JOIN users u ON r.reviewer_id = u.id
        WHERE r.listing_id = ? ORDER BY r.created_at DESC
    """, [lid]).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/listings/<int:lid>/reviews", methods=["POST"])
def post_review(lid):
    user, err = require_user()
    if err: return err
    data = request.json or {}
    try: rating = int(data.get("rating", 0))
    except: rating = 0
    if not 1 <= rating <= 5:
        return jsonify({"detail": "評分需在 1-5 之間"}), 400
    comment = (data.get("comment") or "").strip()
    conn = get_db()
    listing = conn.execute("SELECT user_id FROM listings WHERE id=?", [lid]).fetchone()
    if not listing:
        conn.close(); return jsonify({"detail": "找不到此商品"}), 404
    if listing["user_id"] == user["id"]:
        conn.close(); return jsonify({"detail": "不能評論自己的商品"}), 400
    conn.execute("INSERT OR REPLACE INTO reviews (listing_id, reviewer_id, rating, comment) VALUES (?,?,?,?)",
                 [lid, user["id"], rating, comment])
    conn.commit(); conn.close()
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

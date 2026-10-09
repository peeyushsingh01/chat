import os, re, time, sqlite3, secrets, hashlib, hmac
from fastapi import FastAPI, WebSocket, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI()
HERE = os.path.dirname(os.path.abspath(__file__))
conn = sqlite3.connect(os.getenv("DB_PATH", os.path.join(HERE, "chat.db")), check_same_thread=False)
conn.row_factory = sqlite3.Row
conn.executescript("""
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, salt TEXT, pw TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, created REAL);
CREATE TABLE IF NOT EXISTS convs(id INTEGER PRIMARY KEY, name TEXT, is_group INTEGER, dm_key TEXT UNIQUE, created REAL);
CREATE TABLE IF NOT EXISTS members(conv_id INTEGER, user_id INTEGER, PRIMARY KEY(conv_id, user_id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, conv_id INTEGER, sender_id INTEGER, body TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS idx_msg ON messages(conv_id, id);
""")

def sql(s, a=()):
    cur = conn.execute(s, a)
    conn.commit()
    return cur

# ---------- auth ----------
def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()

def start_session(uid, resp):
    token = secrets.token_urlsafe(32)
    sql("INSERT INTO sessions VALUES(?,?,?)", (token, uid, time.time()))
    resp.set_cookie("sid", token, httponly=True, samesite="lax", max_age=7 * 86400,
                    secure=os.getenv("COOKIE_SECURE") == "1")

def user_from_token(token):
    if not token:
        return None
    return sql("SELECT u.id, u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",
               (token,)).fetchone()

def current(request: Request):
    u = user_from_token(request.cookies.get("sid"))
    if not u:
        raise HTTPException(401, "Not signed in")
    return u

class Creds(BaseModel):
    username: str
    password: str

@app.post("/api/register")
async def register(c: Creds, resp: Response):
    if not re.fullmatch(r"\w{3,20}", c.username) or len(c.password) < 6:
        raise HTTPException(400, "Username: 3-20 letters, digits or _. Password: at least 6 characters.")
    salt = secrets.token_hex(16)
    try:
        uid = sql("INSERT INTO users(username, salt, pw) VALUES(?,?,?)",
                  (c.username, salt, hash_pw(c.password, salt))).lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already taken")
    start_session(uid, resp)
    return {"id": uid, "username": c.username}

@app.post("/api/login")
async def login(c: Creds, resp: Response):
    u = sql("SELECT * FROM users WHERE username=?", (c.username,)).fetchone()
    if not u or not hmac.compare_digest(u["pw"], hash_pw(c.password, u["salt"])):
        raise HTTPException(401, "Wrong username or password")
    start_session(u["id"], resp)
    return {"id": u["id"], "username": u["username"]}

@app.post("/api/logout")
async def logout(request: Request, resp: Response):
    sql("DELETE FROM sessions WHERE token=?", (request.cookies.get("sid"),))
    resp.delete_cookie("sid")
    return {"ok": True}

@app.get("/api/me")
async def me(request: Request):
    return dict(current(request))

# ---------- conversations ----------
def member_ids(cid):
    return [r["user_id"] for r in sql("SELECT user_id FROM members WHERE conv_id=?", (cid,))]

def conv_view(cid, uid):
    c = sql("SELECT * FROM convs WHERE id=?", (cid,)).fetchone()
    mem = [dict(r) for r in sql("SELECT u.id, u.username FROM members m JOIN users u ON u.id=m.user_id "
                                "WHERE m.conv_id=?", (cid,))]
    name = c["name"] if c["is_group"] else next((m["username"] for m in mem if m["id"] != uid), "?")
    last = sql("SELECT body, ts FROM messages WHERE conv_id=? ORDER BY id DESC LIMIT 1", (cid,)).fetchone()
    return {"id": cid, "name": name, "is_group": bool(c["is_group"]), "members": mem,
            "last": last["body"] if last else "", "ts": last["ts"] if last else c["created"]}

@app.get("/api/users")
async def users(request: Request, q: str = ""):
    me_ = current(request)
    rows = sql("SELECT id, username FROM users WHERE id!=? AND username LIKE ? ORDER BY username LIMIT 50",
               (me_["id"], f"%{q}%"))
    return [dict(r) for r in rows]

@app.get("/api/convs")
async def convs(request: Request):
    me_ = current(request)
    ids = [r["conv_id"] for r in sql("SELECT conv_id FROM members WHERE user_id=?", (me_["id"],))]
    return sorted((conv_view(i, me_["id"]) for i in ids), key=lambda c: -c["ts"])

class DM(BaseModel):
    user_id: int

@app.post("/api/dm")
async def dm(b: DM, request: Request):
    me_ = current(request)
    if b.user_id == me_["id"] or not sql("SELECT 1 FROM users WHERE id=?", (b.user_id,)).fetchone():
        raise HTTPException(400, "Invalid user")
    key = ":".join(map(str, sorted([me_["id"], b.user_id])))
    row = sql("SELECT id FROM convs WHERE dm_key=?", (key,)).fetchone()
    if row:
        cid = row["id"]
    else:
        cid = sql("INSERT INTO convs(is_group, dm_key, created) VALUES(0,?,?)", (key, time.time())).lastrowid
        for u in (me_["id"], b.user_id):
            sql("INSERT INTO members VALUES(?,?)", (cid, u))
    return conv_view(cid, me_["id"])

class Group(BaseModel):
    name: str
    member_ids: list[int]

@app.post("/api/groups")
async def group(b: Group, request: Request):
    me_ = current(request)
    name = b.name.strip()[:40]
    ids = {i for i in b.member_ids if sql("SELECT 1 FROM users WHERE id=?", (i,)).fetchone()} | {me_["id"]}
    if not name or len(ids) < 3:
        raise HTTPException(400, "Give the group a name and pick at least 2 other people")
    cid = sql("INSERT INTO convs(name, is_group, created) VALUES(?,1,?)", (name, time.time())).lastrowid
    for u in ids:
        sql("INSERT INTO members VALUES(?,?)", (cid, u))
    await push(ids, {"type": "refresh"})
    return conv_view(cid, me_["id"])

@app.get("/api/convs/{cid}/messages")
async def messages(cid: int, request: Request):
    me_ = current(request)
    if me_["id"] not in member_ids(cid):
        raise HTTPException(403, "Not a member")
    rows = sql("SELECT m.id, m.conv_id, m.sender_id, u.username AS sender, m.body, m.ts FROM messages m "
               "JOIN users u ON u.id=m.sender_id WHERE m.conv_id=? ORDER BY m.id DESC LIMIT 200", (cid,)).fetchall()
    return [dict(r) for r in reversed(rows)]

# ---------- real time ----------
online: dict[int, set] = {}

async def push(uids, payload):
    for u in set(uids):
        for ws in list(online.get(u, ())):
            try:
                await ws.send_json(payload)
            except Exception:
                online[u].discard(ws)

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    user = user_from_token(ws.cookies.get("sid"))
    if not user:
        await ws.close(code=4401)
        return
    await ws.accept()
    uid = user["id"]
    first = not online.get(uid)
    online.setdefault(uid, set()).add(ws)
    await ws.send_json({"type": "online", "ids": [u for u, s in online.items() if s]})
    if first:
        await push(list(online), {"type": "presence", "id": uid, "online": True})
    try:
        while True:
            d = await ws.receive_json()
            cid = d.get("conv_id")
            mem = member_ids(cid) if isinstance(cid, int) else []
            if uid not in mem:
                continue
            if d.get("type") == "message":
                body = str(d.get("body") or "").strip()[:2000]
                if not body:
                    continue
                ts = time.time()
                mid = sql("INSERT INTO messages(conv_id, sender_id, body, ts) VALUES(?,?,?,?)",
                          (cid, uid, body, ts)).lastrowid
                await push(mem, {"type": "message", "id": mid, "conv_id": cid, "sender_id": uid,
                                 "sender": user["username"], "body": body, "ts": ts})
            elif d.get("type") == "typing":
                await push([m for m in mem if m != uid],
                           {"type": "typing", "conv_id": cid, "user": user["username"]})
    except Exception:
        pass
    finally:
        online.get(uid, set()).discard(ws)
        if not online.get(uid):
            online.pop(uid, None)
            await push(list(online), {"type": "presence", "id": uid, "online": False})

@app.get("/")
async def index():
    return FileResponse(os.path.join(HERE, "static", "index.html"))

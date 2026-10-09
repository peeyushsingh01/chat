import os, re, time, sqlite3, secrets, hashlib, hmac
from fastapi import FastAPI, WebSocket, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI()
HERE = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL")  # set this to use Postgres (data survives redeploys)

if DATABASE_URL:
    import psycopg
    from psycopg.rows import dict_row
    IntegrityErr = psycopg.errors.IntegrityError
    PK = "SERIAL PRIMARY KEY"
    def connect():
        return psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row)
else:
    IntegrityErr = sqlite3.IntegrityError
    PK = "INTEGER PRIMARY KEY"
    def connect():
        c = sqlite3.connect(os.getenv("DB_PATH", os.path.join(HERE, "chat.db")),
                            check_same_thread=False, isolation_level=None)
        c.row_factory = sqlite3.Row
        return c

conn = connect()

def sql(s, a=()):
    global conn
    if DATABASE_URL:
        s = s.replace("?", "%s")
    try:
        return conn.execute(s, a)
    except Exception as e:
        if DATABASE_URL and isinstance(e, (psycopg.OperationalError, psycopg.InterfaceError)):
            conn = connect()  # idle connection was dropped by the host: reconnect once
            return conn.execute(s, a)
        raise

def ins(s, a):
    if DATABASE_URL:
        return sql(s + " RETURNING id", a).fetchone()["id"]
    return sql(s, a).lastrowid

for st in f"""
CREATE TABLE IF NOT EXISTS users(id {PK}, username TEXT, salt TEXT, pw TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS ux_user ON users(lower(username));
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, created DOUBLE PRECISION);
CREATE TABLE IF NOT EXISTS convs(id {PK}, name TEXT, is_group INTEGER, dm_key TEXT UNIQUE, created DOUBLE PRECISION);
CREATE TABLE IF NOT EXISTS members(conv_id INTEGER, user_id INTEGER, PRIMARY KEY(conv_id, user_id));
CREATE TABLE IF NOT EXISTS messages(id {PK}, conv_id INTEGER, sender_id INTEGER, body TEXT, ts DOUBLE PRECISION,
  edited INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_msg ON messages(conv_id, id)
""".split(";"):
    if st.strip():
        sql(st)
for col in ("edited", "deleted"):  # upgrade databases created before these columns existed
    try:
        sql(f"ALTER TABLE messages ADD COLUMN {col} INTEGER DEFAULT 0")
    except Exception:
        pass

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
        uid = ins("INSERT INTO users(username, salt, pw) VALUES(?,?,?)",
                  (c.username, salt, hash_pw(c.password, salt)))
    except IntegrityErr:
        raise HTTPException(409, "Username already taken")
    start_session(uid, resp)
    return {"id": uid, "username": c.username}

@app.post("/api/login")
async def login(c: Creds, resp: Response):
    u = sql("SELECT * FROM users WHERE lower(username)=lower(?)", (c.username,)).fetchone()
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
    last = sql("SELECT body, ts, deleted FROM messages WHERE conv_id=? ORDER BY id DESC LIMIT 1", (cid,)).fetchone()
    return {"id": cid, "name": name, "is_group": bool(c["is_group"]), "members": mem,
            "last": ("Message deleted" if last["deleted"] else last["body"]) if last else "", "ts": last["ts"] if last else c["created"]}

@app.get("/api/users")
async def users(request: Request, q: str = ""):
    me_ = current(request)
    rows = sql("SELECT id, username FROM users WHERE id!=? AND lower(username) LIKE lower(?) ORDER BY username LIMIT 50",
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
        cid = ins("INSERT INTO convs(is_group, dm_key, created) VALUES(0,?,?)", (key, time.time()))
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
    cid = ins("INSERT INTO convs(name, is_group, created) VALUES(?,1,?)", (name, time.time()))
    for u in ids:
        sql("INSERT INTO members VALUES(?,?)", (cid, u))
    await push(ids, {"type": "refresh"})
    return conv_view(cid, me_["id"])

@app.get("/api/convs/{cid}/messages")
async def messages(cid: int, request: Request):
    me_ = current(request)
    if me_["id"] not in member_ids(cid):
        raise HTTPException(403, "Not a member")
    rows = sql("SELECT m.id, m.conv_id, m.sender_id, u.username AS sender, m.body, m.ts, m.edited, m.deleted FROM messages m "
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
                mid = ins("INSERT INTO messages(conv_id, sender_id, body, ts) VALUES(?,?,?,?)",
                          (cid, uid, body, ts))
                await push(mem, {"type": "message", "id": mid, "conv_id": cid, "sender_id": uid,
                                 "sender": user["username"], "body": body, "ts": ts})
            elif d.get("type") in ("edit", "delete"):
                mid = d.get("id")
                if not isinstance(mid, int):
                    continue
                if d["type"] == "edit":
                    body = str(d.get("body") or "").strip()[:2000]
                    if body and sql("UPDATE messages SET body=?, edited=1 WHERE id=? AND conv_id=? AND sender_id=? AND deleted=0",
                                    (body, mid, cid, uid)).rowcount:
                        await push(mem, {"type": "edited", "conv_id": cid, "id": mid, "body": body})
                elif sql("UPDATE messages SET body='', deleted=1 WHERE id=? AND conv_id=? AND sender_id=?",
                         (mid, cid, uid)).rowcount:
                    await push(mem, {"type": "deleted", "conv_id": cid, "id": mid})
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

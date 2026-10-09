# Kamand Chat

Real-time chat built for the KamandPrompt "First Commit" hackathon. Python (FastAPI) backend, WebSockets, SQLite, and a dependency-free HTML/JS frontend.

## Features
- Register / log in / log out with a persistent cookie session (PBKDF2-hashed passwords, HttpOnly cookie, server-side session table)
- One-to-one chats, delivered in real time over WebSockets
- Group chats (name + members)
- Persistent storage of users, sessions, conversations, memberships and messages (SQLite)
- Online/offline presence, typing indicators, unread badges
- Auto-reconnect: the client resyncs conversations and history after a dropped connection

## Architecture
```
Browser (static/index.html)  --REST (/api/*)-->  FastAPI (main.py)  -->  SQLite (chat.db)
                             <==WebSocket /ws==>
```
REST handles auth, user search, creating chats and loading history. The `/ws` socket authenticates with the session cookie, checks conversation membership on every event, stores each message, then pushes it to all online members of that conversation.

## Setup
```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```
Open http://localhost:8000 in two different browsers (or one normal + one incognito window), register two users, and start a chat.

## Environment variables (all optional)
| Variable | Default | Purpose |
|---|---|---|
| `DB_PATH` | `./chat.db` | SQLite file location |
| `COOKIE_SECURE` | unset | Set to `1` when serving over HTTPS |

No API keys are required, so none are committed.

## Testing in a clean environment
Run the setup above on a fresh machine, register `alice` and `bob` in separate browsers, message each other, refresh the page (history persists), then create a group with a third user.

## Deploying
Render/Railway: build `pip install -r requirements.txt`, start `uvicorn main:app --host 0.0.0.0 --port $PORT`, set `COOKIE_SECURE=1`. Use a persistent disk for `DB_PATH`, or the data resets on redeploy.

## Database
- **Local:** SQLite file (`chat.db`), no setup.
- **Production:** set `DATABASE_URL` to a Postgres connection string (Neon, Supabase, Render Postgres, etc.). The app creates its tables on startup and your data survives redeploys. Free app hosts wipe local files, so use this when deploying.

## More features
Edit and delete your own messages (updates live for everyone), in-chat message search, desktop notifications and unread count in the tab title.

# P2P Backend

A lightweight WebRTC signaling server used to broker peer-to-peer connections. Clients create a short-lived session token, exchange offer/answer/ICE messages over Socket.IO using that token, and the server relays signaling data between exactly two peers per session — no media or data ever passes through the server itself.

## Tech Stack

- Node.js / Express 5
- Socket.IO (signaling transport)
- Zod (payload validation)
- Helmet, CORS, express-rate-limit, compression
- Winston (logging)

## How It Works

1. A client calls `POST /api/create-session` and receives a token with an expiry (`TOKEN_TTL_MS`, default 30 minutes).
2. Both peers connect over Socket.IO and emit `register` with that token — the first is assigned `host`, the second `joiner`.
3. Once both are registered, the server emits `ready` and relays `signal` events (offer/answer/ICE candidates) between them.
4. Either peer can end the session with `session-complete`, or it expires automatically after the TTL.

## Getting Started

```bash
npm install
npm run dev     # nodemon, local development
npm start        # production
```

## Environment Variables

| Variable | Description |
|---|---|
| `PORT` | Port to listen on (default `4000`) |
| `HOST` | Host to bind to (default `0.0.0.0`) |
| `ALLOWED_ORIGIN` | Allowed CORS/Socket.IO origin |
| `TOKEN_TTL_MS` | Session token lifetime in ms (default 30 min) |
| `SSL_KEY_PATH` / `SSL_CERT_PATH` | Optional, enables HTTPS when both are set |

## Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/health` | Health check |
| `GET /api/keep-alive` | Keep-alive / self-ping target |
| `POST /api/create-session` | Create a new signaling session, returns a token |

Socket.IO events: `register`, `signal`, `session-complete`, `ready`, `error-message`, `session-destroyed`.

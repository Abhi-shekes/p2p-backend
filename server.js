import fs from "fs";
import http from "http";
import https from "https";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import compression from "compression";
import { Server as SocketIOServer } from "socket.io";
import crypto from "crypto";
import winston from "winston";
import { z } from "zod";

// Environment variable validation
const requiredEnvVars = ["PORT", "HOST", "ALLOWED_ORIGIN"];
const missingEnvVars = requiredEnvVars.filter((key) => !process.env[key]);

// Configuration
const PORT = Number(process.env.PORT) || 4000;
const HOST = process.env.HOST || "0.0.0.0";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "http://localhost:3000";
const TOKEN_TTL_MS = Number(process.env.TOKEN_TTL_MS) || 10 * 60 * 1000; // 10 minutes
const TOKEN_LENGTH = 16; // Increased for better security
const SSL_KEY_PATH = process.env.SSL_KEY_PATH || "";
const SSL_CERT_PATH = process.env.SSL_CERT_PATH || "";

// Logger setup with Winston
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "server.log" }),
  ],
});

// In-memory session store
const sessions = new Map();

// Generate secure tokens
function generateToken() {
  return crypto.randomBytes(TOKEN_LENGTH / 2).toString("hex");
}

// Utility functions
function now() {
  return Date.now();
}

function createSession(req) {
  const token = generateToken();
  const createdAt = now();
  const expiresAt = createdAt + TOKEN_TTL_MS;

  const timeout = setTimeout(() => {
    destroySession(token);
  }, TOKEN_TTL_MS);

  const session = {
    createdAt,
    expiresAt,
    hostSocketId: null,
    joinerSocketId: null,
    timeout,
    metadata: {
      createdIp: req?.ip || "unknown",
      createdAt: new Date(createdAt).toISOString(),
    },
  };

  sessions.set(token, session);

  // Print statement for session creation
  logger.info(`Session created: token=${token}, createdAt=${session.metadata.createdAt}, expiresAt=${new Date(expiresAt).toISOString()}`);

  return { token, createdAt, expiresAt };
}

function getSession(token) {
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= now()) {
    destroySession(token);
    return null;
  }
  return session;
}

function destroySession(token) {
  const session = sessions.get(token);
  if (session && session.timeout) clearTimeout(session.timeout);
  sessions.delete(token);
  logger.info(`Session destroyed: token=${token}`);
}

// Periodic session cleanup
setInterval(() => {
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt <= now()) {
      destroySession(token);
    }
  }
}, 60 * 1000);

function isValidToken(token) {
  if (typeof token !== "string") return false;
  if (token.length !== TOKEN_LENGTH) return false;
  return /^[A-Fa-f0-9]+$/.test(token);
}

// Zod schemas for payload validation
const registerPayloadSchema = z.object({
  token: z.string().refine(isValidToken, { message: "Invalid token format" }),
});

const signalPayloadSchema = z.object({
  token: z.string().refine(isValidToken, { message: "Invalid token format" }),
  type: z.enum(["offer", "answer", "ice"]),
  data: z.any(),
});

const sessionCompletePayloadSchema = z.object({
  token: z.string().refine(isValidToken, { message: "Invalid token format" }),
});

const app = express();
app.set("trust proxy", 1);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));
app.use(express.json({ limit: "20kb" }));
app.use(compression());

app.use(
  cors({
    origin: ALLOWED_ORIGIN,
    methods: ["GET", "POST"],
    credentials: false,
  })
);

// HTTP rate limiter (default keyGenerator handles IPv6 correctly)
const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: "Too many requests from this IP, please try again later.",
    });
  },
});


app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.post("/api/create-session", (req, res) => {
  try {
    const { token, createdAt, expiresAt } = createSession(req);
    res.json({ token, createdAt, expiresAt });
  } catch (error) {
    logger.error(`Create session error: ${error.message}`);
    res.status(500).json({ error: "Failed to create session" });
  }
});

// Create server
let server;
if (SSL_KEY_PATH && SSL_CERT_PATH && fs.existsSync(SSL_KEY_PATH) && fs.existsSync(SSL_CERT_PATH)) {
  const key = fs.readFileSync(SSL_KEY_PATH);
  const cert = fs.readFileSync(SSL_CERT_PATH);
  server = https.createServer({ key, cert }, app);
  logger.info("[signaling] HTTPS enabled");
} else {
  server = http.createServer(app);
  logger.warn("[signaling] Running over HTTP for local/dev. Use TLS in production");
}

const io = new SocketIOServer(server, {
  cors: { origin: ALLOWED_ORIGIN, methods: ["GET", "POST"] },
  allowEIO3: false,
});

// Socket.IO rate limiter
const socketLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 50,
  keyGenerator: (req) => req.headers["x-forwarded-for"] || req.socket.remoteAddress,
});

io.use((socket, next) => {
  socketLimiter(socket.request, {}, (err) => {
   
    next();
  });
});

io.on("connection", (socket) => {
  socket.data.fingerprint = crypto.randomBytes(8).toString("hex");
  logger.info(`New connection: socketId=${socket.id}, ip=${socket.request.socket.remoteAddress}`);

  socket.on("register", (payload = {}) => {
    try {
      const { token } = registerPayloadSchema.parse(payload);
      const session = getSession(token);
      if (!session) {
        socket.emit("error-message", { message: "Session not found or expired. Please create a new session." });
        logger.warn(`Register failed: token=${token}, reason=Session not found or expired`);
        return;
      }
      if (!session.hostSocketId && session.joinerSocketId) {
        socket.emit("error-message", { message: "Host not connected. Please try again later." });
        logger.warn(`Register failed: token=${token}, reason=Host not connected`);
        return;
      }

      let role = null;
      if (!session.hostSocketId) {
        session.hostSocketId = socket.id;
        role = "host";
      } else if (!session.joinerSocketId && session.hostSocketId !== socket.id) {
        session.joinerSocketId = socket.id;
        role = "joiner";
      } else {
        socket.emit("error-message", { message: "Session already has two participants." });
        logger.warn(`Register failed: token=${token}, reason=Session full`);
        return;
      }

      socket.join(token);
      socket.emit("registered", { role, token, expiresAt: session.expiresAt });
      logger.info(`Registered: socketId=${socket.id}, token=${token}, role=${role}`);

      if (session.hostSocketId && session.joinerSocketId) {
        io.to(token).emit("ready", { token });
        logger.info(`Session ready: token=${token}, host=${session.hostSocketId}, joiner=${session.joinerSocketId}`);
      }
    } catch (error) {
      const message = error instanceof z.ZodError ? error.errors[0].message : "Registration failed. Please try again.";
      socket.emit("error-message", { message });
      logger.error(`Register error: socketId=${socket.id}, error=${error.message}`);
    }
  });

  socket.on("signal", (payload = {}) => {
    try {
      const { token, type, data } = signalPayloadSchema.parse(payload);
      const session = getSession(token);
      if (!session) {
        logger.warn(`Signal failed: token=${token}, reason=Session not found`);
        return;
      }

      const targetId = socket.id === session.hostSocketId ? session.joinerSocketId : session.hostSocketId;
      if (!targetId) {
        logger.warn(`Signal failed: token=${token}, reason=No target ID`);
        return;
      }
      io.to(targetId).emit("signal", { type, data });
      logger.debug(`Signal sent: token=${token}, type=${type}, from=${socket.id}, to=${targetId}`);
    } catch (error) {
      logger.error(`Signal error: socketId=${socket.id}, error=${error.message}`);
    }
  });

  socket.on("session-complete", (payload = {}) => {
    try {
      const { token } = sessionCompletePayloadSchema.parse(payload);
      destroySession(token);
      io.to(token).emit("session-destroyed", { token });
      io.socketsLeave(token);
      logger.info(`Session completed: token=${token}, socketId=${socket.id}`);
    } catch (error) {
      logger.error(`Session complete error: socketId=${socket.id}, error=${error.message}`);
    }
  });

  socket.on("disconnect", () => {
    for (const [token, session] of sessions.entries()) {
      if (session.hostSocketId === socket.id || session.joinerSocketId === socket.id) {
        destroySession(token);
        io.to(token).emit("session-destroyed", { token });
        io.socketsLeave(token);
        logger.info(`Session destroyed due to disconnect: token=${token}, socketId=${socket.id}`);
      }
    }
  });
});

// Handle graceful shutdown
const gracefulShutdown = () => {
  logger.info("Shutting down server...");
  io.close(() => {
    logger.info("Socket.IO server closed");
  });
  server.close(() => {
    logger.info("HTTP/HTTPS server closed");
    sessions.clear();
    process.exit(0);
  });
};

process.on("SIGINT", gracefulShutdown);
process.on("SIGTERM", gracefulShutdown);

// Global error handling
process.on("uncaughtException", (error) => {
  logger.error(`Uncaught Exception: ${error.message}`);
});
process.on("unhandledRejection", (reason) => {
  logger.error(`Unhandled Rejection: ${reason}`);
});

server.listen(PORT, HOST, () => {
  logger.info(`[signaling] Listening on ${SSL_KEY_PATH && SSL_CERT_PATH ? "https" : "http"}://${HOST}:${PORT}, Memory: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`);
  logger.info(`[signaling] CORS allowed origin: ${ALLOWED_ORIGIN}`);
});

import WebSocket from "ws";
globalThis.WebSocket = WebSocket;

import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import QRCode from "qrcode";
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const baileys = await import("@whiskeysockets/baileys");

const makeWASocket =
  baileys.default?.default ||
  baileys.default ||
  baileys.makeWASocket;

const {
  BufferJSON,
  initAuthCreds,
  DisconnectReason,
  fetchLatestBaileysVersion,
  Browsers
} = baileys;

if (typeof makeWASocket !== "function") {
  throw new Error("makeWASocket tidak ditemukan. Periksa instalasi Baileys.");
}

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 8000;

app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  SESSION_ENCRYPTION_KEY
} = process.env;

const sockets = new Map();
const socketModes = new Map();
const pairingReady = new Set();
const liveState = new Map();
const startLocks = new Map();
const reconnectTimers = new Map();
const pairingLocks = new Map();
const manualDisconnect = new Set();

// =====================================
// SUPABASE
// =====================================

function getAdmin() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Konfigurasi Supabase belum lengkap.");
  }

  if (!/^[a-fA-F0-9]{64}$/.test(SESSION_ENCRYPTION_KEY || "")) {
    throw new Error("SESSION_ENCRYPTION_KEY harus 64 karakter hex.");
  }

  return createClient(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    }
  );
}

// =====================================
// ENKRIPSI SESSION
// =====================================

function encryptJson(value) {
  const key = Buffer.from(SESSION_ENCRYPTION_KEY, "hex");
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const plain = Buffer.from(
    JSON.stringify(value, BufferJSON.replacer),
    "utf8"
  );

  const encrypted = Buffer.concat([
    cipher.update(plain),
    cipher.final()
  ]);

  return {
    encrypted: true,
    iv: iv.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
    data: encrypted.toString("hex")
  };
}

function decryptJson(record) {
  if (!record || record.encrypted !== true) {
    throw new Error("Data sesi tidak valid.");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(SESSION_ENCRYPTION_KEY, "hex"),
    Buffer.from(record.iv, "hex")
  );

  decipher.setAuthTag(Buffer.from(record.tag, "hex"));

  const plain = Buffer.concat([
    decipher.update(Buffer.from(record.data, "hex")),
    decipher.final()
  ]).toString("utf8");

  return JSON.parse(plain, BufferJSON.reviver);
}

// =====================================
// AUTH USER
// =====================================

async function requireUser(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        error: "Token login tidak ditemukan."
      });
    }

    const admin = getAdmin();

    const { data, error } = await admin.auth.getUser(token);

    if (error || !data?.user) {
      return res.status(401).json({
        error: "Sesi login tidak valid."
      });
    }

    req.user = data.user;
    req.admin = admin;

    next();
  } catch (error) {
    console.error("Auth:", error.message);

    return res.status(503).json({
      error: error.message || "Layanan autentikasi tidak tersedia."
    });
  }
}

// =====================================
// DATABASE AUTH STATE
// =====================================

async function createDatabaseAuthState(admin, userId) {
  const { data: existing, error } = await admin
    .from("whatsapp_sessions")
    .select("creds")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) throw error;

  const creds = existing?.creds
    ? decryptJson(existing.creds)
    : initAuthCreds();

  const keys = {
    get: async (type, ids) => {
      if (!ids.length) return {};

      const { data, error } = await admin
        .from("whatsapp_auth_keys")
        .select("key_id,value")
        .eq("user_id", userId)
        .eq("key_type", type)
        .in("key_id", ids);

      if (error) throw error;

      const found = new Map(
        (data || []).map(row => [row.key_id, row.value])
      );

      const result = {};

      for (const id of ids) {
        const stored = found.get(id);
        result[id] = stored ? decryptJson(stored) : null;
      }

      return result;
    },

    set: async data => {
      for (const [type, entries] of Object.entries(data)) {
        const upserts = [];
        const deletes = [];

        for (const [id, value] of Object.entries(entries || {})) {
          if (value === null || value === undefined) {
            deletes.push(id);
          } else {
            upserts.push({
              user_id: userId,
              key_type: type,
              key_id: id,
              value: encryptJson(value)
            });
          }
        }

        if (deletes.length) {
          const { error } = await admin
            .from("whatsapp_auth_keys")
            .delete()
            .eq("user_id", userId)
            .eq("key_type", type)
            .in("key_id", deletes);

          if (error) throw error;
        }

        if (upserts.length) {
          const { error } = await admin
            .from("whatsapp_auth_keys")
            .upsert(upserts, {
              onConflict: "user_id,key_type,key_id"
            });

          if (error) throw error;
        }
      }
    }
  };

  return {
    state: { creds, keys },

    saveCreds: async () => {
      const { error } = await admin
        .from("whatsapp_sessions")
        .update({
          creds: encryptJson(creds),
          updated_at: new Date().toISOString()
        })
        .eq("user_id", userId);

      if (error) throw error;
    }
  };
}

// =====================================
// SESSION DATABASE
// =====================================

async function ensureSession(admin, userId, creds, status) {
  const { error } = await admin
    .from("whatsapp_sessions")
    .upsert({
      user_id: userId,
      creds: encryptJson(creds),
      status,
      updated_at: new Date().toISOString()
    }, {
      onConflict: "user_id"
    });

  if (error) throw error;
}

async function setStatus(admin, userId, status, phoneNumber = null) {
  const { error } = await admin
    .from("whatsapp_sessions")
    .update({
      status,
      phone_number: phoneNumber,
      updated_at: new Date().toISOString()
    })
    .eq("user_id", userId);

  if (error) {
    console.error("Status database:", error.message);
  }
}

// =====================================
// RECONNECT MANAGEMENT
// =====================================

function clearReconnect(userId) {
  const timer = reconnectTimers.get(userId);

  if (timer) clearTimeout(timer);

  reconnectTimers.delete(userId);
}

// =====================================
// TUNGGU SOCKET SIAP
// =====================================

function waitForPairingReady(userId, sock, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    if (sockets.get(userId) !== sock) {
      reject(new Error("Socket WhatsApp sudah berubah. Coba hubungkan ulang."));
      return;
    }

    if (sock.user) {
      reject(new Error("WhatsApp sudah terhubung."));
      return;
    }

    const current = liveState.get(userId);

    if (pairingReady.has(userId) || current?.qr) {
      resolve();
      return;
    }

    let finished = false;
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      sock.ev.off("connection.update", onUpdate);
    };

    const done = error => {
      if (finished) return;

      finished = true;
      cleanup();

      if (error) reject(error);
      else resolve();
    };

    const onUpdate = update => {
      if (sockets.get(userId) !== sock) {
        done(new Error("Socket WhatsApp berubah. Coba hubungkan ulang."));
        return;
      }

      if (update.qr) {
        done();
        return;
      }

      if (update.connection === "open" || sock.user) {
        done(new Error("WhatsApp sudah terhubung."));
        return;
      }

      if (update.connection === "close") {
        const code =
          update.lastDisconnect?.error?.output?.statusCode;

        done(new Error(
          `Koneksi WhatsApp terputus sebelum Pairing Code dibuat. Code: ${code || "unknown"}`
        ));
      }
    };

    timer = setTimeout(() => {
      done(new Error(
        "Waktu tunggu koneksi habis. Coba hubungkan ulang WhatsApp."
      ));
    }, timeoutMs);

    sock.ev.on("connection.update", onUpdate);

    const latest = liveState.get(userId);

    if (pairingReady.has(userId) || latest?.qr) {
      done();
    } else if (sockets.get(userId) !== sock) {
      done(new Error("Koneksi WhatsApp sudah terputus."));
    }
  });
}

// =====================================
// WHATSAPP SOCKET
// =====================================

async function startWhatsApp(userId, admin, mode = "qr") {
  let existing = sockets.get(userId);

  if (existing && socketModes.get(userId) === mode) {
    return existing;
  }

  if (existing && !existing.user) {
    sockets.delete(userId);
    socketModes.delete(userId);
    pairingReady.delete(userId);
    try { existing.end(undefined); } catch {}
    existing = null;
  }

  if (existing?.user) {
    return existing;
  }

  if (startLocks.has(userId)) {
    const pendingSocket = await startLocks.get(userId);

    if (socketModes.get(userId) === mode) {
      return pendingSocket;
    }

    if (pendingSocket?.user) {
      return pendingSocket;
    }

    if (sockets.get(userId) === pendingSocket) {
      sockets.delete(userId);
    }
    socketModes.delete(userId);
    pairingReady.delete(userId);
    try { pendingSocket?.end(undefined); } catch {}
  }

  const task = (async () => {
    const { state, saveCreds } =
      await createDatabaseAuthState(admin, userId);

    await ensureSession(admin, userId, state.creds, "connecting");

    liveState.set(userId, {
      status: "connecting",
      qr: null,
      pairingCode: null,
      phoneNumber: null
    });

    let version;

    try {
      const latest = await fetchLatestBaileysVersion();
      version = latest.version;

      console.log("WhatsApp Web version:", version);
    } catch (error) {
      console.error(
        "Gagal mengambil versi WhatsApp Web:",
        error.message
      );

      throw new Error(
        "Tidak bisa mengambil versi WhatsApp Web. Periksa koneksi server."
      );
    }

    const browser = mode === "pairing"
      ? (Browsers?.macOS ? Browsers.macOS("Desktop") : ["macOS", "Desktop", "14.4.1"])
      : ["Blasting Juara", "Chrome", "1.0.0"];

    const socketOptions = {
      version,
      auth: state,
      markOnlineOnConnect: false,
      syncFullHistory: false,
      browser,
      connectTimeoutMs: 60000,
      defaultQueryTimeoutMs: 60000,
      keepAliveIntervalMs: 25000
    };

    if (mode === "qr") {
      socketOptions.printQRInTerminal = false;
    }

    const sock = makeWASocket(socketOptions);

    sockets.set(userId, sock);
    socketModes.set(userId, mode);
    pairingReady.delete(userId);

    let credsSavePromise = Promise.resolve();

    sock.ev.on("creds.update", () => {
      credsSavePromise = credsSavePromise
        .then(() => saveCreds())
        .catch(error => {
          console.error("Simpan kredensial:", error.message);
        });
    });

    sock.ev.on("connection.update", async update => {
      if (sockets.get(userId) !== sock) return;

      if (update.qr) {
        const previous = liveState.get(userId);

        if (mode === "pairing") {
          pairingReady.add(userId);

          liveState.set(userId, {
            status: "waiting_pairing",
            qr: null,
            pairingCode: previous?.pairingCode || null,
            pairingCreatedAt: previous?.pairingCreatedAt || null,
            phoneNumber: previous?.phoneNumber || null
          });

          console.log("Socket siap untuk Pairing Code:", userId);
          await setStatus(admin, userId, "waiting_pairing");
        } else {
          const hasPairingCode =
            previous?.status === "waiting_pairing" &&
            Boolean(previous?.pairingCode);

          const nextStatus = hasPairingCode
            ? "waiting_pairing"
            : "waiting_qr";

          liveState.set(userId, {
            status: nextStatus,
            qr: update.qr,
            pairingCode: hasPairingCode
              ? previous.pairingCode
              : null,
            pairingCreatedAt: hasPairingCode
              ? previous.pairingCreatedAt || null
              : null,
            phoneNumber: hasPairingCode
              ? previous.phoneNumber
              : null
          });

          console.log("QR WhatsApp diterima:", userId);
          await setStatus(admin, userId, nextStatus);
        }
      }

      if (update.connection === "connecting") {
        console.log("WhatsApp sedang menghubungkan:", userId);
      }

      if (update.connection === "open") {
        clearReconnect(userId);

        const phoneNumber = String(sock.user?.id || "")
          .split(":")[0]
          .split("@")[0] || null;

        liveState.set(userId, {
          status: "connected",
          qr: null,
          pairingCode: null,
          phoneNumber
        });

        await setStatus(admin, userId, "connected", phoneNumber);

        console.log("WhatsApp terhubung:", userId);
      }

      if (update.connection === "close") {
        if (sockets.get(userId) !== sock) return;

        const reconnectMode = socketModes.get(userId) || mode;

        sockets.delete(userId);
        socketModes.delete(userId);
        pairingReady.delete(userId);

        const code =
          update.lastDisconnect?.error?.output?.statusCode;

        const errorMessage =
          update.lastDisconnect?.error?.message || "Tidak diketahui";

        const authRejected = code === DisconnectReason.loggedOut;

        const restartRequired = code === DisconnectReason.restartRequired;
        const shouldRestartPairing =
          restartRequired && reconnectMode === "pairing";

        liveState.set(userId, {
          status: shouldRestartPairing ? "connecting" : "disconnected",
          qr: null,
          pairingCode: null,
          phoneNumber: null
        });

        await setStatus(
          admin,
          userId,
          shouldRestartPairing ? "connecting" : "disconnected"
        );

        console.error(
          "WhatsApp terputus:",
          userId,
          "Code:",
          code,
          "Error:",
          errorMessage
        );

        if (authRejected) {
          clearReconnect(userId);
          console.error(
            "WhatsApp menolak autentikasi. Kredensial tetap disimpan:",
            userId
          );
          return;
        }

        if (
          !manualDisconnect.has(userId) &&
          (reconnectMode === "qr" || shouldRestartPairing)
        ) {
          clearReconnect(userId);

          const reconnectDelay = shouldRestartPairing ? 1000 : 5000;
          const timer = setTimeout(async () => {
            reconnectTimers.delete(userId);

            if (
              !sockets.has(userId) &&
              !manualDisconnect.has(userId)
            ) {
              try {
                if (shouldRestartPairing) {
                  await credsSavePromise;
                }

                await startWhatsApp(userId, admin, reconnectMode);
              } catch (error) {
                console.error("Reconnect WhatsApp:", error.message);
              }
            }
          }, reconnectDelay);

          reconnectTimers.set(userId, timer);
        }
      }
    });

    return sock;
  })();

  startLocks.set(userId, task);

  try {
    return await task;
  } finally {
    startLocks.delete(userId);
  }
}

// =====================================
// HOME / HEALTH
// =====================================

app.get("/", (_req, res) => {
  res.json({
    status: "online",
    app: "Blasting Juara WhatsApp Server"
  });
});

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    whatsappConfigured: Boolean(
      SUPABASE_URL &&
      SUPABASE_SERVICE_ROLE_KEY &&
      /^[a-fA-F0-9]{64}$/.test(SESSION_ENCRYPTION_KEY || "")
    ),
    baileysLoaded: typeof makeWASocket === "function",
    pairingSupported: true
  });
});

const connectLimiter = rateLimit({
  windowMs: 60000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

// =====================================
// KONEKSI QR
// =====================================

app.post(
  "/whatsapp/connect",
  connectLimiter,
  requireUser,
  async (req, res) => {
    try {
      const userId = req.user.id;

      manualDisconnect.delete(userId);
      clearReconnect(userId);

      const sock = await startWhatsApp(userId, req.admin, "qr");
      const state = liveState.get(userId);

      return res.json({
        success: true,
        status: state?.status || "connecting",
        connected: Boolean(sock.user)
      });
    } catch (error) {
      console.error("Koneksi QR:", error);

      return res.status(500).json({
        error: error.message || "Gagal memulai koneksi WhatsApp."
      });
    }
  }
);

// =====================================
// KONEKSI PAIRING CODE
// =====================================

app.post(
  "/whatsapp/pair",
  connectLimiter,
  requireUser,
  async (req, res) => {
    const userId = req.user.id;

    if (pairingLocks.has(userId)) {
      return res.status(409).json({
        error: "Permintaan Pairing Code sedang diproses. Tunggu sebentar."
      });
    }

    let pairingSocket = null;

    const task = (async () => {
      let phoneNumber = String(req.body.phoneNumber || "")
        .replace(/\D/g, "");

      if (phoneNumber.startsWith("0")) {
        phoneNumber = "62" + phoneNumber.slice(1);
      }

      if (!/^[1-9]\d{9,14}$/.test(phoneNumber)) {
        throw new Error(
          "Nomor tidak valid. Gunakan kode negara, contoh 628123456789."
        );
      }

      manualDisconnect.delete(userId);
      clearReconnect(userId);
      pairingReady.delete(userId);

      const sock = await startWhatsApp(userId, req.admin, "pairing");
      pairingSocket = sock;

      if (sockets.get(userId) !== sock) {
        throw new Error(
          "Socket berubah saat memulai koneksi. Coba hubungkan ulang."
        );
      }

      if (sock.user) {
        throw new Error(
          "WhatsApp sudah terhubung. Putuskan koneksi dahulu jika ingin mengganti nomor."
        );
      }

      if (typeof sock.requestPairingCode !== "function") {
        throw new Error(
          "Fitur Pairing Code tidak tersedia pada socket Baileys."
        );
      }

      await waitForPairingReady(userId, sock, 60000);

      if (sockets.get(userId) !== sock) {
        throw new Error(
          "Socket WhatsApp berubah. Silakan coba hubungkan ulang."
        );
      }

      if (sock.user) {
        throw new Error("WhatsApp sudah terhubung.");
      }

      const pairingCode = await sock.requestPairingCode(phoneNumber);

      if (!pairingCode || typeof pairingCode !== "string") {
        throw new Error("WhatsApp tidak mengembalikan Pairing Code yang valid.");
      }

      if (sockets.get(userId) !== sock) {
        throw new Error(
          "Socket berubah setelah permintaan Pairing Code."
        );
      }

      liveState.set(userId, {
        status: "waiting_pairing",
        qr: null,
        pairingCode: String(pairingCode),
        pairingCreatedAt: Date.now(),
        phoneNumber
      });

      await setStatus(
        req.admin,
        userId,
        "waiting_pairing",
        phoneNumber
      );

      console.log(
        "Pairing Code berhasil dibuat untuk sesi:",
        userId,
        "Panjang kode:",
        String(pairingCode).length
      );

      return {
        success: true,
        status: "waiting_pairing",
        phoneNumber,
        pairingCode: String(pairingCode),
        pairingCreatedAt: liveState.get(userId)?.pairingCreatedAt || Date.now()
      };
    })();

    pairingLocks.set(userId, task);

    try {
      const result = await task;
      return res.json(result);
    } catch (error) {
      console.error("Pairing Code gagal:", {
        userId,
        message: error?.message || String(error),
        statusCode: error?.output?.statusCode || error?.statusCode || null
      });

      if (pairingSocket && sockets.get(userId) === pairingSocket && !pairingSocket.user) {
        sockets.delete(userId);
        socketModes.delete(userId);
        pairingReady.delete(userId);
        try { pairingSocket.end(undefined); } catch {}

        liveState.set(userId, {
          status: "disconnected",
          qr: null,
          pairingCode: null,
          phoneNumber: null
        });

        await setStatus(req.admin, userId, "disconnected");
      }

      return res.status(500).json({
        error: error.message || "Gagal membuat Pairing Code. Silakan minta kode baru."
      });
    } finally {
      pairingLocks.delete(userId);
    }
  }
);

// =====================================
// STATUS WHATSAPP
// =====================================

app.get(
  "/whatsapp/status",
  requireUser,
  async (req, res) => {
    try {
      const userId = req.user.id;
      let state = liveState.get(userId);

      if (!state) {
        const { data, error } = await req.admin
          .from("whatsapp_sessions")
          .select("creds,status,phone_number")
          .eq("user_id", userId)
          .maybeSingle();

        if (error) throw error;

        if (data?.creds) {
          const savedCreds = decryptJson(data.creds);

          if (savedCreds.registered) {
            await startWhatsApp(userId, req.admin, "qr");
            state = liveState.get(userId);
          }
        }
      }

      state = state || {
        status: "disconnected",
        qr: null,
        pairingCode: null,
        phoneNumber: null
      };

      let qrImage = null;

      if (state.qr && state.status !== "connected") {
        qrImage = await QRCode.toDataURL(String(state.qr), {
          errorCorrectionLevel: "H",
          type: "image/png",
          margin: 4,
          width: 400,
          color: {
            dark: "#000000",
            light: "#FFFFFF"
          }
        });
      }

      return res.json({
        status: state.status,
        phoneNumber: state.phoneNumber,
        pairingCode: state.pairingCode,
        pairingCreatedAt: state.pairingCreatedAt || null,
        qr: qrImage
      });
    } catch (error) {
      console.error("Status WhatsApp:", error);

      return res.status(500).json({
        error: error.message || "Gagal membaca status WhatsApp."
      });
    }
  }
);

// =====================================
// PUTUSKAN WHATSAPP
// =====================================

app.post(
  "/whatsapp/disconnect",
  requireUser,
  async (req, res) => {
    const userId = req.user.id;

    try {
      manualDisconnect.add(userId);
      clearReconnect(userId);

      const sock = sockets.get(userId);

      sockets.delete(userId);
      socketModes.delete(userId);
      pairingReady.delete(userId);

      if (sock) {
        try {
          await sock.logout();
        } catch (error) {
          console.error("Logout:", error.message);

          try {
            sock.end(undefined);
          } catch {}
        }
      }

      liveState.set(userId, {
        status: "disconnected",
        qr: null,
        pairingCode: null,
        phoneNumber: null
      });

      const { error: sessionError } = await req.admin
        .from("whatsapp_sessions")
        .delete()
        .eq("user_id", userId);

      if (sessionError) throw sessionError;

      const { error: keysError } = await req.admin
        .from("whatsapp_auth_keys")
        .delete()
        .eq("user_id", userId);

      if (keysError) throw keysError;

      return res.json({
        success: true,
        status: "disconnected"
      });
    } catch (error) {
      console.error("Disconnect:", error);

      return res.status(500).json({
        error: error.message || "Gagal memutus koneksi WhatsApp."
      });
    }
  }
);

// =====================================
// SERVER START
// =====================================

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Blasting Juara berjalan di port ${PORT}`);

  console.log(
    "Baileys:",
    typeof makeWASocket === "function" ? "READY" : "ERROR"
  );

  console.log(
    "Supabase:",
    SUPABASE_URL ? "CONFIGURED" : "MISSING"
  );
});


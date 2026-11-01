
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import QRCode from "qrcode";
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";
import makeWASocket, {
  BufferJSON,
  initAuthCreds,
  DisconnectReason
} from "@whiskeysockets/baileys";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  SESSION_ENCRYPTION_KEY
} = process.env;

const sockets = new Map();
const liveState = new Map();
const startLocks = new Map();
const reconnectTimers = new Map();
const manualDisconnect = new Set();

function getAdmin() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY)
    throw new Error("Konfigurasi Supabase belum lengkap.");

  if (!/^[a-fA-F0-9]{64}$/.test(SESSION_ENCRYPTION_KEY || ""))
    throw new Error("SESSION_ENCRYPTION_KEY harus 64 karakter hex.");

  return createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });
}

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
  if (!record || record.encrypted !== true)
    throw new Error("Data sesi tidak valid.");

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

async function requireUser(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token)
      return res.status(401).json({
        error: "Token login tidak ditemukan."
      });

    const admin = getAdmin();
    const { data, error } = await admin.auth.getUser(token);

    if (error || !data?.user)
      return res.status(401).json({
        error: "Sesi login tidak valid."
      });

    req.user = data.user;
    req.admin = admin;
    next();
  } catch (error) {
    console.error("Auth:", error.message);
    res.status(503).json({
      error: "Layanan autentikasi tidak tersedia."
    });
  }
}

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

  if (error) console.error("Status:", error.message);
}

function clearReconnect(userId) {
  const timer = reconnectTimers.get(userId);

  if (timer) clearTimeout(timer);

  reconnectTimers.delete(userId);
}

async function startWhatsApp(userId, admin) {
  if (sockets.has(userId)) return sockets.get(userId);
  if (startLocks.has(userId)) return startLocks.get(userId);

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

    const sock = makeWASocket({
      auth: state,
      printQRInTerminal: false,
      markOnlineOnConnect: false,
      syncFullHistory: false,
      browser: ["Blasting Juara", "Chrome", "1.0.0"],
      connectTimeoutMs: 60000,
      defaultQueryTimeoutMs: 60000
    });

    sockets.set(userId, sock);

    sock.ev.on("creds.update", async () => {
      try {
        await saveCreds();
      } catch (error) {
        console.error("Simpan kredensial:", error.message);
      }
    });

    sock.ev.on("connection.update", async update => {
      if (sockets.get(userId) !== sock) return;

      if (update.qr) {
        liveState.set(userId, {
          status: "waiting_qr",
          qr: update.qr,
          pairingCode: null,
          phoneNumber: null
        });

        await setStatus(admin, userId, "waiting_qr");
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
      }

      if (update.connection === "close") {
        if (sockets.get(userId) === sock)
          sockets.delete(userId);

        const code = update.lastDisconnect?.error?.output?.statusCode;
        const loggedOut = code === DisconnectReason.loggedOut;

        liveState.set(userId, {
          status: "disconnected",
          qr: null,
          pairingCode: null,
          phoneNumber: null
        });

        await setStatus(admin, userId, "disconnected");

        if (loggedOut) {
          clearReconnect(userId);

          await admin.from("whatsapp_sessions")
            .update({
              creds: null,
              phone_number: null,
              status: "disconnected",
              updated_at: new Date().toISOString()
            })
            .eq("user_id", userId);

          await admin.from("whatsapp_auth_keys")
            .delete()
            .eq("user_id", userId);

          return;
        }

        if (!manualDisconnect.has(userId)) {
          clearReconnect(userId);

          const timer = setTimeout(() => {
            reconnectTimers.delete(userId);

            if (!sockets.has(userId) && !manualDisconnect.has(userId)) {
              startWhatsApp(userId, admin).catch(error => {
                console.error("Reconnect:", error.message);
              });
            }
          }, 5000);

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
    )
  });
});

const connectLimiter = rateLimit({
  windowMs: 60000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

// KONEKSI QR
app.post("/whatsapp/connect", connectLimiter, requireUser, async (req, res) => {
  try {
    manualDisconnect.delete(req.user.id);
    clearReconnect(req.user.id);

    const sock = await startWhatsApp(req.user.id, req.admin);

    res.json({
      success: true,
      status: liveState.get(req.user.id)?.status || "connecting"
    });
  } catch (error) {
    console.error("Koneksi QR:", error);
    res.status(500).json({
      error: "Gagal memulai koneksi WhatsApp."
    });
  }
});

// KONEKSI PAIRING CODE
app.post("/whatsapp/pair", connectLimiter, requireUser, async (req, res) => {
  try {
    let phoneNumber = String(req.body.phoneNumber || "")
      .replace(/\D/g, "");

    // Ubah 08xxxxxxxx menjadi 628xxxxxxxx
    if (phoneNumber.startsWith("0")) {
      phoneNumber = "62" + phoneNumber.slice(1);
    }

    if (!/^[1-9]\d{9,14}$/.test(phoneNumber)) {
      return res.status(400).json({
        error: "Nomor tidak valid. Gunakan kode negara, contoh 628123456789."
      });
    }

    const userId = req.user.id;

    manualDisconnect.delete(userId);
    clearReconnect(userId);

    const sock = await startWhatsApp(userId, req.admin);

    if (sock.user) {
      return res.status(409).json({
        error: "WhatsApp sudah terhubung. Putuskan koneksi dahulu jika ingin mengganti nomor."
      });
    }

    const pairingCode = await sock.requestPairingCode(phoneNumber);

    liveState.set(userId, {
      status: "waiting_pairing",
      qr: null,
      pairingCode,
      phoneNumber
    });

    await setStatus(req.admin, userId, "waiting_pairing");

    res.json({
      success: true,
      status: "waiting_pairing",
      phoneNumber,
      pairingCode
    });
  } catch (error) {
    console.error("Pairing Code:", error);

    res.status(500).json({
      error: error.message || "Gagal membuat Pairing Code."
    });
  }
});

// STATUS WHATSAPP
app.get("/whatsapp/status", requireUser, async (req, res) => {
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
          await startWhatsApp(userId, req.admin);
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

    const qrImage = state.qr
      ? await QRCode.toDataURL(state.qr, {
          errorCorrectionLevel: "M",
          margin: 2,
          width: 320
        })
      : null;

    res.json({
      status: state.status,
      phoneNumber: state.phoneNumber,
      pairingCode: state.pairingCode,
      qr: qrImage
    });
  } catch (error) {
    console.error("Status:", error);

    res.status(500).json({
      error: "Gagal membaca status WhatsApp."
    });
  }
});

// PUTUSKAN WHATSAPP
app.post("/whatsapp/disconnect", requireUser, async (req, res) => {
  const userId = req.user.id;

  try {
    manualDisconnect.add(userId);
    clearReconnect(userId);

    const sock = sockets.get(userId);
    sockets.delete(userId);

    if (sock) {
      try {
        await sock.logout();
      } catch (error) {
        console.error("Logout:", error.message);
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

    res.json({
      success: true,
      status: "disconnected"
    });
  } catch (error) {
    console.error("Disconnect:", error);

    res.status(500).json({
      error: "Gagal memutus koneksi WhatsApp."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Blasting Juara berjalan di port ${PORT}`);
});
                                                 

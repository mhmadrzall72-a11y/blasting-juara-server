
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

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;
const SESSION_ENCRYPTION_KEY =
  process.env.SESSION_ENCRYPTION_KEY || "";

const sockets = new Map();
const liveState = new Map();
const startLocks = new Map();

function getAdmin() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Konfigurasi Supabase belum lengkap.");
  }

  if (!/^[a-fA-F0-9]{64}$/.test(SESSION_ENCRYPTION_KEY)) {
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

  const key = Buffer.from(SESSION_ENCRYPTION_KEY, "hex");

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
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

    if (!token) {
      return res.status(401).json({
        error: "Token login tidak ditemukan."
      });
    }

    const admin = getAdmin();

    const { data, error } =
      await admin.auth.getUser(token);

    if (error || !data?.user) {
      return res.status(401).json({
        error: "Sesi login tidak valid."
      });
    }

    req.user = data.user;
    req.admin = admin;

    next();

  } catch (error) {
    console.error("Auth error:", error.message);

    res.status(503).json({
      error: "Layanan autentikasi tidak tersedia."
    });
  }
}

async function saveSessionRow(admin, userId, creds, status) {
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

        result[id] = stored
          ? decryptJson(stored)
          : null;
      }

      return result;
    },

    set: async data => {
      for (const [type, entries] of Object.entries(data)) {
        for (const [id, value] of Object.entries(entries || {})) {
          if (value === null || value === undefined) {
            const { error } = await admin
              .from("whatsapp_auth_keys")
              .delete()
              .eq("user_id", userId)
              .eq("key_type", type)
              .eq("key_id", id);

            if (error) throw error;

          } else {
            const { error } = await admin
              .from("whatsapp_auth_keys")
              .upsert({
                user_id: userId,
                key_type: type,
                key_id: id,
                value: encryptJson(value)
              }, {
                onConflict: "user_id,key_type,key_id"
              });

            if (error) throw error;
          }
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
    console.error("Gagal menyimpan status:", error.message);
  }
}

async function startWhatsApp(userId, admin) {
  if (sockets.has(userId)) {
    return sockets.get(userId);
  }

  if (startLocks.has(userId)) {
    return startLocks.get(userId);
  }

  const task = (async () => {
    const { state, saveCreds } =
      await createDatabaseAuthState(admin, userId);

    await saveSessionRow(
      admin,
      userId,
      state.creds,
      "connecting"
    );

    liveState.set(userId, {
      status: "connecting",
      qr: null,
      phoneNumber: null
    });

    const sock = makeWASocket({
      auth: state,
      printQRInTerminal: false,
      markOnlineOnConnect: false,
      syncFullHistory: false,
      browser: ["Blasting Juara", "Chrome", "1.0.0"]
    });

    sockets.set(userId, sock);

    sock.ev.on("creds.update", async () => {
      try {
        await saveCreds();
      } catch (error) {
        console.error("Gagal menyimpan kredensial:", error.message);
      }
    });

    sock.ev.on("connection.update", async update => {
      const current = liveState.get(userId) || {};

      if (update.qr) {
        liveState.set(userId, {
          ...current,
          status: "waiting_qr",
          qr: update.qr
        });

        await setStatus(admin, userId, "waiting_qr");
      }

      if (update.connection === "open") {
        const phoneNumber = String(sock.user?.id || "")
          .split(":")[0]
          .split("@")[0] || null;

        liveState.set(userId, {
          status: "connected",
          qr: null,
          phoneNumber
        });

        await setStatus(
          admin,
          userId,
          "connected",
          phoneNumber
        );
      }

      if (update.connection === "close") {
        const code =
          update.lastDisconnect?.error?.output?.statusCode;

        const loggedOut = code === DisconnectReason.loggedOut;

        if (sockets.get(userId) === sock) {
          sockets.delete(userId);
        }

        liveState.set(userId, {
          status: "disconnected",
          qr: null,
          phoneNumber: null
        });

        await setStatus(admin, userId, "disconnected");

        if (loggedOut) {
          await admin
            .from("whatsapp_sessions")
            .update({
              creds: null,
              phone_number: null,
              status: "disconnected",
              updated_at: new Date().toISOString()
            })
            .eq("user_id", userId);

          await admin
            .from("whatsapp_auth_keys")
            .delete()
            .eq("user_id", userId);
        } else {
          setTimeout(() => {
            if (!sockets.has(userId)) {
              startWhatsApp(userId, admin).catch(error => {
                console.error("Reconnect gagal:", error.message);
              });
            }
          }, 5000);
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
      /^[a-fA-F0-9]{64}$/.test(SESSION_ENCRYPTION_KEY)
    )
  });
});

const connectLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.post(
  "/whatsapp/connect",
  connectLimiter,
  requireUser,
  async (req, res) => {
    try {
      await startWhatsApp(req.user.id, req.admin);

      res.json({
        success: true,
        status: liveState.get(req.user.id)?.status || "connecting"
      });

    } catch (error) {
      console.error("Koneksi gagal:", error);

      res.status(500).json({
        error: "Gagal memulai koneksi WhatsApp."
      });
    }
  }
);

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
            await startWhatsApp(userId, req.admin);
            state = liveState.get(userId);
          }
        }
      }

      state = state || {
        status: "disconnected",
        qr: null,
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
        qr: qrImage
      });

    } catch (error) {
      console.error("Gagal membaca status:", error);

      res.status(500).json({
        error: "Gagal membaca status WhatsApp."
      });
    }
  }
);

app.post(
  "/whatsapp/disconnect",
  requireUser,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const sock = sockets.get(userId);

      if (sock) {
        sockets.delete(userId);

        try {
          await sock.logout();
        } catch (error) {
          console.error("Logout:", error.message);
        }
      }

      liveState.set(userId, {
        status: "disconnected",
        qr: null,
        phoneNumber: null
      });

      await req.admin
        .from("whatsapp_sessions")
        .delete()
        .eq("user_id", userId);

      await req.admin
        .from("whatsapp_auth_keys")
        .delete()
        .eq("user_id", userId);

      res.json({
        success: true,
        status: "disconnected"
      });

    } catch (error) {
      console.error("Gagal memutus koneksi:", error);

      res.status(500).json({
        error: "Gagal memutus koneksi WhatsApp."
      });
    }
  }
);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Blasting Juara berjalan di port ${PORT}`);
});
  

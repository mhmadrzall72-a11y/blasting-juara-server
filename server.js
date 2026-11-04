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
const campaignDeliveryRuns = new Map();
const campaignDeliveryStop = new Set();
const pendingDeliveryAcks = new Set();

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
// ADMIN AUTHORIZATION
// =====================================

async function requireAdmin(req, res, next) {
  try {
    const { data, error } = await req.admin
      .from("profiles")
      .select("role")
      .eq("id", req.user.id)
      .maybeSingle();

    if (error) throw error;

    if (data?.role !== "admin") {
      return res.status(403).json({
        error: "Akses khusus admin."
      });
    }

    next();
  } catch (error) {
    console.error("Admin authorization:", error.message);

    return res.status(500).json({
      error: "Gagal memverifikasi hak akses admin."
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

    try {
      existing.end(undefined);
    } catch {}

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

    try {
      pendingSocket?.end(undefined);
    } catch {}
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

    const browser = Browsers?.macOS
      ? Browsers.macOS("Desktop")
      : ["macOS", "Desktop", "14.4.1"];

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

    
sock.ev.on("messages.update", async updates => {
  try {
    for (const item of updates || []) {
      const messageId = item?.key?.id;
      const ackStatus = Number(item?.update?.status || 0);

      console.log("CAMPAIGN ACK:", {
        messageId,
        ackStatus,
        workerId: userId
      });

      if (!messageId || ackStatus < 3) continue;

      const deliveredAt = new Date().toISOString();

      const { data, error } = await admin
        .from("campaign_delivery_queue")
        .update({
          status: "delivered",
          delivered_at: deliveredAt,
          updated_at: deliveredAt
        })
        .eq("message_id", messageId)
        .eq("worker_id", userId)
        .in("status", ["sending", "sent", "delivered"])
        .select("id");

      if (error) {
        console.error("SIMPAN DELIVERY RECEIPT GAGAL:", error.message);
        continue;
      }

      if (data?.length) {
        console.log("DELIVERY RECEIPT TERSIMPAN:", messageId);
      } else if (campaignDeliveryRuns.has(userId)) {
        pendingDeliveryAcks.add(messageId);
        console.log("DELIVERY ACK MENUNGGU DATA ANTREAN:", messageId);
      } else {
        console.log("DELIVERY ACK TIDAK MENEMUKAN ANTREAN:", messageId);
      }
    }
  } catch (error) {
    console.error("PROSES DELIVERY RECEIPT:", error.message);
  }
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
// ADMIN: KELOLA AKUN PENGGUNA
// =====================================

app.get("/admin/users", requireUser, requireAdmin, async (req, res) => {
  try {
    const perPage = 1000;

    const { data, error } = await req.admin.auth.admin.listUsers({
      page: 1,
      perPage
    });

    if (error) throw error;

    const authUsers = data?.users || [];
    const ids = authUsers.map(item => item.id);

    let profileRows = [];

    if (ids.length) {
      const { data: profiles, error: profileError } = await req.admin
        .from("profiles")
        .select("*")
        .in("id", ids);

      if (profileError) throw profileError;

      profileRows = profiles || [];
    }

    const profileMap = new Map(
      profileRows.map(row => [row.id, row])
    );

    const now = Date.now();

    const users = authUsers.map(account => {
      const profile = profileMap.get(account.id) || {};
      const bannedUntil = account.banned_until || null;

      const disabled =
        profile.is_active === false ||
        Boolean(
          bannedUntil &&
          new Date(bannedUntil).getTime() > now
        );

      return {
        id: account.id,
        email: account.email || "",
        full_name:
          profile.full_name ||
          profile.name ||
          account.user_metadata?.full_name ||
          account.user_metadata?.name ||
          "",
        role: profile.role || "user",
        created_at: account.created_at || null,
        last_sign_in_at: account.last_sign_in_at || null,
        disabled
      };
    });

    users.sort(
      (a, b) =>
        new Date(b.created_at || 0) -
        new Date(a.created_at || 0)
    );

    return res.json({
      users,
      count: users.length,
      limit: perPage
    });
  } catch (error) {
    console.error("Admin list users:", error);

    return res.status(500).json({
      error: error.message || "Gagal mengambil daftar akun."
    });
  }
});

app.post("/admin/users/:id/status", requireUser, requireAdmin, async (req, res) => {
  try {
    const targetId = String(req.params.id || "");
    const disabled = req.body?.disabled;

    if (!targetId) {
      return res.status(400).json({
        error: "ID akun tidak valid."
      });
    }

    if (typeof disabled !== "boolean") {
      return res.status(400).json({
        error: "Status akun tidak valid."
      });
    }

    if (targetId === req.user.id) {
      return res.status(400).json({
        error: "Admin tidak dapat menonaktifkan akunnya sendiri."
      });
    }

    const { data: targetProfile, error: targetError } = await req.admin
      .from("profiles")
      .select("role,is_active")
      .eq("id", targetId)
      .maybeSingle();

    if (targetError) throw targetError;

    if (targetProfile?.role === "admin") {
      return res.status(403).json({
        error: "Akun admin dilindungi dan tidak dapat diubah dari menu ini."
      });
    }

    const { error: profileUpdateError } = await req.admin
      .from("profiles")
      .update({
        is_active: !disabled
      })
      .eq("id", targetId);

    if (profileUpdateError) throw profileUpdateError;

    const { data, error } = await req.admin.auth.admin.updateUserById(
      targetId,
      {
        ban_duration: disabled ? "876000h" : "none"
      }
    );

    if (error) {
      await req.admin
        .from("profiles")
        .update({
          is_active: targetProfile?.is_active !== false
        })
        .eq("id", targetId);

      throw error;
    }

    return res.json({
      success: true,
      disabled,
      userId: data?.user?.id || targetId
    });
  } catch (error) {
    console.error("Admin update user status:", error);

    return res.status(500).json({
      error: error.message || "Gagal mengubah status akun."
    });
  }
});

app.delete("/admin/users/:id", requireUser, requireAdmin, async (req, res) => {
  try {
    const targetId = String(req.params.id || "");

    if (!targetId) {
      return res.status(400).json({
        error: "ID akun tidak valid."
      });
    }

    if (targetId === req.user.id) {
      return res.status(400).json({
        error: "Admin tidak dapat menghapus akunnya sendiri."
      });
    }

    const { data: targetProfile, error: targetError } = await req.admin
      .from("profiles")
      .select("role")
      .eq("id", targetId)
      .maybeSingle();

    if (targetError) throw targetError;

    if (targetProfile?.role === "admin") {
      return res.status(403).json({
        error: "Akun admin dilindungi dan tidak dapat dihapus dari menu ini."
      });
    }

    const { error } = await req.admin.auth.admin.deleteUser(targetId);

    if (error) throw error;

    return res.json({
      success: true,
      deletedUserId: targetId
    });
  } catch (error) {
    console.error("Admin delete user:", error);

    return res.status(500).json({
      error: error.message ||
        "Gagal menghapus akun. Periksa relasi data pengguna di database."
    });
  }
});

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
// AMBIL JOB - WAJIB TERHUBUNG
// =====================================

app.post("/applications", requireUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const campaignId = String(req.body?.campaignId || "").trim();

    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(campaignId)) {
      return res.status(400).json({
        error: "ID campaign tidak valid."
      });
    }

    const socket = sockets.get(userId);
    const state = liveState.get(userId);

    if (!socket || !socket.user || state?.status !== "connected") {
      return res.status(403).json({
        error: "WhatsApp belum benar-benar terhubung. Tautkan WhatsApp terlebih dahulu sebelum mengambil pekerjaan."
      });
    }

    const { data: session, error: sessionError } = await req.admin
      .from("whatsapp_sessions")
      .select("status")
      .eq("user_id", userId)
      .maybeSingle();

    if (sessionError) throw sessionError;

    if (session?.status !== "connected") {
      return res.status(403).json({
        error: "Status WhatsApp belum terverifikasi. Buka menu WhatsApp dan hubungkan kembali."
      });
    }

    const { data: campaign, error: campaignError } = await req.admin
      .from("campaigns")
      .select("id,status")
      .eq("id", campaignId)
      .maybeSingle();

    if (campaignError) throw campaignError;

    if (!campaign || campaign.status !== "active") {
      return res.status(404).json({
        error: "Campaign tidak tersedia atau belum aktif."
      });
    }

    const { data: existing, error: existingError } = await req.admin
      .from("applications")
      .select("id,status")
      .eq("campaign_id", campaignId)
      .eq("worker_id", userId)
      .maybeSingle();

    if (existingError) throw existingError;

    if (existing) {
      if (existing.status === "rejected") {
        return res.status(403).json({
          error: "Pengambilan job ini pernah ditolak dan perlu bantuan admin."
        });
      }

      if (existing.status === "pending") {
        const { data: activated, error: activateError } = await req.admin
          .from("applications")
          .update({
            status: "approved"
          })
          .eq("id", existing.id)
          .eq("worker_id", userId)
          .select("id,status,created_at")
          .single();

        if (activateError) throw activateError;

        return res.json({
          success: true,
          application: activated,
          message: "Job langsung aktif tanpa menunggu persetujuan admin."
        });
      }

      return res.json({
        success: true,
        application: existing,
        message: "Job ini sudah ada di daftar pekerjaan kamu."
      });
    }

    const { data: application, error: insertError } = await req.admin
      .from("applications")
      .insert({
        campaign_id: campaignId,
        worker_id: userId,
        status: "approved"
      })
      .select("id,status,created_at")
      .single();

    if (insertError) {
      if (insertError.code === "23505") {
        return res.status(409).json({
          error: "Kamu sudah mengambil job ini."
        });
      }

      throw insertError;
    }

    console.log(
      "Job berhasil diambil setelah verifikasi WhatsApp:",
      userId,
      campaignId
    );

    return res.status(201).json({
      success: true,
      application
    });
  } catch (error) {
    console.error("Ambil job:", error);

    return res.status(500).json({
      error: error.message || "Gagal mengambil pekerjaan."
    });
  }
});

// =====================================
// CAMPAIGN DELIVERY VIA BAILEYS
// =====================================

const CAMPAIGN_SEND_BATCH_LIMIT = 10;
const CAMPAIGN_SEND_DELAY_MS = 30000;

const wait = ms =>
  new Promise(resolve => setTimeout(resolve, ms));

async function runCampaignDelivery(userId, applicationId, admin) {
  let attemptedThisRun = 0;

  try {
    const socket = sockets.get(userId);

    if (!socket?.user || liveState.get(userId)?.status !== "connected") {
      throw new Error("WhatsApp pekerja tidak lagi terhubung.");
    }

    while (
      attemptedThisRun < CAMPAIGN_SEND_BATCH_LIMIT &&
      !campaignDeliveryStop.has(userId)
    ) {
      const { data: claimed, error: claimError } = await admin.rpc(
        "claim_campaign_delivery",
        {
          p_application_id: applicationId,
          p_worker_id: userId
        }
      );

      if (claimError) throw claimError;

      const job = Array.isArray(claimed) ? claimed[0] : claimed;

      if (!job) break;

      attemptedThisRun++;

      try {
        if (!job.phone_number || !/^62[0-9]{8,13}$/.test(job.phone_number)) {
          throw new Error("Nomor penerima tidak valid.");
        }

        const result = await socket.sendMessage(
          `${job.phone_number}@s.whatsapp.net`,
          {
            text: String(job.message_template).slice(0, 4000)
          }
        );

        const messageId = result?.key?.id;

        if (!messageId) {
          throw new Error("WhatsApp tidak mengembalikan ID pesan.");
        }

        const now = new Date().toISOString();

        const { error: queueError } = await admin
          .from("campaign_delivery_queue")
          .update({
            status: "sent",
            message_id: messageId,
            sent_at: now,
            updated_at: now
          })
          .eq("id", job.queue_id)
          .eq("worker_id", userId);

        if (queueError) throw queueError;

        if (pendingDeliveryAcks.has(messageId)) {
          pendingDeliveryAcks.delete(messageId);

          const deliveredAt = new Date().toISOString();

          const { error: earlyAckError } = await admin
            .from("campaign_delivery_queue")
            .update({
              status: "delivered",
              delivered_at: deliveredAt,
              updated_at: deliveredAt
            })
            .eq("id", job.queue_id)
            .eq("worker_id", userId);

          if (earlyAckError) {
            console.error("Simpan receipt awal:", earlyAckError.message);
          }
        }

        // campaign_recipients tidak memakai kolom updated_at.
        const { error: recipientError } = await admin
          .from("campaign_recipients")
          .update({
            status: "sent"
          })
          .eq("id", job.recipient_id);

        if (recipientError) {
          console.error(
            "Pembaruan status penerima:",
            recipientError.message
          );
        }

        console.log(
          "Campaign message accepted by WhatsApp:",
          job.queue_id,
          messageId
        );

      } catch (sendError) {
        const now = new Date().toISOString();

        await admin
          .from("campaign_delivery_queue")
          .update({
            status: "failed",
            error_message: String(
              sendError.message || "Gagal mengirim"
            ).slice(0, 500),
            updated_at: now
          })
          .eq("id", job.queue_id);

        await admin
          .from("campaign_recipients")
          .update({
            status: "failed"
          })
          .eq("id", job.recipient_id);

        console.error("Campaign send failed:", sendError.message);
      }

      if (
        attemptedThisRun < CAMPAIGN_SEND_BATCH_LIMIT &&
        !campaignDeliveryStop.has(userId)
      ) {
        await wait(CAMPAIGN_SEND_DELAY_MS);

        if (
          sockets.get(userId) !== socket ||
          liveState.get(userId)?.status !== "connected"
        ) {
          throw new Error(
            "Koneksi WhatsApp terputus saat pengiriman berlangsung."
          );
        }
      }
    }

  } catch (error) {
    console.error("Campaign delivery run:", error.message);

  } finally {
    campaignDeliveryRuns.delete(userId);
    campaignDeliveryStop.delete(userId);
  }
}

app.post("/campaign-delivery/start", requireUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const applicationId = String(req.body?.applicationId || "");

    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(applicationId)) {
      return res.status(400).json({
        error: "ID pekerjaan tidak valid."
      });
    }

    if (campaignDeliveryRuns.has(userId)) {
      return res.status(409).json({
        error: "Pengiriman campaign kamu sedang berjalan."
      });
    }

    const socket = sockets.get(userId);

    if (!socket?.user || liveState.get(userId)?.status !== "connected") {
      return res.status(403).json({
        error: "Tautkan WhatsApp kamu terlebih dahulu."
      });
    }

    const { data: application, error } = await req.admin
      .from("applications")
      .select("id,status,campaign_id,campaigns(status,message_template)")
      .eq("id", applicationId)
      .eq("worker_id", userId)
      .maybeSingle();

    if (error) throw error;

    if (
      !application ||
      application.status === "rejected" ||
      application.campaigns?.status !== "active"
    ) {
      return res.status(403).json({
        error: "Job tidak tersedia atau campaign tidak aktif."
      });
    }

    if (!String(application.campaigns?.message_template || "").trim()) {
      return res.status(400).json({
        error: "Pemasang iklan belum mengisi template pesan."
      });
    }

    const task = runCampaignDelivery(userId, applicationId, req.admin);

    campaignDeliveryRuns.set(userId, {
      applicationId,
      startedAt: new Date().toISOString(),
      task
    });

    return res.status(202).json({
      success: true,
      message: "Pengiriman langsung dimulai. Sistem membagi penerima secara otomatis; batas aman 10 pesan per sesi dengan jeda 30 detik."
    });

  } catch (error) {
    console.error("Mulai campaign delivery:", error);

    return res.status(500).json({
      error: error.message || "Gagal memulai antrean."
    });
  }
});

app.post("/campaign-delivery/stop", requireUser, async (req, res) => {
  if (!campaignDeliveryRuns.has(req.user.id)) {
    return res.json({
      success: true,
      running: false
    });
  }

  campaignDeliveryStop.add(req.user.id);

  return res.json({
    success: true,
    stopping: true
  });
});

app.get("/campaign-delivery/status", requireUser, async (req, res) => {
  try {
    const applicationId = String(req.query.applicationId || "");

    const { data: application, error: appError } = await req.admin
      .from("applications")
      .select("id")
      .eq("id", applicationId)
      .eq("worker_id", req.user.id)
      .maybeSingle();

    if (appError) throw appError;

    if (!application) {
      return res.status(404).json({
        error: "Job tidak ditemukan."
      });
    }

    const { data, error } = await req.admin
      .from("campaign_delivery_queue")
      .select("status")
      .eq("application_id", applicationId)
      .eq("worker_id", req.user.id);

    if (error) throw error;

    const counts = {
      sending: 0,
      sent: 0,
      delivered: 0,
      failed: 0
    };

    for (const row of data || []) {
      if (counts[row.status] !== undefined) {
        counts[row.status]++;
      }
    }

    const run = campaignDeliveryRuns.get(req.user.id);

    return res.json({
      success: true,
      running: Boolean(
        run && run.applicationId === applicationId
      ),
      counts
    });

  } catch (error) {
    return res.status(500).json({
      error: error.message || "Gagal membaca status antrean."
    });
  }
});

app.post("/campaign-delivery/submit-report", requireUser, async (req, res) => {
  try {
    const applicationId = String(req.body?.applicationId || "");

    const { data: application, error: appError } = await req.admin
      .from("applications")
      .select("id,status")
      .eq("id", applicationId)
      .eq("worker_id", req.user.id)
      .maybeSingle();

    if (appError) throw appError;

    if (!application || application.status === "rejected") {
      return res.status(403).json({
        error: "Job tidak tersedia untuk laporan."
      });
    }

    const { data: existingReports, error: existingError } = await req.admin
      .from("reports")
      .select("id,status")
      .eq("application_id", applicationId);

    if (existingError) throw existingError;

    if (
      (existingReports || []).some(
        row => row.status === "pending" || row.status === "approved"
      )
    ) {
      return res.status(409).json({
        error: "Laporan untuk job ini sudah dikirim atau sudah disetujui."
      });
    }

    const { count, error: countError } = await req.admin
      .from("campaign_delivery_queue")
      .select("id", {
        count: "exact",
        head: true
      })
      .eq("application_id", applicationId)
      .eq("worker_id", req.user.id)
      .eq("status", "delivered");

    if (countError) throw countError;

    if (!count) {
      return res.status(400).json({
        error: "Belum ada pesan dengan tanda terima delivery. Laporan belum dapat dikirim."
      });
    }

    const { data: report, error } = await req.admin
      .from("reports")
      .insert({
        application_id: applicationId,
        worker_id: req.user.id,
        delivered_count: count,
        evidence_url: null,
        notes: "Dihitung otomatis dari delivery receipt WhatsApp Baileys."
      })
      .select("id,delivered_count,status")
      .single();

    if (error) throw error;

    return res.status(201).json({
      success: true,
      report
    });

  } catch (error) {
    console.error("Submit verified campaign report:", error);

    return res.status(500).json({
      error: error.message || "Gagal mengirim laporan terverifikasi."
    });
  }
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
        pairingCreatedAt:
          liveState.get(userId)?.pairingCreatedAt || Date.now()
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
        statusCode:
          error?.output?.statusCode ||
          error?.statusCode ||
          null
      });

      if (
        pairingSocket &&
        sockets.get(userId) === pairingSocket &&
        !pairingSocket.user
      ) {
        sockets.delete(userId);
        socketModes.delete(userId);
        pairingReady.delete(userId);

        try {
          pairingSocket.end(undefined);
        } catch {}

        liveState.set(userId, {
          status: "disconnected",
          qr: null,
          pairingCode: null,
          phoneNumber: null
        });

        await setStatus(req.admin, userId, "disconnected");
      }

      return res.status(500).json({
        error: error.message ||
          "Gagal membuat Pairing Code. Silakan minta kode baru."
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

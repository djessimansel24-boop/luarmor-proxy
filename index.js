const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

const LUARMOR_API_KEY = process.env.LUARMOR_API_KEY;
const LUARMOR_PROJECT_ID = process.env.LUARMOR_PROJECT_ID;
const PROXY_SECRET = process.env.PROXY_SECRET;
const LUARMOR_BASE = `https://api.luarmor.net/v3/projects/${LUARMOR_PROJECT_ID}`;

if (!LUARMOR_API_KEY || !LUARMOR_PROJECT_ID || !PROXY_SECRET) {
  console.error("FATAL: Missing env vars");
  process.exit(1);
}

app.use(express.json());

const luarmorHeaders = {
  Authorization: LUARMOR_API_KEY,
  "Content-Type": "application/json",
};

function verifySecret(req, res, next) {
  if (req.headers["x-proxy-secret"] !== PROXY_SECRET) {
    return res.status(403).json({ success: false, error: "Unauthorized" });
  }
  next();
}

// Helper : appel Luarmor avec logs complets
async function luarmorCall(method, path, body = null) {
  const url = path.startsWith("http") ? path : `${LUARMOR_BASE}${path}`;
  const options = { method, headers: luarmorHeaders };
  if (body) options.body = JSON.stringify(body);

  console.log(`[LUARMOR] ${method} ${url}`);
  if (body) console.log(`[LUARMOR] Body:`, JSON.stringify(body));

  const res = await fetch(url, options);
  const text = await res.text();
  console.log(`[LUARMOR] Status: ${res.status} Response: ${text}`);

  try {
    return JSON.parse(text);
  } catch {
    return { success: false, raw: text };
  }
}

// ─────────────────────────────────────────────
// POST /luarmor/create-key
// Crée une clé + l'expire immédiatement
// ─────────────────────────────────────────────
app.post("/luarmor/create-key", verifySecret, async (req, res) => {
  try {
    const { note } = req.body;
    console.log("\n========== CREATE KEY ==========");

    // Étape 1 : Créer la clé avec expiration directement dans le body
    const yesterdayTimestamp = Math.floor(Date.now() / 1000) - 86400;
    console.log("Timestamp hier:", yesterdayTimestamp, "=", new Date(yesterdayTimestamp * 1000).toISOString());

    // Tentative 1 : créer avec auth_expire directement
    const createData = await luarmorCall("POST", "/users", {
      note: note || "",
      auth_expire: yesterdayTimestamp,
    });

    if (!createData.success) {
      console.log("CREATE FAILED:", JSON.stringify(createData));
      return res.status(502).json({ success: false, error: createData.message || "Create failed" });
    }

    const userKey = createData.user_key;
    console.log("Key created:", userKey);

    // Étape 2 : PATCH pour être sûr que l'expiration est en place
    console.log("--- PATCH auth_expire ---");
    const patch1 = await luarmorCall("PATCH", "/users", {
      user_key: userKey,
      auth_expire: yesterdayTimestamp,
    });

    // Étape 3 : Si PATCH échoue ou ne prend pas, essayer d'autres noms de champ
    if (!patch1.success) {
      console.log("--- PATCH auth_expire FAILED, trying 'expiry' ---");
      await luarmorCall("PATCH", "/users", {
        user_key: userKey,
        expiry: yesterdayTimestamp,
      });
    }

    // Étape 4 : Vérifier le résultat
    console.log("--- VERIFY ---");
    const verify = await luarmorCall("GET", `/users?user_key=${userKey}`);
    console.log("========== CREATE KEY END ==========\n");

    return res.json({ success: true, user_key: userKey });
  } catch (err) {
    console.error("create-key error:", err);
    return res.status(500).json({ success: false, error: "Internal error" });
  }
});

// ─────────────────────────────────────────────
// POST /luarmor/activate-plan
// ─────────────────────────────────────────────
app.post("/luarmor/activate-plan", verifySecret, async (req, res) => {
  try {
    const { user_key, auth_expire } = req.body;
    console.log("\n========== ACTIVATE PLAN ==========");
    console.log("Key:", user_key);
    console.log("Expire:", auth_expire, "=", new Date(auth_expire * 1000).toISOString());

    if (!user_key || !auth_expire) {
      return res.status(400).json({ success: false, error: "Missing user_key or auth_expire" });
    }

    const patchData = await luarmorCall("PATCH", "/users", {
      user_key,
      auth_expire,
    });

    // Vérifier
    const verify = await luarmorCall("GET", `/users?user_key=${user_key}`);
    console.log("========== ACTIVATE END ==========\n");

    if (!patchData.success) {
      return res.status(502).json({ success: false, error: patchData.message || "Activate failed" });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("activate-plan error:", err);
    return res.status(500).json({ success: false, error: "Internal error" });
  }
});

// ─────────────────────────────────────────────
// POST /luarmor/reset-hwid
// ─────────────────────────────────────────────
app.post("/luarmor/reset-hwid", verifySecret, async (req, res) => {
  try {
    const { user_key } = req.body;
    console.log("\n========== RESET HWID ==========");

    if (!user_key) {
      return res.status(400).json({ success: false, error: "Missing user_key" });
    }

    const resetData = await luarmorCall("POST", "/users/resethwid", {
      user_key,
      force: true,
    });

    console.log("========== RESET END ==========\n");

    if (!resetData.success) {
      return res.status(502).json({ success: false, error: resetData.message || "Reset failed" });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("reset-hwid error:", err);
    return res.status(500).json({ success: false, error: "Internal error" });
  }
});

// Utilitaires
app.get("/my-ip", async (req, res) => {
  try {
    const r = await fetch("https://api.ipify.org?format=json");
    const data = await r.json();
    res.json({ outbound_ip: data.ip });
  } catch (err) {
    res.status(500).json({ error: "Could not determine IP" });
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Luarmor proxy running on port ${PORT}`);
});

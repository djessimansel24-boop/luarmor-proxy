const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

const LUARMOR_API_KEY = process.env.LUARMOR_API_KEY;
const LUARMOR_PROJECT_ID = process.env.LUARMOR_PROJECT_ID;
const PROXY_SECRET = process.env.PROXY_SECRET;

// Validation au démarrage
if (!LUARMOR_API_KEY || !LUARMOR_PROJECT_ID || !PROXY_SECRET) {
  console.error("FATAL: Missing LUARMOR_API_KEY, LUARMOR_PROJECT_ID, or PROXY_SECRET");
  process.exit(1);
}

app.use(express.json());

// ─────────────────────────────────────────────
// Middleware : vérifie le secret partagé
// Seules tes Edge Functions Lovable connaissent ce secret
// ─────────────────────────────────────────────

function verifySecret(req, res, next) {
  const secret = req.headers["x-proxy-secret"];
  if (secret !== PROXY_SECRET) {
    return res.status(403).json({ success: false, error: "Unauthorized" });
  }
  next();
}

// ─────────────────────────────────────────────
// ROUTE 1 : POST /luarmor/create-key
// Crée une clé Luarmor (expirée par défaut)
// Body attendu : { note: "user_id" }
// ─────────────────────────────────────────────

app.post("/luarmor/create-key", verifySecret, async (req, res) => {
  try {
    const { note } = req.body;

    // Étape 1 : Créer la clé
    const createRes = await fetch(
      `https://api.luarmor.net/v3/projects/${LUARMOR_PROJECT_ID}/users`,
      {
        method: "POST",
        headers: {
          Authorization: LUARMOR_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ note: note || "" }),
      }
    );
    const createData = await createRes.json();

    if (!createData.success) {
      return res.status(502).json({ success: false, error: createData.message });
    }

    // Étape 2 : Expirer immédiatement la clé (pas de plan actif)
    const patchRes = await fetch(
      `https://api.luarmor.net/v3/projects/${LUARMOR_PROJECT_ID}/users`,
      {
        method: "PATCH",
        headers: {
          Authorization: LUARMOR_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          user_key: createData.user_key,
          auth_expire: 1,
        }),
      }
    );
    const patchData = await patchRes.json();

    if (!patchData.success) {
      // Rollback : supprime la clé
      await fetch(
        `https://api.luarmor.net/v3/projects/${LUARMOR_PROJECT_ID}/users?user_key=${createData.user_key}`,
        {
          method: "DELETE",
          headers: { Authorization: LUARMOR_API_KEY, "Content-Type": "application/json" },
        }
      );
      return res.status(502).json({ success: false, error: patchData.message });
    }

    return res.json({ success: true, user_key: createData.user_key });
  } catch (err) {
    console.error("create-key error:", err);
    return res.status(500).json({ success: false, error: "Internal error" });
  }
});

// ─────────────────────────────────────────────
// ROUTE 2 : POST /luarmor/activate-plan
// Active une clé avec une date d'expiration
// Body attendu : { user_key: "xxx", auth_expire: 1234567890 }
// ─────────────────────────────────────────────

app.post("/luarmor/activate-plan", verifySecret, async (req, res) => {
  try {
    const { user_key, auth_expire } = req.body;

    if (!user_key || !auth_expire) {
      return res.status(400).json({ success: false, error: "Missing user_key or auth_expire" });
    }

    const patchRes = await fetch(
      `https://api.luarmor.net/v3/projects/${LUARMOR_PROJECT_ID}/users`,
      {
        method: "PATCH",
        headers: {
          Authorization: LUARMOR_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ user_key, auth_expire }),
      }
    );
    const patchData = await patchRes.json();

    if (!patchData.success) {
      return res.status(502).json({ success: false, error: patchData.message });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("activate-plan error:", err);
    return res.status(500).json({ success: false, error: "Internal error" });
  }
});

// ─────────────────────────────────────────────
// ROUTE 3 : POST /luarmor/reset-hwid
// Reset le HWID d'une clé
// Body attendu : { user_key: "xxx" }
// ─────────────────────────────────────────────

app.post("/luarmor/reset-hwid", verifySecret, async (req, res) => {
  try {
    const { user_key } = req.body;

    if (!user_key) {
      return res.status(400).json({ success: false, error: "Missing user_key" });
    }

    const resetRes = await fetch(
      `https://api.luarmor.net/v3/projects/${LUARMOR_PROJECT_ID}/users/resethwid`,
      {
        method: "POST",
        headers: {
          Authorization: LUARMOR_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ user_key, force: true }),
      }
    );
    const resetData = await resetRes.json();

    if (!resetData.success) {
      return res.status(502).json({ success: false, error: resetData.message });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("reset-hwid error:", err);
    return res.status(500).json({ success: false, error: "Internal error" });
  }
});

// ─────────────────────────────────────────────
// Utilitaire : trouver l'IP sortante
// Visite /my-ip après déploiement, note l'IP,
// whiteliste-la sur luarmor.net/profile
// ─────────────────────────────────────────────

app.get("/my-ip", async (req, res) => {
  try {
    const r = await fetch("https://api.ipify.org?format=json");
    const data = await r.json();
    res.json({ outbound_ip: data.ip });
  } catch (err) {
    res.status(500).json({ error: "Could not determine IP" });
  }
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`Luarmor proxy running on port ${PORT}`);
});

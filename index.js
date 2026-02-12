const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

// ─────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────

const app = express();
const PORT = process.env.PORT || 3000;

const LUARMOR_API_KEY = process.env.LUARMOR_API_KEY;
const LUARMOR_PROJECT_ID = process.env.LUARMOR_PROJECT_ID;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SRK = process.env.SUPABASE_SERVICE_ROLE_KEY;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);

// Validation au démarrage
const requiredVars = { LUARMOR_API_KEY, LUARMOR_PROJECT_ID, SUPABASE_URL, SUPABASE_SRK, WEBHOOK_SECRET };
const missing = Object.entries(requiredVars).filter(([, v]) => !v).map(([k]) => k);

if (missing.length > 0) {
  console.error(`FATAL: Missing environment variables: ${missing.join(", ")}`);
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SRK);

// ─────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────

app.use(express.json());

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("CORS not allowed"), false);
    },
    credentials: true,
  })
);

// ─────────────────────────────────────────────
// Middleware : Vérification JWT Supabase
// ─────────────────────────────────────────────

async function authenticateUser(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      error: "Missing or malformed Authorization header",
    });
  }

  const token = authHeader.substring(7);

  try {
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      return res.status(401).json({
        success: false,
        error: "Invalid or expired token",
      });
    }

    req.user = data.user;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    return res.status(500).json({
      success: false,
      error: "Authentication service error",
    });
  }
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/**
 * Appel générique à l'API Luarmor.
 *
 * Points critiques (doc officielle) :
 *   - Header "Authorization" = la clé API brute (PAS "Bearer xxx")
 *   - Header "Content-Type" = "application/json" obligatoire
 *   - Rate limit : 60 requêtes/minute
 */
async function luarmorRequest(method, path, body = null, queryParams = "") {
  const url = `https://api.luarmor.net/v3/projects/${LUARMOR_PROJECT_ID}${path}${queryParams}`;

  const options = {
    method,
    headers: {
      Authorization: LUARMOR_API_KEY,
      "Content-Type": "application/json",
    },
  };

  if (body && ["POST", "PATCH", "PUT"].includes(method)) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  const data = await response.json();

  return { status: response.status, data };
}

async function getProfile(userId) {
  const { data, error } = await supabase
    .from("profiles")
    .select(
      "id, luarmor_key, plan_status, plan_name, plan_expires_at, hwid_resets_remaining, last_hwid_reset"
    )
    .eq("id", userId)
    .single();

  if (error) return null;
  return data;
}

// ─────────────────────────────────────────────
// ROUTE 1 : POST /api/create-key
//
// Crée une clé Luarmor pour l'utilisateur connecté.
// La clé est immédiatement expirée (auth_expire: 1)
// car l'utilisateur n'a pas encore de plan actif.
// ─────────────────────────────────────────────

app.post("/api/create-key", authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getProfile(userId);

    if (!profile) {
      return res.status(404).json({
        success: false,
        error: "Profile not found. Complete your registration first.",
      });
    }

    // Si une clé existe déjà, on la retourne simplement
    if (profile.luarmor_key) {
      return res.status(200).json({
        success: true,
        message: "Key already exists",
        key: profile.luarmor_key,
      });
    }

    // Étape 1 : Créer la clé sur Luarmor (lifetime par défaut si aucun param)
    const createResult = await luarmorRequest("POST", "/users", {
      note: userId,
    });

    if (!createResult.data.success) {
      console.error("Luarmor POST /users failed:", createResult.data);
      return res.status(502).json({
        success: false,
        error: "Failed to create license key",
        details: createResult.data.message,
      });
    }

    const userKey = createResult.data.user_key;

    // Étape 2 : Expirer immédiatement la clé (auth_expire = 1 = 01/01/1970)
    const patchResult = await luarmorRequest("PATCH", "/users", {
      user_key: userKey,
      auth_expire: 1,
    });

    if (!patchResult.data.success) {
      // Rollback : supprime la clé qui vient d'être créée
      await luarmorRequest("DELETE", "/users", null, `?user_key=${userKey}`);
      console.error("Luarmor PATCH failed after create:", patchResult.data);
      return res.status(502).json({
        success: false,
        error: "Failed to configure license key",
        details: patchResult.data.message,
      });
    }

    // Étape 3 : Sauvegarder dans Supabase
    const { error: updateError } = await supabase
      .from("profiles")
      .update({ luarmor_key: userKey, plan_status: "inactive" })
      .eq("id", userId);

    if (updateError) {
      console.error("Supabase update error:", updateError);
      return res.status(500).json({
        success: false,
        error: "Failed to save key in database",
      });
    }

    return res.status(201).json({
      success: true,
      message: "License key created",
      key: userKey,
    });
  } catch (err) {
    console.error("create-key error:", err);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ─────────────────────────────────────────────
// ROUTE 2 : POST /api/activate-plan
//
// Active ou prolonge le plan d'un utilisateur.
//
// ⚠️ SÉCURITÉ : cette route est appelée par un webhook
// de paiement (Stripe, Sellix, etc.), PAS par le frontend.
// Elle est protégée par un secret partagé (x-webhook-secret).
//
// Body attendu :
//   { user_id: string, plan_name: string, plan_days: number }
//
// Si le plan actuel n'est pas encore expiré, les jours
// sont ajoutés à partir de la date d'expiration existante
// (prolongation, pas remplacement).
// ─────────────────────────────────────────────

app.post("/api/activate-plan", async (req, res) => {
  try {
    // Vérification du secret webhook
    const secret = req.headers["x-webhook-secret"];
    if (secret !== WEBHOOK_SECRET) {
      return res.status(403).json({ success: false, error: "Unauthorized" });
    }

    const { user_id, plan_name, plan_days } = req.body;

    if (!user_id || !plan_name || !plan_days) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: user_id, plan_name, plan_days",
      });
    }

    if (typeof plan_days !== "number" || plan_days < 1) {
      return res.status(400).json({
        success: false,
        error: "plan_days must be a positive integer",
      });
    }

    const profile = await getProfile(user_id);

    if (!profile || !profile.luarmor_key) {
      return res.status(404).json({
        success: false,
        error: "User or license key not found",
      });
    }

    // Calcul de la date d'expiration
    const nowUnix = Math.floor(Date.now() / 1000);
    let baseTimestamp = nowUnix;

    // Si le plan est encore actif → prolonger à partir de l'expiration actuelle
    if (profile.plan_status === "active" && profile.plan_expires_at) {
      const currentExpiry = Math.floor(new Date(profile.plan_expires_at).getTime() / 1000);
      if (currentExpiry > nowUnix) {
        baseTimestamp = currentExpiry;
      }
    }

    const newExpireTimestamp = baseTimestamp + plan_days * 86400;

    // Mise à jour Luarmor
    const patchResult = await luarmorRequest("PATCH", "/users", {
      user_key: profile.luarmor_key,
      auth_expire: newExpireTimestamp,
    });

    if (!patchResult.data.success) {
      console.error("Luarmor activate-plan PATCH failed:", patchResult.data);
      return res.status(502).json({
        success: false,
        error: "Failed to activate plan on Luarmor",
        details: patchResult.data.message,
      });
    }

    // Mise à jour Supabase
    const expiresAtISO = new Date(newExpireTimestamp * 1000).toISOString();

    const { error: updateError } = await supabase
      .from("profiles")
      .update({
        plan_name,
        plan_status: "active",
        plan_expires_at: expiresAtISO,
      })
      .eq("id", user_id);

    if (updateError) {
      console.error("Supabase update error (plan activated on Luarmor though):", updateError);
      return res.status(500).json({
        success: false,
        error: "Plan activated on Luarmor but database update failed",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Plan activated",
      plan_name,
      expires_at: expiresAtISO,
    });
  } catch (err) {
    console.error("activate-plan error:", err);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ─────────────────────────────────────────────
// ROUTE 3 : POST /api/reset-hwid
//
// Reset le HWID d'un utilisateur authentifié.
// Utilise l'endpoint dédié Luarmor : POST /users/resethwid
// Limite : 3 resets max + cooldown de 24h (géré côté proxy).
// Le flag force:true ignore le cooldown côté Luarmor.
// ─────────────────────────────────────────────

app.post("/api/reset-hwid", authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getProfile(userId);

    if (!profile || !profile.luarmor_key) {
      return res.status(404).json({ success: false, error: "License key not found" });
    }

    // Vérifie qu'il reste des resets
    if (profile.hwid_resets_remaining !== null && profile.hwid_resets_remaining <= 0) {
      return res.status(429).json({
        success: false,
        error: "No HWID resets remaining. Contact support.",
      });
    }

    // Cooldown : 1 reset max par 24h
    if (profile.last_hwid_reset) {
      const lastReset = new Date(profile.last_hwid_reset).getTime();
      const cooldownMs = 24 * 60 * 60 * 1000;

      if (Date.now() - lastReset < cooldownMs) {
        const remainingHours = Math.ceil((cooldownMs - (Date.now() - lastReset)) / 3600000);
        return res.status(429).json({
          success: false,
          error: `Cooldown active. Try again in ${remainingHours}h.`,
        });
      }
    }

    // Appel Luarmor : endpoint dédié /users/resethwid
    const resetResult = await luarmorRequest("POST", "/users/resethwid", {
      user_key: profile.luarmor_key,
      force: true,
    });

    if (!resetResult.data.success) {
      console.error("Luarmor resethwid failed:", resetResult.data);
      return res.status(502).json({
        success: false,
        error: "Failed to reset HWID",
        details: resetResult.data.message,
      });
    }

    // Met à jour Supabase
    const newResetsRemaining =
      profile.hwid_resets_remaining !== null ? profile.hwid_resets_remaining - 1 : null;

    await supabase
      .from("profiles")
      .update({
        hwid_resets_remaining: newResetsRemaining,
        last_hwid_reset: new Date().toISOString(),
      })
      .eq("id", userId);

    return res.status(200).json({
      success: true,
      message: "HWID reset successfully",
      resets_remaining: newResetsRemaining,
    });
  } catch (err) {
    console.error("reset-hwid error:", err);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ─────────────────────────────────────────────
// ROUTE 4 : GET /api/key-status
//
// Retourne le statut complet de la clé et du plan.
// Met automatiquement à jour plan_status si le plan
// a expiré entre-temps.
// ─────────────────────────────────────────────

app.get("/api/key-status", authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getProfile(userId);

    if (!profile) {
      return res.status(404).json({ success: false, error: "Profile not found" });
    }

    // Auto-update si le plan a expiré
    let currentStatus = profile.plan_status;

    if (currentStatus === "active" && profile.plan_expires_at) {
      const expiresAt = new Date(profile.plan_expires_at).getTime();
      if (Date.now() > expiresAt) {
        currentStatus = "expired";
        await supabase.from("profiles").update({ plan_status: "expired" }).eq("id", userId);
      }
    }

    return res.status(200).json({
      success: true,
      data: {
        luarmor_key: profile.luarmor_key || null,
        plan_name: profile.plan_name,
        plan_status: currentStatus,
        plan_expires_at: profile.plan_expires_at,
        hwid_resets_remaining: profile.hwid_resets_remaining,
        last_hwid_reset: profile.last_hwid_reset,
      },
    });
  } catch (err) {
    console.error("key-status error:", err);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ─────────────────────────────────────────────
// Utilitaire : Trouver l'IP sortante (pour whitelister sur Luarmor)
// Visite GET /my-ip après déploiement, note l'IP, puis supprime cette route.
// ─────────────────────────────────────────────

app.get("/my-ip", async (req, res) => {
  try {
    const response = await fetch("https://api.ipify.org?format=json");
    const data = await response.json();
    res.json({ outbound_ip: data.ip });
  } catch (err) {
    res.status(500).json({ error: "Could not determine outbound IP" });
  }
});

// ─────────────────────────────────────────────
// Health check
// ─────────────────────────────────────────────

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─────────────────────────────────────────────
// Démarrage
// ─────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Luarmor proxy running on port ${PORT}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(", ") || "(all)"}`);
});

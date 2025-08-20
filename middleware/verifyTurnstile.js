// middleware/verifyTurnstile.js
export async function verifyTurnstile(req, res, next) {
  try {
    const token =
      req.body?.cf_turnstile_token ||
      req.body?.token ||
      req.headers["cf-turnstile-token"];

    if (!token) return res.status(400).json({ error: "Bot check missing" });

    const secret = process.env.TURNSTILE_SECRET;
    if (!secret) {
      console.error("TURNSTILE_SECRET not configured");
      return res
        .status(500)
        .json({ error: "Server misconfigured (turnstile)" });
    }

    const remoteip = req.headers["cf-connecting-ip"] || req.ip;
    const resp = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret,
          response: token,
          ...(remoteip ? { remoteip } : {}),
        }),
      }
    );

    const data = await resp.json();

    if (!data.success) {
      console.error(
        "Turnstile failed:",
        data["error-codes"],
        "hostname:",
        data.hostname
      );
      return res.status(403).json({
        error: "Bot check failed",
        // expose codes only in non-prod to help you debug
        ...(process.env.NODE_ENV !== "production"
          ? { codes: data["error-codes"] }
          : {}),
      });
    }

    return next();
  } catch (e) {
    console.error("Turnstile verify error:", e);
    return res.status(502).json({ error: "Bot check unavailable" });
  }
}

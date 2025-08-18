export async function verifyTurnstile(req, res, next) {
  try {
    const token = req.body?.cf_turnstile_token;
    if (!token) return res.status(400).json({ error: "Bot check missing" });

    const secret = process.env.TURNSTILE_SECRET;
    if (!secret)
      return res
        .status(500)
        .json({ error: "Server misconfigured (turnstile)" });

    // Send to Cloudflare
    const formData = new URLSearchParams();
    formData.append("secret", secret);
    formData.append("response", token);

    const remoteip = req.headers["cf-connecting-ip"] || req.ip;
    if (remoteip) formData.append("remoteip", remoteip);

    const r = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body: formData,
      }
    );
    const data = await r.json();

    if (!data.success) {
      // inspect data "error-codes" to fine-tune responses
      return res.status(403).json({ error: "Bot check failed" });
    }

    return next();
  } catch (e) {
    console.error("Turnstile verify error:", e);
    return res.status(502).json({ error: "Bot check unavailable" });
  }
}

const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5.6";
const PRO_ACCESS_CODE = process.env.PRO_ACCESS_CODE;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

app.use(express.json({ limit: "100kb" }));
app.use(express.static(__dirname));

/* =========================================================
   SECURITY HELPERS
========================================================= */

function sign(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("hex");
}

function createProToken() {
  const payload = Buffer.from(
    JSON.stringify({
      plan: "pro",
      created: Date.now()
    })
  ).toString("base64url");

  return `${payload}.${sign(payload)}`;
}

function verifyProToken(token) {
  if (!token || !token.includes(".")) return false;

  const [payload, signature] = token.split(".");

  if (!payload || !signature) return false;

  const expected = sign(payload);

  if (signature.length !== expected.length) return false;

  try {
    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return false;
    }

    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    return data.plan === "pro";
  } catch {
    return false;
  }
}

function getCookies(req) {
  const header = req.headers.cookie || "";

  const cookies = {};

  header.split(";").forEach((part) => {
    const index = part.indexOf("=");

    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  });

  return cookies;
}

function isPro(req) {
  const cookies = getCookies(req);
  return verifyProToken(cookies.webzo_pro);
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    app: "Webzo",
    version: "2.0.0",
    aiConfigured: Boolean(OPENAI_API_KEY),
    model: OPENAI_MODEL
  });
});

/* =========================================================
   CURRENT PLAN
========================================================= */

app.get("/api/me", (req, res) => {
  res.json({
    ok: true,
    plan: isPro(req) ? "pro" : "free"
  });
});

/* =========================================================
   TEST PRO ACTIVATION
   Later this will be replaced with real payment verification.
========================================================= */

app.post("/api/pro/activate", (req, res) => {
  const code = String(req.body?.code || "").trim();

  if (!PRO_ACCESS_CODE) {
    return res.status(503).json({
      ok: false,
      error: "سیستم فعال‌سازی Pro هنوز تنظیم نشده است."
    });
  }

  if (!code || code !== PRO_ACCESS_CODE) {
    return res.status(403).json({
      ok: false,
      error: "کد Pro اشتباه است."
    });
  }

  const token = createProToken();

  res.setHeader(
    "Set-Cookie",
    `webzo_pro=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`
  );

  res.json({
    ok: true,
    plan: "pro",
    message: "Webzo Pro فعال شد 👑"
  });
});

/* =========================================================
   LOGOUT / RETURN TO FREE
========================================================= */

app.post("/api/pro/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "webzo_pro=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  );

  res.json({
    ok: true,
    plan: "free"
  });
});

/* =========================================================
   REAL OPENAI AI
========================================================= */

app.post("/api/ai", async (req, res) => {
  // SERVER-SIDE PRO LOCK
  if (!isPro(req)) {
    return res.status(403).json({
      ok: false,
      error: "Webzo AI فقط برای کاربران Pro فعال است. 👑"
    });
  }

  if (!OPENAI_API_KEY) {
    return res.status(503).json({
      ok: false,
      error: "OPENAI_API_KEY در سرور تنظیم نشده است."
    });
  }

  const idea = String(req.body?.idea || "").trim();

  if (!idea) {
    return res.status(400).json({
      ok: false,
      error: "ایده سایت را وارد کن."
    });
  }

  if (idea.length > 4000) {
    return res.status(400).json({
      ok: false,
      error: "متن ایده خیلی طولانی است."
    });
  }

  const prompt = `
تو Webzo AI هستی؛ یک متخصص حرفه‌ای طراحی سایت، UX/UI، برندینگ،
دیجیتال مارکتینگ و ایده‌پردازی محصول.

کاربر می‌خواهد یک سایت بسازد.

ایده کاربر:
${idea}

یک پیشنهاد حرفه‌ای و کاربردی به زبان فارسی بده.

حتماً این بخش‌ها را داشته باش:

1. نام پیشنهادی سایت
2. ایده اصلی
3. ساختار صفحه اصلی
4. صفحات پیشنهادی
5. منوی پیشنهادی
6. رنگ‌های مناسب
7. سبک UI/UX
8. امکانات ویژه
9. ایده‌های درآمدزایی
10. پیشنهاد برای نسخه Free
11. پیشنهاد برای نسخه Pro
12. یک ایده خلاقانه که سایت را متفاوت کند

پاسخ را واضح، کوتاه و قابل استفاده برای ساخت سایت بنویس.
`;

  try {
    const response = await fetch(
      "https://api.openai.com/v1/responses",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${OPENAI_API_KEY}`
        },
        body: JSON.stringify({
          model: OPENAI_MODEL,
          input: prompt
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("OpenAI error:", data);

      return res.status(502).json({
        ok: false,
        error: "ارتباط با Webzo AI ناموفق بود."
      });
    }

    const text =
      data.output_text ||
      extractOutputText(data);

    if (!text) {
      return res.status(502).json({
        ok: false,
        error: "AI پاسخی برنگرداند."
      });
    }

    res.json({
      ok: true,
      model: OPENAI_MODEL,
      result: text
    });

  } catch (error) {
    console.error("AI request error:", error);

    res.status(500).json({
      ok: false,
      error: "خطای داخلی سرور هنگام ارتباط با AI."
    });
  }
});

function extractOutputText(data) {
  try {
    const outputs = data.output || [];

    let result = "";

    for (const item of outputs) {
      if (item.type !== "message") continue;

      for (const content of item.content || []) {
        if (content.type === "output_text") {
          result += content.text || "";
        }
      }
    }

    return result.trim();
  } catch {
    return "";
  }
}

/* =========================================================
   MAIN PAGE
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* =========================================================
   FALLBACK
========================================================= */

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "Not Found"
  });
});

/* =========================================================
   START
========================================================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Webzo running on port ${PORT}`);
  console.log(`AI model: ${OPENAI_MODEL}`);
});

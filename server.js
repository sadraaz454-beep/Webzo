const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

app.use(express.json({ limit: "1mb" }));

/* =========================
   CONFIG
========================= */

const PORT = process.env.PORT || 10000;

const OWNER_PASSWORD =
  process.env.OWNER_PASSWORD || "12345678";

const DATABASE_URL =
  process.env.DATABASE_URL;

const OPENAI_API_KEY =
  process.env.OPENAI_API_KEY;

const OPENAI_MODEL =
  process.env.OPENAI_MODEL || "gpt-5.6-luna";

if (!DATABASE_URL) {
  console.error("DATABASE_URL تنظیم نشده است.");
  process.exit(1);
}

/* =========================
   DATABASE
========================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* =========================
   DATABASE INIT
========================= */

async function initDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(20) PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,
      pro_until TIMESTAMPTZ NULL
    )
  `);

  console.log("Database ready.");
}

/* =========================
   HELPERS
========================= */

function createId() {

  return (
    "WZ-" +
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase()
  );

}

function createToken() {

  return crypto
    .randomBytes(32)
    .toString("hex");

}

function getToken(req) {

  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.substring(7).trim();

}

function isProDate(proUntil) {

  if (!proUntil) {
    return false;
  }

  return new Date(proUntil) > new Date();

}

function publicUser(user) {

  return {
    id: user.id,
    username: user.username,
    pro: isProDate(user.pro_until),
    proUntil: user.pro_until || null
  };

}

/* =========================
   AUTH MIDDLEWARE
========================= */

async function userAuth(req, res, next) {

  try {

    const token = getToken(req);

    if (!token) {

      return res.status(401).json({
        error: "وارد حساب نشده‌اید."
      });

    }

    const result =
      await pool.query(
        `
        SELECT
          id,
          username,
          pro_until
        FROM users
        WHERE token = $1
        LIMIT 1
        `,
        [token]
      );

    if (result.rows.length === 0) {

      return res.status(401).json({
        error: "جلسه ورود معتبر نیست."
      });

    }

    req.user = result.rows[0];

    next();

  } catch (error) {

    console.error("USER AUTH ERROR:", error);

    res.status(500).json({
      error: "خطا در احراز هویت."
    });

  }

}

/* =========================
   OWNER AUTH
========================= */

let ownerToken = null;

function ownerAuth(req, res, next) {

  const token = getToken(req);

  if (
    !token ||
    !ownerToken ||
    token !== ownerToken
  ) {

    return res.status(403).json({
      error: "دسترسی غیرمجاز."
    });

  }

  next();

}

/* =========================
   HOME
========================= */

app.get("/", (req, res) => {

  res.sendFile(
    __dirname + "/index.html"
  );

});

/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {

  res.json({
    status: "Webzo is running",
    database: "connected",
    ai: Boolean(OPENAI_API_KEY)
  });

});

/* =========================
   REGISTER
========================= */

app.post(
  "/api/register",
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      if (username.length < 3) {

        return res.status(400).json({
          error:
            "نام کاربری حداقل ۳ کاراکتر باشد."
        });

      }

      if (username.length > 50) {

        return res.status(400).json({
          error:
            "نام کاربری بیش از حد طولانی است."
        });

      }

      if (password.length < 8) {

        return res.status(400).json({
          error:
            "رمز عبور حداقل ۸ کاراکتر باشد."
        });

      }

      const existing =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE LOWER(username) = LOWER($1)
          LIMIT 1
          `,
          [username]
        );

      if (existing.rows.length > 0) {

        return res.status(400).json({
          error:
            "این نام کاربری قبلاً ثبت شده."
        });

      }

      const id = createId();

      const token = createToken();

      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );

      await pool.query(
        `
        INSERT INTO users
        (
          id,
          username,
          password,
          token,
          pro_until
        )
        VALUES
        ($1, $2, $3, $4, NULL)
        `,
        [
          id,
          username,
          hashedPassword,
          token
        ]
      );

      res.json({

        success: true,

        token,

        user: {

          id,
          username,

          pro: false,

          proUntil: null

        }

      });

    } catch (error) {

      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در ساخت حساب."
      });

    }

  }
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/login",
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      if (!username || !password) {

        return res.status(400).json({
          error:
            "نام کاربری و رمز عبور را وارد کنید."
        });

      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE LOWER(username) = LOWER($1)
          LIMIT 1
          `,
          [username]
        );

      if (result.rows.length === 0) {

        return res.status(401).json({
          error:
            "نام کاربری یا رمز عبور اشتباه است."
        });

      }

      const user =
        result.rows[0];

      const correct =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!correct) {

        return res.status(401).json({
          error:
            "نام کاربری یا رمز عبور اشتباه است."
        });

      }

      res.json({

        success: true,

        token: user.token,

        user: publicUser(user)

      });

    } catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در ورود."
      });

    }

  }
);

/* =========================
   ME
========================= */

app.get(
  "/api/me",
  userAuth,
  async (req, res) => {

    res.json(
      publicUser(req.user)
    );

  }
);

/* =========================
   LOGOUT / TOKEN ROTATION
========================= */

app.post(
  "/api/logout",
  userAuth,
  async (req, res) => {

    try {

      const newToken =
        createToken();

      await pool.query(
        `
        UPDATE users
        SET token = $1
        WHERE id = $2
        `,
        [
          newToken,
          req.user.id
        ]
      );

      res.json({
        success: true
      });

    } catch (error) {

      console.error(
        "LOGOUT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در خروج."
      });

    }

  }
);

/* =========================
   AI
========================= */

app.post(
  "/api/ai",
  userAuth,
  async (req, res) => {

    try {

      /* فقط Pro */

      if (!isProDate(req.user.pro_until)) {

        return res.status(403).json({
          error:
            "برای استفاده از Webzo AI باید اشتراک Pro فعال داشته باشید."
        });

      }

      if (!OPENAI_API_KEY) {

        console.error(
          "OPENAI_API_KEY is missing."
        );

        return res.status(503).json({
          error:
            "سرویس هوش مصنوعی هنوز روی سرور تنظیم نشده است."
        });

      }

      const message =
        String(
          req.body.message || ""
        ).trim();

      if (!message) {

        return res.status(400).json({
          error:
            "پیام خالی است."
        });

      }

      if (message.length > 8000) {

        return res.status(400).json({
          error:
            "پیام بیش از حد طولانی است."
        });

      }

      console.log(
        `AI request from ${req.user.id}`
      );

      const controller =
        new AbortController();

      const timeout =
        setTimeout(
          () => controller.abort(),
          60000
        );

      let response;

      try {

        response =
          await fetch(
            "https://api.openai.com/v1/responses",
            {
              method: "POST",

              headers: {
                "Content-Type":
                  "application/json",

                "Authorization":
                  `Bearer ${OPENAI_API_KEY}`
              },

              body: JSON.stringify({

                model:
                  OPENAI_MODEL,

                instructions:
                  `
تو Webzo AI هستی.
یک دستیار هوش مصنوعی فارسی، دوستانه، دقیق و مفید باش.
به زبان کاربر پاسخ بده.
اگر کاربر فارسی صحبت کرد، فارسی پاسخ بده.
پاسخ‌ها را واضح و قابل فهم ارائه کن.
                `,

                input: message,

                max_output_tokens: 1200

              }),

              signal:
                controller.signal

            }
          );

      } finally {

        clearTimeout(timeout);

      }

      const data =
        await response.json();

      if (!response.ok) {

        console.error(
          "OPENAI ERROR:",
          JSON.stringify(data)
        );

        return res.status(502).json({
          error:
            "ارتباط با سرویس هوش مصنوعی برقرار نشد."
        });

      }

      let answer =
        data.output_text;

      /*
        پشتیبان برای ساختارهای مختلف پاسخ
      */

      if (
        !answer &&
        Array.isArray(data.output)
      ) {

        answer =
          data.output
            .flatMap(
              item =>
                Array.isArray(item.content)
                  ? item.content
                  : []
            )
            .filter(
              content =>
                content.type ===
                "output_text"
            )
            .map(
              content =>
                content.text
            )
            .join("\n");

      }

      if (!answer) {

        return res.status(502).json({
          error:
            "پاسخ معتبری از هوش مصنوعی دریافت نشد."
        });

      }

      res.json({

        success: true,

        answer: answer.trim()

      });

    } catch (error) {

      console.error(
        "AI ERROR:",
        error
      );

      if (
        error.name ===
        "AbortError"
      ) {

        return res.status(504).json({
          error:
            "پاسخ AI بیش از حد طول کشید. دوباره امتحان کن."
        });

      }

      res.status(500).json({
        error:
          "خطا در پردازش هوش مصنوعی."
      });

    }

  }
);

/* =========================
   OWNER LOGIN
========================= */

app.post(
  "/api/owner/login",
  (req, res) => {

    const password =
      String(
        req.body.password || ""
      );

    if (
      password !==
      OWNER_PASSWORD
    ) {

      return res.status(401).json({
        error:
          "رمز مالک اشتباه است."
      });

    }

    ownerToken =
      createToken();

    res.json({

      success: true,

      token:
        ownerToken

    });

  }
);

/* =========================
   OWNER USER SEARCH
========================= */

app.get(
  "/api/owner/user/:id",
  ownerAuth,
  async (req, res) => {

    try {

      const id =
        String(
          req.params.id || ""
        ).trim().toUpperCase();

      const result =
        await pool.query(
          `
          SELECT
            id,
            username,
            pro_until
          FROM users
          WHERE UPPER(id) = $1
          LIMIT 1
          `,
          [id]
        );

      if (result.rows.length === 0) {

        return res.status(404).json({
          error:
            "User ID پیدا نشد."
        });

      }

      res.json(
        publicUser(
          result.rows[0]
        )
      );

    } catch (error) {

      console.error(
        "OWNER SEARCH ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در جستجوی کاربر."
      });

    }

  }
);

/* =========================
   OWNER ACTIVATE PRO
========================= */

app.post(
  "/api/owner/pro",
  ownerAuth,
  async (req, res) => {

    try {

      const id =
        String(
          req.body.userId || ""
        ).trim().toUpperCase();

      const days =
        Number(
          req.body.days
        );

      if (
        ![
          30,
          60,
          90,
          365
        ].includes(days)
      ) {

        return res.status(400).json({
          error:
            "مدت اشتراک اشتباه است."
        });

      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            pro_until
          FROM users
          WHERE UPPER(id) = $1
          LIMIT 1
          `,
          [id]
        );

      if (result.rows.length === 0) {

        return res.status(404).json({
          error:
            "User ID پیدا نشد."
        });

      }

      const user =
        result.rows[0];

      const now =
        Date.now();

      let start =
        now;

      if (
        user.pro_until &&
        new Date(
          user.pro_until
        ).getTime() > now
      ) {

        start =
          new Date(
            user.pro_until
          ).getTime();

      }

      const newProUntil =
        new Date(
          start +
          days *
          24 *
          60 *
          60 *
          1000
        );

      await pool.query(
        `
        UPDATE users
        SET pro_until = $1
        WHERE id = $2
        `,
        [
          newProUntil,
          user.id
        ]
      );

      res.json({

        success: true,

        id: user.id,

        proUntil:
          newProUntil.toISOString()

      });

    } catch (error) {

      console.error(
        "ACTIVATE PRO ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در فعال‌سازی Pro."
      });

    }

  }
);

/* =========================
   OWNER REVOKE PRO
========================= */

app.post(
  "/api/owner/revoke",
  ownerAuth,
  async (req, res) => {

    try {

      const id =
        String(
          req.body.userId || ""
        ).trim().toUpperCase();

      const result =
        await pool.query(
          `
          UPDATE users
          SET pro_until = NULL
          WHERE UPPER(id) = $1
          RETURNING id
          `,
          [id]
        );

      if (result.rows.length === 0) {

        return res.status(404).json({
          error:
            "User ID پیدا نشد."
        });

      }

      res.json({
        success: true
      });

    } catch (error) {

      console.error(
        "REVOKE PRO ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در لغو اشتراک."
      });

    }

  }
);

/* =========================
   OWNER STATUS
========================= */

app.get(
  "/api/owner/status",
  ownerAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM users
          `
        );

      res.json({

        success: true,

        users:
          result.rows[0].count,

        ai:
          Boolean(OPENAI_API_KEY),

        database:
          true

      });

    } catch (error) {

      console.error(
        "OWNER STATUS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در دریافت وضعیت سیستم."
      });

    }

  }
);

/* =========================
   404
========================= */

app.use(
  (req, res) => {

    if (
      req.path.startsWith("/api/")
    ) {

      return res.status(404).json({
        error:
          "API endpoint پیدا نشد."
      });

    }

    res.status(404).send(
      "Webzo - Page Not Found"
    );

  }
);

/* =========================
   GLOBAL ERROR
========================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "GLOBAL ERROR:",
      error
    );

    res.status(500).json({
      error:
        "خطای داخلی سرور."
    });

  }
);

/* =========================
   START
========================= */

async function startServer() {

  try {

    await initDatabase();

    app.listen(
      PORT,
      () => {

        console.log(
          `Webzo running on port ${PORT}`
        );

        console.log(
          "AI:",
          OPENAI_API_KEY
            ? "CONFIGURED"
            : "NOT CONFIGURED"
        );

      }
    );

  } catch (error) {

    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);

  }

}

startServer();

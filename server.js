const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;

const DATABASE_URL = process.env.DATABASE_URL;
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || "12345678";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";

if (!DATABASE_URL) {
  console.error("DATABASE_URL تنظیم نشده است.");
  process.exit(1);
}

/* ========================= CORS ========================= */

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,DELETE,OPTIONS"
  );
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: "2mb" }));

/* ========================= DATABASE ========================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* ========================= DATABASE INIT ========================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(20) PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,
      pro_until TIMESTAMPTZ NULL,

      sites_created_today INTEGER NOT NULL DEFAULT 0,
      last_site_created_at TIMESTAMPTZ NULL
    )
  `);

  /*
    اگر دیتابیس قبلی جدول users را داشته باشد،
    ستون‌های جدید را اضافه می‌کنیم.
  */

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS sites_created_today INTEGER NOT NULL DEFAULT 0
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS last_site_created_at TIMESTAMPTZ NULL
  `);

  console.log("DATABASE CONNECTED");
}

/* ========================= HELPERS ========================= */

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
  return crypto.randomBytes(32).toString("hex");
}

function getToken(req) {
  const authorization = req.headers.authorization || "";

  if (
    authorization
      .toLowerCase()
      .startsWith("bearer ")
  ) {
    return authorization
      .substring(7)
      .trim();
  }

  return authorization.trim() || null;
}

function isPro(date) {
  if (!date) {
    return false;
  }

  return (
    new Date(date).getTime() > Date.now()
  );
}

/*
  سهمیه Free:
  هر کاربر Free در هر روز فقط 1 سایت.
*/

function getNextDayReset(date) {
  const d = new Date(date);

  d.setHours(24, 0, 0, 0);

  return d;
}

/*
  سهمیه را در صورت عوض شدن روز ریست می‌کند.
*/

async function refreshDailyQuota(user) {
  if (!user.last_site_created_at) {
    return {
      count: 0,
      lastCreatedAt: null
    };
  }

  const lastCreated = new Date(
    user.last_site_created_at
  );

  const now = new Date();

  const sameDay =
    lastCreated.getFullYear() === now.getFullYear() &&
    lastCreated.getMonth() === now.getMonth() &&
    lastCreated.getDate() === now.getDate();

  if (!sameDay) {
    await pool.query(
      `
      UPDATE users
      SET sites_created_today = 0
      WHERE id = $1
      `,
      [user.id]
    );

    return {
      count: 0,
      lastCreatedAt: null
    };
  }

  return {
    count: Number(user.sites_created_today || 0),
    lastCreatedAt: user.last_site_created_at
  };
}

/*
  اطلاعات کاربر برای APIها
*/

function formatUser(user) {
  const pro = isPro(user.pro_until);

  return {
    id: user.id,
    username: user.username,
    pro,
    proUntil: user.pro_until
  };
}

/* ========================= ROOT ========================= */

app.get("/", (req, res) => {
  res.status(200).json({
    status: "Webzo is running",
    database: "connected",
    ai: Boolean(OPENAI_API_KEY)
  });
});

/* ========================= HEALTH ========================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "Webzo is running",
      database: "connected",
      ai: Boolean(OPENAI_API_KEY)
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      status: "Webzo is running",
      database: "disconnected",
      ai: Boolean(OPENAI_API_KEY)
    });
  }
});

/* ========================= REGISTER ========================= */

app.post("/api/register", async (req, res) => {
  try {
    const username = String(
      req.body.username || ""
    ).trim();

    const password = String(
      req.body.password || ""
    );

    if (username.length < 3) {
      return res.status(400).json({
        error:
          "نام کاربری حداقل ۳ حرف باشد."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error:
          "رمز عبور حداقل ۸ کاراکتر باشد."
      });
    }

    const existing = await pool.query(
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
        10
      );

    await pool.query(
      `
      INSERT INTO users
      (
        id,
        username,
        password,
        token,
        pro_until,
        sites_created_today,
        last_site_created_at
      )
      VALUES
      ($1, $2, $3, $4, NULL, 0, NULL)
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
});

/* ========================= LOGIN ========================= */

app.post("/api/login", async (req, res) => {
  try {
    const username = String(
      req.body.username || ""
    ).trim();

    const password = String(
      req.body.password || ""
    );

    if (!username || !password) {
      return res.status(400).json({
        error:
          "نام کاربری و رمز عبور را وارد کنید."
      });
    }

    const result = await pool.query(
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

    const user = result.rows[0];

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
      user: formatUser(user)
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
});

/* ========================= ME ========================= */

app.get("/api/me", async (req, res) => {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        error:
          "وارد حساب نشده‌اید."
      });
    }

    const result = await pool.query(
      `
      SELECT
        id,
        username,
        pro_until,
        sites_created_today,
        last_site_created_at
      FROM users
      WHERE token = $1
      LIMIT 1
      `,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error:
          "جلسه ورود معتبر نیست."
      });
    }

    const user = result.rows[0];

    const quota =
      await refreshDailyQuota(user);

    const pro =
      isPro(user.pro_until);

    res.json({
      id: user.id,
      username: user.username,
      pro,
      proUntil: user.pro_until,

      /*
        اطلاعات سهمیه
      */

      quota: {
        unlimited: pro,
        limit: pro ? null : 1,
        used: pro ? null : quota.count,
        remaining: pro
          ? null
          : Math.max(
              0,
              1 - quota.count
            ),
        resetAt:
          !pro && quota.lastCreatedAt
            ? getNextDayReset(
                quota.lastCreatedAt
              ).toISOString()
            : null
      }
    });
  } catch (error) {
    console.error(
      "ME ERROR:",
      error
    );

    res.status(500).json({
      error:
        "خطا در دریافت اطلاعات کاربر."
    });
  }
});

/* ========================= SITE QUOTA ========================= */

app.get(
  "/api/site-quota",
  async (req, res) => {
    try {
      const token = getToken(req);

      if (!token) {
        return res.status(401).json({
          error:
            "برای مشاهده سهمیه وارد حساب شوید."
        });
      }

      const result = await pool.query(
        `
        SELECT
          id,
          pro_until,
          sites_created_today,
          last_site_created_at
        FROM users
        WHERE token = $1
        LIMIT 1
        `,
        [token]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          error:
            "جلسه ورود معتبر نیست."
        });
      }

      const user = result.rows[0];

      const quota =
        await refreshDailyQuota(user);

      const pro =
        isPro(user.pro_until);

      res.json({
        success: true,

        pro,

        limit: pro
          ? null
          : 1,

        used: pro
          ? null
          : quota.count,

        remaining: pro
          ? null
          : Math.max(
              0,
              1 - quota.count
            ),

        unlimited: pro,

        resetAt:
          !pro && quota.lastCreatedAt
            ? getNextDayReset(
                quota.lastCreatedAt
              ).toISOString()
            : null
      });
    } catch (error) {
      console.error(
        "QUOTA ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در دریافت سهمیه."
      });
    }
  }
);

/* ========================= CREATE SITE ========================= */

/*
  API اصلی ساخت سایت.

  Free:
  روزی یک بار

  Pro:
  بدون محدودیت

  مهم:
  محدودیت در PostgreSQL بررسی و ثبت می‌شود،
  بنابراین پاک کردن Cache یا Refresh باعث دور زدن آن نمی‌شود.
*/

app.post(
  "/api/sites",
  async (req, res) => {
    try {
      const token = getToken(req);

      if (!token) {
        return res.status(401).json({
          error:
            "برای ساخت سایت وارد حساب شوید."
        });
      }

      const client =
        await pool.connect();

      try {
        await client.query(
          "BEGIN"
        );

        /*
          FOR UPDATE باعث می‌شود
          دو درخواست همزمان نتوانند
          سهمیه را دور بزنند.
        */

        const result =
          await client.query(
            `
            SELECT
              id,
              username,
              pro_until,
              sites_created_today,
              last_site_created_at
            FROM users
            WHERE token = $1
            LIMIT 1
            FOR UPDATE
            `,
            [token]
          );

        if (result.rows.length === 0) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(401).json({
            error:
              "جلسه ورود معتبر نیست."
          });
        }

        const user =
          result.rows[0];

        const pro =
          isPro(user.pro_until);

        let used =
          Number(
            user.sites_created_today || 0
          );

        /*
          بررسی روز جدید
        */

        if (
          user.last_site_created_at
        ) {
          const last =
            new Date(
              user.last_site_created_at
            );

          const now =
            new Date();

          const sameDay =
            last.getFullYear() ===
              now.getFullYear() &&
            last.getMonth() ===
              now.getMonth() &&
            last.getDate() ===
              now.getDate();

          if (!sameDay) {
            used = 0;
          }
        }

        /*
          Free فقط یک سایت در روز
        */

        if (!pro && used >= 1) {
          await client.query(
            "ROLLBACK"
          );

          const resetAt =
            getNextDayReset(
              user.last_site_created_at ||
                new Date()
            );

          return res.status(429).json({
            error:
              "سهمیه ساخت سایت رایگان امروز شما تمام شده است.",

            code:
              "DAILY_SITE_LIMIT",

            pro: false,

            limit: 1,

            used: 1,

            remaining: 0,

            resetAt:
              resetAt.toISOString(),

            message:
              "برای ساخت سایت بیشتر، Pro را فعال کنید."
          });
        }

        /*
          داده‌های سایت از Frontend
        */

        const siteData =
          req.body || {};

        /*
          این قسمت ثبت واقعی ساخت سایت است.
          اطلاعات سایت فعلاً داخل خود حساب
          ذخیره نمی‌شود؛ فقط سهمیه ثبت می‌شود.
        */

        const now =
          new Date();

        if (!pro) {
          await client.query(
            `
            UPDATE users
            SET
              sites_created_today = $1,
              last_site_created_at = $2
            WHERE id = $3
            `,
            [
              used + 1,
              now,
              user.id
            ]
          );
        } else {
          /*
            برای Pro هم زمان آخرین ساخت
            ثبت می‌شود، ولی محدودیت ندارد.
          */

          await client.query(
            `
            UPDATE users
            SET
              last_site_created_at = $1
            WHERE id = $2
            `,
            [
              now,
              user.id
            ]
          );
        }

        await client.query(
          "COMMIT"
        );

        res.json({
          success: true,

          message:
            "سایت با موفقیت ایجاد شد.",

          site: siteData,

          quota: {
            unlimited: pro,

            limit: pro
              ? null
              : 1,

            used: pro
              ? null
              : used + 1,

            remaining: pro
              ? null
              : 0,

            resetAt:
              !pro
                ? getNextDayReset(
                    now
                  ).toISOString()
                : null
          }
        });
      } catch (error) {
        try {
          await client.query(
            "ROLLBACK"
          );
        } catch {}

        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(
        "CREATE SITE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در ساخت سایت."
      });
    }
  }
);

/* ========================= OWNER LOGIN ========================= */

let ownerToken = null;

app.post(
  "/api/owner/login",
  (req, res) => {
    const password = String(
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
      token: ownerToken
    });
  }
);

/* ========================= OWNER AUTH ========================= */

function ownerAuth(
  req,
  res,
  next
) {
  const token =
    getToken(req);

  if (
    !token ||
    !ownerToken ||
    token !== ownerToken
  ) {
    return res.status(403).json({
      error:
        "دسترسی غیرمجاز."
    });
  }

  next();
}

/* ========================= FIND USER ========================= */

app.get(
  "/api/owner/user/:id",
  ownerAuth,
  async (req, res) => {
    try {
      const id = String(
        req.params.id || ""
      ).toUpperCase();

      const result =
        await pool.query(
          `
          SELECT
            id,
            username,
            pro_until,
            sites_created_today,
            last_site_created_at
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

      res.json({
        id: user.id,
        username: user.username,

        pro:
          isPro(user.pro_until),

        proUntil:
          user.pro_until,

        sitesCreatedToday:
          user.sites_created_today,

        lastSiteCreatedAt:
          user.last_site_created_at
      });
    } catch (error) {
      console.error(
        "OWNER USER ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در جستجوی کاربر."
      });
    }
  }
);

/* ========================= ACTIVATE PRO ========================= */

app.post(
  "/api/owner/pro",
  ownerAuth,
  async (req, res) => {
    try {
      const id = String(
        req.body.userId || ""
      ).toUpperCase();

      const days = Number(
        req.body.days
      );

      if (
        ![30, 60, 90, 365]
          .includes(days)
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
        "PRO ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در فعال‌سازی Pro."
      });
    }
  }
);

/* ========================= REVOKE PRO ========================= */

app.post(
  "/api/owner/revoke",
  ownerAuth,
  async (req, res) => {
    try {
      const id = String(
        req.body.userId || ""
      ).toUpperCase();

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
        "REVOKE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در لغو اشتراک."
      });
    }
  }
);

/* ========================= OPENAI AI ========================= */

app.post(
  "/api/ai",
  async (req, res) => {
    try {
      const token =
        getToken(req);

      if (!token) {
        return res.status(401).json({
          error:
            "برای استفاده از AI وارد حساب شوید."
        });
      }

      const userResult =
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

      if (
        userResult.rows.length === 0
      ) {
        return res.status(401).json({
          error:
            "جلسه ورود معتبر نیست."
        });
      }

      const user =
        userResult.rows[0];

      /*
        فقط Pro اجازه AI دارد.
      */

      if (
        !isPro(
          user.pro_until
        )
      ) {
        return res.status(403).json({
          error:
            "برای استفاده از Webzo AI باید Pro فعال باشد.",

          code:
            "PRO_REQUIRED"
        });
      }

      if (!OPENAI_API_KEY) {
        return res.status(503).json({
          error:
            "کلید OpenAI روی Render تنظیم نشده است."
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

      if (
        message.length > 12000
      ) {
        return res.status(400).json({
          error:
            "پیام بیش از حد طولانی است."
        });
      }

      const response =
        await fetch(
          "https://api.openai.com/v1/responses",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",

              Authorization:
                "Bearer " +
                OPENAI_API_KEY
            },

            body: JSON.stringify({
              model:
                OPENAI_MODEL,

              input: [
                {
                  role:
                    "system",

                  content:
                    "You are Webzo AI. Answer clearly and helpfully. If the user writes Persian, answer in Persian."
                },

                {
                  role:
                    "user",

                  content:
                    message
                }
              ]
            })
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        console.error(
          "OPENAI ERROR:",
          data
        );

        return res.status(502).json({
          error:
            data?.error?.message ||
            "خطا در ارتباط با OpenAI."
        });
      }

      let answer = "";

      if (
        typeof data.output_text ===
        "string"
      ) {
        answer =
          data.output_text;
      }

      if (
        !answer &&
        Array.isArray(
          data.output
        )
      ) {
        for (
          const item of
          data.output
        ) {
          if (
            Array.isArray(
              item.content
            )
          ) {
            for (
              const content of
              item.content
            ) {
              if (
                typeof content.text ===
                "string"
              ) {
                answer +=
                  content.text;
              }
            }
          }
        }
      }

      if (
        !answer.trim()
      ) {
        answer =
          "پاسخی از هوش مصنوعی دریافت نشد.";
      }

      res.json({
        success: true,
        answer:
          answer.trim()
      });
    } catch (error) {
      console.error(
        "AI ERROR:",
        error
      );

      res.status(500).json({
        error:
          "خطا در اتصال به هوش مصنوعی."
      });
    }
  }
);

/* ========================= API 404 ========================= */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      error:
        "API endpoint پیدا نشد."
    });
  }
);

/* ========================= SERVER ERROR ========================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    res.status(500).json({
      error:
        "خطای داخلی سرور."
    });
  }
);

/* ========================= START SERVER ========================= */

async function startServer() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          "================================"
        );

        console.log(
          "WEBZO ONLINE"
        );

        console.log(
          "PORT:",
          PORT
        );

        console.log(
          "DATABASE: CONNECTED"
        );

        console.log(
          "AI:",
          OPENAI_API_KEY
            ? "ENABLED"
            : "DISABLED"
        );

        console.log(
          "FREE SITE LIMIT: 1 PER DAY"
        );

        console.log(
          "PRO SITE LIMIT: UNLIMITED"
        );

        console.log(
          "================================"
        );
      }
    );
  } catch (error) {
    console.error(
      "STARTUP ERROR:",
      error
    );

    process.exit(1);
  }
}

startServer();

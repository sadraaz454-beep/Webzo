const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

app.use(express.json());

const PORT = process.env.PORT || 10000;

const OWNER_PASSWORD =
  process.env.OWNER_PASSWORD || "12345678";

const DATABASE_URL =
  process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("DATABASE_URL تنظیم نشده است.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});


/* اتصال و ساخت جدول */

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


/* ابزارها */

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

  return req.headers.authorization
    ?.replace("Bearer ", "");

}


/* صفحه اصلی */

app.get("/", (req, res) => {

  res.sendFile(
    __dirname + "/index.html"
  );

});


/* ثبت نام */

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
            "نام کاربری حداقل ۳ حرف باشد."
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
          `,
          [username]
        );

      if (existing.rows.length > 0) {

        return res.status(400).json({
          error:
            "این نام کاربری قبلاً ثبت شده."
        });

      }

      const id =
        createId();

      const token =
        createToken();

      const hashedPassword =
        await bcrypt.hash(
          password,
          10
        );

      await pool.query(
        `
        INSERT INTO users
        (id, username, password, token, pro_until)
        VALUES ($1, $2, $3, $4, NULL)
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

      console.error(error);

      res.status(500).json({
        error:
          "خطا در ساخت حساب."
      });

    }

  }
);


/* ورود */

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

      const isPro =
        user.pro_until &&
        new Date(
          user.pro_until
        ) > new Date();

      res.json({

        success: true,

        token:
          user.token,

        user: {

          id:
            user.id,

          username:
            user.username,

          pro:
            Boolean(isPro),

          proUntil:
            user.pro_until

        }

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "خطا در ورود."
      });

    }

  }
);


/* اطلاعات کاربر */

app.get(
  "/api/me",
  async (req, res) => {

    try {

      const token =
        getToken(req);

      if (!token) {

        return res.status(401).json({
          error:
            "وارد حساب نشده‌اید."
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
          error:
            "جلسه ورود معتبر نیست."
        });

      }

      const user =
        result.rows[0];

      const isPro =
        user.pro_until &&
        new Date(
          user.pro_until
        ) > new Date();

      res.json({

        id:
          user.id,

        username:
          user.username,

        pro:
          Boolean(isPro),

        proUntil:
          user.pro_until

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت اطلاعات کاربر."
      });

    }

  }
);


/* ورود مالک */

let ownerToken = null;


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


/* احراز هویت مالک */

function ownerAuth(
  req,
  res,
  next
) {

  const token =
    getToken(req);

  if (
    !token ||
    token !== ownerToken
  ) {

    return res.status(403).json({
      error:
        "دسترسی غیرمجاز."
    });

  }

  next();

}


/* پیدا کردن کاربر */

app.get(
  "/api/owner/user/:id",
  ownerAuth,
  async (req, res) => {

    try {

      const id =
        req.params.id
          .toUpperCase();

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

      const user =
        result.rows[0];

      const isPro =
        user.pro_until &&
        new Date(
          user.pro_until
        ) > new Date();

      res.json({

        id:
          user.id,

        username:
          user.username,

        pro:
          Boolean(isPro),

        proUntil:
          user.pro_until

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "خطا در جستجوی کاربر."
      });

    }

  }
);


/* فعال کردن Pro */

app.post(
  "/api/owner/pro",
  ownerAuth,
  async (req, res) => {

    try {

      const id =
        String(
          req.body.userId || ""
        ).toUpperCase();

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

        id:
          user.id,

        proUntil:
          newProUntil.toISOString()

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "خطا در فعال‌سازی Pro."
      });

    }

  }
);


/* لغو Pro */

app.post(
  "/api/owner/revoke",
  ownerAuth,
  async (req, res) => {

    try {

      const id =
        String(
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

      console.error(error);

      res.status(500).json({
        error:
          "خطا در لغو اشتراک."
      });

    }

  }
);


/* وضعیت سرور */

app.get(
  "/api/health",
  (req, res) => {

    res.json({
      status:
        "Webzo is running"
    });

  }
);


/* شروع سرور */

initDatabase()
  .then(() => {

    app.listen(
      PORT,
      () => {

        console.log(
          "Webzo running on port " +
          PORT
        );

      }
    );

  })
  .catch(error => {

    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);

  });

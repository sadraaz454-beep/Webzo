const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();

app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 10000;

const OWNER_PASSWORD =
  process.env.OWNER_PASSWORD || "CHANGE_THIS_PASSWORD";

const users = new Map();

function createId() {
  return (
    "WZ-" +
    crypto.randomBytes(4).toString("hex").toUpperCase()
  );
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function getUser(token) {
  for (const user of users.values()) {
    if (user.token === token) return user;
  }

  return null;
}

/* REGISTER */

app.post("/api/register", async (req, res) => {

  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (username.length < 3) {
    return res.status(400).json({
      error: "نام کاربری حداقل ۳ حرف باشد."
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: "رمز عبور حداقل ۸ کاراکتر باشد."
    });
  }

  for (const user of users.values()) {

    if (
      user.username.toLowerCase() ===
      username.toLowerCase()
    ) {

      return res.status(400).json({
        error: "این نام کاربری قبلاً ثبت شده."
      });

    }

  }

  const id = createId();

  const user = {

    id,

    username,

    password: await bcrypt.hash(password, 10),

    token: createToken(),

    proUntil: null

  };

  users.set(id, user);

  res.json({

    success: true,

    user: {

      id: user.id,

      username: user.username,

      pro: false

    },

    token: user.token

  });

});


/* LOGIN */

app.post("/api/login", async (req, res) => {

  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  for (const user of users.values()) {

    if (
      user.username.toLowerCase() ===
      username.toLowerCase()
    ) {

      const ok =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!ok) break;

      res.json({

        success: true,

        user: {

          id: user.id,

          username: user.username,

          pro:
            user.proUntil &&
            new Date(user.proUntil) > new Date(),

          proUntil: user.proUntil

        },

        token: user.token

      });

      return;

    }

  }

  res.status(401).json({

    error: "نام کاربری یا رمز عبور اشتباه است."

  });

});


/* USER */

app.get("/api/me", (req, res) => {

  const token =
    req.headers.authorization?.replace(
      "Bearer ",
      ""
    );

  const user = getUser(token);

  if (!user) {

    return res.status(401).json({
      error: "وارد حساب نشده‌اید."
    });

  }

  res.json({

    id: user.id,

    username: user.username,

    pro:
      user.proUntil &&
      new Date(user.proUntil) > new Date(),

    proUntil: user.proUntil

  });

});


/* OWNER LOGIN */

app.post("/api/owner/login", (req, res) => {

  const password =
    String(req.body.password || "");

  if (password !== OWNER_PASSWORD) {

    return res.status(401).json({
      error: "رمز مالک اشتباه است."
    });

  }

  const ownerToken = createToken();

  global.ownerToken = ownerToken;

  res.json({

    success: true,

    token: ownerToken

  });

});


function ownerAuth(req, res, next) {

  const token =
    req.headers.authorization?.replace(
      "Bearer ",
      ""
    );

  if (
    !token ||
    token !== global.ownerToken
  ) {

    return res.status(403).json({
      error: "دسترسی غیرمجاز."
    });

  }

  next();

}


/* FIND USER */

app.get(
  "/api/owner/user/:id",
  ownerAuth,
  (req, res) => {

    const user =
      users.get(
        req.params.id.toUpperCase()
      );

    if (!user) {

      return res.status(404).json({
        error: "User ID پیدا نشد."
      });

    }

    res.json({

      id: user.id,

      username: user.username,

      pro:
        user.proUntil &&
        new Date(user.proUntil) > new Date(),

      proUntil: user.proUntil

    });

  }
);


/* ACTIVATE PRO */

app.post(
  "/api/owner/pro",
  ownerAuth,
  (req, res) => {

    const id =
      String(req.body.userId || "")
        .toUpperCase();

    const days =
      Number(req.body.days);

    if (![30, 60, 90, 365].includes(days)) {

      return res.status(400).json({
        error: "مدت اشتراک اشتباه است."
      });

    }

    const user = users.get(id);

    if (!user) {

      return res.status(404).json({
        error: "User ID پیدا نشد."
      });

    }

    const now = Date.now();

    let start = now;

    if (
      user.proUntil &&
      new Date(user.proUntil).getTime() > now
    ) {

      start =
        new Date(user.proUntil).getTime();

    }

    user.proUntil =
      new Date(
        start +
        days *
        24 *
        60 *
        60 *
        1000
      ).toISOString();

    res.json({

      success: true,

      id: user.id,

      proUntil: user.proUntil

    });

  }
);


/* REVOKE PRO */

app.post(
  "/api/owner/revoke",
  ownerAuth,
  (req, res) => {

    const id =
      String(req.body.userId || "")
        .toUpperCase();

    const user = users.get(id);

    if (!user) {

      return res.status(404).json({
        error: "User ID پیدا نشد."
      });

    }

    user.proUntil = null;

    res.json({
      success: true
    });

  }
);


/* HEALTH */

app.get("/api/health", (req, res) => {

  res.json({
    status: "Webzo is running"
  });

});


app.listen(PORT, () => {

  console.log(
    `Webzo running on port ${PORT}`
  );

});

const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const fs = require("fs");

const app = express();

app.use(express.json());

const PORT = process.env.PORT || 10000;

const OWNER_PASSWORD =
  process.env.OWNER_PASSWORD || "12345678";

const usersFile = "./users.json";

let users = [];

if (fs.existsSync(usersFile)) {
  try {
    users = JSON.parse(
      fs.readFileSync(usersFile, "utf8")
    );
  } catch {
    users = [];
  }
}

function saveUsers() {
  fs.writeFileSync(
    usersFile,
    JSON.stringify(users, null, 2)
  );
}

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

function getUser(token) {

  return users.find(
    user => user.token === token
  );

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

    const exists =
      users.find(
        u =>
          u.username.toLowerCase() ===
          username.toLowerCase()
      );

    if (exists) {

      return res.status(400).json({
        error:
          "این نام کاربری قبلاً ثبت شده."
      });

    }

    const user = {

      id: createId(),

      username,

      password:
        await bcrypt.hash(
          password,
          10
        ),

      token:
        createToken(),

      proUntil: null

    };

    users.push(user);

    saveUsers();

    res.json({

      success: true,

      token: user.token,

      user: {

        id: user.id,

        username: user.username,

        pro: false,

        proUntil: null

      }

    });

  }

);


/* ورود */

app.post(
  "/api/login",
  async (req, res) => {

    const username =
      String(
        req.body.username || ""
      ).trim();

    const password =
      String(
        req.body.password || ""
      );

    const user =
      users.find(
        u =>
          u.username.toLowerCase() ===
          username.toLowerCase()
      );

    if (!user) {

      return res.status(401).json({
        error:
          "نام کاربری یا رمز عبور اشتباه است."
      });

    }

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

      user: {

        id: user.id,

        username: user.username,

        pro:
          user.proUntil &&
          new Date(
            user.proUntil
          ) > new Date(),

        proUntil:
          user.proUntil

      }

    });

  }

);


/* اطلاعات کاربر */

app.get(
  "/api/me",
  (req, res) => {

    const token =
      req.headers.authorization
        ?.replace(
          "Bearer ",
          ""
        );

    const user =
      getUser(token);

    if (!user) {

      return res.status(401).json({
        error:
          "وارد حساب نشده‌اید."
      });

    }

    res.json({

      id: user.id,

      username: user.username,

      pro:
        user.proUntil &&
        new Date(
          user.proUntil
        ) > new Date(),

      proUntil:
        user.proUntil

    });

  }

);


/* ورود مالک */

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

    const token =
      createToken();

    global.ownerToken =
      token;

    res.json({

      success: true,

      token

    });

  }

);


function ownerAuth(
  req,
  res,
  next
) {

  const token =
    req.headers.authorization
      ?.replace(
        "Bearer ",
        ""
      );

  if (
    !token ||
    token !== global.ownerToken
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
  (req, res) => {

    const id =
      req.params.id.toUpperCase();

    const user =
      users.find(
        u =>
          u.id.toUpperCase() === id
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User ID پیدا نشد."
      });

    }

    res.json({

      id: user.id,

      username:
        user.username,

      pro:
        user.proUntil &&
        new Date(
          user.proUntil
        ) > new Date(),

      proUntil:
        user.proUntil

    });

  }

);


/* فعال کردن Pro */

app.post(
  "/api/owner/pro",
  ownerAuth,
  (req, res) => {

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

    const user =
      users.find(
        u =>
          u.id.toUpperCase() ===
          id
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User ID پیدا نشد."
      });

    }

    const now =
      Date.now();

    let start =
      now;

    if (
      user.proUntil &&
      new Date(
        user.proUntil
      ).getTime() > now
    ) {

      start =
        new Date(
          user.proUntil
        ).getTime();

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

    saveUsers();

    res.json({

      success: true,

      id: user.id,

      proUntil:
        user.proUntil

    });

  }

);


/* لغو Pro */

app.post(
  "/api/owner/revoke",
  ownerAuth,
  (req, res) => {

    const id =
      String(
        req.body.userId || ""
      ).toUpperCase();

    const user =
      users.find(
        u =>
          u.id.toUpperCase() ===
          id
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User ID پیدا نشد."
      });

    }

    user.proUntil =
      null;

    saveUsers();

    res.json({
      success: true
    });

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


app.listen(
  PORT,
  () => {

    console.log(
      "Webzo running on port " +
      PORT
    );

  }
);

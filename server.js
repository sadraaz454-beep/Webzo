const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// نمایش فایل‌های Webzo
app.use(express.static(__dirname));

// بررسی وضعیت سرور
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    app: "Webzo",
    version: "1.0.0"
  });
});

// AI فعلاً قفل است
app.post("/api/ai", (req, res) => {
  res.status(403).json({
    ok: false,
    error: "Webzo AI فقط برای کاربران Pro فعال است."
  });
});

// صفحه اصلی
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Webzo is running on port ${PORT}`);
});

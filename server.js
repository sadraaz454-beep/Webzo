const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    app: "Webzo",
    version: "1.0.1"
  });
});

app.post("/api/ai", (req, res) => {
  res.status(403).json({
    ok: false,
    error: "Webzo AI فقط برای کاربران Pro فعال است."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Webzo running on port ${PORT}`);
});

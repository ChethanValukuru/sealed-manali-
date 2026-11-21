// Zero-dependency static server for the sealed website.
// Usage:  node serve-web.js        ->  http://localhost:8080
const http = require("http");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "web");
const PORT = process.env.PORT || 8080;
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".jpg": "image/jpeg",
  ".png": "image/png",
  ".mp4": "video/mp4",
};

const server = http.createServer((req, res) => {
  let rel = decodeURIComponent(req.url.split("?")[0]);
  if (rel === "/") rel = "/index.html";
  const file = path.join(ROOT, path.normalize(rel).replace(/^[\/]+/, ""));
  if (!file.startsWith(ROOT)) { res.writeHead(403).end("forbidden"); return; }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { "Content-Type": "text/plain" }).end("404 not found"); return; }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(file).toLowerCase()] || "application/octet-stream" });
    res.end(buf);
  });
});

// If the chosen port is busy, step to the next one instead of crashing.
// (Demo day: something else is often already sitting on 8080.)
let port = Number(PORT);
const MAX_TRIES = 20;
let tries = 0;

server.on("error", (err) => {
  if (err.code === "EADDRINUSE" && tries < MAX_TRIES) {
    tries++;
    console.log(`port ${port} is busy, trying ${port + 1} ...`);
    port++;
    server.listen(port);
  } else {
    console.error("could not start the web server:", err.message);
    process.exit(1);
  }
});

server.listen(port, () => {
  console.log("");
  console.log("  sealed website is running");
  console.log(`  ->  http://localhost:${port}`);
  console.log(`  ->  http://localhost:${port}/console.html   (live console)`);
  console.log(`  ->  http://localhost:${port}/verify.html    (proof verifier)`);
  console.log("");
  console.log("  Press Ctrl+C to stop.");
  console.log("");
});

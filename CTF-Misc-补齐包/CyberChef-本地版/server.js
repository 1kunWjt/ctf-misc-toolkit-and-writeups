#!/usr/bin/env node
/**
 * CyberChef 本地服务（零依赖，只需 Node.js）
 *
 * 为什么必须这样启动：
 *   CyberChef 的所有运算都在 Web Worker 里执行，而 Crypto / Ciphers / Hashing /
 *   Compression / Regex / Charts / Image / PGP 等约 250 个操作是在需要时才从
 *   modules/*.js 加载的（Worker 内部用 importScripts 拉取）。
 *   如果用浏览器直接双击打开 file:// 的 html，浏览器把页面当作 opaque origin，
 *   这些 importScripts 会被拒绝，Worker 不会回报结果，界面就永久卡在
 *   "Baking..."——也就是"有些功能卡死"。官方明确说明 file:// 不受支持：
 *   https://github.com/gchq/CyberChef/issues/2871
 *   通过 http://127.0.0.1 访问一切正常。
 *
 * 用法：node server.js [端口] [--no-open]
 */
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const ROOT = __dirname;
const BASE_PORT = parseInt(process.argv[2] || process.env.PORT || "8787", 10);
const NO_OPEN = process.argv.includes("--no-open") || process.env.CC_NO_OPEN === "1";
const HOST = "127.0.0.1";
const ENTRY = findEntry();

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".webp": "image/webp",
  ".ttf": "font/ttf",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".fnt": "application/octet-stream",
  ".txt": "text/plain; charset=utf-8",
  ".wasm": "application/wasm",
};

function findEntry() {
  const direct = ["CyberChef.html"];
  for (const f of direct) {
    if (fs.existsSync(path.join(ROOT, f))) return f;
  }
  const html = fs.readdirSync(ROOT).filter((f) => /\.html?$/i.test(f)).sort();
  return html[0] || null;
}

function send(res, code, body, headers = {}) {
  res.writeHead(code, { "Cache-Control": "no-cache", ...headers });
  res.end(body);
}

function streamFile(file, req, res) {
  const ext = path.extname(file).toLowerCase();
  const type = MIME[ext] || "application/octet-stream";
  const size = fs.statSync(file).size;
  const range = req.headers.range;

  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    if (m) {
      let start = m[1] === "" ? null : parseInt(m[1], 10);
      let end = m[2] === "" ? null : parseInt(m[2], 10);
      if (start === null) {
        start = Math.max(0, size - (end || 0));
        end = size - 1;
      } else if (end === null || end >= size) {
        end = size - 1;
      }
      if (start > end || start >= size) {
        return send(res, 416, "range not satisfiable", { "Content-Range": "bytes */" + size });
      }
      res.writeHead(206, {
        "Content-Type": type,
        "Content-Length": end - start + 1,
        "Content-Range": "bytes " + start + "-" + end + "/" + size,
        "Accept-Ranges": "bytes",
        "Cache-Control": "no-cache",
      });
      return fs.createReadStream(file, { start, end }).pipe(res);
    }
  }

  res.writeHead(200, {
    "Content-Type": type,
    "Content-Length": size,
    "Accept-Ranges": "bytes",
    "Cache-Control": "no-cache",
  });
  fs.createReadStream(file).pipe(res);
}

const server = http.createServer((req, res) => {
  let pathname = "/";
  try {
    pathname = decodeURIComponent(new URL(req.url, "http://" + HOST).pathname);
  } catch (e) {
    return send(res, 400, "bad request", { "Content-Type": "text/plain; charset=utf-8" });
  }
  if (pathname === "/" || pathname === "") {
    if (!ENTRY) return send(res, 500, "找不到 CyberChef.html", { "Content-Type": "text/plain; charset=utf-8" });
    return streamFile(path.join(ROOT, ENTRY), req, res);
  }
  if (pathname === "/favicon.ico") return send(res, 204, "");

  const target = path.resolve(ROOT, "." + pathname);
  const rel = path.relative(ROOT, target);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    return send(res, 403, "forbidden", { "Content-Type": "text/plain; charset=utf-8" });
  }
  fs.stat(target, (err, st) => {
    if (err || !st) return send(res, 404, "404 Not Found: " + pathname, { "Content-Type": "text/plain; charset=utf-8" });
    if (st.isDirectory()) {
      const idx = path.join(target, "index.html");
      if (fs.existsSync(idx)) return streamFile(idx, req, res);
      return send(res, 404, "404 Not Found: " + pathname, { "Content-Type": "text/plain; charset=utf-8" });
    }
    streamFile(target, req, res);
  });
});

function openBrowser(url) {
  if (NO_OPEN) return;
  try {
    const child = spawn("cmd", ["/c", "start", "", url], { detached: true, stdio: "ignore", windowsHide: true });
    child.unref();
  } catch (e) {
    /* 打不开就让用户手动复制地址 */
  }
}

let port = BASE_PORT;
let attempts = 0;
server.on("error", (e) => {
  if (e.code === "EADDRINUSE" && attempts < 20) {
    attempts++;
    port++;
    server.listen(port, HOST);
    return;
  }
  console.error("[错误] 无法启动服务:", e.message);
  process.exit(1);
});

server.on("listening", () => {
  const url = "http://" + HOST + ":" + port + "/" + (ENTRY || "");
  const line = "=".repeat(52);
  console.log("");
  console.log("  " + line);
  console.log("   CyberChef 本地版已启动（v11.5.0）");
  console.log("  " + line);
  console.log("   地址: " + url);
  console.log("   文件: " + ROOT);
  console.log("");
  console.log("   浏览器会自动打开；没打开就手动复制上面地址。");
  console.log("   这个黑窗口不要关——关掉就等于关掉服务。");
  console.log("   停止服务：关掉本窗口，或按 Ctrl+C。");
  console.log("");
  openBrowser(url);
});

server.listen(port, HOST);

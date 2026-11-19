// Tiny Chrome DevTools Protocol driver (no dependencies; uses Node's built-in WebSocket).
const http = require("http");
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

function httpJson(method, port, urlPath) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, path: urlPath, method, headers: { host: "127.0.0.1:" + port } },
      (res) => {
        let b = "";
        res.on("data", (d) => (b += d));
        res.on("end", () => {
          try {
            resolve(b ? JSON.parse(b) : null);
          } catch (e) {
            resolve(b);
          }
        });
      }
    );
    req.on("error", reject);
    req.setTimeout(15000, () => req.destroy(new Error("http timeout")));
    req.end();
  });
}

async function waitPort(port, ms = 20000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    try {
      return await httpJson("GET", port, "/json/version");
    } catch (e) {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error("devtools port never opened on " + port);
}

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.method + " " + JSON.stringify(msg.error)));
        else resolve(msg.result);
      } else if (msg.method) {
        for (const l of this.listeners) l(msg);
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error("CDP timeout: " + method));
        }
      }, 180000);
    });
  }
  on(fn) {
    this.listeners.push(fn);
  }
  close() {
    try { this.ws.close(); } catch (e) {}
  }
}

/**
 * Launch Chrome and open one blank page.
 * @param {{headless?:boolean, port?:number, extraArgs?:string[], profileDir?:string}} opts
 */
async function launch(opts = {}) {
  const port = opts.port || 9333;
  const headless = opts.headless !== false;
  const profileDir = opts.profileDir || fs.mkdtempSync(path.join(os.tmpdir(), "cc-prof-"));
  const args = [
    "--remote-debugging-port=" + port,
    "--remote-allow-origins=*",
    "--user-data-dir=" + profileDir,
    "--no-first-run",
    "--no-default-browser-check",
    "--no-sandbox",
    "--disable-crash-reporter",
    "--disable-breakpad",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-dev-shm-usage",
    "--disable-features=Translate,OptimizationHints",
    "--window-size=1400,900",
    "about:blank",
  ];
  if (headless) args.unshift("--headless=new", "--disable-gpu");
  if (opts.extraArgs) args.unshift(...opts.extraArgs);

  const proc = spawn(CHROME, args, { stdio: "ignore", windowsHide: true });
  const ver = await waitPort(port);

  // open a page target and connect to it directly
  let target;
  try {
    target = await httpJson("PUT", port, "/json/new?about:blank");
  } catch (e) {
    target = await httpJson("GET", port, "/json/new?about:blank");
  }
  if (!target || !target.webSocketDebuggerUrl) {
    const list = await httpJson("GET", port, "/json/list");
    target = (list || []).find((t) => t.type === "page");
  }
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.addEventListener("open", res);
    ws.addEventListener("error", () => rej(new Error("ws error")));
  });
  const cdp = new Cdp(ws);
  cdp.proc = proc;
  cdp.port = port;
  cdp.console = [];
  cdp.exceptions = [];
  cdp.logs = [];
  cdp.on((msg) => {
    if (msg.method === "Runtime.consoleAPICalled") {
      cdp.console.push({
        type: msg.params.type,
        text: (msg.params.args || [])
          .map((a) => (a.value !== undefined ? String(a.value) : a.description || a.type))
          .join(" "),
      });
    } else if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      cdp.exceptions.push({
        text: d.text,
        desc: d.exception ? d.exception.description : "",
        url: d.url,
        line: d.lineNumber,
      });
    } else if (msg.method === "Log.entryAdded") {
      cdp.logs.push({ level: msg.params.entry.level, text: msg.params.entry.text, url: msg.params.entry.url });
    }
  });
  await cdp.send("Runtime.enable");
  await cdp.send("Page.enable");
  await cdp.send("Log.enable");
  return cdp;
}

async function navigate(cdp, url, timeoutMs = 30000) {
  const loaded = new Promise((resolve) => {
    const off = (msg) => {
      if (msg.method === "Page.loadEventFired") resolve(true);
    };
    cdp.on(off);
    setTimeout(() => resolve(false), timeoutMs);
  });
  const nav = await cdp.send("Page.navigate", { url });
  await loaded;
  return nav;
}

/** Evaluate an expression in the page; returns {ok, value, error} and never hangs the harness. */
async function evaluate(cdp, expression, timeoutMs = 60000) {
  const res = await Promise.race([
    cdp.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
      userGesture: true,
    }),
    new Promise((r) => setTimeout(() => r({ timedOut: true }), timeoutMs)),
  ]);
  if (res.timedOut) return { ok: false, error: "EVALUATE_TIMEOUT(" + timeoutMs + "ms)", timedOut: true };
  if (res.exceptionDetails) {
    const d = res.exceptionDetails;
    return { ok: false, error: d.text + " " + (d.exception ? d.exception.description : "") };
  }
  return { ok: true, value: res.result.value };
}

async function screenshot(cdp, outFile) {
  await cdp.send("Emulation.setDeviceMetricsOverride", {
    width: 1400, height: 900, deviceScaleFactor: 1, mobile: false,
  });
  const { data } = await cdp.send("Page.captureScreenshot", { format: "png" });
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, Buffer.from(data, "base64"));
  return outFile;
}

async function close(cdp) {
  try { cdp.close(); } catch (e) {}
  try { cdp.proc.kill(); } catch (e) {}
  await new Promise((r) => setTimeout(r, 600));
}

module.exports = { launch, navigate, evaluate, screenshot, close, httpJson };

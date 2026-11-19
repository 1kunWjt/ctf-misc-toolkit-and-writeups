// Decisive comparison: file:// vs http:// for CyberChef v11.
// Checks worker boot (app.workerLoaded), a raw blob-worker liveness probe, and real operations
// across lazy modules (Crypto / Regex / Charts / Compression).
// Usage: node verify.js <url1> [url2 ...]
const path = require("path");
const fs = require("fs");
const { launch, navigate, evaluate, screenshot, close } = require("./cdp");

const WORKER_PROBE = `(async () => {
  try {
    const u = URL.createObjectURL(new Blob(["self.postMessage('alive')"], {type: "text/javascript"}));
    const w = new Worker(u);
    const r = await new Promise((resolve) => {
      const t = setTimeout(() => resolve("NO MESSAGE in 3s (worker never ran)"), 3000);
      w.onmessage = (e) => { clearTimeout(t); resolve("alive: " + e.data); };
      w.onerror = (e) => { clearTimeout(t); resolve("onerror: " + (e.message || e.type)); };
    });
    w.terminate();
    return {origin: String(location.origin), result: r};
  } catch (e) {
    return {origin: String(location.origin), result: "CTOR THROW " + e.name + ": " + e.message};
  }
})()`;

const READY_EXPR = `(() => {
  const a = window.app;
  if (!a || !a.manager || !a.manager.worker) return {ready:false, stage:"no-app"};
  const pre = document.getElementById("preloader");
  return {
    ready: a.workerLoaded === true,
    workerLoaded: a.workerLoaded === true,
    chefs: (a.manager.worker.chefWorkers || []).length,
    preloaderVisible: pre ? getComputedStyle(pre).display !== "none" : null,
    preloaderError: (document.getElementById("preloader-error") || {}).textContent || null,
    msg: (document.getElementById("preloader-msg") || {}).textContent || null
  };
})()`;

const CASE_EXPR = (input, recipe) => `(() => {
  const a = window.app;
  try {
    a.setInput(${JSON.stringify(input)});
    a.setRecipeConfig(${JSON.stringify(recipe)});
    a.bake();
  } catch (e) { return {callError: String(e && e.message)}; }
  const o = a.manager.output;
  const keys = Object.keys(o.outputs || {});
  const out = {baking: !!a.baking, status: null, len: 0, text: null};
  for (const k of keys) {
    const rec = o.outputs[k];
    if (rec.statusMessage) out.status = rec.statusMessage;
    const d = rec.data;
    let v = null;
    try {
      if (typeof d === "string") v = d;
      else if (d && d.dish && typeof d.dish.value !== "undefined") v = d.dish.value;
      else if (d && typeof d.string !== "undefined") v = d.string;
    } catch (e) {}
    if (typeof v === "string") { out.text = v.slice(0, 100); out.len = v.length; }
  }
  if (!out.len) {
    const el = document.getElementById("output-text");
    if (el) {
      const t = el.value !== undefined ? el.value : el.textContent;
      if (t) { out.text = String(t).slice(0, 100); out.len = String(t).length; }
    }
  }
  return out;
})()`;

const STATE_EXPR = `(() => {
  const a = window.app;
  const o = a.manager.output;
  const keys = Object.keys(o.outputs || {});
  const out = {baking: !!a.baking, status: null, len: 0, text: null};
  for (const k of keys) {
    const rec = o.outputs[k];
    if (rec.statusMessage) out.status = rec.statusMessage;
    const d = rec.data;
    let v = null;
    try {
      if (typeof d === "string") v = d;
      else if (d && d.dish && typeof d.dish.value !== "undefined") v = d.dish.value;
      else if (d && typeof d.string !== "undefined") v = d.string;
    } catch (e) {}
    if (typeof v === "string") { out.text = v.slice(0, 100); out.len = v.length; }
  }
  if (!out.len) {
    const el = document.getElementById("output-text");
    if (el) {
      const t = el.value !== undefined ? el.value : el.textContent;
      if (t) { out.text = String(t).slice(0, 100); out.len = String(t).length; }
    }
  }
  return out;
})()`;

const CASES = [
  { name: "To Base64  [Default]", input: "hello", recipe: [{ op: "To Base64", args: [] }], expect: "aGVsbG8=" },
  { name: "MD5  [Crypto]", input: "hello", recipe: [{ op: "MD5", args: [] }], expect: "5d41402abc4b2a76b9719d911017c592" },
  { name: "Regular expression  [Regex]", input: "abc123def456", recipe: [{ op: "Regular expression", args: ["[0-9]+", "g", false, true, false, false, false] }], expect: "123" },
  { name: "Entropy  [Charts]", input: "aaaaaaaaaaaaaaaaaaaa", recipe: [{ op: "Entropy", args: ["Shannon", 5] }], expect: "" },
  { name: "Zlib Deflate+To Hex  [Compression]", input: "hello hello hello", recipe: [{ op: "Zlib Deflate", args: [9] }, { op: "To Hex", args: ["Space"] }], expect: "" },
  { name: "Magic  [Default]", input: "aGVsbG8=", recipe: [{ op: "Magic", args: [3, false, false, ""] }], expect: "hello" },
];

const READY_TIMEOUT = 25000;
const BAKE_TIMEOUT = 15000;

async function pollReady(cdp) {
  const t0 = Date.now();
  let last = null;
  while (Date.now() - t0 < READY_TIMEOUT) {
    const r = await evaluate(cdp, READY_EXPR, 12000);
    if (r.timedOut) return { ready: false, hang: true, last };
    last = r.value;
    if (last && last.ready) return { ready: true, detail: last, ms: Date.now() - t0 };
    await new Promise((res) => setTimeout(res, 500));
  }
  return { ready: false, timeout: true, detail: last, ms: Date.now() - t0 };
}

async function runUrl(url, idx) {
  const res = { url, workerProbe: null, boot: null, cases: [] };
  const cdp = await launch({ port: 9400 + idx });
  try {
    await navigate(cdp, url, 45000);
    await new Promise((r) => setTimeout(r, 2500));

    const wp = await evaluate(cdp, WORKER_PROBE, 20000);
    res.workerProbe = wp.ok ? wp.value : { error: wp.error };

    const boot = await pollReady(cdp);
    res.boot = boot.ready
      ? { ready: true, ms: boot.ms, detail: boot.detail }
      : { ready: false, hang: !!boot.hang, timeout: !!boot.timeout, detail: boot.detail };

    if (!boot.ready) {
      // Workers never came up: every bake will spin forever. Record one demonstration attempt.
      const demo = await evaluate(cdp, CASE_EXPR("hello", [{ op: "To Base64", args: [] }]), 15000);
      await new Promise((r) => setTimeout(r, 6000));
      const after = await evaluate(cdp, READY_EXPR + " && null", 8000).catch(() => null);
      const st = await evaluate(cdp, `(() => {
        const a = window.app;
        const o = a && a.manager ? a.manager.output : null;
        const k = o && o.outputs ? Object.keys(o.outputs) : [];
        return {baking: a ? !!a.baking : null, outputs: k.length,
                status: k.length ? (o.outputs[k[0]].statusMessage || null) : null};
      })()`, 10000);
      res.cases.push({
        case: "To Base64 (after 6s wait)",
        verdict: st.ok && st.value && st.value.baking ? "HANG_FOREVER" : "NO_OUTPUT",
        state: st.ok ? st.value : null,
        demo: demo.ok ? demo.value : demo.error,
      });
      res.spinnerScreenshot = await screenshot(cdp, path.resolve(__dirname, "..", ".reports", "file-hang.png")).catch((e) => "failed");
      res.exceptions = cdp.exceptions.map((e) => (e.text + " | " + (e.desc || "")).slice(0, 300));
      return res;
    }

    for (const c of CASES) {
      const t0 = Date.now();
      const kick = await evaluate(cdp, CASE_EXPR(c.input, c.recipe), 15000);
      if (!kick.ok || (kick.value && kick.value.callError)) {
        res.cases.push({ case: c.name, verdict: "CALL_FAILED", error: (kick.value && kick.value.callError) || kick.error });
        continue;
      }
      let final = null;
      while (Date.now() - t0 < BAKE_TIMEOUT) {
        const st = await evaluate(cdp, STATE_EXPR, 12000);
        final = st.ok ? st.value : final;
        if (final && final.baking === false && final.len > 0) break;
        await new Promise((r) => setTimeout(r, 350));
      }
      const ms = Date.now() - t0;
      const text = (final && final.text) || "";
      let verdict = "OK";
      if (final && final.baking) verdict = "HANG";
      else if (!final || final.len === 0) verdict = c.expect ? "EMPTY_OUTPUT" : "EMPTY_OUTPUT";
      else if (c.expect && !text.includes(c.expect)) verdict = "WRONG_OUTPUT";
      res.cases.push({ case: c.name, verdict, ms, output: text.slice(0, 80), status: final && final.status });
    }
    res.exceptions = cdp.exceptions.map((e) => (e.text + " | " + (e.desc || "")).slice(0, 300));
    res.consoleErrors = cdp.console.filter((c) => c.type === "error").map((c) => c.text.slice(0, 250)).slice(0, 10);
  } catch (e) {
    res.error = e.message;
  } finally {
    await close(cdp);
  }
  return res;
}

(async () => {
  const urls = process.argv.slice(2);
  if (!urls.length) {
    console.error("usage: node verify.js <url> [url...]");
    process.exit(2);
  }
  fs.mkdirSync(path.resolve(__dirname, "..", ".reports"), { recursive: true });
  const all = [];
  for (let i = 0; i < urls.length; i++) {
    console.log("\n########## " + urls[i]);
    const r = await runUrl(urls[i], i);
    all.push(r);
    console.log("  worker probe :", JSON.stringify(r.workerProbe));
    console.log("  boot         :", JSON.stringify(r.boot));
    for (const c of r.cases) {
      console.log(
        "  " + String(c.verdict).padEnd(13) + String(c.ms || "-").padStart(6) + "ms  " + c.case.padEnd(36) +
        (c.status ? "  status:" + c.status : "") + (c.output ? "  out:" + c.output.replace(/\n/g, "\\n").slice(0, 32) : "")
      );
    }
    if (r.exceptions && r.exceptions.length) console.log("  exceptions:", JSON.stringify(r.exceptions.slice(0, 5)));
    if (r.error) console.log("  ERROR:", r.error);
  }
  const out = path.resolve(__dirname, "..", ".reports", "verify.json");
  fs.writeFileSync(out, JSON.stringify(all, null, 2));
  console.log("\nwritten: " + out);
  process.exit(0);
})();

// Final acceptance test: every major lazy-loaded module must work over the local server.
// Usage: node accept.js <url>
const path = require("path");
const fs = require("fs");
const { launch, navigate, evaluate, screenshot, close } = require("./cdp");

const READY_EXPR = `(() => {
  const a = window.app;
  if (!a || !a.manager || !a.manager.worker) return {ready:false};
  return {ready: a.workerLoaded === true, chefs: (a.manager.worker.chefWorkers || []).length};
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
    if (typeof v === "string") { out.text = v.slice(0, 200); out.len = v.length; }
  }
  if (!out.len) {
    const el = document.getElementById("output-text");
    if (el) {
      const t = el.value !== undefined ? el.value : el.textContent;
      if (t) { out.text = String(t).slice(0, 200); out.len = String(t).length; }
    }
  }
  return out;
})()`;

const BIG = "A".repeat(1024 * 1024);

const CASES = [
  { mod: "Default",     name: "From Base64",            input: "aGVsbG8=",  recipe: [{ op: "From Base64", args: [] }], expect: "hello" },
  { mod: "Default",     name: "To Base64 (1MB input)",  input: BIG,         recipe: [{ op: "To Base64", args: [] }], expect: "QUFB", maxMs: 12000 },
  { mod: "Crypto",      name: "MD5",                    input: "hello",     recipe: [{ op: "MD5", args: [] }], expect: "5d41402abc4b2a76b9719d911017c592" },
  { mod: "Crypto",      name: "SHA2 (default 512)",      input: "hello",     recipe: [{ op: "SHA2", args: [] }], expect: "9b71d224bd62f378" },
  { mod: "Crypto",      name: "JWT Decode",             input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", recipe: [{ op: "JWT Decode", args: [] }], expect: "John Doe" },
  { mod: "Code",        name: "JSON Beautify",          input: '{"a":1,"b":[2,3]}', recipe: [{ op: "JSON Beautify", args: [] }], expect: '"a": 1' },
  { mod: "Regex",       name: "Regular expression",     input: "abc123def456", recipe: [{ op: "Regular expression", args: ["[0-9]+", "g", false, true, false, false, false] }], expect: "123" },
  { mod: "Charts",      name: "Entropy",                input: "aaaaaaaaaaaaaaaaaaaa", recipe: [{ op: "Entropy", args: [] }], expect: "" },
  { mod: "Compression", name: "Gzip -> To Hex",         input: "hello hello hello", recipe: [{ op: "Gzip", args: [] }, { op: "To Hex", args: ["Space"] }], expect: "1f 8b" },
  { mod: "Default",     name: "Magic on base64",        input: "aGVsbG8=",  recipe: [{ op: "Magic", args: [] }], expect: "Recipe" },
];

const READY_TIMEOUT = 30000;
const BAKE_TIMEOUT = 20000;

async function pollReady(cdp) {
  const t0 = Date.now();
  while (Date.now() - t0 < READY_TIMEOUT) {
    const r = await evaluate(cdp, READY_EXPR, 10000);
    if (r.ok && r.value && r.value.ready) return { ready: true, ms: Date.now() - t0, detail: r.value };
    await new Promise((res) => setTimeout(res, 400));
  }
  return { ready: false };
}

(async () => {
  const url = process.argv[2];
  if (!url) {
    console.error("usage: node accept.js <url>");
    process.exit(2);
  }
  fs.mkdirSync(path.resolve(__dirname, "..", ".reports"), { recursive: true });
  const report = { url, startedAt: new Date().toISOString(), boot: null, cases: [], exceptions: [], pass: 0, fail: 0 };

  const cdp = await launch({ port: 9420 });
  try {
    await navigate(cdp, url, 45000);
    await new Promise((r) => setTimeout(r, 2000));
    report.boot = await pollReady(cdp);
    console.log("boot:", JSON.stringify(report.boot));

    for (const c of CASES) {
      const t0 = Date.now();
      const kick = await evaluate(
        cdp,
        `(() => {
          const a = window.app;
          try {
            a.setInput(${JSON.stringify(c.input)});
            a.setRecipeConfig(${JSON.stringify(c.recipe)});
            a.bake();
            return {ok: true};
          } catch (e) { return {ok: false, err: String(e && e.message)}; }
        })()`,
        20000
      );
      if (!kick.ok) {
        report.cases.push({ ...c, verdict: "CALL_FAILED", error: kick.error });
        report.fail++;
        continue;
      }
      let final = null;
      const limit = c.maxMs ? c.maxMs + 8000 : BAKE_TIMEOUT;
      while (Date.now() - t0 < limit) {
        const st = await evaluate(cdp, STATE_EXPR, 12000);
        final = st.ok ? st.value : final;
        if (final && final.baking === false && final.len > 0) break;
        await new Promise((res) => setTimeout(res, 300));
      }
      const ms = Date.now() - t0;
      const text = (final && final.text) || "";
      let verdict = "OK";
      if (final && final.baking) verdict = "HANG";
      else if (!final || final.len === 0) verdict = "EMPTY";
      else if (c.expect && !text.includes(c.expect)) verdict = "MISMATCH";
      if (c.maxMs && ms > c.maxMs) verdict = "SLOW";
      if (verdict === "OK") report.pass++;
      else report.fail++;
      report.cases.push({ mod: c.mod, name: c.name, verdict, ms, output: text.slice(0, 120), status: final && final.status });
      console.log(
        "  " + verdict.padEnd(6) + String(ms).padStart(6) + "ms  [" + c.mod.padEnd(11) + "] " + c.name.padEnd(22) +
        (verdict === "OK" ? "" : "  out:" + text.replace(/\n/g, "\\n").slice(0, 50)) +
        (verdict === "OK" && text ? "  -> " + text.replace(/\n/g, "\\n").slice(0, 40) : "")
      );
    }

    report.exceptions = cdp.exceptions.map((e) => (e.text + " | " + (e.desc || "")).slice(0, 300));
    report.consoleErrors = cdp.console.filter((c) => c.type === "error").map((c) => c.text.slice(0, 200)).slice(0, 10);
    report.screenshot = await screenshot(cdp, path.resolve(__dirname, "..", ".reports", "accept.png")).catch((e) => "failed: " + e.message);
  } catch (e) {
    report.error = e.message;
  } finally {
    await close(cdp);
  }

  report.finishedAt = new Date().toISOString();
  const out = path.resolve(__dirname, "..", ".reports", "accept.json");
  fs.writeFileSync(out, JSON.stringify(report, null, 2));
  console.log("\nPASS " + report.pass + " / FAIL " + report.fail + "   -> " + out);
  if (report.exceptions.length) console.log("exceptions:", JSON.stringify(report.exceptions.slice(0, 4)));
  process.exit(report.fail === 0 && report.boot && report.boot.ready ? 0 : 1);
})();

// Widgets for the "How CHIP works" explainer below the demo. Each step-through widget is a
// function of the step number (the same pattern as the Sagittal MSM page). Hashing uses the
// browser's SHA-256 through chain.js, so the widgets respond instantly while Pyodide loads.

import {
  EXAMPLE, b64, chipChain, concat, fromHex, lowBits, sha256, toHex, utf8, xor,
} from "./chain.js";

const SVG = "http://www.w3.org/2000/svg";
const $ = (id) => document.getElementById(id);
const fmt = (n) => Math.round(n).toLocaleString("en-US");
const pct = (x, digits = 1) => `${(100 * x).toFixed(digits)}%`;
const sum = (xs) => xs.reduce((a, b) => a + b, 0);
const mean = (xs) => sum(xs) / xs.length;
const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
const bin = (value, width) => value.toString(2).padStart(width, "0");
const hl = (x, color = "var(--accent)") => `<b style="color:${color}">${x}</b>`;
const hit = (x) => hl(x, "var(--hit)");
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

// ---------------------------------------------------------------------------------------------
// Helpers

function el(tag, attrs = {}, parent = null, text = null) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== null) node.textContent = text;
  if (parent) parent.appendChild(node);
  return node;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function txt(parent, x, y, text, attrs = {}) {
  return el("text", { x, y, "font-size": 13, fill: "var(--text)", ...attrs }, parent, text);
}

/** Reset / Prev / Play / Next controls for a widget. `render(step)` draws the step and returns
 * the caption (HTML). `count()` returns the number of steps, so widgets can change length. */
function stepper(root, count, render, { interval = 900 } = {}) {
  const controls = root.querySelector("[data-controls]");
  const caption = root.querySelector("[data-caption]");
  const make = (label, cls = "") => {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    if (cls) b.className = cls;
    controls.appendChild(b);
    return b;
  };
  const reset = make("Reset"), prev = make("Prev"), play = make("Play", "primary"), next = make("Next");
  const counter = document.createElement("span");
  counter.className = "step-count";
  controls.appendChild(counter);

  let step = 0, timer = null;
  const stop = () => { clearInterval(timer); timer = null; play.textContent = "Play"; };
  const show = () => {
    const n = count();
    step = Math.max(0, Math.min(step, n - 1));
    caption.innerHTML = render(step);
    counter.textContent = `Step ${step + 1} of ${n}`;
    prev.disabled = step === 0;
    next.disabled = step === n - 1;
  };
  reset.onclick = () => { stop(); step = 0; show(); };
  prev.onclick = () => { stop(); step -= 1; show(); };
  next.onclick = () => { stop(); step += 1; show(); };
  play.onclick = () => {
    if (timer) return stop();
    if (step >= count() - 1) step = 0;
    play.textContent = "Pause";
    show();
    timer = setInterval(() => {
      if (step >= count() - 1) return stop();
      step += 1;
      show();
    }, reducedMotion ? interval * 2 : interval);
  };
  show();
  return { refresh: show, restart: () => { stop(); step = 0; show(); } };
}

async function loadCsv(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`could not load ${path}`);
  const [header, ...rows] = (await response.text()).trim().split("\n");
  return { header: header.split(","), rows: rows.map((r) => r.split(",").map(Number)) };
}

/** Pick a random element of `xs`. */
const pick = (xs) => xs[Math.floor(Math.random() * xs.length)];

// ---------------------------------------------------------------------------------------------
// 1. Same password, different salts

function saltDemo() {
  const root = $("w-salt");
  const input = root.querySelector("[data-password]");
  const rows = root.querySelector("[data-view]");
  let salts = [randomBytes(16), randomBytes(16)];

  async function draw() {
    const pw = utf8(input.value);
    const plain = toHex(await sha256(pw));
    const salted = await Promise.all(salts.map(async (s) => toHex(await sha256(concat(s, pw)))));
    const row = (who, salt, digest, same) => `
      <div class="hash-row">
        <div class="who">${who}</div>
        <div class="mono small">${salt ? `salt <span class="muted">${toHex(salt)}</span>` : `<span class="muted">no salt</span>`}</div>
        <div class="mono digest ${same ? "same" : ""}">${digest}</div>
      </div>`;
    rows.innerHTML =
      `<div class="hash-group"><div class="group-title">Unsalted: SHA-256(password)</div>` +
      row("Alice", null, plain, true) + row("Bob", null, plain, true) + `</div>` +
      `<div class="hash-group"><div class="group-title">Salted: SHA-256(salt ‖ password)</div>` +
      row("Alice", salts[0], salted[0], false) + row("Bob", salts[1], salted[1], false) + `</div>`;
  }
  input.addEventListener("input", draw);
  root.querySelector("[data-new]").onclick = () => { salts = [randomBytes(16), randomBytes(16)]; draw(); };
  draw();
}

// ---------------------------------------------------------------------------------------------
// 2 and 9. Lockstep threads: a warp of 32 guesses that must run together

/** A warp of 32 guesses. The section 2 copy has no controls and always waits for the slowest
 * guess; the section 9 copy adds the attacker's counter-moves. */
function lockstep(lengths, id) {
  const root = $(id);
  const svg = root.querySelector("[data-view]");
  const caption = root.querySelector("[data-caption]");
  const mode = root.querySelector("[data-mode]");
  const abandon = root.querySelector("[data-abandon]");
  const dropping = () => abandon?.checked ?? false;
  const LANES = 32, BOUND = 250_000, WINDOW = 1_000_000, W = 640, X0 = 30, LANE = 9;
  let draws = [];

  const shuffle = () => { draws = Array.from({ length: LANES * 40 }, () => pick(lengths)); };

  /** Run the lanes for WINDOW iterations of time; draw the bars if `paint`. */
  function simulate(refill, paint) {
    const cap = (t) => (dropping() ? Math.min(t, BOUND) : t);
    const sx = (t) => X0 + (Math.min(t, WINDOW) / WINDOW) * (W - X0 - 10);
    let finished = 0, busy = 0, q = 0;
    const bar = (lane, t, len, k, gaveUp) => {
      if (!paint) return;
      el("rect", { x: sx(t), y: 8 + lane * LANE, width: Math.max(0.5, sx(t + len) - sx(t) - 0.6),
                   height: LANE - 2, rx: 1.5,
                   fill: gaveUp ? "var(--bad)" : k % 2 ? "var(--accent-2)" : "var(--accent)",
                   "fill-opacity": gaveUp ? 0.55 : 0.85 }, svg);
    };
    if (refill) {
      // Each lane starts its next guess as soon as the last one ends.
      for (let lane = 0; lane < LANES; lane++) {
        for (let t = 0, k = 0; t < WINDOW; k++) {
          const next = draws[q++ % draws.length], len = cap(next);
          bar(lane, t, len, k, dropping() && next > BOUND);
          busy += Math.min(len, WINDOW - t);
          if (t + len <= WINDOW) finished++;
          t += len;
        }
      }
    } else {
      // A whole warp starts together and ends when its slowest guess ends.
      for (let t = 0, k = 0; t < WINDOW; k++) {
        const warp = draws.slice(q, q + LANES).map((n) => [n, cap(n)]);
        q = (q + LANES) % (draws.length - LANES);
        const end = t + Math.max(...warp.map(([, len]) => len));
        warp.forEach(([n, len], lane) => {
          bar(lane, t, len, k, dropping() && n > BOUND);
          busy += Math.max(0, Math.min(len, WINDOW - t));
        });
        if (end <= WINDOW) finished += LANES;
        if (paint && end < WINDOW) el("line", { x1: sx(end), x2: sx(end), y1: 4, y2: 8 + LANES * LANE,
                                                stroke: "var(--text-2)", "stroke-dasharray": "3 3" }, svg);
        t = end;
      }
    }
    return { finished, used: busy / (LANES * WINDOW) };
  }

  function draw() {
    clear(svg);
    for (let lane = 0; lane < LANES; lane++) {
      el("rect", { x: X0, y: 8 + lane * LANE, width: W - X0 - 10, height: LANE - 2, fill: "var(--track)", rx: 1.5 }, svg);
    }
    const refill = mode?.value === "refill";
    const { finished, used } = simulate(refill, true);
    txt(svg, X0 - 6, 8 + LANE * LANES / 2, "32 lanes", { "text-anchor": "middle", "font-size": 11,
        fill: "var(--text-2)", transform: `rotate(-90 ${X0 - 12} ${8 + LANE * LANES / 2})` });
    const axisY = 8 + LANES * LANE + 14;
    txt(svg, X0, axisY, "0", { "font-size": 11, fill: "var(--muted)" });
    txt(svg, W - 10, axisY, `${fmt(WINDOW)} iterations of time`, { "font-size": 11, fill: "var(--muted)", "text-anchor": "end" });

    const dropped = dropping() ? ` Red guesses passed the upper bound, so they can't be the right password and are cut short.` : "";
    if (refill) {
      const waiting = simulate(false, false).finished;
      caption.innerHTML =
        `Each lane starts a new guess as soon as its last one ends. The lanes hash ${hl(pct(used, 0))} ` +
        `of the time and finish ${hl(finished)} guesses, against ${waiting} when every group waits for ` +
        `its slowest guess (${(finished / waiting).toFixed(1)}×).` + dropped;
    } else {
      caption.innerHTML =
        `Each group of 32 guesses starts together and ends with its slowest guess (dashed lines). The ` +
        `lanes hash only ${hl(pct(used, 0))} of the time; the grey is waiting. ${hl(finished)} guesses ` +
        `finished.` + dropped;
    }
  }
  if (mode) mode.onchange = draw;
  if (abandon) abandon.onchange = draw;
  root.querySelector("[data-new]").onclick = () => { shuffle(); draw(); };
  shuffle();
  draw();
}

// ---------------------------------------------------------------------------------------------
// 3. Look at the low bits

function lowBitsDemo() {
  const root = $("w-lowbits");
  const input = root.querySelector("[data-text]");
  const slider = root.querySelector("[data-bits]");
  const out = root.querySelector("[data-bits-out]");
  const view = root.querySelector("[data-view]");

  async function draw() {
    const b = +slider.value;
    out.textContent = b;
    const digest = await sha256(utf8(input.value));
    const hex = toHex(digest);
    const last32 = bin(lowBits(digest, 32), 32);
    const bits = [...last32].map((c, i) => (i >= 32 - b ? `<span class="lowbit">${c}</span>` : c));
    const grouped = [0, 1, 2, 3].map((g) => bits.slice(g * 8, g * 8 + 8).join("")).join(" ");
    const key = lowBits(digest, b);
    view.innerHTML = `
      <div class="kv"><span class="k">SHA-256, 64 hex digits (256 bits)</span>
        <span class="mono digest">${hex.slice(0, -8)}<span class="lowhex">${hex.slice(-8)}</span></span></div>
      <div class="kv"><span class="k">Last 32 bits (the highlighted hex digits) in binary</span>
        <span class="mono bits">${grouped}</span></div>
      <div class="kv"><span class="k">Low ${b} bits as a number</span>
        <span class="mono">${fmt(key)} <span class="muted">of 2${sup(b)} = ${fmt(2 ** b)} possible values</span></span></div>`;
  }
  input.addEventListener("input", draw);
  slider.addEventListener("input", draw);
  draw();
}

const sup = (n) => String(n).split("").map((d) => "⁰¹²³⁴⁵⁶⁷⁸⁹"[d]).join("");

// ---------------------------------------------------------------------------------------------
// 4. The birthday paradox: random values into 2^b boxes

function birthday() {
  const root = $("w-birthday");
  const svg = root.querySelector("[data-view]");
  const select = root.querySelector("[data-bits]");
  const hist = root.querySelector("[data-hist]");
  const histCaption = root.querySelector("[data-hist-caption]");
  const COLLISIONS = 3;
  let draws = [];

  const N = () => 2 ** +select.value;
  const newDraws = () => {
    draws = [];
    const seen = new Set();
    let hits = 0;
    while (hits < COLLISIONS) {
      const v = Math.floor(Math.random() * N());
      draws.push(v);
      if (seen.has(v)) hits++;
      seen.add(v);
    }
  };

  function render(s) {
    clear(svg);
    const n = N(), cols = Math.sqrt(n) >= 8 ? 16 : 8, rows = Math.ceil(n / cols);
    const C = 640 / 16, size = Math.min(C, 30);
    const width = cols * size;
    svg.setAttribute("viewBox", `0 0 ${Math.max(width, 200)} ${rows * size + 4}`);
    const firstAt = new Map();
    let collisions = 0, lastHit = null;
    for (let k = 0; k < s; k++) {
      const v = draws[k];
      if (firstAt.has(v)) { collisions++; lastHit = v; } else firstAt.set(v, k + 1);
    }
    const current = s > 0 ? draws[s - 1] : null;
    const isHit = s > 0 && draws.indexOf(current) < s - 1;
    for (let v = 0; v < n; v++) {
      const x = (v % cols) * size, y = Math.floor(v / cols) * size;
      const filled = firstAt.has(v);
      el("rect", { x: x + 1.5, y: y + 1.5, width: size - 3, height: size - 3, rx: 3,
                   fill: v === current && isHit ? "var(--hit)" : filled ? "var(--accent)" : "var(--track)",
                   "fill-opacity": v === current ? 1 : filled ? 0.45 : 1,
                   stroke: v === current ? "var(--text)" : "none", "stroke-width": 1.5 }, svg);
    }
    if (s === 0) {
      return `${fmt(n)} boxes, one for each ${select.value}-bit value. Each step draws a random ` +
        `value and fills its box. Press Play.`;
    }
    const where = isHit
      ? `${hit("already filled")} at draw ${draws.indexOf(current) + 1}: collision ${collisions}`
      : `a new box`;
    const done = s === draws.length
      ? ` ${hl(COLLISIONS)} collisions after ${hl(s)} draws.`
      : "";
    return `Draw ${hl(s)}: value ${current} (${bin(current, +select.value)}) lands in ${where}. ` +
      `${firstAt.size} of ${fmt(n)} boxes filled (${pct(firstAt.size / n, 0)}).${done}`;
  }

  const step = stepper(root, () => draws.length + 1, render, { interval: 450 });
  root.querySelector("[data-new]").onclick = () => { newDraws(); step.restart(); };
  select.onchange = () => { newDraws(); step.restart(); hist.replaceChildren(); histCaption.textContent = ""; };

  // Many trials: when does the first collision arrive?
  root.querySelector("[data-trials]").onclick = () => {
    const n = N(), TRIALS = 1000;
    const firsts = Array.from({ length: TRIALS }, () => {
      const seen = new Set();
      for (let k = 1; ; k++) {
        const v = Math.floor(Math.random() * n);
        if (seen.has(v)) return k;
        seen.add(v);
      }
    });
    const W = 640, H = 170, X0 = 30, Y0 = 140;
    const top = Math.max(...firsts);
    const bins = 30, width = Math.ceil(top / bins);
    const counts = Array(bins).fill(0);
    for (const f of firsts) counts[Math.min(bins - 1, Math.floor((f - 1) / width))]++;
    const peak = Math.max(...counts);
    const sx = (k) => X0 + (k / (bins * width)) * (W - X0 - 10);
    clear(hist);
    hist.setAttribute("viewBox", `0 0 ${W} ${H}`);
    counts.forEach((c, i) => el("rect", { x: sx(i * width) + 1, y: Y0 - (c / peak) * 120,
      width: sx(width) - X0 - 2, height: (c / peak) * 120, fill: "var(--accent)", "fill-opacity": 0.6 }, hist));
    const theory = Math.sqrt((Math.PI / 2) * n), measured = mean(firsts);
    el("line", { x1: sx(theory), x2: sx(theory), y1: 10, y2: Y0, stroke: "var(--hit)", "stroke-width": 2 }, hist);
    txt(hist, sx(theory) + 5, 22, `√(π/2 · ${fmt(n)}) ≈ ${theory.toFixed(1)}`, { fill: "var(--hit)", "font-size": 12 });
    el("line", { x1: X0, x2: W - 10, y1: Y0, y2: Y0, stroke: "var(--muted)" }, hist);
    txt(hist, X0, Y0 + 18, "1", { "font-size": 11, fill: "var(--muted)" });
    txt(hist, W - 10, Y0 + 18, `${fmt(bins * width)} draws`, { "font-size": 11, fill: "var(--muted)", "text-anchor": "end" });
    histCaption.innerHTML = `${fmt(TRIALS)} trials. The first collision came after ${hl(measured.toFixed(1))} ` +
      `draws on average; the formula predicts ${hit(theory.toFixed(1))} (it runs a little low ` +
      `when there are only a few boxes). With ${fmt(n)} boxes, that ` +
      `is only ${pct(theory / n, 0)} of them filled.`;
  };

  newDraws();
  step.refresh();
}

// ---------------------------------------------------------------------------------------------
// 5. The CHIP chain, step by step

function chainDemo(stats) {
  const root = $("w-chain");
  const view = root.querySelector("[data-view]");
  const grid = root.querySelector("[data-grid]");
  const pwInput = root.querySelector("[data-password]");
  const bitsSel = root.querySelector("[data-bits]");
  const cSel = root.querySelector("[data-c]");
  const saltOut = root.querySelector("[data-salt]");
  let salt = fromHex(EXAMPLE.salt);
  let chain = null, maxIter = 0, token = 0;

  const short = (bytes, n = 16) => `${toHex(bytes).slice(0, n)}…`;
  const D = (i) => `D<sub>${i}</sub>`;

  function suggestedMax(b, c) {
    const s = stats.get(`${b},${c}`);
    return s ? Math.ceil((s.mean + s.std) / 10) * 10 : 1000;
  }

  async function rebuild() {
    const mine = ++token;
    const b = +bitsSel.value, c = +cSel.value;
    maxIter = suggestedMax(b, c);
    saltOut.textContent = toHex(salt);
    const result = await chipChain(concat(salt, utf8(pwInput.value)), b, c, maxIter);
    if (mine !== token) return; // a newer input arrived while hashing
    chain = result;
    step.restart();
  }

  function drawGrid(s) {
    clear(grid);
    const b = +bitsSel.value, n = 2 ** b, cols = 2 ** Math.ceil(b / 2), size = 30;
    const rows = n / cols;
    grid.setAttribute("viewBox", `0 0 ${cols * size} ${rows * size}`);
    const steps = chain.steps.slice(0, Math.min(s, chain.steps.length));
    const firstAt = new Map();
    for (const st of steps) if (!st.earlier) firstAt.set(st.key, st.i);
    const cur = s >= 1 && s <= chain.steps.length ? chain.steps[s - 1] : null;
    for (let v = 0; v < n; v++) {
      const x = (v % cols) * size, y = Math.floor(v / cols) * size;
      const filled = firstAt.has(v);
      const isCur = cur && cur.key === v;
      el("rect", { x: x + 1.5, y: y + 1.5, width: size - 3, height: size - 3, rx: 3,
                   fill: isCur && cur.earlier ? "var(--hit)" : filled ? "var(--accent)" : "var(--track)",
                   "fill-opacity": isCur ? 1 : filled ? 0.4 : 1,
                   stroke: isCur ? "var(--text)" : "none", "stroke-width": 1.5 }, grid);
      if (filled) txt(grid, x + size / 2, y + size / 2 + 4, String(firstAt.get(v)),
                      { "text-anchor": "middle", "font-size": 10.5, fill: "var(--text)" });
    }
  }

  function render(s) {
    if (!chain) return "Hashing…";
    drawGrid(s);
    const b = +bitsSel.value, c = +cSel.value, T = chain.steps.length;
    const accepted = chain.collisionIterations.length === c;
    const rows = chain.steps.slice(Math.max(0, Math.min(s, T) - 6), Math.min(s, T)).map((st) => `
      <tr class="${st.earlier ? "is-hit" : ""} ${st.i === s ? "is-current" : ""}">
        <td>${st.i}</td><td class="mono">${short(st.digest, 12)}</td>
        <td class="mono">${bin(st.key, b)}</td>
        <td>${st.earlier ? `collision with ${D(st.earlier.i)}` : "new: remember it"}</td>
      </tr>`).join("");
    const table = `<table class="chain-table"><tr><th>i</th><th>D<sub>i</sub></th><th>low ${b} bits</th><th></th></tr>${rows}</table>`;

    if (s === 0) {
      view.innerHTML = `<div class="kv"><span class="k">h = salt ‖ password</span>
        <span class="mono digest">${toHex(salt)} <span class="muted">‖</span> ${toHex(utf8(pwInput.value))}</span></div>`;
      return `Start: the 16-byte salt followed by the password's bytes. The grid has ` +
        `one box for each of the ${2 ** b} possible ${b}-bit values. Goal: ${hl(c)} collision${c > 1 ? "s" : ""}, ` +
        `within ${fmt(maxIter)} iterations (the suggested upper bound for b = ${b}, C = ${c}).`;
    }
    if (s <= T) {
      const st = chain.steps[s - 1];
      const n = chain.collisionIterations.indexOf(st.i) + 1;
      const from = st.i === 1 ? "salt ‖ password" : chain.steps[st.i - 2].earlier ? "the perturbed value" : D(st.i - 1);
      let detail = table;
      if (st.earlier) {
        detail += `<div class="xor mono">
          <div><span class="lbl">${D(st.i)}</span>${short(st.digest, 32)}</div>
          <div><span class="lbl">${D(st.earlier.i)}</span>${short(st.earlier.digest, 32)}</div>
          <div class="rule"><span class="lbl">XOR</span>${short(st.next, 32)}</div></div>`;
      }
      view.innerHTML = detail;
      if (!st.earlier) {
        return `Iteration ${hl(st.i)}: ${D(st.i)} = SHA-256(${from}). Its low ${b} bits are ` +
          `${hl(bin(st.key, b))} = ${st.key}, not seen before, so CHIP stores the full digest in box ${st.key}.`;
      }
      return `Iteration ${hit(st.i)}: ${D(st.i)} ends in ${hit(bin(st.key, b))} = ${st.key}, the same as ` +
        `${D(st.earlier.i)}. ${hit(`Collision ${n} of ${c}`)}. CHIP looks up the full ${D(st.earlier.i)} ` +
        `and sets h = ${D(st.i)} XOR ${D(st.earlier.i)}; the next iteration hashes that instead.`;
    }
    view.innerHTML = table + `<div class="kv"><span class="k">Final hash = SHA-256(h)</span>
      <span class="mono digest">${toHex(chain.digest)}</span></div>` +
      (accepted ? `<div class="kv"><span class="k">Stored string</span><span class="mono digest">` +
        `$chip$h=sha256,b=${b},c=${c},min=0,max=${maxIter}$${b64(salt)}$${b64(chain.digest)}</span></div>` : "");
    return accepted
      ? `${hl(`Done after ${T} iterations`)}, collisions at ${chain.collisionIterations.join(", ")}. CHIP ` +
        `hashes once more so the last XOR affects the output. This string is what ${hl("verify")} ` +
        `needs: it reruns the same chain from the stored salt.`
      : `${hit(`Rejected`)}: only ${chain.collisionIterations.length} of ${c} collisions within ` +
        `${fmt(maxIter)} iterations. Real CHIP would draw a new salt and start over. Press New salt.`;
  }

  const step = stepper(root, () => (chain ? chain.steps.length + 2 : 1), render, { interval: 700 });
  for (const input of [pwInput, bitsSel, cSel]) input.addEventListener("input", rebuild);
  root.querySelector("[data-new]").onclick = () => { salt = randomBytes(16); rebuild(); };
  root.querySelector("[data-example]").onclick = () => {
    salt = fromHex(EXAMPLE.salt);
    pwInput.value = EXAMPLE.password;
    bitsSel.value = EXAMPLE.bits;
    cSel.value = EXAMPLE.collisions;
    rebuild();
  };
  rebuild();

  // Check this JavaScript against the Python library's result for the example chain.
  chipChain(concat(fromHex(EXAMPLE.salt), utf8(EXAMPLE.password)), EXAMPLE.bits, EXAMPLE.collisions)
    .then((r) => {
      const ok = toHex(r.digest) === EXAMPLE.digest &&
        r.collisionIterations.join() === EXAMPLE.collisionIterations.join();
      if (!ok) console.error("chain.js disagrees with the Python library on EXAMPLE");
    });
}

// ---------------------------------------------------------------------------------------------
// 6. Pick a perturbation

function perturbation() {
  const root = $("w-perturb");
  const view = root.querySelector("[data-view]");
  const ITER = 200_000;
  const VARIANTS = {
    none: {
      does: "Nothing. The chain is H, H, H, … whatever the collisions are; they only decide where it stops.",
      keeps: "Nothing. Compute D<sub>1</sub>, D<sub>2</sub>, … and compare SHA-256(D<sub>i</sub>) with the stored hash after every step. " +
        "Stop at the upper bound in the hash string.",
      bytes: 0,
    },
    flip: {
      does: "Flips one fixed bit of D<sub>i</sub>. The chain now depends on when collisions happen, but not on which earlier digest matched.",
      keeps: "The low b bits of every digest, to notice collisions: 4 bytes each at b = 32.",
      bytes: 4,
    },
    xor: {
      does: "XORs D<sub>i</sub> with the earlier full digest D<sub>j</sub> whose low bits matched. The chain depends on D<sub>j</sub>'s other 224 bits.",
      keeps: "Every full digest, so any D<sub>j</sub> can be fetched: 32 bytes each.",
      bytes: 32,
    },
  };
  function draw() {
    const choice = root.querySelector("[data-variant]:checked").value;
    const v = VARIANTS[choice];
    const bars = Object.entries(VARIANTS).map(([k, x]) => `
      <div class="bar-row ${k === choice ? "on" : ""}">
        <span class="bar-label">${{ none: "No perturbation", flip: "Flip one bit", xor: "XOR with D<sub>j</sub> (CHIP)" }[k]}</span>
        <span class="bar"><span style="width:${(100 * x.bytes) / 32}%"></span></span>
        <span class="bar-value">${((x.bytes * ITER) / 1e6).toFixed(1)} MB</span>
      </div>`).join("");
    view.innerHTML = `
      <div class="kv"><span class="k">What a collision does</span><span>${v.does}</span></div>
      <div class="kv"><span class="k">What an attacker must keep</span><span>${v.keeps}</span></div>
      <div class="kv"><span class="k">Memory per guess, about 200,000 iterations (b = 32, C = 5)</span>${bars}</div>`;
  }
  root.querySelectorAll("[data-variant]").forEach((r) => (r.onchange = draw));
  draw();
}

// ---------------------------------------------------------------------------------------------
// 7. Where to put the upper bound

function bound(lengths) {
  const root = $("w-bound");
  const svg = root.querySelector("[data-view]");
  const slider = root.querySelector("[data-max]");
  const out = root.querySelector("[data-max-out]");
  const stats = root.querySelector("[data-stats]");
  const caption = root.querySelector("[data-caption]");
  const W = 640, H = 210, X0 = 10, Y0 = 180, LO = 50_000, HI = 350_000, BINS = 60;
  const width = (HI - LO) / BINS;
  const counts = Array(BINS).fill(0);
  for (const t of lengths) counts[Math.max(0, Math.min(BINS - 1, Math.floor((t - LO) / width)))]++;
  const peak = Math.max(...counts);
  const sx = (t) => X0 + ((t - LO) / (HI - LO)) * (W - 2 * X0);

  function draw() {
    const max = +slider.value;
    out.textContent = fmt(max);
    clear(svg);
    counts.forEach((c, i) => {
      const t = LO + i * width;
      el("rect", { x: sx(t) + 0.5, y: Y0 - (c / peak) * 150, width: sx(t + width) - sx(t) - 1,
                   height: (c / peak) * 150, fill: t + width / 2 > max ? "var(--bad)" : "var(--accent)",
                   "fill-opacity": 0.65 }, svg);
    });
    el("line", { x1: sx(max), x2: sx(max), y1: 14, y2: Y0, stroke: "var(--text)", "stroke-width": 2 }, svg);
    txt(svg, sx(max) + (max > 290_000 ? -6 : 6), 26, `max ${fmt(max)}`,
        { "font-size": 12, "text-anchor": max > 290_000 ? "end" : "start" });
    el("line", { x1: X0, x2: W - X0, y1: Y0, y2: Y0, stroke: "var(--muted)" }, svg);
    for (const t of [100_000, 200_000, 300_000]) {
      txt(svg, sx(t), Y0 + 18, fmt(t), { "font-size": 11, fill: "var(--muted)", "text-anchor": "middle" });
    }
    const kept = lengths.filter((t) => t <= max);
    const p = 1 - kept.length / lengths.length;
    const attempts = 1 / (1 - p);
    const total = kept.length ? mean(kept) + (attempts - 1) * max : Infinity;
    stats.innerHTML = `
      <div class="stat"><div class="value">${pct(p)}</div><div class="label">salts rejected</div></div>
      <div class="stat"><div class="value">${attempts.toFixed(2)}</div><div class="label">attempts per hash, on average</div></div>
      <div class="stat"><div class="value">${fmt(total)}</div><div class="label">iterations per hash, including retries</div></div>`;
    caption.innerHTML = `${fmt(lengths.length)} chains at b = 32, C = 5 (mean ${fmt(mean(lengths))}). ` +
      `Every red chain is cut off at ${fmt(max)} and thrown away, so it costs ${fmt(max)} wasted ` +
      `iterations. Expected cost = (mean of the kept chains) + (extra attempts) × max = ` +
      `${fmt(kept.length ? mean(kept) : 0)} + ${(attempts - 1).toFixed(2)} × ${fmt(max)}.`;
  }
  slider.addEventListener("input", draw);
  draw();
}

// ---------------------------------------------------------------------------------------------
// 8. Heatmap of mean iterations for every (b, C)

function heatmap(stats) {
  const root = $("w-heatmap");
  const svg = root.querySelector("[data-view]");
  const caption = root.querySelector("[data-caption]");
  const B = 32, C = 20, X0 = 34, Y0 = 22, CW = 29.5, CH = 13;
  const maxLog = Math.log10(stats.get(`${B},${C}`).mean);

  svg.setAttribute("viewBox", `0 0 ${X0 + C * CW + 4} ${Y0 + B * CH + 22}`);
  for (let c = 1; c <= C; c++) {
    txt(svg, X0 + (c - 0.5) * CW, Y0 - 8, String(c), { "text-anchor": "middle", "font-size": 10, fill: "var(--text-2)" });
  }
  txt(svg, X0 + (C * CW) / 2, Y0 + B * CH + 16, "Collisions, C →", { "text-anchor": "middle", "font-size": 11, fill: "var(--text-2)" });
  const cells = new Map();
  for (let b = 1; b <= B; b++) {
    if (b % 2 === 0 || b === 1) {
      txt(svg, X0 - 6, Y0 + (b - 0.5) * CH + 4, String(b), { "text-anchor": "end", "font-size": 10, fill: "var(--text-2)" });
    }
    for (let c = 1; c <= C; c++) {
      const s = stats.get(`${b},${c}`);
      const t = Math.log10(Math.max(1, s.mean)) / maxLog;
      const rect = el("rect", { x: X0 + (c - 1) * CW + 0.5, y: Y0 + (b - 1) * CH + 0.5, width: CW - 1, height: CH - 1,
                                fill: `color-mix(in oklab, var(--accent) ${Math.round(8 + 92 * t)}%, var(--track))`,
                                style: "cursor:pointer;outline:none" }, svg);
      rect.addEventListener("mouseenter", () => { if (!pinned) select(b, c); });
      rect.addEventListener("click", () => {
        // Clicking pins a cell so hovering stops changing it; clicking it again releases it.
        pinned = pinned === `${b},${c}` ? null : `${b},${c}`;
        select(b, c);
      });
      cells.set(`${b},${c}`, rect);
    }
  }
  txt(svg, 4, Y0 - 8, "b ↓", { "font-size": 11, fill: "var(--text-2)" });
  // Drawn just inside the cell's edge, so it doesn't spill over the gaps between cells.
  const ring = el("rect", { width: CW - 3, height: CH - 3, fill: "none", "stroke-width": 2,
                            "pointer-events": "none" }, svg);
  let pinned = null;

  function select(b, c) {
    const r = cells.get(`${b},${c}`);
    ring.setAttribute("x", +r.getAttribute("x") + 1);
    ring.setAttribute("y", +r.getAttribute("y") + 1);
    ring.setAttribute("stroke", pinned ? "var(--hit)" : "var(--text)");
    const s = stats.get(`${b},${c}`);
    const rule = Math.sqrt(2 * c * 2 ** b);
    caption.innerHTML = `b = ${hl(b)}, C = ${hl(c)}: ${hl(fmt(s.mean))} iterations on average ` +
      `(standard deviation ${fmt(s.std)}). Rule of thumb √(2·C·2${sup(b)}) = ${fmt(rule)} ` +
      `(${rule >= s.mean ? "+" : "−"}${pct(Math.abs(rule / s.mean - 1), 0)}). ` +
      `Suggested upper bound (mean + 1σ): ${fmt(Math.ceil((s.mean + s.std) / 10) * 10)}.` +
      (pinned ? ` <span class="sub">Pinned: click the cell again to release it.</span>` : "");
  }
  select(32, 5);
}

// ---------------------------------------------------------------------------------------------
// 8. Line charts: one y-axis, a legend and direct labels, a crosshair tooltip, and a data table

/** Round up to a tick step of 1, 2, 2.5 or 5 times a power of ten. */
function niceStep(range, ticks = 5) {
  const raw = range / ticks, mag = 10 ** Math.floor(Math.log10(raw));
  return [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw);
}

/**
 * `x` is the shared x value of every point; each series has `name`, `color` (a CSS variable)
 * and `y`, one value per x. `title(i)` heads the tooltip and the table row for point i.
 */
function lineChart(root, { x, series, xTicks, xFmt, yFmt, xLabel, yLabel, title, columns }) {
  const svg = root.querySelector("[data-view]");
  const W = 640, H = 300, L = 58, R = 120, T = 30, B = 44;
  const xMin = Math.min(...x), xMax = Math.max(...x);
  const yTop = Math.max(...series.flatMap((s) => s.y));
  const step = niceStep(yTop), yMax = Math.ceil(yTop / step) * step;
  const sx = (v) => L + ((v - xMin) / (xMax - xMin)) * (W - L - R);
  const sy = (v) => T + (1 - v / yMax) * (H - T - B);
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);

  for (let v = 0; v <= yMax + 1e-9; v += step) {
    el("line", { x1: L, x2: W - R, y1: sy(v), y2: sy(v), stroke: "var(--border)" }, svg);
    txt(svg, L - 8, sy(v) + 4, yFmt(v), { "text-anchor": "end", "font-size": 11, fill: "var(--muted)" });
  }
  for (const v of xTicks) {
    txt(svg, sx(v), H - B + 18, xFmt(v), { "text-anchor": "middle", "font-size": 11, fill: "var(--muted)" });
  }
  txt(svg, (L + W - R) / 2, H - 6, xLabel, { "text-anchor": "middle", "font-size": 12, fill: "var(--text-2)" });
  txt(svg, 4, 12, yLabel, { "font-size": 12, fill: "var(--text-2)" });

  for (const s of series) {
    el("path", { d: s.y.map((v, i) => `${i ? "L" : "M"}${sx(x[i])},${sy(v)}`).join(""), fill: "none",
                 stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, svg);
    // Direct label at the line's end, in text ink beside a swatch of the series color.
    const yEnd = sy(s.y[s.y.length - 1]);
    el("line", { x1: W - R + 8, x2: W - R + 18, y1: yEnd, y2: yEnd, stroke: s.color, "stroke-width": 3,
                 "stroke-linecap": "round" }, svg);
    txt(svg, W - R + 22, yEnd + 4, s.name, { "font-size": 12, fill: "var(--text-2)" });
  }

  const legend = root.querySelector("[data-legend]");
  legend.replaceChildren(...series.map((s) => {
    const item = document.createElement("span");
    const swatch = document.createElement("i");
    swatch.style.background = s.color;
    item.append(swatch, document.createTextNode(s.name));
    return item;
  }));

  // Crosshair: snap to the nearest x and list every series there.
  const cross = el("line", { y1: T, y2: H - B, stroke: "var(--text-2)", "stroke-dasharray": "3 3", visibility: "hidden" }, svg);
  const dots = series.map((s) => el("circle", { r: 4, fill: s.color, stroke: "var(--surface)", "stroke-width": 2,
                                                 visibility: "hidden" }, svg));
  const tip = document.createElement("div");
  tip.className = "tip";
  tip.hidden = true;
  root.append(tip);
  const hit = el("rect", { x: L, y: T, width: W - L - R, height: H - T - B, fill: "transparent" }, svg);
  const show = (event) => {
    const box = svg.getBoundingClientRect();
    const px = ((event.clientX - box.left) / box.width) * W;
    let i = 0;
    x.forEach((v, j) => { if (Math.abs(sx(v) - px) < Math.abs(sx(x[i]) - px)) i = j; });
    cross.setAttribute("x1", sx(x[i]));
    cross.setAttribute("x2", sx(x[i]));
    cross.setAttribute("visibility", "visible");
    dots.forEach((d, k) => { d.setAttribute("cx", sx(x[i])); d.setAttribute("cy", sy(series[k].y[i])); d.setAttribute("visibility", "visible"); });
    const head = document.createElement("div");
    head.className = "tip-title";
    head.textContent = title(i);
    tip.replaceChildren(head, ...series.map((s) => {
      const row = document.createElement("div");
      row.className = "tip-row";
      const swatch = document.createElement("i");
      swatch.style.background = s.color;
      const value = document.createElement("b");
      value.textContent = yFmt(s.y[i], true);
      const name = document.createElement("span");
      name.textContent = s.name;
      row.append(swatch, value, name);
      return row;
    }));
    tip.hidden = false;
    const scale = box.width / W, left = sx(x[i]) * scale;
    const rootBox = root.getBoundingClientRect();
    const offsetX = box.left - rootBox.left, offsetY = box.top - rootBox.top;
    tip.style.top = `${offsetY + T * scale}px`;
    tip.style.left = left + tip.offsetWidth + 16 > box.width
      ? `${offsetX + left - tip.offsetWidth - 12}px` : `${offsetX + left + 12}px`;
  };
  const hide = () => {
    tip.hidden = true;
    cross.setAttribute("visibility", "hidden");
    dots.forEach((d) => d.setAttribute("visibility", "hidden"));
  };
  hit.addEventListener("pointermove", show);
  hit.addEventListener("pointerdown", show);
  hit.addEventListener("pointerleave", hide);

  // The same numbers as a table, for readers who can't or don't want to hover.
  const table = document.createElement("table");
  const headRow = table.insertRow();
  for (const name of [...columns, ...series.map((s) => s.name)]) {
    const th = document.createElement("th");
    th.textContent = name;
    headRow.append(th);
  }
  x.forEach((_, i) => {
    const row = table.insertRow();
    for (const cell of [...title(i, true), ...series.map((s) => yFmt(s.y[i], true))]) row.insertCell().textContent = cell;
  });
  root.querySelector("[data-table]").replaceChildren(table);
}

function iterationsByC(stats) {
  const C = Array.from({ length: 20 }, (_, i) => i + 1);
  const bits = [32, 30, 28];
  lineChart($("w-by-c"), {
    x: C,
    series: bits.map((b, k) => ({ name: `b = ${b}`, color: `var(--series-${k + 1})`,
                                  y: C.map((c) => stats.get(`${b},${c}`).mean) })),
    xTicks: [1, 5, 10, 15, 20],
    xFmt: String,
    yFmt: (v, exact) => (exact ? fmt(v) : v === 0 ? "0" : `${fmt(v / 1000)}k`),
    xLabel: "Collisions, C",
    yLabel: "Mean iterations",
    title: (i, row) => (row ? [String(C[i])] : `C = ${C[i]}`),
    columns: ["C"],
  });
}

function memoryChart({ rows }) {
  // Columns: bits, collisions, runs, mean_iterations, peak_python_mb, raw_digests_mb, tradeoff_mb, …
  const data = [...rows].sort((a, b) => a[3] - b[3]);
  lineChart($("w-memory"), {
    x: data.map((r) => r[3]),
    series: [
      { name: "Python peak", color: "var(--series-1)", y: data.map((r) => r[4]) },
      { name: "Raw digests", color: "var(--series-2)", y: data.map((r) => r[5]) },
      { name: "Tradeoff", color: "var(--series-3)", y: data.map((r) => r[6]) },
    ],
    xTicks: [0, 250_000, 500_000, 750_000, 1_000_000].filter((v) => v >= data[0][3]),
    xFmt: (v) => (v >= 1e6 ? `${v / 1e6}M` : `${v / 1000}k`),
    yFmt: (v, exact) => (exact ? `${v.toFixed(1)} MB` : `${v} MB`),
    xLabel: "Mean iterations per chain",
    yLabel: "Memory per chain",
    title: (i, row) => {
      const [b, c, , t] = data[i];
      return row ? [String(b), String(c), fmt(t)] : `b = ${b}, C = ${c}: ${fmt(t)} iterations`;
    },
    columns: ["b", "C", "Mean iterations"],
  });
}

// ---------------------------------------------------------------------------------------------
// 9. Time–memory tradeoff: replaying from a checkpoint

function replay() {
  const root = $("w-replay");
  const svg = root.querySelector("[data-view]");
  const N = 24, K = 6, HIT = 20, J = 9, W = 640, X0 = 10, Y = 40;
  const size = (W - 2 * X0) / N;
  const x = (i) => X0 + (i - 1) * size;
  const STEPS = 7;

  function render(s) {
    clear(svg);
    const computed = s >= 1 ? HIT : HIT - 1;
    const replayed = s >= 3 ? Math.min(J, K + (s - 2)) : null;
    for (let i = 1; i <= N; i++) {
      const isCheckpoint = i % K === 0 && i <= computed;
      const fill = i > computed ? "var(--surface)"
        : i === HIT && s >= 1 ? "var(--hit)"
        : replayed !== null && i > K && i <= replayed ? "var(--good)"
        : isCheckpoint ? "var(--accent)" : "var(--track)";
      el("rect", { x: x(i) + 1, y: Y, width: size - 2, height: size - 2, rx: 3, fill,
                   "fill-opacity": fill === "var(--track)" || fill === "var(--surface)" ? 1 : 0.8,
                   stroke: i > computed ? "var(--border)" : "none" }, svg);
      txt(svg, x(i) + size / 2, Y + size / 2 + 4, String(i), { "text-anchor": "middle", "font-size": 11 });
    }
    txt(svg, X0, Y - 12, "Kept: the iteration index of each low-bit value, plus the full digest at every 6th iteration (blue)",
        { "font-size": 12, fill: "var(--text-2)" });
    if (s >= 1) {
      const arc = (from, to, color, label) => {
        const x1 = x(from) + size / 2, x2 = x(to) + size / 2, yb = Y + size + 2;
        el("path", { d: `M${x1},${yb} C${x1},${yb + 46} ${x2},${yb + 46} ${x2},${yb}`, fill: "none",
                     stroke: color, "stroke-width": 2, "marker-end": "" }, svg);
        txt(svg, (x1 + x2) / 2, yb + 50, label, { "text-anchor": "middle", "font-size": 12, fill: color });
      };
      arc(HIT, J, "var(--hit)", "needs D₉");
      if (s >= 2) arc(J, K, "var(--accent)", "nearest checkpoint: D₆");
    }
    svg.setAttribute("viewBox", `0 0 ${W} ${Y + size + 70}`);
    return [
      `The chain has run to iteration 19. Instead of 19 full digests, only the iteration index of ` +
        `each low-bit value is kept, plus full digests at checkpoints 6, 12 and 18.`,
      `Iteration ${hit(20)} collides: its low bits match the value first seen at iteration 9. ` +
        `CHIP needs the full ${hit("D<sub>9</sub>")}, which wasn't kept.`,
      `Go back to the nearest checkpoint at or before 9: ${hl("D<sub>6</sub>")}, which was kept.`,
      `Re-hash: D<sub>7</sub> = SHA-256(D<sub>6</sub>). ${hl("1 extra hash")}.`,
      `D<sub>8</sub> = SHA-256(D<sub>7</sub>). ${hl("2 extra hashes")}.`,
      `D<sub>9</sub> = SHA-256(D<sub>8</sub>). ${hl("3 extra hashes")}, and D<sub>9</sub> is back.`,
      `XOR D<sub>20</sub> with D<sub>9</sub> and carry on. On average a recovery costs half the checkpoint spacing, and ` +
        `there are only C of them per chain.`,
    ][s];
  }
  stepper(root, () => STEPS, render, { interval: 1100 });
}

// ---------------------------------------------------------------------------------------------
// 9. Time–memory tradeoff: checkpoint spacing

function tradeoff() {
  const root = $("w-tradeoff");
  const svg = root.querySelector("[data-view]");
  const preset = root.querySelector("[data-preset]");
  const slider = root.querySelector("[data-spacing]");
  const out = root.querySelector("[data-spacing-out]");
  const stats = root.querySelector("[data-stats]");
  const caption = root.querySelector("[data-caption]");
  // Mean iterations and the measured extra hashing at spacing 1,000, from benchmarks/results/memory.md.
  const PRESETS = {
    "24,5": [12_908, 0.186], "28,5": [52_113, 0.047], "32,5": [199_770, 0.013],
    "32,30": [508_667, 0.03], "34,30": [1_006_702, 0.015],
  };
  const spacing = () => Math.round(10 ** +slider.value);
  // Memory: a 4-byte key and 4-byte index per stored value, plus a 32-byte digest per checkpoint.
  // Extra hashing: each of the C recoveries replays (j mod k) hashes, (k − 1)/2 on average.
  const model = (T, C, k) => ({ mem: (T - C) * 8 + Math.floor(T / k) * 32, extra: (C * (k - 1)) / 2 / T });

  function draw() {
    const [b, C] = preset.value.split(",").map(Number);
    const [T, measured] = PRESETS[preset.value];
    const k = spacing();
    out.textContent = fmt(k);
    const W = 640, H = 230, X0 = 52, X1 = 590, Y0 = 190, Y1 = 22;
    const full = (T - C) * 32;
    const logs = Array.from({ length: 101 }, (_, i) => i / 20); // log10 of the spacing, 0 to 5
    const pts = logs.map((l) => ({ l, ...model(T, C, Math.round(10 ** l)) }));
    const memTop = full * 1.3, extraTop = Math.min(1, Math.max(...pts.map((p) => p.extra)));
    const sx = (l) => X0 + (l / 5) * (X1 - X0);
    const sm = (m) => Y0 - (Math.min(m, memTop) / memTop) * (Y0 - Y1);
    const se = (e) => Y0 - (Math.min(e, extraTop) / extraTop) * (Y0 - Y1);
    clear(svg);
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    el("line", { x1: X0, x2: X1, y1: Y0, y2: Y0, stroke: "var(--muted)" }, svg);
    for (let l = 0; l <= 5; l++) {
      txt(svg, sx(l), Y0 + 16, fmt(10 ** l), { "text-anchor": "middle", "font-size": 11, fill: "var(--muted)" });
    }
    txt(svg, (X0 + X1) / 2, Y0 + 34, "checkpoint spacing (iterations, log scale)", { "text-anchor": "middle", "font-size": 11, fill: "var(--muted)" });
    // Left axis: memory. Right axis: extra hashing.
    txt(svg, X0 - 6, sm(full) + 4, `${(full / 1e6).toFixed(1)} MB`, { "text-anchor": "end", "font-size": 11, fill: "var(--accent)" });
    txt(svg, X0 - 6, Y0, "0", { "text-anchor": "end", "font-size": 11, fill: "var(--muted)" });
    txt(svg, X1 + 6, se(extraTop) + 4, pct(extraTop, 0), { "font-size": 11, fill: "var(--hit)" });
    el("line", { x1: X0, x2: X1, y1: sm(full), y2: sm(full), stroke: "var(--accent)", "stroke-dasharray": "4 4", "stroke-opacity": 0.6 }, svg);
    txt(svg, sx(2.5), sm(full) - 6, "storing every digest", { "text-anchor": "middle", "font-size": 11, fill: "var(--accent)" });
    const line = (key, scale, color) => el("path", { fill: "none", stroke: color, "stroke-width": 2.2,
      d: pts.map((p, i) => `${i ? "L" : "M"}${sx(p.l)},${scale(p[key])}`).join("") }, svg);
    line("mem", sm, "var(--accent)");
    line("extra", se, "var(--hit)");
    txt(svg, sx(0.15), sm(pts[3].mem) - 8, "memory", { "font-size": 12, fill: "var(--accent)", "font-weight": 600 });
    txt(svg, sx(4.85), se(pts[97].extra) - 8, "extra hashing", { "text-anchor": "end", "font-size": 12, fill: "var(--hit)", "font-weight": 600 });
    const cur = model(T, C, k);
    el("line", { x1: sx(+slider.value), x2: sx(+slider.value), y1: Y1 - 8, y2: Y0, stroke: "var(--text)", "stroke-width": 1.5 }, svg);
    el("circle", { cx: sx(+slider.value), cy: sm(cur.mem), r: 5, fill: "var(--accent)" }, svg);
    el("circle", { cx: sx(+slider.value), cy: se(cur.extra), r: 5, fill: "var(--hit)" }, svg);
    stats.innerHTML = `
      <div class="stat"><div class="value">${(cur.mem / 1e6).toFixed(2)} MB</div><div class="label">memory, vs ${(full / 1e6).toFixed(1)} MB for every digest</div></div>
      <div class="stat"><div class="value">${pct(cur.extra)}</div><div class="label">extra hashing (${fmt(C * (k - 1) / 2)} hashes)</div></div>
      <div class="stat"><div class="value">${fmt(Math.floor(T / k))}</div><div class="label">checkpoints kept</div></div>`;
    caption.innerHTML = `b = ${b}, C = ${C}: about ${fmt(T)} iterations. Memory never drops below ` +
      `${((T - C) * 8 / 1e6).toFixed(2)} MB (the 8-byte key and index per value), a quarter of storing ` +
      `every digest. At spacing 1,000 this model gives ${pct(model(T, C, 1000).extra)} extra hashing; ` +
      `the benchmark measured ${pct(measured)}.`;
  }
  preset.onchange = draw;
  slider.addEventListener("input", draw);
  draw();
}

// ---------------------------------------------------------------------------------------------

saltDemo();
lowBitsDemo();
birthday();
replay();
tradeoff();
perturbation();

loadCsv("iterations.csv").then(({ rows }) => {
  const stats = new Map(rows.map(([b, c, m, s]) => [`${b},${c}`, { mean: m, std: s }]));
  chainDemo(stats);
  heatmap(stats);
  iterationsByC(stats);
});

loadCsv("memory.csv").then(memoryChart);

loadCsv("distribution.csv").then(({ rows }) => {
  const lengths = rows.map((r) => r[r.length - 1]);
  lockstep(lengths, "w-lockstep");
  lockstep(lengths, "w-lockstep-attack");
  bound(lengths);
});

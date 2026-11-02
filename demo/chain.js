// CHIP's hash chain in JavaScript, for the explainer's step-through widgets. It mirrors
// Chip.compute in src/chip/core.py with the browser's SHA-256 (WebCrypto), and records every
// iteration so a widget can replay it. tests/test_core.py pins EXAMPLE's result in Python, and
// the page checks this code against it on load (logging to the console only on a mismatch).

export const EXAMPLE = {
  password: "hunter2",
  salt: "5c1e4a9b7f0362d8e1a74c2b90f3d65e",
  bits: 4,
  collisions: 3,
  collisionIterations: [9, 11, 12],
  digest: "063a918a4bcd790bf964fdaf7d64ad03ec5fef6b85bcbc21fe02ceb12f4e7093",
};

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
export const fromHex = (hex) => Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
export const utf8 = (text) => new TextEncoder().encode(text);

export function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

export const xor = (a, b) => a.map((x, i) => x ^ b[i]);

/** The low `bits` bits of a digest read as a big-endian integer (`h_int & mask` in core.py). */
export function lowBits(digest, bits) {
  let v = 0n;
  for (const byte of digest.slice(-8)) v = (v << 8n) | BigInt(byte);
  return Number(v & ((1n << BigInt(bits)) - 1n));
}

/** Unpadded standard base64, as in the stored hash string. */
export const b64 = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/=+$/, "");

/**
 * Run one chain on `data` (salt + password). Each step records the digest, its low bits, and,
 * on a collision, the earlier step it matched. Stops after `collisions` collisions or
 * `maxIterations` iterations, like Chip.compute(bounded=True).
 */
export async function chipChain(data, bits, collisions, maxIterations = Infinity) {
  const seen = new Map(); // low bits -> the step that first produced them
  const steps = [];
  const collisionIterations = [];
  let h = data;
  while (collisionIterations.length < collisions && steps.length < maxIterations) {
    const digest = await sha256(h);
    const step = { i: steps.length + 1, input: h, digest, key: lowBits(digest, bits), earlier: null };
    const earlier = seen.get(step.key);
    if (earlier === undefined) {
      seen.set(step.key, step);
      h = digest;
    } else {
      step.earlier = earlier;
      collisionIterations.push(step.i);
      h = xor(digest, earlier.digest); // perturb with the earlier full digest
    }
    step.next = h;
    steps.push(step);
  }
  return { steps, collisionIterations, iterations: steps.length, last: h, digest: await sha256(h) };
}

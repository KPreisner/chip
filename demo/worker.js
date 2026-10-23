// Runs the real `chip` package in Pyodide (Python compiled to WebAssembly) in a module
// worker, off the main thread so the page stays responsive. The library's debug log
// (the same events `chip hash --verbose` prints) is forwarded to the page as messages.

import { loadPyodide } from "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/pyodide.mjs";

const CHIP_FILES = ["__init__.py", "core.py", "passwords.py"];

const SETUP = `
import logging
import sys
import time

import js
from pyodide.ffi import to_js

sys.path.insert(0, "/lib/chip_src")
from chip import Chip, hash_password, verify
from chip.core import HASH_FUNCS

_start = time.perf_counter()

class ForwardToPage(logging.Handler):
    def emit(self, record):
        event = {
            "type": "log",
            "template": record.msg.strip(),
            "args": list(record.args),
            "text": record.getMessage().strip(),
            "ms": (time.perf_counter() - _start) * 1000,
        }
        js.postMessage(to_js(event, dict_converter=js.Object.fromEntries))

_logger = logging.getLogger("chip")
_logger.addHandler(ForwardToPage())
_logger.setLevel(logging.DEBUG)

def run_hash(password, hash_name, bits, collisions, max_iterations):
    global _start
    chip = Chip(
        bits=bits,
        collisions=collisions,
        max_iterations=max_iterations,
        hash_func=HASH_FUNCS[hash_name],
    )
    _start = time.perf_counter()
    encoded = hash_password(password, chip)
    return encoded, (time.perf_counter() - _start) * 1000

def run_verify(password, encoded):
    _logger.setLevel(logging.WARNING)  # keep the page's log for hashing
    try:
        return verify(password, encoded)
    finally:
        _logger.setLevel(logging.DEBUG)
`;

let pyodide = null;

async function init() {
  pyodide = await loadPyodide();
  pyodide.FS.mkdirTree("/lib/chip_src/chip");
  for (const name of CHIP_FILES) {
    const response = await fetch(`chip/${name}`);
    if (!response.ok) throw new Error(`could not load chip/${name}`);
    pyodide.FS.writeFile(`/lib/chip_src/chip/${name}`, await response.text());
  }
  pyodide.runPython(SETUP);
  postMessage({ type: "ready", python: pyodide.runPython("import sys; sys.version.split()[0]") });
}

const ready = init().catch((error) => postMessage({ type: "fatal", message: String(error) }));

onmessage = async ({ data }) => {
  await ready;
  try {
    if (data.type === "hash") {
      const run = pyodide.globals.get("run_hash");
      const result = run(data.password, data.hashName, data.bits, data.collisions, data.max);
      const [encoded, ms] = result.toJs();
      result.destroy();
      run.destroy();
      postMessage({ type: "done", encoded, ms });
    } else if (data.type === "verify") {
      const check = pyodide.globals.get("run_verify");
      const ok = check(data.password, data.encoded);
      check.destroy();
      postMessage({ type: "verified", ok });
    }
  } catch (error) {
    // Python exceptions arrive as PythonError; keep just the final "Type: message" line.
    const lines = String(error.message || error).trim().split("\n");
    postMessage({ type: "error", message: lines[lines.length - 1] });
  }
};

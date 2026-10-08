const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');

// Pull the concatenated engine script out of a built artifact and run it in a
// bare vm context (no DOM). Vendors register themselves in VENDOR_REGISTRY.
function engineSource(file) {
  const html = fs.readFileSync(path.join(ROOT, 'dist', file), 'utf8');
  const m = html.match(/<script id="engine-scripts">\n([\s\S]*?)\n<\/script>/);
  if (!m) throw new Error('engine script not found in ' + file);
  return m[1];
}

function loadVendor(file, id) {
  const ctx = vm.createContext({ console });
  vm.runInContext(engineSource(file), ctx);
  const vendor = vm.runInContext('VENDOR_REGISTRY', ctx).find(v => v.id === id);
  if (!vendor) throw new Error('vendor not registered: ' + id);
  return vendor;
}

const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');

// Objects built inside the vm context have foreign prototypes; round-trip
// through JSON before deepStrictEqual (also drops undefined-valued keys).
const plain = (x) => JSON.parse(JSON.stringify(x));

// Load a built page in jsdom and feed it a config through #fileInput.
async function loadPage(file, cfg) {
  const { JSDOM } = require('jsdom');
  const html = fs.readFileSync(path.join(ROOT, 'dist', file), 'utf8');
  const dom = new JSDOM(html, { runScripts: 'dangerously', pretendToBeVisual: true });
  const w = dom.window;
  const input = w.document.getElementById('fileInput');
  Object.defineProperty(input, 'files', { value: [new w.File([cfg], 'c.txt')] });
  input.dispatchEvent(new w.Event('change'));
  await new Promise(r => setTimeout(r, 300));
  return { w, d: w.document };
}

module.exports = { ROOT, loadVendor, fixture, plain, loadPage };

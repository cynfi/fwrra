#!/usr/bin/env node
/**
 * build.js
 *
 * Assembles the single-file, distributable dist/fwrra.html from the
 * modular source files in /source. There is no bundler, transpiler, or
 * npm dependency here on purpose — this concatenates plain scripts into
 * the two <script> tags source/template.html expects.
 *
 * Usage:
 *   node build.js                # builds all vendors currently wired in VENDORS below
 *   node build.js --vendor=asa   # builds a single vendor's engine only
 *
 * Output:
 *   dist/fwrra.html                  (all vendors, if more than one is wired in)
 *   dist/fwrra-<vendor>.html         (per-vendor builds, always produced too)
 *
 * Adding a new vendor:
 *   1. Create source/vendors/<name>/parser.js and source/vendors/<name>/resolve.js
 *      (see source/vendors/asa/ for the shape resolve.js's buildRuleset()
 *      and scoreEntry() need to return — ui.js consumes that shape as a
 *      black box and doesn't care which vendor produced it).
 *   2. Add '<name>' to the VENDORS array below.
 *   3. If the vendor's rules aren't distinguishable from existing vendors
 *      well enough for a combined build to pick the right parser
 *      automatically, that auto-detection lives in ui.js's file-load
 *      handler — see CLAUDE.md for where that hook is.
 */

const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, 'source');
const OUT_DIR = path.join(__dirname, 'dist');

// Vendors wired into the build. Each needs source/vendors/<name>/parser.js
// and source/vendors/<name>/resolve.js.
const VENDORS = ['asa', 'fortios'];

function read(...parts) {
  return fs.readFileSync(path.join(SRC, ...parts), 'utf8');
}

function sharedModules() {
  // Load order within shared/: logging.js and risk.js have no dependencies;
  // registry.js defines VENDOR_REGISTRY/registerVendor/detectVendor, which the
  // vendor IIFEs (below) and ui.js both rely on being global by the time they
  // run. All three are plain globals shared across every vendor.
  return [
    read('shared', 'logging.js'),
    read('shared', 'registry.js'),
    read('shared', 'risk.js'),
    read('shared', 'policy.js'), // uses buybackKeyForCombo from risk.js
  ].join('\n');
}

function vendorEngine(vendorName) {
  const dir = ['vendors', vendorName];
  // parser.js must load before resolve.js: resolve.js's scoreEntry()/
  // buildRuleset() consume the parsed-config shape parser.js produces.
  const body = [read(...dir, 'parser.js'), read(...dir, 'resolve.js')].join('\n');
  // Wrap each vendor's engine in its OWN IIFE. Without this, every vendor's
  // top-level declarations (buildRuleset, scoreEntry, resolveEndpoint,
  // classifyLogging, tokenize, ...) would be globals and the second vendor
  // concatenated into a combined build would clobber the first. Inside the
  // IIFE those names stay private; the vendor exposes itself to the rest of
  // the page only by calling the global registerVendor() (from resolve.js).
  // Shared helpers (risk.js, logging.js, registry.js) remain global and are
  // reachable from inside the IIFE via normal closure over the outer scope.
  return `// ---- vendor engine: ${vendorName} ----\n;(function () {\n${body}\n})();`;
}

function buildOne(template, vendorNames, outFile) {
  const engine = [sharedModules(), ...vendorNames.map(vendorEngine)].join('\n');
  const ui = read('ui.js');

  let html = template;
  if (!html.includes('<script id="engine-scripts"></script>')) {
    throw new Error('template.html is missing the empty <script id="engine-scripts"></script> placeholder');
  }
  if (!html.includes('<script id="ui-script"></script>')) {
    throw new Error('template.html is missing the empty <script id="ui-script"></script> placeholder');
  }

  html = html.replace(
    '<script id="engine-scripts"></script>',
    `<script id="engine-scripts">\n${engine}\n</script>`
  );
  html = html.replace(
    '<script id="ui-script"></script>',
    `<script id="ui-script">\n${ui}\n</script>`
  );

  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });
  const outPath = path.join(OUT_DIR, outFile);
  fs.writeFileSync(outPath, html, 'utf8');
  console.log(`Built ${path.relative(process.cwd(), outPath)} (${(html.length / 1024).toFixed(1)} KB)`);
}

function main() {
  const arg = process.argv.find(a => a.startsWith('--vendor='));
  const template = read('template.html');

  if (arg) {
    const vendorName = arg.split('=')[1];
    if (!VENDORS.includes(vendorName)) {
      throw new Error(`Unknown vendor "${vendorName}". Known vendors: ${VENDORS.join(', ')}`);
    }
    buildOne(template, [vendorName], `fwrra-${vendorName}.html`);
    return;
  }

  // Default: build a combined artifact with every wired-in vendor, plus a
  // per-vendor artifact for each one individually.
  buildOne(template, VENDORS, 'fwrra.html');
  for (const vendorName of VENDORS) {
    buildOne(template, [vendorName], `fwrra-${vendorName}.html`);
  }
}

main();

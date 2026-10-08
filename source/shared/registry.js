// ============================================================
// Vendor registry + auto-detection
// ============================================================
// Each vendor's engine (its parser.js + resolve.js, wrapped together in a
// single IIFE by build.js so their internal top-level names stay private and
// don't collide across vendors) calls registerVendor() with its public API.
// ui.js consumes this registry to pick the right parser for a dropped config
// WITHOUT ever branching on vendor identity itself — it just asks each vendor
// to score the text via detect() and uses the best match.
//
// vendor shape:
//   {
//     id:          'asa' | 'fortios' | ...   (stable machine id)
//     label:       'Cisco ASA'               (human-facing name)
//     detect(text) -> number                 (confidence 0..N; higher wins, 0 = not mine)
//     parse(text)  -> config                 (vendor-internal parsed shape)
//     buildRuleset(config) -> Array<Row>     (the vendor contract ui.js renders)
//     buildInventory(config, options) -> Inventory | null     (OPTIONAL)
//         Extra, vendor-specific read-only views rendered by ui.js as a tab.
//         Inventory = { title, sections: Section[] }
//         Section   = { id, heading, columns:[{key,label}], rows:[{cells, detail?}] }
//                   | { id, heading, ruleRows: RuleRow[] }   (scored rule rows)
//                   | { id, heading, groups: [{ key, title, summary: cell[], sections: Section[] }] }
//                       (collapsible blocks, collapsed by default, +/- per block and expand/collapse all)
//         cell = string | { text, tone?: 'warn'|'dim', note? }
//         detail block = {kind:'kv'|'networks'|'list', title, ...}
//         Return null when the config has nothing to show (no tab).
//   }
const VENDOR_REGISTRY = [];

function registerVendor(vendor) {
  VENDOR_REGISTRY.push(vendor);
}

// Pick the highest-confidence vendor for a given config text.
// Returns the winning vendor object, or null if nothing claims it.
function detectVendor(text) {
  let best = null;
  let bestScore = 0;
  for (const v of VENDOR_REGISTRY) {
    const score = typeof v.detect === 'function' ? (v.detect(text) || 0) : 0;
    if (score > bestScore) {
      bestScore = score;
      best = v;
    }
  }
  return best;
}

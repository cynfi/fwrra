# ASA Remote-Access VPN (AnyConnect) Enumeration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** For Cisco ASA, enumerate remote-access VPN access (address pools, tunnel-groups, group-policies, per-user overrides, VPN-filter ACLs, split-tunnel state) in a second "Remote-access VPN" tab, with VPN-filter ACEs scored and hideable via the existing "Risk analysis" toggle.

**Architecture:** Two new ASA vendor files (`vpn-parser.js`, `vpn-resolve.js`) are concatenated into the ASA vendor IIFE by `build.js`. The vendor exposes an optional new contract hook `buildInventory(config)` returning a generic `{title, sections}` structure; `ui.js` renders it as a tab without knowing anything about ASA. VPN-filter ACEs reuse the existing `scoreEntry()` and the existing rule-row/detail renderers.

**Tech Stack:** Vanilla JS, Node stdlib `build.js`; tests are plain Node scripts using `assert` (engine tests via `vm`, UI tests via ad-hoc-installed `jsdom`).

**Spec:** `docs/superpowers/specs/2026-10-08-asa-anyconnect-design.md`

## Global Constraints

- Vanilla JS, no framework, no new runtime dependencies; `jsdom` is a dev-only, ad-hoc (`npm i --no-save jsdom`) test dependency and is never committed.
- `dist/` is generated: never hand-edit; run `node build.js` (no `--vendor` flag) and commit the regenerated files with `source/`.
- NAT is out of scope for every vendor.
- Only enforced rules are scored: VPN-filter ACLs are included only when reached through a remote-access tunnel-group, group-policy or user; they stay out of the main rule table.
- Inactive/disabled ACEs are tagged (`inactive: true`), never dropped.
- `ui.js` and `shared/` must not branch on vendor identity; the only cross-boundary surface is the registered vendor object (now optionally including `buildInventory`).
- Vendor-specific grammar stays inside `source/vendors/asa/`.
- All user-derived strings go through `escapeHtml()` before `innerHTML`.
- Passwords from `username ... password ...` lines are never stored.
- Split tunneling Enabled/Disabled and all findings are factual state: not scored, and NOT hidden by the risk toggle. Only per-ACE score/band/calculation and risk-based filters are hidden.
- VPN-filter ACEs are scored with direction `'internal'` (client = source, internal = destination).
- Commit locally only. **Do NOT `git push`** (the user is testing before anything goes to the remote).
- Commit messages end with: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`

## Review Focus

Inputs/conditions the spec implies but the happy-path fixture does not exercise (each is pinned by a test in the owning task):

1. ASA config with **no** remote-access VPN content → `buildInventory` returns `null`, no tab, no errors (Task 2).
2. **Dangling references** (tunnel-group → undefined group-policy/pool; group-policy → undefined vpn-filter / split ACL) → warn findings, never an exception (Task 2).
3. **CRLF line endings** in the config → identical parse result (Task 1).
4. **Inverted pool range** (`end` < `start`, a typo) → `count` clamps to 0, never negative (Task 1).
5. **HTML in object names** (`<img src=x onerror=...>` as a tunnel-group name) → rendered escaped, no live element (Task 4).

## File Structure

| File | Responsibility |
|---|---|
| `build.js` (modify) | Load optional `vpn-parser.js` / `vpn-resolve.js` into each vendor IIFE when present |
| `source/vendors/asa/vpn-parser.js` (create) | `parseASAVpn(lines)`: pools, group-policies, tunnel-groups, users, standard ACLs, VPN globals |
| `source/vendors/asa/parser.js` (modify) | Call `parseASAVpn` and merge its result into the returned config |
| `source/vendors/asa/vpn-resolve.js` (create) | `buildVpnInventory(config)`: inheritance, split-tunnel state, filter ACE scoring, sections, findings |
| `source/vendors/asa/resolve.js` (modify) | Register `buildInventory` on the ASA vendor |
| `source/shared/registry.js` (modify) | Document the optional `buildInventory` hook + Inventory shape |
| `source/template.html` (modify) | Tab bar, `#rulesView`/`#inventoryView`, CSS, move risk toggle into header actions |
| `source/ui.js` (modify) | Tabs, generic inventory renderer, VPN CSV export |
| `tests/` (create) | `run.js`, `helpers.js`, `fixtures/asa-vpn.cfg`, `*.test.js` |
| `CLAUDE.md`, `README.md`, spec (modify) | Document the hook, tests, feature |

## Interfaces (shared across tasks)

```
// config additions (Task 1) — returned by ASA parse()
config.pools[name]          = { name, start, end, mask|null, count }
config.groupPolicies[name]  = { name, kind?, vpnFilter?, splitPolicy?, splitAcl?, addressPools?, tunnelProtocols?,
                                dnsServers?, simultaneousLogins?, rawAttrs: string[] }
        // vpnFilter / splitAcl: {mode:'value', acl} | {mode:'none'} | undefined (= unset/inherit)
        // addressPools / dnsServers: string[] ([] = explicit none) | undefined
config.tunnelGroups[name]   = { name, type|null, addressPools: string[], defaultGroupPolicy|null,
                                authServerGroup|null, aliases: string[], urls: string[] }
config.users[name]          = { name, vpnGroupPolicy?, vpnFilter?, groupLock?, framedIp?: {ip, mask|null}, rawAttrs: string[] }
config.standardAcls[name]   = [ { action, src: <parseEndpoint endpoint>, raw } ]
config.vpnGlobal            = { permitVpn: bool, permitVpnExplicit: bool, webvpnEnabledOn: string[],
                                anyconnectEnabled: bool, tunnelGroupList: bool }

// Inventory (Task 3) — returned by vendor.buildInventory(config, options) or null
Inventory = { title: string, sections: Section[] }
Section   = { id, heading, columns: [{key,label}], rows: Row[] }          // generic table
          | { id, heading, ruleRows: RuleRow[] }                          // scored filter ACEs
Row       = { cells: { [key]: string | {text, tone?:'warn'|'dim', note?} }, detail?: Block[] }
Block     = {kind:'kv', title, pairs:[[k, string|cell]]}
          | {kind:'networks', title, entries:[{action, resolved}]}
          | {kind:'list', title, items:[string]}
RuleRow   = normal rule row ({id>=100000,type:'rule',aclName,ruleNumber,entry,scored,interface:'vpn-filter',
            direction:'vpn-filter',implicit:false,inactive}) + usedBy: string[]
```

---

### Task 1: ASA VPN parser, build wiring, test harness

**Files:**
- Modify: `build.js` (function `vendorEngine`)
- Create: `source/vendors/asa/vpn-parser.js`
- Modify: `source/vendors/asa/parser.js:195` (the `return` of `parseASAConfig`)
- Create: `tests/run.js`, `tests/helpers.js`, `tests/fixtures/asa-vpn.cfg`, `tests/vpn-parser.test.js`

**Interfaces:**
- Consumes: `tokenize(s)`, `parseEndpoint(tokens, idx)` from `parser.js` (same vendor IIFE).
- Produces: `parseASAVpn(lines: string[]) -> {pools, groupPolicies, tunnelGroups, users, standardAcls, vpnGlobal}` (shapes above); `loadVendor(file, id)`, `fixture(name)`, `plain(x)`, `loadPage(file, cfg)` test helpers.

- [ ] **Step 1: Install jsdom ad hoc (dev only) and create the test runner + helpers**

Run: `cd D:/appdev/fwrra && npm i --no-save jsdom` (node_modules/ is already gitignored).

Create `tests/run.js`:

```js
const fs = require('fs');
const path = require('path');

(async () => {
  let failed = 0;
  const files = fs.readdirSync(__dirname).filter(f => f.endsWith('.test.js')).sort();
  for (const f of files) {
    try {
      await require(path.join(__dirname, f))();
      console.log('ok   ', f);
    } catch (e) {
      failed++;
      console.error('FAIL ', f, '\n', e.stack);
    }
  }
  process.exit(failed ? 1 : 0);
})();
```

Create `tests/helpers.js`:

```js
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
```

- [ ] **Step 2: Create the shared fixture `tests/fixtures/asa-vpn.cfg`**

```
ASA Version 9.16(1)
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
object network SRV_DB
 host 10.0.0.50
object-group network ENG_SERVERS
 network-object host 10.0.0.60
 network-object host 10.0.0.61
ip local pool ENG_POOL 10.9.0.10-10.9.0.59 mask 255.255.255.0
ip local pool CONTRACTOR_POOL 10.9.1.10-10.9.1.29 mask 255.255.255.0
access-list ENG_FILTER extended permit tcp 10.9.0.0 255.255.255.0 object-group ENG_SERVERS eq 22
access-list ENG_FILTER extended permit ip 10.9.0.0 255.255.255.0 any log
access-list CONTR_FILTER extended permit tcp 10.9.1.0 255.255.255.0 host 10.0.0.50 eq 1433 log
access-list CONTR_FILTER extended permit tcp 10.9.1.0 255.255.255.0 host 10.0.0.50 eq 22 inactive
access-list CONTR_FILTER extended deny ip any any log
access-list ENG_SPLIT standard permit 10.0.0.0 255.255.255.0
access-list CONTR_SPLIT standard permit 192.168.100.0 255.255.255.0
access-list OUT_IN extended deny ip any any log
access-group OUT_IN in interface outside
group-policy DfltGrpPolicy attributes
 vpn-tunnel-protocol ssl-client
 split-tunnel-policy tunnelall
group-policy ENG_GP internal
group-policy ENG_GP attributes
 vpn-filter value ENG_FILTER
 split-tunnel-policy tunnelspecified
 split-tunnel-network-list value ENG_SPLIT
 address-pools value ENG_POOL
 vpn-tunnel-protocol ssl-client ikev2
 vpn-simultaneous-logins 2
 dns-server value 10.0.0.53
 webvpn
  anyconnect keep-installer installed
group-policy CONTR_GP internal
group-policy CONTR_GP attributes
 vpn-filter value CONTR_FILTER
 split-tunnel-policy excludespecified
 split-tunnel-network-list value CONTR_SPLIT
group-policy OPEN_GP internal
group-policy OPEN_GP attributes
 vpn-filter none
 split-tunnel-policy tunnelspecified
group-policy INHERIT_GP internal
group-policy INHERIT_GP attributes
 dns-server value 10.0.0.53
tunnel-group ENG type remote-access
tunnel-group ENG general-attributes
 address-pool ENG_POOL
 default-group-policy ENG_GP
 authentication-server-group RADIUS1
tunnel-group ENG webvpn-attributes
 group-alias Engineering enable
tunnel-group CONTR type remote-access
tunnel-group CONTR general-attributes
 address-pool CONTRACTOR_POOL
 default-group-policy CONTR_GP
tunnel-group OPEN type remote-access
tunnel-group OPEN general-attributes
 address-pool ENG_POOL
 default-group-policy OPEN_GP
tunnel-group INH type remote-access
tunnel-group INH general-attributes
 address-pool CONTRACTOR_POOL
 default-group-policy INHERIT_GP
tunnel-group 198.51.100.7 type ipsec-l2l
username alice password xxxx encrypted
username alice attributes
 vpn-group-policy CONTR_GP
 vpn-filter value ENG_FILTER
 group-lock value ENG
 vpn-framed-ip-address 10.9.0.99 255.255.255.0
sysopt connection permit-vpn
webvpn
 enable outside
 anyconnect enable
 tunnel-group-list enable
```

- [ ] **Step 3: Write the failing parser test `tests/vpn-parser.test.js`**

```js
const assert = require('assert');
const { loadVendor, fixture, plain } = require('./helpers');

module.exports = async () => {
  const asa = loadVendor('fwrra-asa.html', 'asa');
  const c = plain(asa.parse(fixture('asa-vpn.cfg')));

  // pools
  assert.deepStrictEqual(c.pools.ENG_POOL,
    { name: 'ENG_POOL', start: '10.9.0.10', end: '10.9.0.59', mask: '255.255.255.0', count: 50 });
  assert.strictEqual(c.pools.CONTRACTOR_POOL.count, 20);

  // group-policies
  const eng = c.groupPolicies.ENG_GP;
  assert.deepStrictEqual(eng.vpnFilter, { mode: 'value', acl: 'ENG_FILTER' });
  assert.strictEqual(eng.splitPolicy, 'tunnelspecified');
  assert.deepStrictEqual(eng.splitAcl, { mode: 'value', acl: 'ENG_SPLIT' });
  assert.deepStrictEqual(eng.addressPools, ['ENG_POOL']);
  assert.deepStrictEqual(eng.tunnelProtocols, ['ssl-client', 'ikev2']);
  assert.deepStrictEqual(eng.dnsServers, ['10.0.0.53']);
  assert.strictEqual(eng.simultaneousLogins, 2);
  assert.deepStrictEqual(eng.rawAttrs, [], 'nested webvpn block must be skipped, not raw');
  assert.deepStrictEqual(c.groupPolicies.OPEN_GP.vpnFilter, { mode: 'none' });
  assert.strictEqual(c.groupPolicies.INHERIT_GP.vpnFilter, undefined);
  assert.strictEqual(c.groupPolicies.DfltGrpPolicy.splitPolicy, 'tunnelall');

  // tunnel-groups
  const t = c.tunnelGroups.ENG;
  assert.strictEqual(t.type, 'remote-access');
  assert.deepStrictEqual(t.addressPools, ['ENG_POOL']);
  assert.strictEqual(t.defaultGroupPolicy, 'ENG_GP');
  assert.strictEqual(t.authServerGroup, 'RADIUS1');
  assert.deepStrictEqual(t.aliases, ['Engineering']);
  assert.strictEqual(c.tunnelGroups['198.51.100.7'].type, 'ipsec-l2l');

  // users (password never stored)
  assert.strictEqual(c.users.alice.vpnGroupPolicy, 'CONTR_GP');
  assert.deepStrictEqual(c.users.alice.vpnFilter, { mode: 'value', acl: 'ENG_FILTER' });
  assert.strictEqual(c.users.alice.groupLock, 'ENG');
  assert.deepStrictEqual(c.users.alice.framedIp, { ip: '10.9.0.99', mask: '255.255.255.0' });
  assert.ok(!JSON.stringify(c).includes('xxxx'), 'password must not be stored');

  // standard ACLs kept separate from extended ACLs (main rule table unaffected)
  assert.deepStrictEqual(c.standardAcls.ENG_SPLIT, [{
    action: 'permit',
    src: { kind: 'subnet', address: '10.0.0.0', mask: '255.255.255.0' },
    raw: 'access-list ENG_SPLIT standard permit 10.0.0.0 255.255.255.0',
  }]);
  assert.strictEqual(c.acls.ENG_SPLIT, undefined);
  assert.strictEqual(c.acls.ENG_FILTER.length, 2);
  assert.strictEqual(c.accessGroups.length, 1);

  // globals
  assert.deepStrictEqual(c.vpnGlobal, {
    permitVpn: true, permitVpnExplicit: true,
    webvpnEnabledOn: ['outside'], anyconnectEnabled: true, tunnelGroupList: true,
  });

  // Review focus: CRLF line endings parse identically
  const crlf = plain(asa.parse(fixture('asa-vpn.cfg').replace(/\n/g, '\r\n')));
  assert.deepStrictEqual(crlf.pools, c.pools);
  assert.deepStrictEqual(crlf.groupPolicies, c.groupPolicies);
  assert.deepStrictEqual(crlf.tunnelGroups, c.tunnelGroups);

  // Review focus: inverted pool range clamps to 0, never negative
  const inv = plain(asa.parse('ip local pool BAD 10.1.1.50-10.1.1.10 mask 255.255.255.0\n'));
  assert.strictEqual(inv.pools.BAD.count, 0);

  // Explicit "no sysopt connection permit-vpn"
  const no = plain(asa.parse('no sysopt connection permit-vpn\n'));
  assert.strictEqual(no.vpnGlobal.permitVpn, false);
  assert.strictEqual(no.vpnGlobal.permitVpnExplicit, true);

  // No VPN content at all -> empty collections, defaults
  const empty = plain(asa.parse('interface Gi0/0\n nameif outside\n security-level 0\n'));
  assert.deepStrictEqual(empty.pools, {});
  assert.strictEqual(empty.vpnGlobal.permitVpn, true);
  assert.strictEqual(empty.vpnGlobal.permitVpnExplicit, false);
};
```

- [ ] **Step 4: Run it to verify it fails**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: `FAIL vpn-parser.test.js` with `TypeError: Cannot read properties of undefined (reading 'ENG_POOL')` (config has no `pools` yet).

- [ ] **Step 5: Wire optional vendor files into `build.js`**

Replace the body of `vendorEngine`'s file loading (the `const body = ...` line) so it reads:

```js
  // parser.js and resolve.js are required; vpn-parser.js / vpn-resolve.js are
  // optional per-vendor extras. Order matters only for top-level `const`s:
  // function declarations hoist within the vendor IIFE.
  const ORDER = ['parser.js', 'vpn-parser.js', 'resolve.js', 'vpn-resolve.js'];
  const REQUIRED = ['parser.js', 'resolve.js'];
  const files = ORDER.filter(f => REQUIRED.includes(f) || fs.existsSync(path.join(SRC, ...dir, f)));
  const body = files.map(f => read(...dir, f)).join('\n');
```

(Delete the old `const body = [read(...dir, 'parser.js'), read(...dir, 'resolve.js')].join('\n');`.)

- [ ] **Step 6: Create `source/vendors/asa/vpn-parser.js`**

```js
// ============================================================
// ASA remote-access VPN (AnyConnect) grammar
// ============================================================
// Parses: ip local pool, group-policy (+attributes), tunnel-group (+general-
// and webvpn-attributes), username <n> attributes, standard ACLs (used by
// split tunneling), sysopt connection permit-vpn, and global webvpn.
// Runs as its own pass over the same line array as parseASAConfig. Uses
// tokenize()/parseEndpoint() from parser.js (same vendor IIFE).

function vpnIpToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
}

// Indented sub-block following lines[i]; each item keeps its indent so nested
// sub-blocks (e.g. `webvpn` under a group-policy) can be skipped.
function vpnBlock(lines, i) {
  const block = [];
  let j = i + 1;
  while (j < lines.length && /^\s+\S/.test(lines[j])) {
    block.push({ text: lines[j].trim(), indent: lines[j].match(/^\s*/)[0].length });
    j++;
  }
  return { block, nextIdx: j };
}

// "value NAME" -> {mode:'value', acl:NAME}; "none" -> {mode:'none'}; else undefined
function vpnRef(tokens) {
  if (tokens[0] === 'none') return { mode: 'none' };
  if (tokens[0] === 'value' && tokens[1]) return { mode: 'value', acl: tokens[1] };
  return undefined;
}

function applyGroupPolicyAttrs(gp, block) {
  let skipIndent = -1;
  for (const { text, indent } of block) {
    if (skipIndent >= 0) { if (indent > skipIndent) continue; skipIndent = -1; }
    if (text === 'webvpn') { skipIndent = indent; continue; }
    const t = tokenize(text);
    const key = t[0];
    let r;
    if (key === 'vpn-filter' && (r = vpnRef(t.slice(1)))) gp.vpnFilter = r;
    else if (key === 'split-tunnel-policy' && t[1]) gp.splitPolicy = t[1];
    else if (key === 'split-tunnel-network-list' && (r = vpnRef(t.slice(1)))) gp.splitAcl = r;
    else if (key === 'address-pools' && t[1] === 'value') gp.addressPools = t.slice(2);
    else if (key === 'address-pools' && t[1] === 'none') gp.addressPools = [];
    else if (key === 'vpn-tunnel-protocol') gp.tunnelProtocols = t.slice(1);
    else if (key === 'dns-server' && t[1] === 'value') gp.dnsServers = t.slice(2);
    else if (key === 'dns-server' && t[1] === 'none') gp.dnsServers = [];
    else if (key === 'vpn-simultaneous-logins' && /^\d+$/.test(t[1] || '')) gp.simultaneousLogins = parseInt(t[1], 10);
    else gp.rawAttrs.push(text);
  }
}

function applyUserAttrs(u, block) {
  for (const { text } of block) {
    const t = tokenize(text);
    const key = t[0];
    let r;
    if (key === 'vpn-group-policy' && t[1]) u.vpnGroupPolicy = t[1];
    else if (key === 'vpn-filter' && (r = vpnRef(t.slice(1)))) u.vpnFilter = r;
    else if (key === 'group-lock' && t[1] === 'value' && t[2]) u.groupLock = t[2];
    else if (key === 'vpn-framed-ip-address' && t[1]) u.framedIp = { ip: t[1], mask: t[2] || null };
    else u.rawAttrs.push(text);
  }
}

function parseASAVpn(lines) {
  const pools = {}, groupPolicies = {}, tunnelGroups = {}, users = {}, standardAcls = {};
  const vpnGlobal = { permitVpn: true, permitVpnExplicit: false, webvpnEnabledOn: [], anyconnectEnabled: false, tunnelGroupList: false };
  const gpOf = (name) => (groupPolicies[name] = groupPolicies[name] || { name, rawAttrs: [] });
  const tgOf = (name) => (tunnelGroups[name] = tunnelGroups[name] ||
    { name, type: null, addressPools: [], defaultGroupPolicy: null, authServerGroup: null, aliases: [], urls: [] });

  let i = 0;
  while (i < lines.length) {
    const rawLine = lines[i];
    const line = rawLine.trim();
    // Only top-level (non-indented) lines open constructs; nested lines are
    // consumed by vpnBlock().
    if (!line || line[0] === '!' || /^\s/.test(rawLine)) { i++; continue; }
    let m;

    if ((m = line.match(/^ip\s+local\s+pool\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)(?:\s+mask\s+(\S+))?/))) {
      pools[m[1]] = { name: m[1], start: m[2], end: m[3], mask: m[4] || null,
        count: Math.max(0, vpnIpToInt(m[3]) - vpnIpToInt(m[2]) + 1) };
      i++; continue;
    }

    if ((m = line.match(/^access-list\s+(\S+)\s+standard\s+(permit|deny)\s+(.+)$/))) {
      const endpoint = parseEndpoint(tokenize(m[3]), 0).endpoint;
      (standardAcls[m[1]] = standardAcls[m[1]] || []).push({ action: m[2], src: endpoint, raw: line });
      i++; continue;
    }

    if ((m = line.match(/^group-policy\s+(\S+)\s+(internal|external)\b/))) {
      gpOf(m[1]).kind = m[2];
      i++; continue;
    }
    if ((m = line.match(/^group-policy\s+(\S+)\s+attributes\s*$/))) {
      const { block, nextIdx } = vpnBlock(lines, i);
      applyGroupPolicyAttrs(gpOf(m[1]), block);
      i = nextIdx; continue;
    }

    if ((m = line.match(/^tunnel-group\s+(\S+)\s+type\s+(\S+)/))) {
      tgOf(m[1]).type = m[2];
      i++; continue;
    }
    if ((m = line.match(/^tunnel-group\s+(\S+)\s+(general-attributes|webvpn-attributes)\s*$/))) {
      const tg = tgOf(m[1]);
      const { block, nextIdx } = vpnBlock(lines, i);
      for (const { text } of block) {
        const t = tokenize(text);
        const noIf = t.slice(1).filter(x => !x.startsWith('('));
        if (m[2] === 'general-attributes') {
          if (t[0] === 'address-pool') tg.addressPools = noIf;
          else if (t[0] === 'default-group-policy' && t[1]) tg.defaultGroupPolicy = t[1];
          else if (t[0] === 'authentication-server-group' && noIf.length) tg.authServerGroup = noIf.join(' ');
        } else {
          if (t[0] === 'group-alias' && t[1] && t[2] !== 'disable') tg.aliases.push(t[1]);
          else if (t[0] === 'group-url' && t[1] && t[2] !== 'disable') tg.urls.push(t[1]);
        }
      }
      i = nextIdx; continue;
    }

    if ((m = line.match(/^username\s+(\S+)\s+attributes\s*$/))) {
      const u = users[m[1]] = users[m[1]] || { name: m[1], rawAttrs: [] };
      const { block, nextIdx } = vpnBlock(lines, i);
      applyUserAttrs(u, block);
      i = nextIdx; continue;
    }

    if (/^no\s+sysopt\s+connection\s+permit-vpn\b/.test(line)) {
      vpnGlobal.permitVpn = false; vpnGlobal.permitVpnExplicit = true; i++; continue;
    }
    if (/^sysopt\s+connection\s+permit-vpn\b/.test(line)) {
      vpnGlobal.permitVpn = true; vpnGlobal.permitVpnExplicit = true; i++; continue;
    }
    if (/^webvpn\s*$/.test(line)) {
      const { block, nextIdx } = vpnBlock(lines, i);
      for (const { text } of block) {
        let w;
        if ((w = text.match(/^enable\s+(\S+)/))) vpnGlobal.webvpnEnabledOn.push(w[1]);
        else if (/^anyconnect\s+enable\b/.test(text)) vpnGlobal.anyconnectEnabled = true;
        else if (/^tunnel-group-list\s+enable\b/.test(text)) vpnGlobal.tunnelGroupList = true;
      }
      i = nextIdx; continue;
    }

    i++;
  }

  return { pools, groupPolicies, tunnelGroups, users, standardAcls, vpnGlobal };
}
```

- [ ] **Step 7: Merge the VPN pass into `parseASAConfig`** (`source/vendors/asa/parser.js`)

Change the final line of `parseASAConfig`:

```js
  return { objects, groups, interfaces, acls, accessGroups, ...parseASAVpn(lines) };
```

- [ ] **Step 8: Rebuild and run tests**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: `ok    vpn-parser.test.js`, exit code 0.

- [ ] **Step 9: Commit (local only)**

```bash
cd D:/appdev/fwrra
git add build.js source tests dist
git commit -m "Parse ASA remote-access VPN config (pools, group-policies, tunnel-groups, users)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: VPN identity resolution — inheritance, split-tunnel state, pools, findings

**Files:**
- Create: `source/vendors/asa/vpn-resolve.js`
- Modify: `source/vendors/asa/resolve.js` (the final `registerVendor({...})` call)
- Create: `tests/vpn-inventory.test.js`

**Interfaces:**
- Consumes: `config` from Task 1; `resolveEndpoint(config, endpoint)` from `resolve.js`.
- Produces: `buildVpnInventory(config, options) -> Inventory | null` with sections `tunnel-groups`, `group-policies`, `users`, `pools`, `findings` (the `filter-rules` section is added in Task 3). Helpers used by Task 3: `vpnIdentityInfo(config, kind, owner)` returning `{kind, name, owner, chain, filter:{aclName|null, source, explicitNone, missing?, entries|null}, split, poolSel, pools, poolTotal, protocols, logins, dns}`; `vpnCell(text, tone, note)`; constants `VPN_DFLT`, `VPN_ROW_ID_BASE`. Registered vendor gains `buildInventory: buildVpnInventory`.

- [ ] **Step 1: Write the failing test `tests/vpn-inventory.test.js`**

```js
const assert = require('assert');
const { loadVendor, fixture, plain } = require('./helpers');

const ct = (c) => (c && typeof c === 'object') ? c.text : c;
const note = (c) => (c && typeof c === 'object') ? c.note : undefined;
const tone = (c) => (c && typeof c === 'object') ? c.tone : undefined;

module.exports = async () => {
  const asa = loadVendor('fwrra-asa.html', 'asa');
  assert.strictEqual(typeof asa.buildInventory, 'function', 'ASA must register buildInventory');
  const inv = plain(asa.buildInventory(asa.parse(fixture('asa-vpn.cfg')), {}));
  const sec = (id) => inv.sections.find(s => s.id === id);
  const row = (id, name) => sec(id).rows.find(r => ct(r.cells.name) === name);

  assert.strictEqual(inv.title, 'Remote-access VPN');
  assert.deepStrictEqual(inv.sections.map(s => s.id),
    ['tunnel-groups', 'group-policies', 'users', 'pools', 'findings']);

  // tunnel-groups: site-to-site excluded, 4 remote-access rows
  assert.strictEqual(sec('tunnel-groups').rows.length, 4);
  assert.strictEqual(row('tunnel-groups', '198.51.100.7'), undefined);

  // ENG: split include, comes from its group-policy; filter from group-policy
  const eng = row('tunnel-groups', 'ENG');
  assert.strictEqual(ct(eng.cells.split), 'Enabled (include)');
  assert.strictEqual(note(eng.cells.split), 'from ENG_GP');
  assert.strictEqual(ct(eng.cells.filter), 'ENG_FILTER');
  assert.ok(ct(eng.cells.pools).includes('ENG_POOL') && ct(eng.cells.pools).includes('50'));
  assert.strictEqual(note(eng.cells.pools), 'from ENG_GP');
  assert.ok(ct(eng.cells.alias).includes('Engineering'));

  // CONTR: split exclude; pool comes from the tunnel-group itself (no note)
  const contr = row('tunnel-groups', 'CONTR');
  assert.strictEqual(ct(contr.cells.split), 'Enabled (exclude)');
  assert.strictEqual(note(contr.cells.pools), undefined);

  // INH: nothing set -> inherits DfltGrpPolicy tunnelall -> Disabled
  const inh = row('tunnel-groups', 'INH');
  assert.strictEqual(ct(inh.cells.split), 'Disabled');
  assert.strictEqual(note(inh.cells.split), 'inherited: DfltGrpPolicy');
  assert.strictEqual(ct(inh.cells.filter), 'none');
  assert.strictEqual(tone(inh.cells.filter), 'warn');

  // OPEN: explicit "vpn-filter none" and split enabled with no list -> flagged
  const open = row('tunnel-groups', 'OPEN');
  assert.strictEqual(ct(open.cells.filter), 'none (explicit)');
  assert.strictEqual(ct(open.cells.split), 'Enabled (include)');
  assert.strictEqual(tone(open.cells.split), 'warn');

  // group-policies: referenced ones + DfltGrpPolicy
  assert.deepStrictEqual(sec('group-policies').rows.map(r => ct(r.cells.name)),
    ['DfltGrpPolicy', 'ENG_GP', 'CONTR_GP', 'OPEN_GP', 'INHERIT_GP']);
  const dflt = row('group-policies', 'DfltGrpPolicy');
  assert.strictEqual(ct(dflt.cells.split), 'Disabled');
  assert.strictEqual(note(dflt.cells.split), undefined, 'own value => no note');
  assert.strictEqual(ct(row('group-policies', 'ENG_GP').cells.logins), '2');

  // user override: own filter, framed IP, split from its group-policy
  const alice = row('users', 'alice');
  assert.strictEqual(ct(alice.cells.groupPolicy), 'CONTR_GP');
  assert.strictEqual(ct(alice.cells.filter), 'ENG_FILTER');
  assert.strictEqual(note(alice.cells.filter), undefined);
  assert.strictEqual(ct(alice.cells.pools), '10.9.0.99 (framed)');
  assert.strictEqual(ct(alice.cells.split), 'Enabled (exclude)');
  assert.strictEqual(note(alice.cells.split), 'from CONTR_GP');

  // pools
  const ep = row('pools', 'ENG_POOL');
  assert.strictEqual(ct(ep.cells.count), '50');
  assert.ok(ct(ep.cells.usedBy).includes('tunnel-group ENG'));

  // detail blocks exist and the split networks resolve
  assert.ok(eng.detail.some(b => b.kind === 'networks' && b.entries.length === 1));

  // findings (factual, not scored)
  const f = sec('findings').rows.map(r => `${ct(r.cells.level)}|${ct(r.cells.subject)}|${ct(r.cells.finding)}`);
  assert.ok(f.some(x => x.startsWith('info|Global|sysopt connection permit-vpn')));
  assert.ok(f.some(x => /warn\|tunnel-group OPEN\|no vpn-filter \(explicit "none"\)/.test(x)));
  assert.ok(f.some(x => /warn\|tunnel-group INH\|no vpn-filter \(unset\)/.test(x)));
  assert.ok(f.some(x => /warn\|tunnel-group OPEN\|split tunneling enabled but no split-tunnel-network-list/.test(x)));

  // Review focus: no VPN content at all -> null (no tab)
  assert.strictEqual(asa.buildInventory(asa.parse('interface Gi0/0\n nameif outside\n security-level 0\n'), {}), null);

  // Review focus: dangling references -> warn findings, no exception
  const dangling = [
    'ip local pool P1 10.1.1.1-10.1.1.5 mask 255.255.255.0',
    'tunnel-group T1 type remote-access',
    'tunnel-group T1 general-attributes',
    ' address-pool NOPOOL',
    ' default-group-policy NOGP',
    'group-policy G2 internal',
    'group-policy G2 attributes',
    ' vpn-filter value NOACL',
    ' split-tunnel-policy tunnelspecified',
    ' split-tunnel-network-list value NOSPLIT',
    'tunnel-group T2 type remote-access',
    'tunnel-group T2 general-attributes',
    ' default-group-policy G2',
    '',
  ].join('\n');
  const dinv = plain(asa.buildInventory(asa.parse(dangling), {}));
  const df = dinv.sections.find(s => s.id === 'findings').rows.map(r => `${ct(r.cells.subject)}|${ct(r.cells.finding)}`);
  assert.ok(df.some(x => /tunnel-group T1\|default-group-policy NOGP is not defined/.test(x)));
  assert.ok(df.some(x => /tunnel-group T1\|address pool NOPOOL is not defined/.test(x)));
  assert.ok(df.some(x => /tunnel-group T2\|vpn-filter ACL NOACL is not defined/.test(x)));
  assert.ok(df.some(x => /tunnel-group T2\|split tunneling enabled but split-tunnel ACL NOSPLIT is not defined/.test(x)));
};
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: `FAIL vpn-inventory.test.js` with `AssertionError: ASA must register buildInventory`.

- [ ] **Step 3: Create `source/vendors/asa/vpn-resolve.js`**

```js
// ============================================================
// ASA remote-access VPN (AnyConnect) inventory
// ============================================================
// buildVpnInventory(config) -> Inventory | null. See shared/registry.js for
// the vendor-neutral Inventory shape ui.js renders.
//
// Inheritance (ASA): user -> group-policy -> DfltGrpPolicy. A value of
// `undefined` on an object means "unset, keep looking"; an explicit `none`
// is a real value that stops the search.

const VPN_DFLT = 'DfltGrpPolicy';
const VPN_ROW_ID_BASE = 100000;

function vpnIsRemoteAccess(tg) { return tg.type === 'remote-access' || tg.type === 'ipsec-ra'; }

function vpnCell(text, tone, note) {
  const c = { text };
  if (tone) c.tone = tone;
  if (note) c.note = note;
  return c;
}

function vpnChain(config, ownerKind, owner) {
  const chain = [];
  let gpName = null;
  if (ownerKind === 'user') {
    chain.push({ source: 'user', label: owner.name, obj: owner });
    gpName = owner.vpnGroupPolicy || null;
  } else if (ownerKind === 'tunnel-group') {
    gpName = owner.defaultGroupPolicy || null;
  } else {
    chain.push({ source: 'group-policy', label: owner.name, obj: owner });
  }
  if (ownerKind !== 'group-policy' && gpName && config.groupPolicies[gpName]) {
    chain.push({ source: 'group-policy', label: gpName, obj: config.groupPolicies[gpName] });
  }
  const dflt = config.groupPolicies[VPN_DFLT];
  if (dflt && !chain.some(l => l.obj === dflt)) {
    chain.push({ source: 'DfltGrpPolicy', label: VPN_DFLT, obj: dflt });
  }
  return chain;
}

function vpnEffective(chain, getter) {
  for (const link of chain) {
    const v = getter(link.obj);
    if (v !== undefined) return { value: v, source: link.source, label: link.label };
  }
  return { value: undefined, source: 'default', label: null };
}

// Where did an effective value come from, relative to the row that shows it?
function vpnNote(eff, ownKind) {
  if (eff.source === 'default') return 'default';
  if (eff.source === ownKind) return undefined;
  if (eff.source === 'DfltGrpPolicy') return 'inherited: DfltGrpPolicy';
  return 'from ' + eff.label;
}

function vpnAclNetworks(config, name) {
  if (config.standardAcls[name]) {
    return config.standardAcls[name].map(e => ({ action: e.action, resolved: resolveEndpoint(config, e.src) }));
  }
  if (config.acls[name]) { // extended ACL used as a split-tunnel list: show destinations
    return config.acls[name].filter(e => !e.remark).map(e => ({ action: e.action, resolved: resolveEndpoint(config, e.dst) }));
  }
  return null;
}

function vpnFilterInfo(config, chain) {
  const f = vpnEffective(chain, o => o.vpnFilter);
  if (f.value === undefined || f.value.mode === 'none') {
    return { aclName: null, source: f.source, label: f.label, explicitNone: f.value !== undefined, entries: null };
  }
  const acl = config.acls[f.value.acl];
  return {
    aclName: f.value.acl, source: f.source, label: f.label, explicitNone: false,
    missing: !acl, entries: acl ? acl.filter(e => !e.remark) : [],
  };
}

// Split tunneling: tunnelall = Disabled; tunnelspecified/excludespecified =
// Enabled (include/exclude). Unset everywhere = DfltGrpPolicy default tunnelall.
function vpnSplitState(config, chain) {
  const pol = vpnEffective(chain, o => o.splitPolicy);
  const policy = pol.value || 'tunnelall';
  const enabled = policy === 'tunnelspecified' || policy === 'excludespecified';
  const mode = policy === 'tunnelspecified' ? 'include' : policy === 'excludespecified' ? 'exclude' : 'off';
  const acl = vpnEffective(chain, o => o.splitAcl);
  const out = {
    policy, enabled, mode,
    text: enabled ? `Enabled (${mode})` : 'Disabled', // display text; `label` stays the provenance name used by vpnNote()
    source: pol.value ? pol.source : 'default', label: pol.label,
    aclName: acl.value && acl.value.acl ? acl.value.acl : null,
    networks: [], problem: null,
  };
  if (enabled) {
    if (!acl.value || acl.value.mode === 'none') {
      out.problem = 'no split-tunnel-network-list is configured';
    } else {
      const nets = vpnAclNetworks(config, acl.value.acl);
      if (!nets) out.problem = `split-tunnel ACL ${acl.value.acl} is not defined`;
      else if (!nets.length) out.problem = `split-tunnel ACL ${acl.value.acl} is empty`;
      else out.networks = nets;
    }
  }
  return out;
}

function vpnPools(ownerKind, owner, chain) {
  if (ownerKind === 'user' && owner.framedIp) {
    return { names: [], single: owner.framedIp.ip, source: 'user', label: owner.name };
  }
  const eff = vpnEffective(chain, o => o.addressPools);
  if (eff.value !== undefined && eff.value.length) {
    return { names: eff.value, single: null, source: eff.source, label: eff.label };
  }
  if (ownerKind === 'tunnel-group' && owner.addressPools.length) {
    return { names: owner.addressPools, single: null, source: 'tunnel-group', label: owner.name };
  }
  return { names: [], single: null, source: 'default', label: null };
}

function vpnIdentityInfo(config, kind, owner) {
  const chain = vpnChain(config, kind, owner);
  const poolSel = vpnPools(kind, owner, chain);
  const pools = poolSel.names.map(n => ({ name: n, pool: config.pools[n] || null }));
  const poolTotal = pools.reduce((s, p) => s + (p.pool ? p.pool.count : 0), 0) + (poolSel.single ? 1 : 0);
  return {
    kind, name: owner.name, owner, chain,
    filter: vpnFilterInfo(config, chain),
    split: vpnSplitState(config, chain),
    poolSel, pools, poolTotal,
    protocols: vpnEffective(chain, o => o.tunnelProtocols),
    logins: vpnEffective(chain, o => o.simultaneousLogins),
    dns: vpnEffective(chain, o => o.dnsServers),
  };
}

function vpnPoolsText(info) {
  if (info.poolSel.single) return `${info.poolSel.single} (framed)`;
  if (!info.pools.length) return info.kind === 'user' ? '\u2014 (per tunnel-group at login)' : '\u2014';
  return info.pools.map(p => p.pool
    ? `${p.name} (${p.pool.start}\u2013${p.pool.end}, ${p.pool.count})`
    : `${p.name} (not defined)`).join(', ');
}

function vpnFilterText(info) {
  if (info.filter.aclName) return info.filter.aclName;
  return info.filter.explicitNone ? 'none (explicit)' : 'none';
}

function vpnJoin(eff) { return eff.value === undefined ? '\u2014' : (Array.isArray(eff.value) ? (eff.value.join(', ') || 'none') : String(eff.value)); }

// Cells shared by tunnel-group / group-policy / user rows
function vpnCommonCells(info) {
  const k = info.kind;
  return {
    pools: vpnCell(vpnPoolsText(info), null, vpnNote(info.poolSel, k)),
    filter: vpnCell(vpnFilterText(info), info.filter.aclName ? null : 'warn', vpnNote(info.filter, k)),
    split: vpnCell(info.split.text, info.split.problem ? 'warn' : null, vpnNote(info.split, k)),
  };
}

function vpnCommonDetail(info) {
  const k = info.kind;
  const pairs = [
    ['Address pool(s)', vpnCell(vpnPoolsText(info), null, vpnNote(info.poolSel, k))],
    ['VPN filter', vpnCell(vpnFilterText(info), info.filter.aclName ? null : 'warn', vpnNote(info.filter, k))],
    ['Split tunneling', vpnCell(info.split.text + (info.split.aclName ? `, list ${info.split.aclName}` : ''), info.split.problem ? 'warn' : null, vpnNote(info.split, k))],
    ['Tunnel protocols', vpnCell(vpnJoin(info.protocols), null, vpnNote(info.protocols, k))],
    ['Simultaneous logins', vpnCell(vpnJoin(info.logins), null, vpnNote(info.logins, k))],
    ['DNS servers', vpnCell(vpnJoin(info.dns), null, vpnNote(info.dns, k))],
  ];
  return pairs;
}

function vpnDetailBlocks(info, extraPairs) {
  const blocks = [{ kind: 'kv', title: 'Effective attributes', pairs: extraPairs.concat(vpnCommonDetail(info)) }];
  if (info.split.networks.length) {
    blocks.push({
      kind: 'networks',
      title: `Split-tunnel networks (${info.split.aclName}, ${info.split.mode === 'include' ? 'tunneled' : 'excluded from tunnel'})`,
      entries: info.split.networks,
    });
  }
  if (info.owner.rawAttrs && info.owner.rawAttrs.length) {
    blocks.push({ kind: 'list', title: 'Unmodelled attributes', items: info.owner.rawAttrs });
  }
  return blocks;
}

function vpnTunnelGroupRow(info) {
  const tg = info.owner;
  const gpName = tg.defaultGroupPolicy || VPN_DFLT;
  return {
    cells: Object.assign({
      name: tg.name,
      alias: [].concat(tg.aliases, tg.urls).join(', ') || '\u2014',
      groupPolicy: gpName,
      auth: tg.authServerGroup || '\u2014',
    }, vpnCommonCells(info)),
    detail: vpnDetailBlocks(info, [
      ['Group-policy', gpName],
      ['Group aliases', tg.aliases.join(', ') || '\u2014'],
      ['Group URLs', tg.urls.join(', ') || '\u2014'],
      ['Authentication server group', tg.authServerGroup || '\u2014'],
    ]),
  };
}

function vpnGroupPolicyRow(info) {
  const gp = info.owner;
  return {
    cells: Object.assign({
      name: gp.name,
      protocols: vpnCell(vpnJoin(info.protocols), null, vpnNote(info.protocols, 'group-policy')),
      logins: vpnCell(vpnJoin(info.logins), null, vpnNote(info.logins, 'group-policy')),
    }, vpnCommonCells(info)),
    detail: vpnDetailBlocks(info, [['Type', gp.kind || '\u2014']]),
  };
}

function vpnUserRow(info) {
  const u = info.owner;
  return {
    cells: Object.assign({
      name: u.name,
      groupPolicy: u.vpnGroupPolicy || '\u2014',
      groupLock: u.groupLock || '\u2014',
    }, vpnCommonCells(info)),
    detail: vpnDetailBlocks(info, [
      ['vpn-group-policy', u.vpnGroupPolicy || '\u2014'],
      ['group-lock', u.groupLock || '\u2014'],
      ['vpn-framed-ip-address', u.framedIp ? `${u.framedIp.ip}${u.framedIp.mask ? ' ' + u.framedIp.mask : ''}` : '\u2014'],
    ]),
  };
}

function vpnFindings(config, tgInfos, userInfos) {
  const out = [];
  const add = (level, subject, finding) => out.push({
    cells: { level: vpnCell(level, level === 'warn' ? 'warn' : 'dim'), subject, finding },
  });
  const g = config.vpnGlobal;
  add('info', 'Global', g.permitVpn
    ? `sysopt connection permit-vpn${g.permitVpnExplicit ? '' : ' (ASA default)'}: decrypted VPN traffic bypasses interface ACLs; only each identity's vpn-filter restricts it.`
    : 'sysopt connection permit-vpn is disabled: VPN traffic is also checked against interface ACLs.');
  add('info', 'Global', 'Attributes supplied by RADIUS/LDAP (pools, filters, group-policy) are not visible in the config and are not reflected here.');
  for (const info of tgInfos.concat(userInfos)) {
    const subj = `${info.kind} ${info.name}`;
    const o = info.owner;
    if (info.kind === 'tunnel-group' && o.defaultGroupPolicy && !config.groupPolicies[o.defaultGroupPolicy]) {
      add('warn', subj, `default-group-policy ${o.defaultGroupPolicy} is not defined`);
    }
    if (info.kind === 'user' && o.vpnGroupPolicy && !config.groupPolicies[o.vpnGroupPolicy]) {
      add('warn', subj, `vpn-group-policy ${o.vpnGroupPolicy} is not defined`);
    }
    if (!info.filter.aclName) {
      add('warn', subj, `no vpn-filter (${info.filter.explicitNone ? 'explicit "none"' : 'unset'}): authenticated users are not restricted by an ACL`);
    } else if (info.filter.missing) {
      add('warn', subj, `vpn-filter ACL ${info.filter.aclName} is not defined`);
    } else if (!info.filter.entries.length) {
      add('warn', subj, `vpn-filter ACL ${info.filter.aclName} has no entries`);
    }
    for (const p of info.pools) if (!p.pool) add('warn', subj, `address pool ${p.name} is not defined`);
    if (info.kind === 'tunnel-group' && !info.pools.length && !info.poolSel.single) {
      add('info', subj, 'no local address pool resolved (DHCP/AAA-assigned pools are not visible in the config)');
    }
    if (info.split.problem) add('warn', subj, `split tunneling enabled but ${info.split.problem}`);
  }
  return out;
}

function buildVpnInventory(config, options) {
  const tgs = Object.keys(config.tunnelGroups).map(k => config.tunnelGroups[k]).filter(vpnIsRemoteAccess);
  if (!tgs.length && !Object.keys(config.pools).length) return null;

  const userList = Object.keys(config.users).map(k => config.users[k])
    .filter(u => u.vpnGroupPolicy || u.vpnFilter || u.groupLock || u.framedIp);

  const gpNames = new Set();
  for (const tg of tgs) if (tg.defaultGroupPolicy && config.groupPolicies[tg.defaultGroupPolicy]) gpNames.add(tg.defaultGroupPolicy);
  for (const u of userList) if (u.vpnGroupPolicy && config.groupPolicies[u.vpnGroupPolicy]) gpNames.add(u.vpnGroupPolicy);
  if (config.groupPolicies[VPN_DFLT]) gpNames.add(VPN_DFLT);

  const tgInfos = tgs.map(tg => vpnIdentityInfo(config, 'tunnel-group', tg));
  const gpInfos = Object.keys(config.groupPolicies).filter(n => gpNames.has(n))
    .sort((a, b) => (a === VPN_DFLT ? -1 : b === VPN_DFLT ? 1 : 0))
    .map(n => vpnIdentityInfo(config, 'group-policy', config.groupPolicies[n]));
  const userInfos = userList.map(u => vpnIdentityInfo(config, 'user', u));
  const all = tgInfos.concat(gpInfos, userInfos);

  const sections = [];
  if (tgInfos.length) sections.push({
    id: 'tunnel-groups', heading: 'Tunnel-groups',
    columns: [
      { key: 'name', label: 'Tunnel-group' }, { key: 'alias', label: 'Alias / URL' },
      { key: 'pools', label: 'Address pool(s)' }, { key: 'groupPolicy', label: 'Group-policy' },
      { key: 'filter', label: 'VPN filter' }, { key: 'split', label: 'Split tunneling' },
      { key: 'auth', label: 'Auth server' },
    ],
    rows: tgInfos.map(vpnTunnelGroupRow),
  });
  if (gpInfos.length) sections.push({
    id: 'group-policies', heading: 'Group-policies',
    columns: [
      { key: 'name', label: 'Group-policy' }, { key: 'pools', label: 'Address pool(s)' },
      { key: 'filter', label: 'VPN filter' }, { key: 'split', label: 'Split tunneling' },
      { key: 'protocols', label: 'Tunnel protocols' }, { key: 'logins', label: 'Simult. logins' },
    ],
    rows: gpInfos.map(vpnGroupPolicyRow),
  });
  if (userInfos.length) sections.push({
    id: 'users', heading: 'User overrides',
    columns: [
      { key: 'name', label: 'User' }, { key: 'groupPolicy', label: 'Group-policy' },
      { key: 'groupLock', label: 'Group-lock' }, { key: 'pools', label: 'Address' },
      { key: 'filter', label: 'VPN filter' }, { key: 'split', label: 'Split tunneling' },
    ],
    rows: userInfos.map(vpnUserRow),
  });

  const poolNames = Object.keys(config.pools);
  if (poolNames.length) sections.push({
    id: 'pools', heading: 'Address pools',
    columns: [
      { key: 'name', label: 'Pool' }, { key: 'range', label: 'Range' }, { key: 'mask', label: 'Mask' },
      { key: 'count', label: 'Addresses' }, { key: 'usedBy', label: 'Used by' },
    ],
    rows: poolNames.map(n => {
      const p = config.pools[n];
      const users = all.filter(i => i.poolSel.names.includes(n)).map(i => `${i.kind} ${i.name}`);
      return { cells: { name: n, range: `${p.start}\u2013${p.end}`, mask: p.mask || '\u2014', count: String(p.count), usedBy: users.join(', ') || '\u2014' } };
    }),
  });

  // 'filter-rules' section is inserted here by Task 3.

  sections.push({
    id: 'findings', heading: 'Findings',
    columns: [{ key: 'level', label: 'Level' }, { key: 'subject', label: 'Subject' }, { key: 'finding', label: 'Finding' }],
    rows: vpnFindings(config, tgInfos, userInfos),
  });

  return { title: 'Remote-access VPN', sections };
}
```

- [ ] **Step 4: Register the hook in `source/vendors/asa/resolve.js`**

In the final `registerVendor({...})` object add one line after `detectRole`:

```js
  buildInventory: buildVpnInventory,
```

- [ ] **Step 5: Rebuild and run tests**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: both `vpn-parser.test.js` and `vpn-inventory.test.js` print `ok`.
If `row('group-policies', ...)` order assertion fails, confirm the `.sort` puts `DfltGrpPolicy` first and the rest keep config order (`Array.prototype.sort` is stable in Node ≥ 11).

- [ ] **Step 6: Commit (local only)**

```bash
cd D:/appdev/fwrra
git add source tests dist
git commit -m "Resolve ASA VPN identities: inheritance, split-tunnel state, pools, findings

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Scored VPN-filter rule rows

**Files:**
- Modify: `source/vendors/asa/vpn-resolve.js` (add `vpnFilterRuleRows`, insert section)
- Modify: `tests/vpn-inventory.test.js` (append assertions)
- Modify: `source/shared/registry.js` (document the hook)

**Interfaces:**
- Consumes: `vpnIdentityInfo` results (`info.filter.aclName`, `info.kind`, `info.name`), `scoreEntry(config, entry, direction)`, `resolveEndpoint`, `resolveRuleServices` from `resolve.js`; `VPN_ROW_ID_BASE`.
- Produces: section `{id:'filter-rules', heading:'VPN filter rules', ruleRows: RuleRow[]}` placed between `pools` and `findings`.

- [ ] **Step 1: Append failing assertions to `tests/vpn-inventory.test.js`** (inside the exported async function, before the closing `};`)

```js
  // ---- filter rule rows (scored) ----
  const fr = sec('filter-rules');
  assert.ok(fr && Array.isArray(fr.ruleRows), 'filter-rules section with ruleRows');
  assert.deepStrictEqual(inv.sections.map(s => s.id),
    ['tunnel-groups', 'group-policies', 'users', 'pools', 'filter-rules', 'findings']);
  // ENG_FILTER (2 ACEs) + CONTR_FILTER (3 ACEs), one row per distinct ACE
  assert.strictEqual(fr.ruleRows.length, 5);
  assert.ok(fr.ruleRows.every(r => r.id >= 100000 && r.type === 'rule' && r.interface === 'vpn-filter'));
  assert.strictEqual(new Set(fr.ruleRows.map(r => r.id)).size, 5, 'row ids unique');
  const e1 = fr.ruleRows[0], e2 = fr.ruleRows[1];
  assert.strictEqual(e1.aclName, 'ENG_FILTER');
  assert.strictEqual(e1.ruleNumber, 1);
  assert.deepStrictEqual(e1.usedBy, ['tunnel-group ENG', 'group-policy ENG_GP', 'user alice']);
  assert.strictEqual(e1.scored.action, 'permit');
  assert.strictEqual(typeof e1.scored.score, 'number');
  assert.ok(e2.scored.score > e1.scored.score, 'subnet->any ip must outscore subnet->2 hosts ssh? check');
  const contr = fr.ruleRows.filter(r => r.aclName === 'CONTR_FILTER');
  assert.deepStrictEqual(contr[0].usedBy, ['tunnel-group CONTR', 'group-policy CONTR_GP']);
  assert.strictEqual(contr[1].inactive, true);
  assert.strictEqual(contr[2].scored.action, 'deny');
  assert.strictEqual(contr[2].scored.score, 0);
  assert.strictEqual(contr[2].scored.srcResolved.kind, 'any', 'deny rows must carry resolved endpoints');
  assert.strictEqual(contr[2].scored.services.length >= 1, true);
```

> NOTE for the implementer: the `e2.scored.score > e1.scored.score` assertion encodes "ip to any (log) scores above ssh to a 2-host group". If the shared scoring table makes that false, print both scores and, if the ordering is merely different (not a bug), replace the comparison with `assert.notStrictEqual(e1.scored.score, e2.scored.score)` and fix the failure message — do not change scoring logic.

- [ ] **Step 2: Run to verify it fails**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: `FAIL vpn-inventory.test.js` — `filter-rules section with ruleRows`.

- [ ] **Step 3: Add `vpnFilterRuleRows` to `vpn-resolve.js`** (above `buildVpnInventory`)

```js
// One scored rule row per distinct (vpn-filter ACL, ACE), with the identities
// that use it. Direction is 'internal' (client -> internal, symmetric blend).
function vpnFilterRuleRows(config, infos) {
  const usedBy = new Map(); // aclName -> ["tunnel-group ENG", ...]
  for (const info of infos) {
    if (!info.filter.aclName) continue;
    if (!usedBy.has(info.filter.aclName)) usedBy.set(info.filter.aclName, []);
    usedBy.get(info.filter.aclName).push(`${info.kind} ${info.name}`);
  }
  const rows = [];
  let id = VPN_ROW_ID_BASE;
  for (const [aclName, users] of usedBy) {
    const acl = config.acls[aclName];
    if (!acl) continue;
    let seq = 0;
    for (const entry of acl) {
      if (entry.remark) continue;
      seq += 1;
      const scored = scoreEntry(config, entry, 'internal');
      if (!scored.srcResolved) { // scoreEntry's deny shortcut omits these
        scored.srcResolved = resolveEndpoint(config, entry.src);
        scored.dstResolved = resolveEndpoint(config, entry.dst);
        scored.services = resolveRuleServices(config, entry);
      }
      rows.push({
        id: id++, type: 'rule', aclName, ruleNumber: seq, entry, scored,
        interface: 'vpn-filter', direction: 'vpn-filter', implicit: false,
        inactive: !!entry.inactive, usedBy: users,
      });
    }
  }
  return rows;
}
```

Replace the placeholder comment `// 'filter-rules' section is inserted here by Task 3.` with:

```js
  const filterRows = vpnFilterRuleRows(config, all);
  if (filterRows.length) sections.push({ id: 'filter-rules', heading: 'VPN filter rules', ruleRows: filterRows });
```

- [ ] **Step 4: Document the hook in `source/shared/registry.js`**

Extend the vendor-shape comment (after the `buildRuleset` line) with:

```js
//     buildInventory(config, options) -> Inventory | null     (OPTIONAL)
//         Extra, vendor-specific read-only views rendered by ui.js as a tab.
//         Inventory = { title, sections: Section[] }
//         Section   = { id, heading, columns:[{key,label}], rows:[{cells, detail?}] }
//                   | { id, heading, ruleRows: RuleRow[] }   (scored rule rows)
//         cell = string | { text, tone?: 'warn'|'dim', note? }
//         detail block = {kind:'kv'|'networks'|'list', title, ...}
//         Return null when the config has nothing to show (no tab).
```

- [ ] **Step 5: Rebuild and run tests**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: all test files `ok`.

- [ ] **Step 6: Commit (local only)**

```bash
cd D:/appdev/fwrra
git add source tests dist
git commit -m "Score ASA VPN-filter ACEs and expose them in the VPN inventory

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: UI — tabs, inventory renderer, toggle placement

**Files:**
- Modify: `source/template.html` (CSS, tab bar, view wrappers, move risk toggle into header actions)
- Modify: `source/ui.js`
- Create: `tests/vpn-ui.test.js`

**Interfaces:**
- Consumes: `vendor.buildInventory(config, options)` (optional); existing `buildRuleRow(row)`, `buildDetailRow(row)`, `renderMemberTree`, `endpointText`, `serviceText`, `escapeHtml`, `EXPANDED`, `riskOn`.
- Produces: tab UI (`#tabBar`, `#rulesView`, `#inventoryView`, `#invBody`, `#invSearch`); functions `setTab`, `renderInventory`, `ruleRowMatchesQuery(row, q)`, `cellText`, `cellHtml`; risk toggle now at `#headerActions` (id `riskToggle` unchanged).

- [ ] **Step 1: Write the failing UI test `tests/vpn-ui.test.js`**

```js
const assert = require('assert');
const { fixture, loadPage } = require('./helpers');

const FORTI = `#config-version=FGT60F-7.0.1-FW-build0157:opmode=0:vdom=0
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
`;

const visible = (w, sel) => [...w.document.querySelectorAll(sel)]
  .filter(e => w.getComputedStyle(e).display !== 'none').length;

module.exports = async () => {
  // ---- ASA: tab present and populated ----
  const { w, d } = await loadPage('fwrra-asa.html', fixture('asa-vpn.cfg'));
  assert.notStrictEqual(d.getElementById('tabBar').style.display, 'none');
  assert.strictEqual(d.getElementById('inventoryTabBtn').textContent, 'Remote-access VPN');
  assert.strictEqual(d.getElementById('inventoryView').style.display, 'none', 'rules tab is the default');

  d.getElementById('inventoryTabBtn').click();
  assert.strictEqual(d.getElementById('inventoryView').style.display, '');
  assert.strictEqual(d.getElementById('rulesView').style.display, 'none');
  const heads = [...d.querySelectorAll('#invBody h3')].map(h => h.textContent);
  assert.deepStrictEqual(heads,
    ['Tunnel-groups', 'Group-policies', 'User overrides', 'Address pools', 'VPN filter rules', 'Findings']);
  const body = d.getElementById('invBody').textContent;
  assert.ok(body.includes('Enabled (include)') && body.includes('Enabled (exclude)') && body.includes('Disabled'));
  assert.ok(body.includes('inherited: DfltGrpPolicy'));

  // expand a tunnel-group row -> detail shows split networks
  const engRow = [...d.querySelectorAll('#invBody tr.rule-row')].find(tr => tr.textContent.startsWith('\u25B8ENG') || tr.textContent.includes('Engineering'));
  engRow.click();
  assert.ok(d.getElementById('invBody').textContent.includes('Split-tunnel networks'));

  // filter-rule row expands with the risk calculation while risk is ON
  const ruleTable = [...d.querySelectorAll('#invBody .table-wrap')].find(t => t.previousSibling && t.previousSibling.textContent === 'VPN filter rules');
  ruleTable.querySelector('tr.rule-row').click();
  assert.ok(d.getElementById('invBody').textContent.includes('Risk calculation'));
  assert.ok(visible(w, '#invBody td.risk-cell') > 0);

  // ---- risk toggle OFF hides scores in the VPN tab, keeps factual state ----
  const t = d.getElementById('riskToggle');
  t.checked = false; t.dispatchEvent(new w.Event('change'));
  assert.strictEqual(visible(w, '#invBody td.risk-cell'), 0);
  assert.strictEqual(visible(w, '#invBody th.risk-only'), 0);
  assert.ok(!d.getElementById('invBody').textContent.includes('Risk calculation'));
  assert.ok(d.getElementById('invBody').textContent.includes('Enabled (include)'), 'split state is not scoring');

  // ---- search filters rows ----
  const s = d.getElementById('invSearch');
  s.value = 'CONTR'; s.dispatchEvent(new w.Event('input'));
  await new Promise(r => setTimeout(r, 250));
  const bodyText = d.getElementById('invBody').textContent;
  assert.ok(bodyText.includes('CONTR_GP') && !bodyText.includes('Engineering'));

  // ---- non-ASA: no tab ----
  const f = await loadPage('fwrra-fortios.html', FORTI);
  assert.strictEqual(f.d.getElementById('tabBar').style.display, 'none');
  // combined build with a non-ASA config: no tab; with ASA config: tab
  const c1 = await loadPage('fwrra.html', FORTI);
  assert.strictEqual(c1.d.getElementById('tabBar').style.display, 'none');
  const c2 = await loadPage('fwrra.html', fixture('asa-vpn.cfg'));
  assert.notStrictEqual(c2.d.getElementById('tabBar').style.display, 'none');

  // ---- Review focus: HTML in names is escaped ----
  const evil = fixture('asa-vpn.cfg') +
    'tunnel-group <img/src=x/onerror=alert(1)> type remote-access\n';
  const e = await loadPage('fwrra-asa.html', evil);
  e.d.getElementById('inventoryTabBtn').click();
  assert.strictEqual(e.d.querySelectorAll('#invBody img').length, 0, 'no live <img> from config text');
  assert.ok(e.d.getElementById('invBody').textContent.includes('<img/src=x/onerror=alert(1)>'));
};
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: `FAIL vpn-ui.test.js` (`Cannot read properties of null (reading 'style')` — no `#tabBar` yet).

- [ ] **Step 3: Edit `source/template.html`**

(a) Add CSS just above the `/* ---- Risk analysis off ... */` block:

```css
  /* ---- Tabs + inventory view ---- */
  .tabs { display: flex; gap: 4px; margin-bottom: 14px; border-bottom: 1px solid var(--border); }
  .tab-btn {
    font-family: var(--mono); font-size: 12.5px; cursor: pointer; background: transparent;
    color: var(--text-dim); border: 1px solid transparent; border-bottom: none;
    border-radius: 6px 6px 0 0; padding: 7px 14px;
  }
  .tab-btn:hover { color: var(--text); }
  .tab-btn.active { color: var(--text-bright); background: var(--panel); border-color: var(--border); }
  .inv-section { margin-bottom: 22px; }
  .inv-section h3 {
    font-family: var(--mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--text-dim); margin: 0 0 8px;
  }
  .inv-section .tag { color: var(--text-dim); font-size: 10.5px; margin-left: 6px; }
  .tone-warn { color: var(--c-high); }
  .tone-dim { color: var(--text-dim); }
```

(b) Move the risk toggle out of `.controls` into the header actions. Delete this block from `.controls`:

```html
      <label class="toggle-label" for="riskToggle" title="Turn off to hide all risk scoring, policy verdicts and score-based filters/columns (e.g. for audit screenshots of the rules).">
        <input type="checkbox" id="riskToggle" checked>
        <span>Risk analysis</span>
      </label>
```

and insert it as the first child of `<div class="header-actions" id="headerActions" ...>` (before the `loadNewBtn` button), unchanged.

(c) Tab bar + wrappers. Replace `    <div class="summary" id="summary"></div>` with:

```html
    <div class="tabs" id="tabBar" style="display:none;">
      <button class="tab-btn active" data-tab="rules">Rules</button>
      <button class="tab-btn" data-tab="inventory" id="inventoryTabBtn"></button>
    </div>
    <div id="rulesView">
    <div class="summary" id="summary"></div>
```

and replace `    <footer class="note" id="footerNote"></footer>` with:

```html
    <footer class="note" id="footerNote"></footer>
    </div>
    <div id="inventoryView" style="display:none;">
      <div class="controls">
        <input type="text" id="invSearch" placeholder="filter by name, ACL, pool, network...">
      </div>
      <div id="invBody"></div>
    </div>
```

- [ ] **Step 4: Edit `source/ui.js`**

(a) State + element refs — after `let riskOn = true;` add:

```js
  let INVENTORY = null;
  let activeTab = 'rules';
  let INV_EXPANDED = new Set();
```

and after `const riskToggle = ...` add:

```js
  const tabBar = document.getElementById('tabBar');
  const rulesView = document.getElementById('rulesView');
  const inventoryView = document.getElementById('inventoryView');
  const invBody = document.getElementById('invBody');
  const invSearch = document.getElementById('invSearch');
```

(b) In `processConfig`, after the line `ROWS = vendor.buildRuleset(CONFIG, { firewallRole: CURRENT_ROLE });` add:

```js
    INVENTORY = vendor.buildInventory ? vendor.buildInventory(CONFIG, { firewallRole: CURRENT_ROLE }) : null;
    INV_EXPANDED = new Set();
    tabBar.style.display = INVENTORY ? '' : 'none';
    document.getElementById('inventoryTabBtn').textContent = INVENTORY ? INVENTORY.title : '';
```

and at the end of `processConfig` (after `renderTable();`) add `setTab('rules');`.

(c) In the risk-toggle `change` handler, after `renderTable();` add:

```js
      if (INVENTORY) renderInventory();
```

(d) Add the inventory code just before the `// ---- CSV export ----` comment:

```js
  // ---- tabs + vendor inventory (generic; see shared/registry.js) ----
  tabBar.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));
  if (invSearch) invSearch.addEventListener('input', debounce(renderInventory, 150));

  function setTab(tab) {
    activeTab = tab;
    rulesView.style.display = tab === 'rules' ? '' : 'none';
    inventoryView.style.display = tab === 'inventory' ? '' : 'none';
    tabBar.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    if (tab === 'inventory') renderInventory();
  }

  function cellText(c) { return c && typeof c === 'object' ? c.text : (c ?? ''); }
  function cellHtml(c) {
    if (c && typeof c === 'object') {
      return `<span class="${c.tone ? 'tone-' + c.tone : ''}">${escapeHtml(c.text)}</span>` +
        (c.note ? `<span class="tag">${escapeHtml(c.note)}</span>` : '');
    }
    return escapeHtml(c);
  }

  function invRowMatches(row, q) {
    if (!q) return true;
    return Object.values(row.cells).map(cellText).join(' ').toLowerCase().includes(q);
  }

  function ruleRowMatchesQuery(row, q) {
    if (!q) return true;
    const s = row.scored;
    return [endpointText(s.srcResolved), endpointText(s.dstResolved), serviceText(s.services),
      row.aclName || '', (row.usedBy || []).join(' ')].join(' ').toLowerCase().includes(q);
  }

  function detailHtml(blocks) {
    const sec = (title, inner) => `<div class="detail-section" style="margin-bottom:12px;"><h4>${escapeHtml(title)}</h4>${inner}</div>`;
    return (blocks || []).map(b => {
      if (b.kind === 'kv') {
        return sec(b.title, '<div class="score-explain">' + b.pairs.map(([k, v]) =>
          `<div class="row"><span class="k">${escapeHtml(k)}</span><span>${cellHtml(v)}</span></div>`).join('') + '</div>');
      }
      if (b.kind === 'networks') {
        return sec(b.title, '<div class="member-tree"><ul>' + b.entries.map(e =>
          `<li><span class="tag">${escapeHtml(e.action)}</span> ${renderMemberTree(e.resolved)}</li>`).join('') + '</ul></div>');
      }
      if (b.kind === 'list') {
        return sec(b.title, '<div class="member-tree"><ul>' + b.items.map(x => `<li>${escapeHtml(x)}</li>`).join('') + '</ul></div>');
      }
      return '';
    }).join('');
  }

  function buildInvTable(sec, q) {
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    const table = document.createElement('table');
    table.innerHTML = '<thead><tr><th style="width:20px;"></th>' +
      sec.columns.map(c => `<th>${escapeHtml(c.label)}</th>`).join('') + '</tr></thead>';
    const tb = document.createElement('tbody');
    const rows = sec.rows.filter(r => invRowMatches(r, q));
    if (!rows.length) {
      tb.innerHTML = `<tr><td colspan="${sec.columns.length + 1}"><div class="empty-state">No matching entries.</div></td></tr>`;
    }
    for (const row of rows) {
      const key = sec.id + ':' + sec.rows.indexOf(row);
      const open = !!row.detail && INV_EXPANDED.has(key);
      const tr = document.createElement('tr');
      tr.className = 'rule-row' + (open ? ' expanded' : '');
      tr.innerHTML = `<td><span class="expand-caret ${open ? 'open' : ''}">${row.detail ? '\u25B8' : ''}</span></td>` +
        sec.columns.map(c => `<td class="mono">${cellHtml(row.cells[c.key])}</td>`).join('');
      if (row.detail) {
        tr.addEventListener('click', () => {
          if (INV_EXPANDED.has(key)) INV_EXPANDED.delete(key); else INV_EXPANDED.add(key);
          renderInventory();
        });
      }
      tb.appendChild(tr);
      if (open) {
        const dr = document.createElement('tr');
        dr.className = 'detail-row';
        const td = document.createElement('td');
        td.colSpan = sec.columns.length + 1;
        td.innerHTML = '<div class="detail-panel">' + detailHtml(row.detail) + '</div>';
        dr.appendChild(td);
        tb.appendChild(dr);
      }
    }
    table.appendChild(tb);
    wrap.appendChild(table);
    return wrap;
  }

  // Scored rule rows reuse the main table's row/detail builders (and therefore
  // the risk toggle); only the click handler is swapped so it re-renders here.
  function buildInvRuleTable(sec, q) {
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    const table = document.createElement('table');
    const thead = document.querySelector('#ruleTable thead').cloneNode(true);
    thead.querySelectorAll('th').forEach(th => th.removeAttribute('data-sort'));
    thead.querySelector('tr').insertAdjacentHTML('beforeend', '<th>Used by</th>');
    table.appendChild(thead);
    const tb = document.createElement('tbody');
    const rows = sec.ruleRows.filter(r => ruleRowMatchesQuery(r, q));
    if (!rows.length) tb.innerHTML = '<tr><td colspan="12"><div class="empty-state">No matching entries.</div></td></tr>';
    for (const row of rows) {
      const tr = buildRuleRow(row).cloneNode(true); // cloneNode drops the rules-table click handler
      const used = document.createElement('td');
      used.className = 'mono';
      used.textContent = (row.usedBy || []).join(', ');
      tr.appendChild(used);
      tr.addEventListener('click', () => {
        if (EXPANDED.has(row.id)) EXPANDED.delete(row.id); else EXPANDED.add(row.id);
        renderInventory();
      });
      tb.appendChild(tr);
      if (EXPANDED.has(row.id)) {
        const dr = buildDetailRow(row);
        dr.firstChild.colSpan = 12;
        tb.appendChild(dr);
      }
    }
    table.appendChild(tb);
    wrap.appendChild(table);
    return wrap;
  }

  function renderInventory() {
    if (!INVENTORY) { invBody.innerHTML = ''; return; }
    const q = invSearch.value.trim().toLowerCase();
    invBody.innerHTML = '';
    for (const sec of INVENTORY.sections) {
      const box = document.createElement('div');
      box.className = 'inv-section';
      const h = document.createElement('h3');
      h.textContent = sec.heading;
      box.appendChild(h);
      box.appendChild(sec.ruleRows ? buildInvRuleTable(sec, q) : buildInvTable(sec, q));
      invBody.appendChild(box);
    }
  }
```

- [ ] **Step 5: Rebuild and run tests**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: all tests `ok`. If the `engRow` lookup fails, print `[...d.querySelectorAll('#invBody tr.rule-row')].map(t=>t.textContent)` and adjust the test selector (first cell text is `▸`-prefixed); do not change product code to suit the selector.

- [ ] **Step 6: Commit (local only)**

```bash
cd D:/appdev/fwrra
git add source tests dist
git commit -m "Render vendor inventory as a Remote-access VPN tab; move risk toggle to header

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: VPN CSV export

**Files:**
- Modify: `source/ui.js` (export handler, new `exportInventoryCsv`, extract `downloadCsv`)
- Modify: `tests/vpn-ui.test.js` (append)

**Interfaces:**
- Consumes: `INVENTORY`, `activeTab`, `riskOn`, `invRowMatches`, `ruleRowMatchesQuery`, `cellText`, `csvEscape`, `endpointText`, `serviceText`.
- Produces: `downloadCsv(text, filename)`; header Export CSV exports the inventory when the VPN tab is active (blocks per section: `# <heading>` line, header row, data rows, blank line).

- [ ] **Step 1: Append failing assertions to `tests/vpn-ui.test.js`** (end of exported function)

```js
  // ---- VPN CSV export ----
  const g = await loadPage('fwrra-asa.html', fixture('asa-vpn.cfg'));
  let csv = '';
  g.w.Blob = function (parts) { csv = parts.join(''); };
  g.w.URL.createObjectURL = () => 'blob:x';
  g.w.URL.revokeObjectURL = () => {};
  g.w.HTMLAnchorElement.prototype.click = function () {};
  g.d.getElementById('inventoryTabBtn').click();
  g.d.getElementById('exportBtn').click();
  assert.ok(csv.includes('# Tunnel-groups') && csv.includes('# VPN filter rules') && csv.includes('# Findings'));
  assert.ok(csv.includes('ACL,Rule #,Score,Band,Action'), 'risk ON: score columns present');
  assert.ok(csv.includes('Enabled (include) (from ENG_GP)'), 'cell notes are exported');
  const rt = g.d.getElementById('riskToggle');
  rt.checked = false; rt.dispatchEvent(new g.w.Event('change'));
  g.d.getElementById('exportBtn').click();
  assert.ok(csv.includes('ACL,Rule #,Action'), 'risk OFF: header without score');
  assert.ok(!csv.includes(',Score,') && !csv.includes(',Band,'));
  // rules tab export is unchanged: starts with the rule header
  g.d.querySelector('[data-tab="rules"]').click();
  g.d.getElementById('exportBtn').click();
  assert.ok(csv.startsWith('Rule #,'));
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: `FAIL vpn-ui.test.js` — CSV lacks `# Tunnel-groups` (rules CSV is emitted instead).

- [ ] **Step 3: Implement in `source/ui.js`**

Extract the download tail of the existing handler. Replace in `exportBtn.addEventListener('click', () => { ... })` the lines

```js
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'asa-rule-risk-export.csv';
    a.click();
    URL.revokeObjectURL(url);
```

with `downloadCsv(lines.join('\n'), 'asa-rule-risk-export.csv');`, and add as the first statement of that handler:

```js
    if (activeTab === 'inventory' && INVENTORY) { exportInventoryCsv(); return; }
```

Then add (next to `csvEscape`):

```js
  function downloadCsv(text, filename) {
    const blob = new Blob([text], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportInventoryCsv() {
    const q = invSearch.value.trim().toLowerCase();
    const out = [];
    for (const sec of INVENTORY.sections) {
      out.push(csvEscape('# ' + sec.heading));
      if (sec.ruleRows) {
        out.push(['ACL', 'Rule #', ...(riskOn ? ['Score', 'Band'] : []), 'Action', 'Inactive', 'Protocol',
          'Source', 'Destination', 'Service', 'Logging', 'Used by'].join(','));
        for (const row of sec.ruleRows.filter(r => ruleRowMatchesQuery(r, q))) {
          const s = row.scored;
          out.push([row.aclName, row.ruleNumber, ...(riskOn ? [s.score, s.band.label] : []), s.action,
            row.inactive ? 'yes' : 'no', (s.services[0] && s.services[0].protocol) || 'ip',
            endpointText(s.srcResolved), endpointText(s.dstResolved), serviceText(s.services),
            s.logging.label, (row.usedBy || []).join('; ')].map(csvEscape).join(','));
        }
      } else {
        out.push(sec.columns.map(c => csvEscape(c.label)).join(','));
        for (const row of sec.rows.filter(r => invRowMatches(r, q))) {
          out.push(sec.columns.map(c => {
            const v = row.cells[c.key];
            const n = v && typeof v === 'object' && v.note ? ` (${v.note})` : '';
            return csvEscape(cellText(v) + n);
          }).join(','));
        }
      }
      out.push('');
    }
    downloadCsv(out.join('\n'), 'asa-vpn-inventory.csv');
  }
```

- [ ] **Step 4: Rebuild and run tests**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: all `ok`.

- [ ] **Step 5: Commit (local only)**

```bash
cd D:/appdev/fwrra
git add source tests dist
git commit -m "Add VPN inventory CSV export (respects risk toggle and search)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Regression test for the risk toggle, docs, final verification

**Files:**
- Create: `tests/risk-toggle.test.js`
- Modify: `CLAUDE.md`, `README.md`
- Modify: `docs/superpowers/specs/2026-10-08-asa-anyconnect-design.md`

**Interfaces:**
- Consumes: everything above.
- Produces: committed regression coverage for the toggle on all vendors; docs aligned with the implementation.

- [ ] **Step 1: Create `tests/risk-toggle.test.js`**

```js
const assert = require('assert');
const { fixture, loadPage } = require('./helpers');

const FORTI = `#config-version=FGT60F-7.0.1-FW-build0157:opmode=0:vdom=0
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
        set role wan
    next
    edit "lan"
        set ip 10.0.0.1 255.255.255.0
        set role lan
    next
end
config router static
    edit 1
        set device "wan1"
        set gateway 203.0.113.1
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
`;

const PAN = `set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
set rulebase security rules r1 from untrust
set rulebase security rules r1 to trust
set rulebase security rules r1 source any
set rulebase security rules r1 destination any
set rulebase security rules r1 application ssh
set rulebase security rules r1 service application-default
set rulebase security rules r1 action allow
`;

const visible = (w, sel) => [...w.document.querySelectorAll(sel)]
  .filter(e => w.getComputedStyle(e).display !== 'none').length;

async function check(file, cfg) {
  const { w, d } = await loadPage(file, cfg);
  assert.ok(d.querySelectorAll('td.risk-cell').length > 0, file + ': rows rendered');
  d.querySelector('tr.rule-row').click();
  assert.ok(d.querySelector('.detail-row').textContent.includes('Risk calculation'));

  const t = d.getElementById('riskToggle');
  t.checked = false; t.dispatchEvent(new w.Event('change'));
  assert.strictEqual(d.body.className.includes('no-risk'), true);
  assert.strictEqual(visible(w, 'td.risk-cell'), 0, file + ': risk cells hidden');
  assert.strictEqual(visible(w, 'th.risk-only'), 0);
  assert.strictEqual(visible(w, '#filterBand'), 0);
  assert.strictEqual(visible(w, '#filterPolicy'), 0);
  assert.strictEqual(d.querySelectorAll('.policy-pill').length, 0);
  assert.ok(!d.querySelector('.detail-row').textContent.includes('Risk calculation'));
  assert.ok(!/heuristic/.test(d.getElementById('footerNote').textContent));
  assert.strictEqual(visible(w, '.summary .cell'), 3);

  let csv = '';
  w.Blob = function (p) { csv = p.join(''); };
  w.URL.createObjectURL = () => 'x'; w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = function () {};
  d.getElementById('exportBtn').click();
  assert.ok(!csv.split('\n')[0].includes('Score'), file + ': CSV header has no score columns');

  t.checked = true; t.dispatchEvent(new w.Event('change'));
  assert.strictEqual(visible(w, 'td.risk-cell') > 0, true, file + ': restored');
  assert.strictEqual(visible(w, '.summary .cell'), 9);
}

module.exports = async () => {
  await check('fwrra-asa.html', fixture('asa-vpn.cfg'));
  await check('fwrra-fortios.html', FORTI);
  await check('fwrra-panos.html', PAN);
  await check('fwrra.html', FORTI);
};
```

- [ ] **Step 2: Run the whole suite**

Run: `cd D:/appdev/fwrra && node build.js && node tests/run.js`
Expected: every test file prints `ok`. If `check('fwrra-asa.html', ...)` fails on `.summary .cell` counts, print `visible(w,'.summary .cell')` first: the ASA fixture may produce a different cell count only if the summary template changed — the expected values are 9 (on) and 3 (off) per `renderSummary`.

- [ ] **Step 3: Update `CLAUDE.md`**

(a) In **Repo layout**, add under `vendors/asa/`:

```
      vpn-parser.js              # parseASAVpn(lines): ip local pool, group-policy,
                                  # tunnel-group, username attributes, standard
                                  # ACLs, sysopt permit-vpn, global webvpn. Merged
                                  # into the config by parseASAConfig().
      vpn-resolve.js             # buildVpnInventory(config): user -> group-policy
                                  # -> DfltGrpPolicy inheritance, split-tunnel
                                  # Enabled/Disabled state, scored vpn-filter ACE
                                  # rows (direction 'internal'), findings
```

(b) In **The vendor contract**, add a paragraph after the `buildRuleset` description:

```
Optional fourth entry point: `buildInventory(config, options) -> Inventory | null`
(documented in `shared/registry.js`). A vendor with extra read-only views (ASA:
remote-access VPN) returns generic `{title, sections}`; `ui.js` renders it as a
second tab without knowing the vendor. Scored rows inside an inventory
(`ruleRows`) reuse the normal rule-row shape, so the risk toggle hides their
score columns automatically. Return `null` for "nothing to show" (no tab).
```

(c) In **Design decisions**, add:

```
- **VPN inventory (ASA).** VPN-filter ACEs are scored with direction `'internal'`
  (client = source, internal = destination) and emitted once per distinct
  (ACL, ACE) with a `usedBy` list; they never appear in the main rule table.
  Split tunneling is shown as factual Enabled/Disabled (`tunnelall` = Disabled;
  `tunnelspecified` = Enabled include; `excludespecified` = Enabled exclude;
  unset everywhere = Disabled/default) and is never hidden by the risk toggle.
  RADIUS/LDAP-supplied attributes are not visible in the config; the findings
  section says so.
```

(d) Replace the **Testing** section's first paragraph with:

```
Tests live in `tests/` (plain Node, no framework). Install the dev-only
dependency ad hoc — `npm i --no-save jsdom` — then run
`node build.js && node tests/run.js`. Engine tests load the built artifact's
engine script into a `vm` context; UI tests drive the built page in jsdom
(synthetic `File` + `change` event on `#fileInput`). `tests/fixtures/asa-vpn.cfg`
is the shared ASA VPN sample. When adding a vendor, still write a representative
sample config (permit + deny, nested group, inactive rule, with/without logging,
several trust levels) and cover it the same way.
```

- [ ] **Step 4: Update `README.md`**

Under **What it does**, add two bullets:

```
- A **Risk analysis** switch (top right) hides every score, band, policy
  verdict and score-based filter/column — useful for clean audit screenshots of
  the rules. The CSV export drops its score columns too.
- For Cisco ASA, a **Remote-access VPN** tab enumerates AnyConnect access:
  address pools, tunnel-groups, group-policies, per-user overrides, each
  group's vpn-filter ACL (scored), and whether split tunneling is Enabled or
  Disabled — with where each value is inherited from.
```

- [ ] **Step 5: Align the spec with what was built**

In `docs/superpowers/specs/2026-10-08-asa-anyconnect-design.md`:
- Section 1: replace "`access-list NAME standard ...` parsed into the same `acls` map (entry `{standard:true, ...}`)" with "parsed into a separate `standardAcls` map so the main rule table is untouched".
- Section 2: replace "The role selector triggers a rebuild..." statements with "VPN-filter ACEs always use direction `'internal'`; the firewall-role selector does not affect the VPN tab." Replace "per filter ACE" row wording with "filter ACEs are emitted once per distinct (ACL, ACE) with a *Used by* list".
- Section 3: remove `risk?` from the column definition and add `ruleRows` as the second section form.
- Section 4: state the CSV is one file with a `# <heading>` block per section, exported from the header Export CSV button when the VPN tab is active.

- [ ] **Step 6: Final verification and commit (local only — do NOT push)**

Run:

```bash
cd D:/appdev/fwrra && node build.js && node tests/run.js && git status -sb
```

Expected: all tests `ok`; `git status` shows only intended changes. Then:

```bash
git add -A
git commit -m "Add risk-toggle regression tests, document VPN inventory, align spec

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
git log --oneline -8
```

Expected: branch is ahead of `origin/main` by the new commits; **nothing pushed**.

- [ ] **Step 7: Manual check handed to the user**

Load `tests/fixtures/asa-vpn.cfg` into `dist/fwrra-asa.html`: confirm the Rules tab is unchanged, the Remote-access VPN tab shows six sections, expanding `ENG` shows the split-tunnel networks, and flipping Risk analysis off hides scores on both tabs while Enabled/Disabled and findings remain.

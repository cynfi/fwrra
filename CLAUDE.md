# CLAUDE.md

Guidance for Claude (or any assistant) working in this repository.

## What this is

`fwrra` (Firewall Rule Risk Analyzer) is a client-side, multi-vendor
firewall config risk analyzer. One HTML file per build, no backend, no
build dependencies beyond Node's standard library. `source/` holds the
real source of truth; everything in `dist/` is generated — **never
hand-edit `dist/`**, edit `source/` and run `node build.js`.

Cisco ASA, Fortinet FortiOS, and Palo Alto PAN-OS are all implemented
today. This document exists mainly to make adding a vendor straightforward
and consistent with the decisions already made. (Cisco Firepower / FTD is a
**distinct planned vendor**, not an ASA variant — its FMC-managed Access
Control Policy is zone/app-based, closer to PAN-OS; see `DESIGN.md` §10.
Don't extend the ASA parser for it.)

> **Active blueprint: see [`DESIGN.md`](DESIGN.md).** The next major
> evolution — a firewall-role toggle, direction-aware exposure, a
> compensating-control "buyback" credit, and a declarative policy-standards
> layer with a risk-assessment/exception workflow — is specified there. It
> **intentionally reverses** the "interface direction stays out of the risk
> model" decision recorded below; `DESIGN.md` is authoritative where the two
> disagree. The scoring+policy engine is also being built to be portable
> into a separate firewall-rule-request tool, so keep it vendor-neutral and
> DOM-free in `source/shared/`.

## Repo layout

```
build.js                    # assembles source/ into dist/*.html — no deps.
                             # `node build.js` builds a combined artifact
                             # (all VENDORS) plus one per-vendor artifact.
                             # `node build.js --vendor=<name>` builds just
                             # that vendor.
source/
  template.html              # page shell: <head>, CSS, DOM structure, two
                              # empty <script id="engine-scripts">/<script
                              # id="ui-script"> placeholders build.js fills in
  shared/
    logging.js                # SYSLOG_LEVEL_NAMES — RFC 5424 severity names,
                               # universal across vendors
    registry.js                # VENDOR_REGISTRY + registerVendor() +
                                # detectVendor(). The vendor-neutral dispatch
                                # layer: each vendor self-registers { id,
                                # label, detect, parse, buildRuleset }; ui.js
                                # calls detectVendor(text) to pick a parser.
    risk.js                    # vendor-neutral scoring: SERVICE_RISK_TABLE,
                                # computeExposureScore() (direction-aware),
                                # combineRisk(), riskBand(),
                                # classifyEndpointScope(), trustClassFromLevel(),
                                # ruleDirection(), the buyback engine
                                # (BUYBACK_CREDIT, computeRuleBuyback,
                                # applyBuyback). Pure functions on a normalized
                                # {kind, prefixLen, breadth} scope shape and
                                # (protocol, port) pairs — no vendor grammar.
    policy.js                  # vendor-neutral policy-standards layer:
                                # DEFAULT_POLICY_STANDARD (declarative deny-by-
                                # default patterns) + evaluatePolicy() ->
                                # compliant/against-policy verdict. Uses
                                # buybackKeyForCombo() from risk.js, so loads
                                # after it. See DESIGN.md §5-6.
  vendors/
    asa/
      parser.js                 # parseASAConfig(text) -> {objects, groups,
                                 # interfaces, acls, accessGroups} — ASA
                                 # config-line grammar only
      resolve.js                 # ASA-specific: resolves objects/groups
                                  # recursively, scoreEntry() (calls into
                                  # shared/risk.js for the actual math),
                                  # classifyLogging() (ASA's log/log
                                  # disable/log <level> grammar),
                                  # buildRuleset() (implicit-permit synthesis,
                                  # default ordering, rule numbering), and
                                  # detectASAConfig() + registerVendor() at
                                  # the bottom
      vpn-parser.js              # parseASAVpn(lines): ip local pool, group-policy,
                                  # tunnel-group, username attributes, standard
                                  # ACLs, sysopt permit-vpn, global webvpn. Merged
                                  # into the config by parseASAConfig().
      vpn-resolve.js             # buildVpnInventory(config): user -> group-policy
                                  # -> DfltGrpPolicy inheritance, split-tunnel
                                  # Enabled/Disabled state, scored vpn-filter ACE
                                  # rows (direction 'internal'), findings
    fortios/
      parser.js                 # parseFortiOSConfig(text) -> {interfaces,
                                 # zones, addresses, addrgrps, services,
                                 # serviceGroups, policies, staticRoutes} —
                                 # walks FortiGate's config/edit/set/next/end
                                 # block grammar
      resolve.js                 # FortiOS-specific: resolves addresses/
                                  # addrgrps/services, fortiScorePolicy(),
                                  # fortiClassifyLogging() (logtraffic
                                  # all/utm/disable), interface-trust from
                                  # default-route egress + role,
                                  # fortiBuildRuleset() (NO implicit-permit
                                  # synthesis — FortiOS default-denies), and
                                  # detectFortiOSConfig() + registerVendor()
    panos/
      parser.js                 # parsePanOSConfig(text) -> {interfaces, zones,
                                 # addresses, addressGroups, services,
                                 # serviceGroups, rules, routes} — accepts both
                                 # the Palo Alto "set" format (one attribute per
                                 # line) and the XML running-config export
                                 # (parsed via the platform DOMParser into the
                                 # same shape; pbf/nat rulebases skipped)
      resolve.js                 # PAN-OS-specific: PANOS_APPID_PORTS map (so
                                  # application-default rules score on their
                                  # App-ID's real ports), zone trust from
                                  # default-route egress + zone-name, default-
                                  # deny (no synthesis), panClassifyLogging
                                  # (log-end/log-start), negate-source/-dest ->
                                  # resolved.negated (complement breadth +
                                  # geofence buyback, see below), panBuildRuleset,
                                  # and detectPanOSConfig() + registerVendor()
  ui.js                        # all DOM code: file handling, table
                                # rendering, sort/filter, expand/collapse,
                                # CSV export. Vendor-neutral — calls
                                # detectVendor()/parse()/buildRuleset() and
                                # consumes the row output as a black box,
                                # never inspecting vendor-specific fields
                                # directly except through the contract below
dist/
  fwrra.html                  # combined build (all wired-in vendors)
  fwrra-asa.html              # per-vendor build
  fwrra-fortios.html          # per-vendor build
  fwrra-panos.html            # per-vendor build
```

`build.js` loads scripts in this order for any given build:
`shared/logging.js`, `shared/registry.js`, `shared/risk.js`,
`shared/policy.js`, then each vendor's engine, then `ui.js` last. There's no module system — the
`shared/` files and `ui.js` hang off the global scope inside the page, so
load order is load-bearing: anything a vendor or `ui.js` needs from
`shared/` must already be defined by the time it runs, which the order
above guarantees.

**Vendor engines are the exception to "everything is global."** Each
vendor's `parser.js` + `resolve.js` are concatenated and wrapped by
`build.js` in a single per-vendor IIFE, so their top-level names
(`parseXConfig`, `buildRuleset`, `scoreEntry`, `tokenize`, ...) stay
**private to that vendor** and don't collide when multiple vendors are
concatenated into the combined build. A vendor exposes itself to the rest
of the page only by calling the global `registerVendor(...)` at the bottom
of its `resolve.js`. This is why a new vendor can freely reuse names like
`buildRuleset` internally — do NOT rename them to be vendor-unique, and do
NOT rely on one vendor's internal helper being visible to another vendor
or to `ui.js`; the only cross-boundary surface is the registered
`{ detect, parse, buildRuleset }` and the shared globals.

## The vendor contract

This is the part that matters most for adding a vendor (FortiOS is done;
PAN-OS is the remaining one). `ui.js` never parses vendor syntax and never
branches on vendor identity — it asks the registry which vendor a config
belongs to, then calls that vendor's two entry points and renders whatever
comes back:

```
detect(text)         -> number       // confidence; highest across vendors wins, 0 = not mine
parse(text)          -> config       // vendor-internal parsed shape
buildRuleset(config) -> Array<Row>   // the rows ui.js renders
```

Each vendor's `resolve.js` ends by calling
`registerVendor({ id, label, detect, parse, buildRuleset })`. `detect()`
should score on grammar that is unambiguous for that vendor (ASA: `access-
list ... extended`, `boot system disk*:`, `asdm image`; FortiOS:
`#config-version=`, `config firewall policy`) and return 0 — or zero out —
when a rival vendor's signature is present, so the combined build never
mis-dispatches. `parse()` returns whatever internal shape that vendor's own
`buildRuleset()` consumes, with one soft requirement: it should expose a
top-level `interfaces` object (keyed by name) because `ui.js`'s file-info
strip counts `Object.keys(config.interfaces).length`.

`buildRuleset()` (plus whatever internal helpers it needs —
`scoreEntry()`/`fortiScorePolicy()`, `classifyLogging()`, etc., which
`ui.js` never calls directly) returns an array of row objects. Two `type`s
exist:

- `{ type: 'remark', aclName, text }` — a comment/label, not scored,
  rendered as an inline dim row.
- `{ type: 'rule', id, aclName, ruleNumber, entry, scored, interface,
  direction, implicit, inactive, defaultOrder, implicitNote? }` — a
  scored rule. `ui.js` reads `row.interface`, `row.aclName`,
  `row.ruleNumber`, `row.implicit`, `row.inactive`, and drills into
  `row.scored` for everything risk-related.

Optional fourth entry point: `buildInventory(config, options) -> Inventory | null`
(documented in `shared/registry.js`). A vendor with extra read-only views (ASA:
remote-access VPN) returns generic `{title, sections}`; `ui.js` renders it as a
second tab without knowing the vendor. Scored rows inside an inventory
(`ruleRows`) reuse the normal rule-row shape, so the risk toggle hides their
score columns automatically. Return `null` for "nothing to show" (no tab).
`build.js` loads a vendor's optional `vpn-parser.js` / `vpn-resolve.js` (between
and after `parser.js` / `resolve.js`) into the same private vendor IIFE.

`row.scored` (the return value of that vendor's `scoreEntry()`) must have
this shape — this is the actual contract, and it's what `shared/risk.js`
and `ui.js` both depend on:

```
{
  action: 'permit' | 'deny',
  score: number,              // 0-100, final combined score
  band: { label, color },     // from shared riskBand()
  exposure: { score, label },
  service: { score, name, note, subnetPenaltyEligible? },
  subnetPenaltyApplied: boolean,
  subnetPenalty: number,      // 0 if not applied
  services: Array<{ protocol, destPort?, destPortEnd?, isRange? }>,
  srcResolved, dstResolved,   // resolved endpoint trees, see below
  srcScope, dstScope,         // from shared classifyEndpointScope(), includes `breadth`
  logging: { flagged, severity, label, detail },
}
```

`srcResolved`/`dstResolved` use a small shared vocabulary of `kind`
values that `shared/risk.js`'s `classifyEndpointScope()` and `ui.js`'s
tree-rendering both understand: `any`, `host`, `subnet` (needs
`prefixLen`), `range`, `fqdn`, `literal`, and `group` (needs `members: []`
of the same shape, for recursive rendering). A new vendor's `resolve.js`
must translate its own object model into this vocabulary — don't invent
new `kind` values without updating `classifyEndpointScope()` in
`shared/risk.js` and the tree renderer in `ui.js` to handle them.

`defaultOrder: { level, ifName, ruleNumber }` drives the default sort
(see below) — `level` should be a number where higher = more trusted, on
whatever scale makes sense for that vendor (ASA uses its native 0–100
security-level; a vendor without an explicit numeric trust level will
need to invent a reasonable ordinal, e.g. by zone role).

`row.scored.logging` is produced by that vendor's own `classifyLogging()`
— the ASA one lives in `vendors/asa/resolve.js` and reads ASA's specific
`log`/`log disable`/`log <level>` grammar via `entry.logSetting`. A new
vendor will have different logging syntax (FortiOS: `log-traffic` /
`log-traffic-start`; PAN-OS: log-forwarding-profile attached to a rule)
and needs its own `classifyLogging()` that maps its grammar into the same
`{ flagged, severity, label, detail }` shape, using `SYSLOG_LEVEL_NAMES`
from `shared/logging.js` where a numeric/named severity applies.

## Design decisions worth knowing before you change scoring logic

These were deliberated with the user across several rounds while building
the ASA implementation and aren't arbitrary — check with the user before
changing them silently, and default to keeping new vendors consistent
with them unless a vendor's model genuinely doesn't fit:

- **NAT is explicitly out of scope for every vendor.** This is a
  rule-risk-analysis tool, not a full visualizer. Don't add NAT parsing
  without being asked.
- **Only enforced rules are scored.** For ASA, an ACL not bound via
  `access-group` has no effect on traffic and is excluded entirely (see
  `appliedAcls` in `vendors/asa/resolve.js`). FortiOS has no "unapplied"
  concept — every policy is inherently bound to its srcintf/dstintf — so
  its `resolve.js` scores every parsed policy (disabled ones are tagged,
  not dropped; see next bullet). PAN-OS (rule must not be disabled, and
  rulebase/vsys context matters) should follow the same spirit — don't
  score rules that can't currently fire.
- **Inactive/disabled rules are parsed and tagged, not deleted.** ASA's
  `... inactive` keyword and FortiOS's `set status disable` both set
  `row.inactive`, which the UI hides by default via a toggle rather than
  dropping the row. Rule numbering **includes** inactive rules so numbers
  don't shift when the toggle flips: ASA uses the ACE's per-ACL sequence,
  FortiOS uses the FortiGate policy ID as `row.ruleNumber` (its canonical
  reference) with evaluation-order position as the sort tiebreak. PAN-OS
  (`disabled yes`) should follow the same tag-don't-drop pattern.
- **Risk score = a "noisy-OR" combine of exposure and service:
  `combined = exposure + service − (exposure × service ⁄ 100)`, plus an
  additive "indiscriminate subnet" penalty for eligible services, capped
  at 100.** This replaced an earlier `max(exposure, service) +
  10-if-both-≥55` formula (see git history if you need the old one) after
  a governance review found the threshold-cliff version let SSH/RDP
  (service score 50) permanently miss the elevated-bonus that
  otherwise-comparable services at 55+ received, and let scope-narrowing
  below the service score have literally zero effect on the combined
  number. The noisy-OR form is monotonic and cliff-free by construction —
  increasing either input can never decrease the combined score — and at
  zero exposure (a strict host↔host rule) it reduces to exactly the
  service's own table score, which is what makes the least-privilege
  story work: a host-to-host SSH rule lands at SSH's score (50, Medium)
  because that's SSH's own inherent risk, not a special case. This lives
  in `combineRisk()` in `shared/risk.js` and is vendor-neutral. Don't
  reintroduce a threshold/cliff mechanism without checking in.
- **Exposure scoring is address-space-breadth-based, not a bucketed
  lookup table.** `classifyEndpointScope()` reduces every endpoint to a
  `breadth` score on a continuous log2 scale:
  `breadth = log2(addressCount) / 32 × 100` — a `/32` host is 0, a `/24`
  is 25, a `/16` is 50, a `/8` is 75, `any` (2^32 addresses) is 100. This
  is what makes a "/32 subnet" object and a host object score identically
  (both `addressCount = 1`), and what makes broadening a destination
  always score ≥ a narrower one — the previous per-combination bucket
  table had a monotonicity bug where a `/24` destination could score
  *below* a single-host destination. `computeExposureScore()` blends
  src/dst breadth as `0.75 × broader-side + 0.25 × narrower-side` (so
  "any" on one side alone doesn't saturate to the same score as "any" on
  both sides) before combining with service risk. An object-group's
  breadth is the **sum** of its members' address counts (recursively),
  not just its narrowest member — a 3-host group and a 300-host group are
  no longer indistinguishable. `deny` is still always 0, `any↔any` is
  still always 100 (the noisy-OR formula gives this for free: if either
  input is 100, the result is 100 regardless of the other). A vendor
  whose object model doesn't map cleanly onto host/subnet/any/group (e.g.
  FQDN objects, dynamic address groups) should resolve down to the
  closest fit in this vocabulary rather than inventing a parallel scoring
  path.
- **Negated endpoints (allow-lists / geofencing).** A rule endpoint can be
  *negated* (PAN-OS `negate-source`/`negate-destination`; FortiOS
  `srcaddr-negate` when added), meaning it matches everything EXCEPT the listed
  set. The shared engine models this with a `negated: true` flag on the resolved
  endpoint (a modifier on the existing vocabulary, **not** a new `kind`):
  `estimateAddressCount()` returns the **complement** (`2^32 − listed`), so
  "source = NOT (US + friendly countries)" scores as near-`any` breadth, not the
  small friendly-country group's breadth — which is what makes both a geofence
  deny and a negated allow score correctly (and why "any new country is blocked"
  holds). A negated endpoint never takes the indiscriminate-subnet penalty (it's
  a complement, not a raw CIDR). `scopeLabel()` renders `not(...)`; `ui.js`
  prefixes `NOT ` and flags the member tree. The **geofence buyback**
  (`BUYBACK_GEOFENCE_PER`/`_CAP` in `shared/risk.js`) is the negated-allow-list
  analogue of the threat-geo buyback: a preceding enabled `deny` with a negated
  source/destination credits a later permit that is broad on that same axis
  (moderate, ≈8, capped 16). Per a user governance decision it **respects the
  exposure floor** like the other buybacks — so a classic geofenced *any-source*
  leftover permit keeps its exposure score (the credit is recorded and shown in
  the buyback breakdown but does not pierce exposure); the credit only moves the
  number when the permit's other axis pulls exposure below 100. Don't change the
  floor behavior or the credit magnitude without checking in.
- **Indiscriminate-subnet penalty**: a small set of services
  (`subnetPenaltyEligible: true` in `SERVICE_RISK_TABLE`) get an
  additional, explicit penalty when either endpoint is a **raw CIDR
  subnet** larger than `/30` (more than 4 addresses):
  `penalty = 2^(32 − prefixLen)`, added on top of the noisy-OR combine
  and capped at 100 (e.g. host→`/27` SSH = `50 (SSH's score) + 32 (2^5)
  = 82`). This does **not** apply to object-groups, no matter how large —
  the rationale (per user governance input) is that a subnet is
  *indiscriminate* (anyone who lands an address in that range gets
  access, intentionally or not — DHCP reassignment, a new VM, a
  compromised neighbor), while a group is a *deliberately curated,
  documented* list of hosts and stays lower-risk even at similar size.
  Currently flagged eligible: SSH, RDP, Telnet, FTP/FTP-DATA/TFTP,
  SMB/NetBIOS-SSN, the database/infra ports (MS-SQL, MySQL, PostgreSQL,
  Redis, Elasticsearch, MongoDB, Docker API, Kubernetes API/kubelet, alt
  web/admin ports, Memcached, SNMP), and the legacy/no-legitimate-use
  ports commonly used to disguise C2/backdoor traffic (tcpmux, echo,
  discard, systat, daytime, netstat, chargen, finger, bootp, XDMCP,
  rexec, lpr, talk/ntalk, uucp, the Cisco AUX binary port, UPnP/SSDP, and
  NetBus). Don't flag additional services eligible, or change the `/30`
  threshold or `2^hostBits` growth rate, without checking in — this is a
  deliberately steep curve (a `/26` or larger already saturates a
  flagged service to Critical) and was calibrated against specific
  worked examples with the user.
- **Service risk table (`SERVICE_RISK_TABLE` / `PROTOCOL_WHOLE_RISK` in
  `shared/risk.js`)** is vendor-neutral (keyed by protocol/port, not
  vendor syntax) and is a starting point, not exhaustive. It now also
  distinguishes *why* a protocol is risky, not just how much: SSH is
  scored on its tunneling/inspection-defeating capability (it can
  encapsulate arbitrary protocols even when perfectly scoped to
  host↔host), Telnet is scored higher despite being passively inspectable
  because cleartext credential exposure isn't mitigated by
  after-the-fact detection, and file-transfer protocols (FTP/TFTP/SMB)
  are scored on bulk exfil/lateral-movement risk rather than either of
  those. Keep that reasoning in mind before changing an existing score —
  the exact number matters less than which of these risk mechanisms it's
  meant to represent. Every vendor shares this table — don't fork it per
  vendor. If the user asks to add/adjust ports, edit this table directly.
- **Implicit permit-any/any synthesis** is ASA-specific logic
  (in `vendors/asa/resolve.js`) modeling the ASA's real default behavior:
  for every interface pair where the source's security level is strictly
  higher than the destination's, if the source has no inbound ACL
  applied, a flagged score-100 "implicit" rule is synthesized. FortiOS
  default-denies inter-zone traffic without an explicit policy, so — as
  this doc predicted — its `resolve.js` does **not** synthesize anything;
  it only scores explicit policies. PAN-OS also default-denies, so the
  same holds there. Confirm with the user before assuming a vendor needs
  an equivalent.
- **FortiOS interface trust (default ordering only).** FortiGate has no
  native numeric security-level like ASA's 0–100. `fortiInterfaceTrust()`
  derives an ordinal from routing and role, in priority order: the
  interface that egresses a **default route** (a `router static` entry
  with no `set dst`, i.e. dst 0.0.0.0/0 — the gateway may be dynamic/DHCP
  with no IP, so the `device` is the signal) is the internet edge and
  scores 0 (least trusted); otherwise `set role` maps wan→0, dmz→50,
  lan→100; an untagged interface defaults to 60 (internal-ish, below
  explicit lan); a zone inherits the minimum trust of its members. This
  feeds `row.defaultOrder.level` only — it is deliberately kept out of the
  risk model (exposure is address-based, not interface-based), same as
  ASA's security-level. The default-route signal was a specific user
  governance decision; don't replace it with role-only detection without
  checking in, since real configs frequently leave `set role` unset on
  internal interfaces. (Note: `defaultOrder.level`/`ifName` no longer drive
  the default *sort* — see next bullet — but the trust ordinal is still
  computed and may be surfaced as a sortable column later.)
- **Default sort order = rulebase order.** Rules are listed exactly as they
  appear in the configuration (first-match evaluation order), via
  `compareDefaultOrder()` sorting on `row.id` (assigned in parse/build
  order). This **reverses** an earlier ASA-specific default that regrouped
  rules most-trusted-interface-first; a user governance decision — a
  firewall's rulebase order is what engineers reason about, and regrouping
  by interface hid where a rule actually sits relative to the denies above
  it (which matters for the buyback's "blocked first" logic). Inactive
  rules keep their position; ASA's synthesized implicit rules sort last
  (they aren't in the config). This is a UI convenience, not part of the
  risk model. Don't reintroduce interface-grouped default sort without
  checking in.
- **Logging classification**: no logging configured, or logging
  explicitly disabled, is flagged; `deny`/block rules without logging are
  flagged at higher severity than `permit`/allow rules without logging,
  since silent denies hide attack/recon traffic. This severity asymmetry
  should carry over to every vendor's `classifyLogging()`.

- **Risk analysis toggle.** A header switch (`#riskToggle`, on by default) puts
  `body.no-risk` on the page; everything score-dependent carries `.risk-only`
  and is hidden by CSS, with small JS guards for sort/filter/CSV/footer/detail.
  Scores are still computed underneath, so flipping back is instant. Purpose:
  clean audit screenshots of the rules.
- **VPN inventory (ASA) is grouped by group-policy.** One collapsible block per
  policy (`DfltGrpPolicy` first, then a `Global / unassigned` block for unused
  pools, users with no resolvable policy and global findings). Tunnel-groups land
  under their `default-group-policy`; users under their `vpn-group-policy`, else
  the group-lock'ed tunnel-group's policy. Blocks are collapsed by default, with
  `+`/`-` per block and Expand all / Collapse all. Vendor-neutral contract: a
  `groups` section type (see `shared/registry.js`).
- **VPN inventory (ASA).** VPN-filter ACEs are scored with direction `'internal'`
  (client = source, internal = destination) and emitted once per distinct
  (ACL, ACE) with a `usedBy` list; they never appear in the main rule table.
  Split tunneling is shown as factual Enabled/Disabled (`tunnelall` = Disabled;
  `tunnelspecified` = Enabled include; `excludespecified` = Enabled exclude;
  unset everywhere = Disabled/default) and is never hidden by the risk toggle.
  RADIUS/LDAP-supplied attributes are not visible in the config; the findings
  section says so.
- **Version.** `VERSION` in `build.js` is stamped into every build's `<title>`
  and header (`{{VERSION}}` in `template.html`). Bump it on each release.

## Testing

Tests live in `tests/` (plain Node, no framework). Install the dev-only
dependency ad hoc — `npm i --no-save jsdom` — then run
`node build.js && node tests/run.js`. Engine tests load the built artifact's
engine script into a `vm` context; UI tests drive the built page in jsdom.
`tests/fixtures/asa-vpn.cfg` is the shared ASA VPN sample.

When changing `source/`
files, the pattern used during ASA development was headless DOM testing
with `jsdom` (not committed as a dependency — install ad hoc if needed):
build the artifact, load it in `jsdom` with `runScripts: 'dangerously'`,
simulate a file drop via a synthetic `File` + `change` event on
`#fileInput`, then assert on the rendered `#ruleTableBody` rows. When
adding a new vendor, write a small representative sample config in that
vendor's syntax (covering: a permit and a deny rule, at least one nested
object-group, an inactive/disabled rule, a rule with and without
logging, and enough interfaces/zones with different trust levels to
exercise default ordering) and run it through this same pattern before
considering the vendor "done."

Before committing changes to shared scoring logic, rebuild
(`node build.js`, with no `--vendor` flag so every vendor's artifact
gets regenerated) and diff the output to confirm the change took effect
in every vendor's build, not just the one you were testing against.

## Style notes

- Vanilla JS throughout, no framework, no build tooling beyond
  `build.js`. Keep it that way — the whole point is a zero-dependency
  file someone can open directly in a browser.
- Dark, monospace-forward UI (CSS variables in `template.html`'s
  `:root`) intentionally modeled on terminal/CLI output — this is a
  tool for engineers reading firewall config data, not a marketing
  surface. Match that register in any UI additions (data-dense tables
  over cards/graphics, mono font for addresses/ports/rule names). Avoid
  vendor-branded colors or iconography in the UI — this tool is
  deliberately vendor-neutral in presentation even though it's
  vendor-aware in parsing.
- HTML escaping: always run user-derived strings (object names, config
  content) through `escapeHtml()` in `ui.js` before interpolating into
  `innerHTML`. The config file is untrusted input, regardless of vendor.
- Keep vendor-specific grammar knowledge inside that vendor's
  `parser.js`/`resolve.js`. If you find yourself wanting to add a
  vendor-name check (`if (vendor === 'fortios')`) inside `ui.js` or
  `shared/`, that's a signal the vendor contract above needs a new field
  instead — raise it with the user rather than special-casing silently.
